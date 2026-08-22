use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::{authorize_owner, generate_owner_token, hash_token};
use super::limits::client_ip;
use super::{ApiError, AppState, is_unique_violation};
use crate::config::TierPolicy;
use crate::entitlements::Tier;
use crate::model::Mailbox;

const LOCAL_PART_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const RANDOM_LOCAL_PART_LEN: usize = 10;
const MAX_LOCAL_PART_LEN: usize = 64;
const RANDOM_CREATE_ATTEMPTS: usize = 5;

#[derive(Debug, Default, Deserialize)]
pub struct CreateAddressRequest {
    /// Optional custom local part (the bit before `@`). Random if omitted.
    pub local_part: Option<String>,
    /// Optional domain; must be one of the configured domains. Defaults to the
    /// first configured domain.
    pub domain: Option<String>,
}

/// Create response: the mailbox plus its owner token. This is one of exactly
/// two places the raw token ever appears (the other is rotate); clients must
/// store it to authorize extend/delete/subscribe operations.
#[derive(Debug, Serialize)]
pub struct CreateAddressResponse {
    #[serde(flatten)]
    pub mailbox: Mailbox,
    pub owner_token: String,
}

/// Rotate response: the replacement owner token (the old one is now dead).
#[derive(Debug, Serialize)]
pub struct RotateTokenResponse {
    pub owner_token: String,
}

/// `GET /api/domains` - list the domains this server accepts mail for.
pub async fn list_domains(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "domains": state.config.domains }))
}

/// `POST /api/addresses` - create a disposable mailbox.
pub async fn create(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Option<Json<CreateAddressRequest>>,
) -> Result<(StatusCode, Json<CreateAddressResponse>), ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();

    // Attestation gate (docs/09) and tier gate (docs/10), from one token
    // parse. Tier is `None` unless ENTITLEMENTS_ENFORCED; the device hash is
    // recorded whenever the token is attested, scoping per-device caps.
    let client = super::entitlements::attestation_gate(&state, &headers)?;
    let policy: Option<&TierPolicy> = state.config.entitlements_enforced.then(|| {
        let tier = client.as_ref().map(|c| c.tier).unwrap_or(Tier::Free);
        state.config.tier_policy(tier)
    });
    let device_hash = client
        .as_ref()
        .and_then(|c| c.kid.as_deref())
        .map(hash_token);

    let domain = match req.domain {
        Some(d) => {
            let d = d.trim().to_ascii_lowercase();
            if let Some(index) = state.config.domains.iter().position(|x| x == &d) {
                if let Some(policy) = policy {
                    // FREE_DOMAIN_COUNT: only the first N configured domains
                    // (0 = all) are usable on this tier.
                    if policy.domain_count > 0 && index >= policy.domain_count as usize {
                        return Err(ApiError::pro_required(format!(
                            "domain requires a higher tier: {d}"
                        )));
                    }
                }
                d
            } else if state.config.custom_domains_enabled {
                if let Some(policy) = policy
                    && !policy.custom_domains
                {
                    return Err(ApiError::pro_required(
                        "custom domains require a higher tier",
                    ));
                }
                // docs/11: a verified custom domain works too, but only for
                // whoever holds its claim token — otherwise anyone could mint
                // mailboxes on someone else's domain.
                super::custom_domains::authorize_mailbox_on_custom_domain(&state, &d, &headers)
                    .await?;
                d
            } else {
                return Err(ApiError::BadRequest(format!("unknown domain: {d}")));
            }
        }
        None => state.config.domains[0].clone(),
    };

    // Validate the requested local part fully before consuming quota.
    let local = match req.local_part {
        Some(local_part) => {
            let local = local_part.trim().to_ascii_lowercase();
            if !is_valid_local_part(&local) {
                return Err(ApiError::BadRequest(
                    "local_part must be 1-64 chars of a-z, 0-9, '.', '_' or '-' and not start/end with a separator".to_string(),
                ));
            }
            // Role/validation addresses (admin@, postmaster@, ...) would let a
            // user pass CA domain-control checks or intercept operator mail (A1).
            if state.config.is_reserved_local_part(&local) {
                return Err(ApiError::BadRequest(format!(
                    "local_part is reserved: {local}"
                )));
            }
            if let Some(policy) = policy
                && !policy.custom_local_parts
            {
                return Err(ApiError::pro_required(
                    "custom local parts require a higher tier",
                ));
            }
            Some(local)
        }
        None => None,
    };

    // Per-device active-mailbox cap (docs/10 phase 2), enforceable only when
    // the request proves which device it is (attested token). Checked before
    // the daily IP quota so a capped create does not burn quota.
    if let (Some(policy), Some(hash)) = (policy, device_hash.as_deref())
        && policy.active_mailboxes > 0
    {
        let active = state
            .store
            .count_active_mailboxes_by_device(hash, Utc::now())
            .await?;
        if active >= u64::from(policy.active_mailboxes) {
            return Err(ApiError::mailbox_cap(format!(
                "this tier allows {} active mailboxes per device",
                policy.active_mailboxes
            )));
        }
    }

    // Per-IP daily creation quota (A3): every mailbox is a real, spammable
    // resource, so cap how many one client can mint per day.
    let ip = client_ip(&headers, peer.ip(), state.config.api_trust_proxy_headers);
    if !state
        .limits
        .note_address_created(ip, Utc::now().date_naive())
    {
        return Err(ApiError::TooManyRequests(
            "daily address creation limit reached".to_string(),
        ));
    }

    let ttl = Duration::seconds(state.config.default_ttl.as_secs() as i64);
    let expires_at = Utc::now() + ttl;

    // Custom local part: fail loudly on collision.
    if let Some(local) = local {
        let (owner_token, token_hash) = generate_owner_token();
        let address = format!("{local}@{domain}");
        return match state
            .store
            .create_mailbox(
                &address,
                &domain,
                expires_at,
                Some(&token_hash),
                device_hash.as_deref(),
            )
            .await
        {
            Ok(mailbox) => Ok((
                StatusCode::CREATED,
                Json(CreateAddressResponse {
                    mailbox,
                    owner_token,
                }),
            )),
            Err(e) if is_unique_violation(&e) => Err(ApiError::Conflict(format!(
                "address already exists: {address}"
            ))),
            Err(e) => Err(ApiError::Internal(e)),
        };
    }

    // Random local part: retry a few times on the (rare) collision.
    for _ in 0..RANDOM_CREATE_ATTEMPTS {
        let (owner_token, token_hash) = generate_owner_token();
        let address = format!("{}@{}", random_local_part(), domain);
        match state
            .store
            .create_mailbox(
                &address,
                &domain,
                expires_at,
                Some(&token_hash),
                device_hash.as_deref(),
            )
            .await
        {
            Ok(mailbox) => {
                return Ok((
                    StatusCode::CREATED,
                    Json(CreateAddressResponse {
                        mailbox,
                        owner_token,
                    }),
                ));
            }
            Err(e) if is_unique_violation(&e) => continue,
            Err(e) => return Err(ApiError::Internal(e)),
        }
    }
    Err(ApiError::Internal(anyhow::anyhow!(
        "could not allocate a unique random address after {RANDOM_CREATE_ATTEMPTS} attempts"
    )))
}

/// `GET /api/addresses/{address}` - mailbox metadata / existence check.
pub async fn get(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Mailbox>, ApiError> {
    let address = address.to_ascii_lowercase();
    match state.store.get_mailbox(&address).await? {
        Some(mb) => Ok(Json(mb)),
        None => Err(ApiError::NotFound("mailbox not found".to_string())),
    }
}

/// `POST /api/addresses/{address}/extend` - push expiry back by the default
/// TTL. Owner-token gated (A2); the token itself is unchanged by design.
///
/// Under entitlements (docs/10) the total lifetime — new expiry minus
/// creation — is capped per tier (`*_MAX_LIFETIME_SECONDS`, 0 = unlimited).
/// A ceiling, not an extend counter: manual extends stay free, but only pro
/// keeps a mailbox alive past the free window.
pub async fn extend(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Mailbox>, ApiError> {
    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    let mailbox = authorize_owner(&state, &address, &headers).await?;
    let ttl = Duration::seconds(state.config.default_ttl.as_secs() as i64);
    let new_expiry = Utc::now() + ttl;

    if let Some(tier) = super::entitlements::enforced_tier(&state, &headers)? {
        let policy = state.config.tier_policy(tier);
        if policy.max_lifetime_seconds > 0
            && new_expiry - mailbox.created_at
                > Duration::seconds(policy.max_lifetime_seconds as i64)
        {
            return Err(ApiError::lifetime_cap(format!(
                "extending would exceed this tier's max mailbox lifetime of {}s",
                policy.max_lifetime_seconds
            )));
        }
    }

    match state.store.extend_mailbox(&address, new_expiry).await? {
        Some(mb) => Ok(Json(mb)),
        None => Err(ApiError::NotFound("mailbox not found".to_string())),
    }
}

/// `DELETE /api/addresses/{address}` - delete a mailbox and all its messages.
/// Owner-token gated (A2).
pub async fn delete(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;
    if state.store.delete_mailbox(&address).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("mailbox not found".to_string()))
    }
}

/// `POST /api/addresses/{address}/rotate` - reissue the owner token, instantly
/// revoking the old one (A2). For the "my token may have leaked" case.
pub async fn rotate(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RotateTokenResponse>, ApiError> {
    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;
    let (owner_token, token_hash) = generate_owner_token();
    if state
        .store
        .rotate_owner_token(&address, &token_hash)
        .await?
    {
        Ok(Json(RotateTokenResponse { owner_token }))
    } else {
        Err(ApiError::NotFound("mailbox not found".to_string()))
    }
}

fn random_local_part() -> String {
    let mut rng = rand::rng();
    (0..RANDOM_LOCAL_PART_LEN)
        .map(|_| {
            let idx = rng.random_range(0..LOCAL_PART_CHARSET.len());
            LOCAL_PART_CHARSET[idx] as char
        })
        .collect()
}

/// Validate a user-supplied local part: 1-64 chars from `[a-z0-9._-]`, and it
/// may not start or end with a separator (`.`, `_`, `-`).
fn is_valid_local_part(local: &str) -> bool {
    if local.is_empty() || local.len() > MAX_LOCAL_PART_LEN {
        return false;
    }
    let ok_chars = local
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if !ok_chars {
        return false;
    }
    let is_sep = |b: u8| matches!(b, b'.' | b'_' | b'-');
    let bytes = local.as_bytes();
    !is_sep(bytes[0]) && !is_sep(bytes[bytes.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_local_parts_are_well_formed() {
        for _ in 0..100 {
            let lp = random_local_part();
            assert_eq!(lp.len(), RANDOM_LOCAL_PART_LEN);
            assert!(
                is_valid_local_part(&lp),
                "generated invalid local part: {lp}"
            );
        }
    }

    #[test]
    fn validates_local_parts() {
        assert!(is_valid_local_part("john"));
        assert!(is_valid_local_part("john.doe"));
        assert!(is_valid_local_part("a1_b-c"));
        assert!(!is_valid_local_part(""));
        assert!(!is_valid_local_part(".john"));
        assert!(!is_valid_local_part("john."));
        assert!(!is_valid_local_part("John")); // uppercase not allowed (callers lowercase first)
        assert!(!is_valid_local_part("a b"));
        assert!(!is_valid_local_part("a@b"));
        assert!(!is_valid_local_part(&"x".repeat(65)));
    }
}
