use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::{authorize_owner, generate_owner_token};
use super::limits::client_ip;
use super::{ApiError, AppState, is_unique_violation};
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

    let domain = match req.domain {
        Some(d) => {
            let d = d.trim().to_ascii_lowercase();
            if !state.config.accepts_domain(&d) {
                return Err(ApiError::BadRequest(format!("unknown domain: {d}")));
            }
            d
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
            Some(local)
        }
        None => None,
    };

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
            .create_mailbox(&address, &domain, expires_at, Some(&token_hash))
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
            .create_mailbox(&address, &domain, expires_at, Some(&token_hash))
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
pub async fn extend(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Mailbox>, ApiError> {
    let address = address.to_ascii_lowercase();
    authorize_owner(&state, &address, &headers).await?;
    let ttl = Duration::seconds(state.config.default_ttl.as_secs() as i64);
    let new_expiry = Utc::now() + ttl;
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
