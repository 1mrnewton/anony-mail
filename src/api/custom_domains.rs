//! Custom-domain endpoints (docs/11): claim, inspect, verify, release.
//!
//! All routes except create are gated by the domain's `amd_…` claim token,
//! returned exactly once by the create call. Mounted only when
//! `CUSTOM_DOMAINS_ENABLED` is on (the default); disabled servers 404 and
//! advertise `"custom_domains": false` via `GET /api/capabilities`.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::Serialize;

use super::auth::{DOMAIN_TOKEN_PREFIX, bearer_token, generate_token, token_matches_hash};
use super::limits::client_ip;
use super::{ApiError, AppState, is_unique_violation};
use crate::custom_domains::{
    DnsCheck, check_and_record, generate_txt_token, txt_value, validate_claimable,
};
use crate::model::{CustomDomain, CustomDomainStatus};

#[derive(Debug, Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
}

/// Custom-domain resource as rendered to clients. `claim_token` appears only
/// in the create response; `checks` only in verify responses.
#[derive(Debug, Serialize)]
pub struct CustomDomainResponse {
    pub domain: String,
    pub status: CustomDomainStatus,
    /// Value to publish at `_anonymail.<domain>` as a TXT record.
    pub txt_record: String,
    /// Host the domain's MX record must point at.
    pub mx_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<DnsCheck>>,
}

impl CustomDomainResponse {
    fn new(state: &AppState, record: &CustomDomain) -> Self {
        Self {
            domain: record.domain.clone(),
            status: record.status,
            txt_record: txt_value(&record.txt_token),
            mx_target: state.config.smtp_hostname.to_ascii_lowercase(),
            claim_token: None,
            verified_at: record.verified_at,
            checks: None,
        }
    }
}

/// `POST /api/custom-domains` - claim a domain. Returns the DNS records to
/// publish and the one-time `amd_…` claim token that owns the claim.
pub async fn create(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<CustomDomainResponse>), ApiError> {
    super::entitlements::attestation_gate(&state, &headers)?;
    // Tier gate (docs/10): claiming a domain is the custom-domains feature's
    // entry point, so this is where FREE_CUSTOM_DOMAINS bites.
    if let Some(tier) = super::entitlements::enforced_tier(&state, &headers)?
        && !state.config.tier_policy(tier).custom_domains
    {
        return Err(ApiError::pro_required(
            "custom domains require a higher tier",
        ));
    }

    let domain = validate_claimable(&state.config, &req.domain).map_err(ApiError::BadRequest)?;

    // Claims are cheap to mint and hold a permanent name, so cap them harder
    // than mailboxes (A3).
    let ip = client_ip(&headers, peer.ip(), state.config.api_trust_proxy_headers);
    if !state
        .limits
        .note_domain_created(ip, Utc::now().date_naive())
    {
        return Err(ApiError::TooManyRequests(
            "daily custom-domain limit reached".to_string(),
        ));
    }

    let (claim_token, claim_token_hash) = generate_token(DOMAIN_TOKEN_PREFIX);
    let txt_token = generate_txt_token();
    match state
        .store
        .create_custom_domain(&domain, &claim_token_hash, &txt_token)
        .await
    {
        Ok(record) => {
            let mut response = CustomDomainResponse::new(&state, &record);
            response.claim_token = Some(claim_token);
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(e) if is_unique_violation(&e) => Err(ApiError::Conflict(format!(
            "domain already claimed: {domain}"
        ))),
        Err(e) => Err(ApiError::Internal(e)),
    }
}

/// `GET /api/custom-domains/{domain}` - claim status and the DNS records to
/// publish. Claim-token gated.
pub async fn get(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    let record = authorize_domain(&state, &domain, &headers).await?;
    Ok(Json(CustomDomainResponse::new(&state, &record)))
}

/// `POST /api/custom-domains/{domain}/verify` - run the DNS checks now and
/// persist the outcome. Claim-token gated and throttled per domain (the run
/// costs live DNS lookups).
pub async fn verify(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CustomDomainResponse>, ApiError> {
    super::entitlements::attestation_gate(&state, &headers)?;
    let record = authorize_domain(&state, &domain, &headers).await?;
    if !state.limits.try_begin_domain_verify(&record.domain) {
        return Err(ApiError::TooManyRequests(
            "verification already ran moments ago, retry shortly".to_string(),
        ));
    }

    let (checks, status, verified_at) = check_and_record(
        state.store.as_ref(),
        state.dns.as_ref(),
        &state.config,
        &record,
    )
    .await?;

    let mut response = CustomDomainResponse::new(&state, &record);
    response.status = status;
    response.verified_at = verified_at;
    response.checks = Some(checks);
    Ok(Json(response))
}

/// `DELETE /api/custom-domains/{domain}` - release the claim. Mail and new
/// mailbox creation stop immediately; existing mailboxes live out their TTL.
/// Claim-token gated.
pub async fn delete(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    super::entitlements::attestation_gate(&state, &headers)?;
    let record = authorize_domain(&state, &domain, &headers).await?;
    if state.store.delete_custom_domain(&record.domain).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("domain not found".to_string()))
    }
}

/// Authorize a claim-token-gated operation on `domain`. Mirrors
/// [`super::auth::authorize_owner`]: `404` when the claim doesn't exist,
/// `401` for a missing or wrong token.
async fn authorize_domain(
    state: &AppState,
    domain: &str,
    headers: &HeaderMap,
) -> Result<CustomDomain, ApiError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let record = state
        .store
        .get_custom_domain(&domain)
        .await?
        .ok_or_else(|| ApiError::NotFound("domain not found".to_string()))?;

    let presented = bearer_token(headers)
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".to_string()))?;
    if token_matches_hash(presented, &record.claim_token_hash) {
        Ok(record)
    } else {
        Err(ApiError::Unauthorized("invalid claim token".to_string()))
    }
}

/// Gate for creating a mailbox on a custom domain (docs/11): the domain must
/// be claimed, `verified`, and the request must carry its claim token.
pub async fn authorize_mailbox_on_custom_domain(
    state: &AppState,
    domain: &str,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let record = state
        .store
        .get_custom_domain(domain)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("unknown domain: {domain}")))?;

    let presented = bearer_token(headers).ok_or_else(|| {
        ApiError::Unauthorized("custom domains require their claim token".to_string())
    })?;
    if !token_matches_hash(presented, &record.claim_token_hash) {
        return Err(ApiError::Unauthorized("invalid claim token".to_string()));
    }
    if record.status != CustomDomainStatus::Verified {
        return Err(ApiError::BadRequest(format!(
            "domain not verified: {domain}"
        )));
    }
    Ok(())
}
