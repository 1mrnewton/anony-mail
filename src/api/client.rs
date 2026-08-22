//! App Attest endpoints (docs/09): challenge issuance, one-time device
//! attestation, and assertion-based token refresh.
//!
//! Live whenever App Attest is *configured* (`APP_ATTEST_TEAM_ID` +
//! `_BUNDLE_ID` + `TOKEN_SIGNING_KEY`), 503 otherwise — the push-route
//! convention. `CLIENT_ATTESTATION_REQUIRED` only controls whether mutations
//! demand the resulting token, so devices can attest ahead of the
//! enforcement flip. All three routes share the strict create-route rate
//! budget.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::entitlements::resolve_tier;
use super::{ApiError, AppState};
use crate::attest::{self, CHALLENGE_TTL_SECONDS};
use crate::entitlements::{CLIENT_TOKEN_TTL_SECONDS, KIND_IOS, Tier, mint_client_token};

/// Reasonable ceiling on the base64 App Attest key id (real ones are 44
/// chars: base64 of 32 bytes).
const MAX_KEY_ID_LEN: usize = 64;

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// Single-use, expires after `expires_in` seconds. Hash it (SHA-256 of
    /// the UTF-8 string) into `clientDataHash` for attest/assert.
    pub challenge: String,
    pub expires_in: u64,
}

/// `POST /api/client/challenge` — issue a single-use attestation challenge.
pub async fn challenge(State(state): State<AppState>) -> Result<Json<ChallengeResponse>, ApiError> {
    require_configured(&state)?;
    Ok(Json(ChallengeResponse {
        challenge: state.challenges.issue(),
        expires_in: CHALLENGE_TTL_SECONDS,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    /// Base64 App Attest key id from `DCAppAttestService.generateKey`.
    pub key_id: String,
    /// Base64 CBOR attestation object from `attestKey`.
    pub attestation: String,
    /// The challenge the attestation was produced against.
    pub challenge: String,
    /// Optional RevenueCat app-user id for the tier check (docs/10).
    pub rc_app_user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClientTokenResponse {
    /// Send as `X-Client-Token` on writes while it is valid.
    pub client_token: String,
    pub tier: Tier,
    pub expires_at: DateTime<Utc>,
}

/// `POST /api/client/attest` — verify a one-time attestation, register the
/// device key, and mint an attested client token.
pub async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<ClientTokenResponse>, ApiError> {
    let app_id = require_configured(&state)?;
    validate_key_id(&req.key_id)?;
    consume_challenge(&state, &req.challenge)?;

    let public_key = attest::verify_attestation(
        &app_id,
        root_pem(&state),
        &req.challenge,
        &req.key_id,
        &req.attestation,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "attestation rejected");
        ApiError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_attestation",
            message: e.to_string(),
        }
    })?;

    state
        .store
        .upsert_attested_device(&req.key_id, &public_key, Utc::now())
        .await?;
    tracing::info!("device attested");

    mint(&state, &req.key_id, req.rc_app_user_id.as_deref()).await
}

#[derive(Debug, Deserialize)]
pub struct AssertRequest {
    /// Base64 App Attest key id registered via a previous attest.
    pub key_id: String,
    /// Base64 CBOR assertion from `generateAssertion`.
    pub assertion: String,
    /// The challenge the assertion was produced against.
    pub challenge: String,
    /// Optional RevenueCat app-user id for the tier check (docs/10).
    pub rc_app_user_id: Option<String>,
}

/// `POST /api/client/assert` — refresh an attested client token by proving
/// possession of the registered device key. The assertion counter must
/// strictly increase, which blocks replay.
pub async fn assert(
    State(state): State<AppState>,
    Json(req): Json<AssertRequest>,
) -> Result<Json<ClientTokenResponse>, ApiError> {
    let app_id = require_configured(&state)?;
    validate_key_id(&req.key_id)?;
    consume_challenge(&state, &req.challenge)?;

    let Some(device) = state.store.get_attested_device(&req.key_id).await? else {
        // Unknown key: pruned, never attested, or another server's. The fix
        // is the same as for a missing token — run the attest flow.
        return Err(ApiError::Coded {
            status: StatusCode::UNAUTHORIZED,
            code: "attestation_required",
            message: "unknown key id, attest this device first".to_string(),
        });
    };

    let new_counter = attest::verify_assertion(
        &app_id,
        &req.challenge,
        &req.assertion,
        &device.public_key,
        device.counter,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "assertion rejected");
        ApiError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_assertion",
            message: e.to_string(),
        }
    })?;

    // The strictly-monotonic write is the serialization point: if a
    // concurrent assertion for the same key already advanced the counter,
    // this one loses and must retry with a fresh challenge.
    let advanced = state
        .store
        .advance_attested_device_counter(&req.key_id, new_counter, Utc::now())
        .await?;
    if !advanced {
        return Err(ApiError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_assertion",
            message: "assertion counter conflict, retry with a fresh challenge".to_string(),
        });
    }

    mint(&state, &req.key_id, req.rc_app_user_id.as_deref()).await
}

/// 503 unless App Attest is configured; returns the expected app id.
fn require_configured(state: &AppState) -> Result<String, ApiError> {
    state.config.app_attest_app_id().ok_or_else(|| {
        ApiError::ServiceUnavailable("app attestation is not configured on this server".to_string())
    })
}

fn root_pem(state: &AppState) -> &[u8] {
    state
        .config
        .app_attest_root_pem
        .as_deref()
        .unwrap_or(attest::APPLE_ROOT_CA_PEM)
}

fn validate_key_id(key_id: &str) -> Result<(), ApiError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(ApiError::BadRequest("invalid key_id".to_string()));
    }
    Ok(())
}

fn consume_challenge(state: &AppState, challenge: &str) -> Result<(), ApiError> {
    if !state.challenges.consume(challenge) {
        return Err(ApiError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_challenge",
            message: "challenge unknown, expired, or already used; request a new one".to_string(),
        });
    }
    Ok(())
}

/// Resolve the tier and mint an attested token carrying the device key id.
async fn mint(
    state: &AppState,
    key_id: &str,
    rc_app_user_id: Option<&str>,
) -> Result<Json<ClientTokenResponse>, ApiError> {
    let signing_key = state.config.token_signing_key.as_deref().ok_or_else(|| {
        // Boot validation ties APP_ATTEST_* to TOKEN_SIGNING_KEY, so this is
        // unreachable in practice.
        ApiError::ServiceUnavailable("token signing is not configured".to_string())
    })?;
    let tier = resolve_tier(state, rc_app_user_id).await?;
    let (client_token, expires_at) = mint_client_token(
        signing_key,
        KIND_IOS,
        Some(key_id),
        tier,
        Duration::seconds(CLIENT_TOKEN_TTL_SECONDS),
    )?;
    Ok(Json(ClientTokenResponse {
        client_token,
        tier,
        expires_at,
    }))
}
