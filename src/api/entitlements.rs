//! Entitlement endpoints and the per-request tier/attestation gates
//! (docs/09 + docs/10).
//!
//! `POST /api/entitlements/verify` turns an anonymous RevenueCat app-user id
//! into a short-lived signed client token whose `tier` claim the write
//! handlers enforce. The route is live whenever `TOKEN_SIGNING_KEY` is set
//! (503 otherwise, mirroring the push routes); `ENTITLEMENTS_ENFORCED` only
//! controls whether anything checks the token. When
//! `CLIENT_ATTESTATION_REQUIRED` is on, minting moves to the attested
//! `/api/client/*` flow and this route (like every mutation) demands an
//! attested token.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{ApiError, AppState};
use crate::entitlements::{
    CLIENT_TOKEN_TTL_SECONDS, ClientClaims, KIND_UNATTESTED, Tier, TokenError, mint_client_token,
    verify_client_token,
};

/// Header carrying the signed client token. `Authorization` stays reserved
/// for mailbox owner tokens (`am_…`) and domain claim tokens (`amd_…`).
pub const CLIENT_TOKEN_HEADER: &str = "x-client-token";

#[derive(Debug, Default, Deserialize)]
pub struct VerifyRequest {
    /// The app's anonymous RevenueCat app-user id. Omit it (or the whole
    /// body) to mint a free-tier token.
    pub rc_app_user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// Send as `X-Client-Token` on writes while it is valid.
    pub client_token: String,
    pub tier: Tier,
    pub expires_at: DateTime<Utc>,
}

/// `POST /api/entitlements/verify` - check the purchase and mint a tier
/// token. No token or RevenueCat id means free; pro comes only from an
/// active entitlement.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<VerifyRequest>>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let Some(signing_key) = state.config.token_signing_key.as_deref() else {
        return Err(ApiError::ServiceUnavailable(
            "entitlements are not configured on this server".to_string(),
        ));
    };
    // Tier minting must itself be attested when the flag is on (docs/09) —
    // otherwise this open route would hand out tokens that defeat the gate.
    attestation_gate(&state, &headers)?;
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let tier = resolve_tier(&state, req.rc_app_user_id.as_deref()).await?;
    let (client_token, expires_at) = mint_client_token(
        signing_key,
        KIND_UNATTESTED,
        None,
        tier,
        Duration::seconds(CLIENT_TOKEN_TTL_SECONDS),
    )?;
    Ok(Json(VerifyResponse {
        client_token,
        tier,
        expires_at,
    }))
}

/// Resolve the tier for a purchase id: pro only from an active RevenueCat
/// entitlement. RevenueCat outages are a 503 so clients keep their current
/// token and retry, rather than being silently downgraded.
pub async fn resolve_tier(
    state: &AppState,
    rc_app_user_id: Option<&str>,
) -> Result<Tier, ApiError> {
    let rc_id = rc_app_user_id.map(str::trim).filter(|s| !s.is_empty());
    match (rc_id, &state.pro) {
        (Some(id), Some(pro)) => match pro.is_pro(id).await {
            Ok(true) => Ok(Tier::Pro),
            Ok(false) => Ok(Tier::Free),
            Err(e) => {
                tracing::warn!(error = %e, "entitlement verification failed");
                Err(ApiError::ServiceUnavailable(
                    "entitlement verification is temporarily unavailable, retry later".to_string(),
                ))
            }
        },
        // No RevenueCat key on the server, or no purchase id from the
        // client: free tier by definition.
        _ => Ok(Tier::Free),
    }
}

/// Parse and verify the request's `X-Client-Token`, if any. `Ok(None)` when
/// the header is absent (unauthenticated free tier is a normal state) or
/// when this server has no signing key (a stray token means nothing here).
/// Expired or forged tokens are coded 401s so the app knows to refresh.
pub fn client_claims(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<ClientClaims>, ApiError> {
    let Some(raw) = headers
        .get(CLIENT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let Some(signing_key) = state.config.token_signing_key.as_deref() else {
        return Ok(None);
    };
    match verify_client_token(signing_key, raw) {
        Ok(claims) => Ok(Some(claims)),
        Err(TokenError::Expired) => Err(ApiError::Coded {
            status: StatusCode::UNAUTHORIZED,
            code: "client_token_expired",
            message: "client token expired, refresh it and retry".to_string(),
        }),
        Err(TokenError::Invalid) => Err(ApiError::Coded {
            status: StatusCode::UNAUTHORIZED,
            code: "client_token_invalid",
            message: "client token invalid".to_string(),
        }),
    }
}

/// The attestation gate for mutating handlers (docs/09). When
/// `CLIENT_ATTESTATION_REQUIRED` is on, the request must carry a valid
/// client token minted by the attested `/api/client/*` flow; unattested
/// tokens (and no token) are rejected with a coded 401. Returns the parsed
/// claims so handlers can reuse the tier and device key without re-verifying.
pub fn attestation_gate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<ClientClaims>, ApiError> {
    let claims = client_claims(state, headers)?;
    if !state.config.client_attestation_required {
        return Ok(claims);
    }
    match claims {
        Some(c) if c.is_attested() => Ok(Some(c)),
        _ => Err(ApiError::Coded {
            status: StatusCode::UNAUTHORIZED,
            code: "attestation_required",
            message: "this server requires an attested client token; \
                      obtain one via POST /api/client/attest"
                .to_string(),
        }),
    }
}

/// Effective tier of a request: the `tier` claim of a valid `X-Client-Token`,
/// or free when the header is absent.
pub fn client_tier(state: &AppState, headers: &HeaderMap) -> Result<Tier, ApiError> {
    Ok(client_claims(state, headers)?
        .map(|c| c.tier)
        .unwrap_or(Tier::Free))
}

/// The tier gate for write handlers: resolves the request's tier when
/// enforcement is on, `None` when it is off (no checks apply at all).
pub fn enforced_tier(state: &AppState, headers: &HeaderMap) -> Result<Option<Tier>, ApiError> {
    if !state.config.entitlements_enforced {
        return Ok(None);
    }
    client_tier(state, headers).map(Some)
}
