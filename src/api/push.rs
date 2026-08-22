//! Push subscription endpoints (docs/06) for both channels: Web Push
//! (browsers/PWAs, VAPID) and APNs (native iOS apps).
//!
//! Reads stay open; subscription writes are owner-token gated so third parties
//! cannot attach or remove notification targets for someone else's inbox.
//! Subscribing to a channel the server has no credentials for answers `503`;
//! unsubscribing always works so clients can clean up after reconfiguration.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;
use uuid::Uuid;

use super::auth::authorize_owner;
use super::{ApiError, AppState};
use crate::model::SubscriptionKind;
use crate::store::SubscriptionLimit;

/// Subscription registration. Two shapes share one endpoint:
///
/// - Web Push (browser `PushSubscription.toJSON()`): `{ endpoint, keys }`
/// - APNs (native app): `{ device_token }` (optionally `kind: "apns"`)
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub kind: Option<SubscriptionKind>,
    pub endpoint: Option<String>,
    pub keys: Option<SubscriptionKeys>,
    pub device_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

/// Unregister by whichever identifier the client holds: the push-service
/// `endpoint` (Web Push) or the `device_token` (APNs).
#[derive(Debug, Deserialize)]
pub struct UnsubscribeRequest {
    pub endpoint: Option<String>,
    pub device_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub id: Uuid,
    pub kind: SubscriptionKind,
}

/// `GET /api/push/config` - which push channels this server can deliver on.
/// Lets clients decide whether to prompt for notification permission at all.
pub async fn config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "webpush": state.config.push_configured(),
        "apns": state.config.apns_configured(),
    }))
}

/// `GET /api/push/vapid-public-key` - the key clients pass as
/// `applicationServerKey` when calling `PushManager.subscribe`.
pub async fn vapid_public_key(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    match &state.config.vapid_public_key {
        Some(key) => Ok(Json(json!({ "vapid_public_key": key }))),
        None => Err(ApiError::ServiceUnavailable(
            "push not configured".to_string(),
        )),
    }
}

/// `POST /api/addresses/{address}/subscriptions` - register a push
/// subscription of either kind. Owner-token gated; idempotent per
/// `(mailbox, endpoint/token)`.
pub async fn subscribe(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
    body: Option<Json<SubscribeRequest>>,
) -> Result<(StatusCode, Json<SubscribeResponse>), ApiError> {
    let Some(Json(req)) = body else {
        return Err(ApiError::BadRequest(
            "body must be either { endpoint, keys: { p256dh, auth } } (webpush) \
             or { device_token } (apns)"
                .to_string(),
        ));
    };
    let (kind, endpoint, p256dh, auth) = validate_subscription(&req)?;

    match kind {
        SubscriptionKind::WebPush if !state.config.push_configured() => {
            return Err(ApiError::ServiceUnavailable(
                "web push not configured".to_string(),
            ));
        }
        SubscriptionKind::Apns if !state.config.apns_configured() => {
            return Err(ApiError::ServiceUnavailable(
                "apns not configured".to_string(),
            ));
        }
        _ => {}
    }

    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;

    match state
        .store
        .add_subscription(
            &address,
            kind,
            endpoint,
            p256dh,
            auth,
            state.config.max_subscriptions_per_mailbox,
        )
        .await
    {
        Ok(sub) => {
            info!(
                address = %address,
                kind = kind.as_str(),
                "push subscription registered"
            );
            Ok((
                StatusCode::CREATED,
                Json(SubscribeResponse {
                    id: sub.id,
                    kind: sub.kind,
                }),
            ))
        }
        Err(e) => match e.downcast_ref::<SubscriptionLimit>() {
            Some(limit) => Err(ApiError::TooManyRequests(limit.to_string())),
            None => Err(ApiError::Internal(e)),
        },
    }
}

/// `DELETE /api/addresses/{address}/subscriptions` - unregister by endpoint or
/// device token. Owner-token gated. Deliberately not gated on push being
/// configured: removal must work even after the server loses its credentials.
pub async fn unsubscribe(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
    body: Option<Json<UnsubscribeRequest>>,
) -> Result<StatusCode, ApiError> {
    let identifier = body
        .as_ref()
        .and_then(|Json(req)| req.endpoint.as_deref().or(req.device_token.as_deref()))
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(identifier) = identifier else {
        return Err(ApiError::BadRequest(
            "body must be: { endpoint } or { device_token }".to_string(),
        ));
    };

    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;

    if state
        .store
        .delete_subscription(&address, identifier)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("subscription not found".to_string()))
    }
}

/// Determine the subscription kind and validate its fields. These are client
/// credentials for third-party push services, so insist on HTTPS and sane
/// sizes. Returns `(kind, endpoint_or_token, p256dh, auth)`.
fn validate_subscription(
    req: &SubscribeRequest,
) -> Result<(SubscriptionKind, &str, &str, &str), ApiError> {
    // Infer the kind when absent: exactly one of endpoint/device_token.
    let kind = match req.kind {
        Some(k) => k,
        None => match (&req.endpoint, &req.device_token) {
            (Some(_), None) => SubscriptionKind::WebPush,
            (None, Some(_)) => SubscriptionKind::Apns,
            _ => {
                return Err(ApiError::BadRequest(
                    "provide either endpoint+keys (webpush) or device_token (apns)".to_string(),
                ));
            }
        },
    };

    match kind {
        SubscriptionKind::WebPush => {
            let endpoint = req
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ApiError::BadRequest("webpush subscriptions require endpoint".to_string())
                })?;
            if !endpoint.starts_with("https://") {
                return Err(ApiError::BadRequest(
                    "endpoint must be an https:// push-service URL".to_string(),
                ));
            }
            if endpoint.len() > 2048 {
                return Err(ApiError::BadRequest("endpoint too long".to_string()));
            }
            let keys = req.keys.as_ref().ok_or_else(|| {
                ApiError::BadRequest(
                    "webpush subscriptions require keys: { p256dh, auth }".to_string(),
                )
            })?;
            let p256dh = keys.p256dh.trim();
            let auth = keys.auth.trim();
            if p256dh.is_empty() || p256dh.len() > 256 || auth.is_empty() || auth.len() > 128 {
                return Err(ApiError::BadRequest(
                    "keys.p256dh and keys.auth must be the base64url values from the browser subscription"
                        .to_string(),
                ));
            }
            Ok((kind, endpoint, p256dh, auth))
        }
        SubscriptionKind::Apns => {
            let token = req
                .device_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ApiError::BadRequest("apns subscriptions require device_token".to_string())
                })?;
            if token.len() > 200 || token.chars().any(char::is_whitespace) {
                return Err(ApiError::BadRequest(
                    "device_token must be the hex token from didRegisterForRemoteNotifications"
                        .to_string(),
                ));
            }
            Ok((kind, token, "", ""))
        }
    }
}
