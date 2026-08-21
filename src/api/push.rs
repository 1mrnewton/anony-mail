//! Web Push subscription endpoints (docs/06).
//!
//! Reads stay open; subscription writes are owner-token gated so third parties
//! cannot attach or remove notification targets for someone else's inbox. All
//! push routes answer `503` when the server has no VAPID keypair configured.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::authorize_owner;
use super::{ApiError, AppState};
use crate::store::SubscriptionLimit;

/// Browser `PushSubscription.toJSON()` shape.
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub endpoint: String,
    pub keys: SubscriptionKeys,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Debug, Deserialize)]
pub struct UnsubscribeRequest {
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub id: Uuid,
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

/// `POST /api/addresses/{address}/subscriptions` - register a Web Push
/// subscription. Owner-token gated; idempotent per `(mailbox, endpoint)`.
pub async fn subscribe(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
    body: Option<Json<SubscribeRequest>>,
) -> Result<(StatusCode, Json<SubscribeResponse>), ApiError> {
    if !state.config.push_configured() {
        return Err(ApiError::ServiceUnavailable(
            "push not configured".to_string(),
        ));
    }
    let Some(Json(req)) = body else {
        return Err(ApiError::BadRequest(
            "body must be the subscription JSON: { endpoint, keys: { p256dh, auth } }".to_string(),
        ));
    };
    validate_subscription(&req)?;

    let address = address.to_ascii_lowercase();
    authorize_owner(&state, &address, &headers).await?;

    match state
        .store
        .add_subscription(
            &address,
            req.endpoint.trim(),
            req.keys.p256dh.trim(),
            req.keys.auth.trim(),
            state.config.max_subscriptions_per_mailbox,
        )
        .await
    {
        Ok(sub) => Ok((StatusCode::CREATED, Json(SubscribeResponse { id: sub.id }))),
        Err(e) => match e.downcast_ref::<SubscriptionLimit>() {
            Some(limit) => Err(ApiError::TooManyRequests(limit.to_string())),
            None => Err(ApiError::Internal(e)),
        },
    }
}

/// `DELETE /api/addresses/{address}/subscriptions` - unregister by endpoint.
/// Owner-token gated.
pub async fn unsubscribe(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
    body: Option<Json<UnsubscribeRequest>>,
) -> Result<StatusCode, ApiError> {
    if !state.config.push_configured() {
        return Err(ApiError::ServiceUnavailable(
            "push not configured".to_string(),
        ));
    }
    let Some(Json(req)) = body else {
        return Err(ApiError::BadRequest(
            "body must be: { endpoint }".to_string(),
        ));
    };

    let address = address.to_ascii_lowercase();
    authorize_owner(&state, &address, &headers).await?;

    if state
        .store
        .delete_subscription(&address, req.endpoint.trim())
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("subscription not found".to_string()))
    }
}

/// Basic shape checks on a subscription before it hits the database. These are
/// client credentials for third-party push services, so insist on HTTPS and
/// sane sizes.
fn validate_subscription(req: &SubscribeRequest) -> Result<(), ApiError> {
    let endpoint = req.endpoint.trim();
    if !endpoint.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "endpoint must be an https:// push-service URL".to_string(),
        ));
    }
    if endpoint.len() > 2048 {
        return Err(ApiError::BadRequest("endpoint too long".to_string()));
    }
    let p256dh = req.keys.p256dh.trim();
    let auth = req.keys.auth.trim();
    if p256dh.is_empty() || p256dh.len() > 256 || auth.is_empty() || auth.len() > 128 {
        return Err(ApiError::BadRequest(
            "keys.p256dh and keys.auth must be the base64url values from the browser subscription"
                .to_string(),
        ));
    }
    Ok(())
}
