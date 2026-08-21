//! Handler-level tests for the Web Push endpoints (docs/06): 503 when
//! unconfigured, owner-token gating, subscribe/unsubscribe flow, and the
//! per-mailbox cap.

use std::sync::Arc;

use anony_mail::api::push::{
    SubscribeRequest, SubscriptionKeys, UnsubscribeRequest, subscribe, unsubscribe,
    vapid_public_key,
};
use anony_mail::api::{ApiError, AppState};
use anony_mail::config::Config;
use anony_mail::events::EventBus;
use anony_mail::store::MemoryStore;
use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use chrono::{Duration, Utc};

const TOKEN: &str = "am_test-owner-token";

fn state_with_push(configured: bool) -> AppState {
    let mut config = Config {
        domains: vec!["example.com".to_string()],
        database_url: "sqlite://unused-in-tests".to_string(),
        max_subscriptions_per_mailbox: 2,
        ..Config::default()
    };
    if configured {
        config.vapid_public_key = Some("test-public-key".to_string());
        config.vapid_private_key = Some("test-private-key".to_string());
    }
    AppState::new(
        Arc::new(MemoryStore::new()),
        Arc::new(config),
        EventBus::new(16),
    )
}

async fn owned_mailbox(state: &AppState, addr: &str) {
    let hash = anony_mail::api::auth::hash_token(TOKEN);
    state
        .store
        .create_mailbox(
            addr,
            "example.com",
            Utc::now() + Duration::hours(1),
            Some(&hash),
        )
        .await
        .unwrap();
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

fn sub_request(endpoint: &str) -> SubscribeRequest {
    SubscribeRequest {
        endpoint: endpoint.to_string(),
        keys: SubscriptionKeys {
            p256dh: "BPubKey".to_string(),
            auth: "authsecret".to_string(),
        },
    }
}

#[tokio::test]
async fn push_routes_answer_503_when_unconfigured() {
    let state = state_with_push(false);
    owned_mailbox(&state, "inbox@example.com").await;

    match vapid_public_key(State(state.clone())).await {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("vapid key without config must be 503"),
    }
    match subscribe(
        State(state.clone()),
        AxumPath("inbox@example.com".to_string()),
        bearer(TOKEN),
        Some(Json(sub_request("https://push.example/ep"))),
    )
    .await
    {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("subscribe without config must be 503"),
    }
    match unsubscribe(
        State(state),
        AxumPath("inbox@example.com".to_string()),
        bearer(TOKEN),
        Some(Json(UnsubscribeRequest {
            endpoint: "https://push.example/ep".to_string(),
        })),
    )
    .await
    {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("unsubscribe without config must be 503"),
    }
}

#[tokio::test]
async fn vapid_public_key_is_served_when_configured() {
    let state = state_with_push(true);
    let Ok(Json(body)) = vapid_public_key(State(state)).await else {
        panic!("configured vapid key must be served");
    };
    assert_eq!(body["vapid_public_key"], "test-public-key");
}

#[tokio::test]
async fn subscription_writes_are_owner_gated() {
    let state = state_with_push(true);
    let addr = "inbox@example.com";
    owned_mailbox(&state, addr).await;

    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        HeaderMap::new(),
        Some(Json(sub_request("https://push.example/ep"))),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("subscribe without token must be 401"),
    }
    match unsubscribe(
        State(state),
        AxumPath(addr.to_string()),
        bearer("am_wrong"),
        Some(Json(UnsubscribeRequest {
            endpoint: "https://push.example/ep".to_string(),
        })),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("unsubscribe with wrong token must be 401"),
    }
}

#[tokio::test]
async fn subscribe_unsubscribe_roundtrip_and_cap() {
    let state = state_with_push(true);
    let addr = "inbox@example.com";
    owned_mailbox(&state, addr).await;

    // Non-HTTPS endpoints are rejected before touching the store.
    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(sub_request("http://insecure.example/ep"))),
    )
    .await
    {
        Err(ApiError::BadRequest(_)) => {}
        _ => panic!("non-https endpoint must be rejected"),
    }

    let (status, _) = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(sub_request("https://push.example/ep1"))),
    )
    .await
    .expect("first subscribe succeeds");
    assert_eq!(status, StatusCode::CREATED);

    let _ = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(sub_request("https://push.example/ep2"))),
    )
    .await
    .expect("second subscribe succeeds");

    // Cap is 2 in this config; the third distinct endpoint is refused.
    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(sub_request("https://push.example/ep3"))),
    )
    .await
    {
        Err(ApiError::TooManyRequests(msg)) => {
            assert!(msg.contains("limit"), "unhelpful message: {msg}")
        }
        _ => panic!("subscription over the cap must be 429"),
    }

    let status = unsubscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(UnsubscribeRequest {
            endpoint: "https://push.example/ep1".to_string(),
        })),
    )
    .await
    .expect("unsubscribe succeeds");
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Unknown endpoint → 404.
    match unsubscribe(
        State(state),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(UnsubscribeRequest {
            endpoint: "https://push.example/ep1".to_string(),
        })),
    )
    .await
    {
        Err(ApiError::NotFound(_)) => {}
        _ => panic!("unsubscribing an unknown endpoint must be 404"),
    }
}
