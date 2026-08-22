//! Handler-level tests for the push endpoints (docs/06): 503 when the target
//! channel is unconfigured, owner-token gating, subscribe/unsubscribe flows
//! for both kinds, the per-mailbox cap, and channel discovery.

use std::sync::Arc;

use anony_mail::api::push::{
    SubscribeRequest, SubscriptionKeys, UnsubscribeRequest, config as push_config, subscribe,
    unsubscribe, vapid_public_key,
};
use anony_mail::api::{ApiError, AppState};
use anony_mail::config::Config;
use anony_mail::events::EventBus;
use anony_mail::model::SubscriptionKind;
use anony_mail::store::MemoryStore;
use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use chrono::{Duration, Utc};

const TOKEN: &str = "am_test-owner-token";

fn state_with(webpush: bool, apns: bool) -> AppState {
    let mut config = Config {
        domains: vec!["example.com".to_string()],
        database_url: "sqlite://unused-in-tests".to_string(),
        max_subscriptions_per_mailbox: 2,
        ..Config::default()
    };
    if webpush {
        config.vapid_public_key = Some("test-public-key".to_string());
        config.vapid_private_key = Some("test-private-key".to_string());
    }
    if apns {
        config.apns_team_id = Some("TEAMID1234".to_string());
        config.apns_key_id = Some("KEYID12345".to_string());
        config.apns_private_key = Some("-----BEGIN PRIVATE KEY-----".to_string());
        config.apns_topic = Some("com.example.anonymail".to_string());
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
            None,
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

fn web_request(endpoint: &str) -> SubscribeRequest {
    SubscribeRequest {
        kind: None,
        endpoint: Some(endpoint.to_string()),
        keys: Some(SubscriptionKeys {
            p256dh: "BPubKey".to_string(),
            auth: "authsecret".to_string(),
        }),
        device_token: None,
    }
}

fn apns_request(token: &str) -> SubscribeRequest {
    SubscribeRequest {
        kind: None,
        endpoint: None,
        keys: None,
        device_token: Some(token.to_string()),
    }
}

fn unsub_endpoint(endpoint: &str) -> UnsubscribeRequest {
    UnsubscribeRequest {
        endpoint: Some(endpoint.to_string()),
        device_token: None,
    }
}

#[tokio::test]
async fn push_config_reports_enabled_channels() {
    let Json(none) = push_config(State(state_with(false, false))).await;
    assert_eq!(none["webpush"], false);
    assert_eq!(none["apns"], false);

    let Json(both) = push_config(State(state_with(true, true))).await;
    assert_eq!(both["webpush"], true);
    assert_eq!(both["apns"], true);

    let Json(apns_only) = push_config(State(state_with(false, true))).await;
    assert_eq!(apns_only["webpush"], false);
    assert_eq!(apns_only["apns"], true);
}

#[tokio::test]
async fn subscribing_an_unconfigured_channel_answers_503() {
    let state = state_with(false, false);
    owned_mailbox(&state, "inbox@example.com").await;

    match vapid_public_key(State(state.clone())).await {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("vapid key without config must be 503"),
    }
    match subscribe(
        State(state.clone()),
        AxumPath("inbox@example.com".to_string()),
        bearer(TOKEN),
        Some(Json(web_request("https://push.example/ep"))),
    )
    .await
    {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("webpush subscribe without VAPID must be 503"),
    }
    match subscribe(
        State(state.clone()),
        AxumPath("inbox@example.com".to_string()),
        bearer(TOKEN),
        Some(Json(apns_request("cafebabe"))),
    )
    .await
    {
        Err(ApiError::ServiceUnavailable(_)) => {}
        _ => panic!("apns subscribe without APNs credentials must be 503"),
    }

    // A webpush-only server still refuses apns subscriptions.
    let state = state_with(true, false);
    owned_mailbox(&state, "other@example.com").await;
    match subscribe(
        State(state),
        AxumPath("other@example.com".to_string()),
        bearer(TOKEN),
        Some(Json(apns_request("cafebabe"))),
    )
    .await
    {
        Err(ApiError::ServiceUnavailable(msg)) => {
            assert!(msg.contains("apns"), "unhelpful message: {msg}")
        }
        _ => panic!("apns subscribe on a webpush-only server must be 503"),
    }
}

#[tokio::test]
async fn unsubscribe_works_even_when_push_is_unconfigured() {
    // Clients must be able to clean up after the server loses credentials.
    let state = state_with(false, false);
    let addr = "inbox@example.com";
    owned_mailbox(&state, addr).await;

    match unsubscribe(
        State(state),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(unsub_endpoint("https://push.example/ep"))),
    )
    .await
    {
        Err(ApiError::NotFound(_)) => {}
        other => panic!("expected 404 for unknown subscription, got {other:?}"),
    }
}

#[tokio::test]
async fn vapid_public_key_is_served_when_configured() {
    let state = state_with(true, false);
    let Ok(Json(body)) = vapid_public_key(State(state)).await else {
        panic!("configured vapid key must be served");
    };
    assert_eq!(body["vapid_public_key"], "test-public-key");
}

#[tokio::test]
async fn subscription_writes_are_owner_gated() {
    let state = state_with(true, true);
    let addr = "inbox@example.com";
    owned_mailbox(&state, addr).await;

    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        HeaderMap::new(),
        Some(Json(web_request("https://push.example/ep"))),
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
        Some(Json(unsub_endpoint("https://push.example/ep"))),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("unsubscribe with wrong token must be 401"),
    }
}

#[tokio::test]
async fn subscribe_unsubscribe_roundtrip_and_cap() {
    let state = state_with(true, false);
    let addr = "inbox@example.com";
    owned_mailbox(&state, addr).await;

    // Non-HTTPS endpoints are rejected before touching the store.
    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(web_request("http://insecure.example/ep"))),
    )
    .await
    {
        Err(ApiError::BadRequest(_)) => {}
        _ => panic!("non-https endpoint must be rejected"),
    }

    let (status, Json(created)) = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(web_request("https://push.example/ep1"))),
    )
    .await
    .expect("first subscribe succeeds");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created.kind, SubscriptionKind::WebPush, "kind is inferred");

    let _ = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(web_request("https://push.example/ep2"))),
    )
    .await
    .expect("second subscribe succeeds");

    // Cap is 2 in this config; the third distinct endpoint is refused.
    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(web_request("https://push.example/ep3"))),
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
        Some(Json(unsub_endpoint("https://push.example/ep1"))),
    )
    .await
    .expect("unsubscribe succeeds");
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Unknown endpoint → 404.
    match unsubscribe(
        State(state),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(unsub_endpoint("https://push.example/ep1"))),
    )
    .await
    {
        Err(ApiError::NotFound(_)) => {}
        _ => panic!("unsubscribing an unknown endpoint must be 404"),
    }
}

#[tokio::test]
async fn apns_subscribe_roundtrip_by_device_token() {
    let state = state_with(false, true);
    let addr = "iphone@example.com";
    owned_mailbox(&state, addr).await;

    // Tokens with whitespace are rejected.
    match subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(apns_request("not a token"))),
    )
    .await
    {
        Err(ApiError::BadRequest(_)) => {}
        _ => panic!("device token with whitespace must be rejected"),
    }

    let (status, Json(created)) = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(apns_request("cafebabe1234"))),
    )
    .await
    .expect("apns subscribe succeeds");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created.kind, SubscriptionKind::Apns, "kind is inferred");

    // Re-registering the same token is idempotent (no cap consumption).
    let (status, _) = subscribe(
        State(state.clone()),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(apns_request("cafebabe1234"))),
    )
    .await
    .expect("re-subscribe is idempotent");
    assert_eq!(status, StatusCode::CREATED);

    // Unsubscribe by device_token.
    let status = unsubscribe(
        State(state),
        AxumPath(addr.to_string()),
        bearer(TOKEN),
        Some(Json(UnsubscribeRequest {
            endpoint: None,
            device_token: Some("cafebabe1234".to_string()),
        })),
    )
    .await
    .expect("unsubscribe by device token succeeds");
    assert_eq!(status, StatusCode::NO_CONTENT);
}
