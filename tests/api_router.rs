//! Router-level HTTP tests (U4): drive the real `api::router` through
//! `tower::ServiceExt::oneshot`, so routing, extractors, middleware, and
//! handler wiring are all exercised exactly as in production. Uses the
//! in-memory store; rate limits are disabled so requests need no peer-IP
//! bookkeeping beyond the `ConnectInfo` extension.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use serde_json::Value;
use tower::ServiceExt;

use anony_mail::api::{self, AppState};
use anony_mail::config::Config;
use anony_mail::events::EventBus;
use anony_mail::model::{NewAttachment, NewMessage};
use anony_mail::store::{MemoryStore, Store};

fn test_state() -> (Router, Arc<MemoryStore>) {
    test_state_with(Config {
        domains: vec!["example.com".to_string()],
        // Rate limiting is covered by its own config; disabled here so
        // oneshot requests don't need governor bookkeeping.
        api_rate_limit_per_second: 0,
        create_rate_limit_per_minute: 0,
        max_addresses_per_ip_per_day: 0,
        ..Config::default()
    })
}

fn test_state_with(config: Config) -> (Router, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let state = AppState::new(
        store.clone() as Arc<dyn Store>,
        Arc::new(config),
        EventBus::new(16),
    );
    (api::router(state), store)
}

fn peer() -> ConnectInfo<SocketAddr> {
    ConnectInfo("198.51.100.7:4242".parse().unwrap())
}

/// Build a request with the `ConnectInfo` extension the handlers expect from
/// `into_make_service_with_connect_info`.
fn req(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .extension(peer())
        .body(Body::empty())
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Seed one message (with an HTML attachment and raw bytes) directly through
/// the store, returning `(message_id, attachment_id)`.
async fn seed_message(store: &MemoryStore, address: &str) -> (uuid::Uuid, uuid::Uuid) {
    let saved = store
        .save_message(
            address,
            NewMessage {
                mail_from: "sender@elsewhere.test".to_string(),
                subject: Some("hello".to_string()),
                message_date: None,
                text_body: Some("body".to_string()),
                html_body: None,
                raw_size: 64,
                raw_content: Some(b"Subject: hello\r\n\r\nbody\r\n".to_vec()),
                attachments: vec![NewAttachment {
                    filename: Some("naïve page.html".to_string()),
                    content_type: "text/html".to_string(),
                    content: b"<script>alert(1)</script>".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    (saved.id, saved.attachments[0].id)
}

#[tokio::test]
async fn docs_enabled_by_default_serves_scalar_and_spec() {
    let (app, _) = test_state();

    let docs = app.clone().oneshot(req("GET", "/docs")).await.unwrap();
    assert_eq!(docs.status(), StatusCode::OK);
    assert!(
        docs.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let html = String::from_utf8(
        axum::body::to_bytes(docs.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("@scalar/api-reference"));
    assert!(html.contains("/openapi.json"));

    let spec = app.oneshot(req("GET", "/openapi.json")).await.unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    assert!(
        spec.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let body = json_body(spec).await;
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(body["info"]["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn docs_disabled_returns_not_found() {
    let (app, _) = test_state_with(Config {
        domains: vec!["example.com".to_string()],
        api_rate_limit_per_second: 0,
        create_rate_limit_per_minute: 0,
        max_addresses_per_ip_per_day: 0,
        api_docs_enabled: false,
        ..Config::default()
    });

    let docs = app.clone().oneshot(req("GET", "/docs")).await.unwrap();
    assert_eq!(docs.status(), StatusCode::NOT_FOUND);
    let spec = app.oneshot(req("GET", "/openapi.json")).await.unwrap();
    assert_eq!(spec.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn liveness_and_readiness_probes() {
    let (app, _) = test_state();

    let health = app.clone().oneshot(req("GET", "/healthz")).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(json_body(health).await["status"], "ok");

    let ready = app.oneshot(req("GET", "/readyz")).await.unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(json_body(ready).await["status"], "ready");
}

#[tokio::test]
async fn create_list_read_clear_lifecycle() {
    let (app, store) = test_state();

    // Create a mailbox through the real route.
    let created = app
        .clone()
        .oneshot(req("POST", "/api/addresses"))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = json_body(created).await;
    let address = body["address"].as_str().expect("address").to_string();
    let token = body["owner_token"]
        .as_str()
        .expect("owner_token")
        .to_string();

    // Empty inbox lists as [], unknown mailbox as 404.
    let empty = app
        .clone()
        .oneshot(req("GET", &format!("/api/addresses/{address}/messages")))
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(json_body(empty).await, serde_json::json!([]));
    let missing = app
        .clone()
        .oneshot(req("GET", "/api/addresses/ghost@example.com/messages"))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let (msg_id, _) = seed_message(&store, &address).await;

    // Listing shows the message, unseen.
    let list = app
        .clone()
        .oneshot(req("GET", &format!("/api/addresses/{address}/messages")))
        .await
        .unwrap();
    let list = json_body(list).await;
    assert_eq!(list[0]["id"], msg_id.to_string());
    assert_eq!(list[0]["seen"], false);

    // Mark read (open endpoint), then the flag flips.
    let read = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/addresses/{address}/messages/{msg_id}/read"),
        ))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::NO_CONTENT);
    let list = json_body(
        app.clone()
            .oneshot(req("GET", &format!("/api/addresses/{address}/messages")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(list[0]["seen"], true);

    // Clear inbox: 401 without token, 200 with, and the mailbox survives.
    let unauthorized = app
        .clone()
        .oneshot(req("DELETE", &format!("/api/addresses/{address}/messages")))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert!(
        unauthorized
            .headers()
            .contains_key(header::WWW_AUTHENTICATE)
    );

    let mut clear = req("DELETE", &format!("/api/addresses/{address}/messages"));
    clear.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let cleared = app.clone().oneshot(clear).await.unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(json_body(cleared).await["deleted"], 1);
    assert!(store.get_mailbox(&address).await.unwrap().is_some());
}

#[tokio::test]
async fn pagination_params_are_honored_and_validated() {
    let (app, store) = test_state();
    store
        .create_mailbox(
            "page@example.com",
            "example.com",
            Utc::now() + chrono::Duration::hours(1),
            None,
        )
        .await
        .unwrap();
    for _ in 0..3 {
        seed_message(&store, "page@example.com").await;
    }

    let page = json_body(
        app.clone()
            .oneshot(req(
                "GET",
                "/api/addresses/page@example.com/messages?limit=2",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(page.as_array().unwrap().len(), 2);

    let newest = page[0]["id"].as_str().unwrap();
    let delta = json_body(
        app.clone()
            .oneshot(req(
                "GET",
                &format!("/api/addresses/page@example.com/messages?since={newest}"),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(delta, serde_json::json!([]));

    // Malformed query values are a client error, not a 500.
    let bad = app
        .oneshot(req(
            "GET",
            "/api/addresses/page@example.com/messages?limit=banana",
        ))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attachment_download_is_hardened() {
    let (app, store) = test_state();
    store
        .create_mailbox(
            "att@example.com",
            "example.com",
            Utc::now() + chrono::Duration::hours(1),
            None,
        )
        .await
        .unwrap();
    let (msg_id, att_id) = seed_message(&store, "att@example.com").await;

    let response = app
        .oneshot(req(
            "GET",
            &format!("/api/addresses/att@example.com/messages/{msg_id}/attachments/{att_id}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A6: HTML is forced to octet-stream, nosniff always set, RFC 5987 name.
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let disposition = response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap();
    assert!(disposition.contains("filename=\"nave page.html\""));
    assert!(disposition.contains("filename*=UTF-8''na%C3%AFve%20page.html"));
}

#[tokio::test]
async fn raw_download_served_as_rfc822() {
    let (app, store) = test_state();
    store
        .create_mailbox(
            "raw@example.com",
            "example.com",
            Utc::now() + chrono::Duration::hours(1),
            None,
        )
        .await
        .unwrap();
    let (msg_id, _) = seed_message(&store, "raw@example.com").await;

    let response = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/addresses/raw@example.com/messages/{msg_id}/raw"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "message/rfc822");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"Subject: hello\r\n\r\nbody\r\n");

    // Unknown message id -> 404.
    let missing = app
        .oneshot(req(
            "GET",
            &format!(
                "/api/addresses/raw@example.com/messages/{}/raw",
                uuid::Uuid::new_v4()
            ),
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn push_endpoints_answer_503_when_unconfigured() {
    let (app, _) = test_state();
    let response = app
        .oneshot(req("GET", "/api/push/vapid-public-key"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
