//! Router-level tests for App Attest (docs/09, phase 2): the
//! challenge/attest/assert endpoints, single-use challenges, assertion
//! counter replay protection, the attestation gate on mutating routes, and
//! the per-device active-mailbox cap.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use appattest::testing::{
    TEST_ROOT_CA_CERT_PEM, TestAttestation, build_test_assertion, build_test_attestation,
};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use anony_mail::api::{self, AppState};
use anony_mail::config::{Config, TierPolicy};
use anony_mail::entitlements::{KIND_UNATTESTED, ProVerifier, Tier, mint_client_token};
use anony_mail::events::EventBus;
use anony_mail::store::{MemoryStore, Store};

const SIGNING_KEY: [u8; 32] = [9u8; 32];
const APP_ID: &str = "TESTTEAM12.com.example.app";

/// Scriptable [`ProVerifier`] with per-id verdicts.
#[derive(Default)]
struct FakePro {
    verdicts: Mutex<HashMap<String, bool>>,
}

impl FakePro {
    fn grant(&self, id: &str) {
        self.verdicts.lock().unwrap().insert(id.to_string(), true);
    }
}

#[async_trait]
impl ProVerifier for FakePro {
    async fn is_pro(&self, rc_app_user_id: &str) -> anyhow::Result<bool> {
        Ok(self
            .verdicts
            .lock()
            .unwrap()
            .get(rc_app_user_id)
            .copied()
            .unwrap_or(false))
    }
}

fn base_config() -> Config {
    Config {
        domains: vec!["example.com".to_string()],
        smtp_hostname: "mx.example.com".to_string(),
        token_signing_key: Some(SIGNING_KEY.to_vec()),
        // Rate limiting is covered by its own tests.
        api_rate_limit_per_second: 0,
        create_rate_limit_per_minute: 0,
        max_addresses_per_ip_per_day: 0,
        max_custom_domains_per_ip_per_day: 0,
        ..Config::default()
    }
}

/// App Attest configured against the crate's synthetic test CA.
fn attest_config(required: bool) -> Config {
    Config {
        client_attestation_required: required,
        app_attest_team_id: Some("TESTTEAM12".to_string()),
        app_attest_bundle_id: Some("com.example.app".to_string()),
        app_attest_root_pem: Some(TEST_ROOT_CA_CERT_PEM.to_vec()),
        ..base_config()
    }
}

fn test_app(config: Config) -> (Router, Arc<FakePro>) {
    let pro = Arc::new(FakePro::default());
    let state = AppState::new(
        Arc::new(MemoryStore::new()) as Arc<dyn Store>,
        Arc::new(config),
        EventBus::new(16),
    )
    .with_pro_verifier(pro.clone());
    (api::router(state), pro)
}

/// Request builder: `owner` becomes `Authorization: Bearer …`, `client`
/// becomes `X-Client-Token`.
fn req(
    method: &str,
    uri: &str,
    owner: Option<&str>,
    client: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder =
        Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo::<SocketAddr>(
                "198.51.100.7:4242".parse().unwrap(),
            ));
    if let Some(token) = owner {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(token) = client {
        builder = builder.header("X-Client-Token", token);
    }
    match body {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// `POST /api/client/challenge` → the challenge string.
async fn fetch_challenge(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(req("POST", "/api/client/challenge", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["challenge"]
        .as_str()
        .expect("challenge string")
        .to_string()
}

/// Full attest flow: fresh challenge, synthetic attestation, register.
/// Returns the minted token response and the synthetic device (keep it to
/// sign later assertions).
async fn attest_device(app: &Router, rc_app_user_id: Option<&str>) -> (Value, TestAttestation) {
    let challenge = fetch_challenge(app).await;
    let ta = build_test_attestation(&challenge, APP_ID);
    let mut body = json!({
        "key_id": ta.key_id,
        "attestation": B64.encode(&ta.cbor),
        "challenge": challenge,
    });
    if let Some(id) = rc_app_user_id {
        body["rc_app_user_id"] = json!(id);
    }
    let response = app
        .clone()
        .oneshot(req("POST", "/api/client/attest", None, None, Some(body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "attest must succeed");
    (json_body(response).await, ta)
}

/// Sign and submit an assertion for `previous_counter` (device claims
/// `previous_counter + 1`).
async fn submit_assertion(
    app: &Router,
    ta: &TestAttestation,
    previous_counter: u32,
) -> axum::response::Response {
    let challenge = fetch_challenge(app).await;
    let client_data_hash: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();
    let assertion =
        build_test_assertion(APP_ID, client_data_hash, previous_counter, &ta.device_key);
    app.clone()
        .oneshot(req(
            "POST",
            "/api/client/assert",
            None,
            None,
            Some(json!({
                "key_id": ta.key_id,
                "assertion": B64.encode(&assertion),
                "challenge": challenge,
            })),
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn endpoints_503_when_unconfigured() {
    let (app, _) = test_app(base_config());

    for (uri, body) in [
        ("/api/client/challenge", None),
        (
            "/api/client/attest",
            Some(json!({ "key_id": "k", "attestation": "aGk=", "challenge": "c" })),
        ),
        (
            "/api/client/assert",
            Some(json!({ "key_id": "k", "assertion": "aGk=", "challenge": "c" })),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(req("POST", uri, None, None, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{uri} must 503 while App Attest is unconfigured"
        );
    }

    let response = app
        .clone()
        .oneshot(req("GET", "/api/capabilities", None, None, None))
        .await
        .unwrap();
    let body = json_body(response).await;
    assert_eq!(body["attestation"]["supported"], json!(false));
    assert_eq!(body["attestation"]["required"], json!(false));
}

#[tokio::test]
async fn capabilities_report_attestation_posture() {
    let (app, _) = test_app(attest_config(true));
    let response = app
        .clone()
        .oneshot(req("GET", "/api/capabilities", None, None, None))
        .await
        .unwrap();
    let body = json_body(response).await;
    assert_eq!(body["attestation"]["supported"], json!(true));
    assert_eq!(body["attestation"]["required"], json!(true));
}

#[tokio::test]
async fn attest_flow_mints_a_token_that_unlocks_writes() {
    let (app, _) = test_app(attest_config(true));

    // Attestation required: creating without any token is a coded 401.
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("attestation_required")
    );

    // A locally forged *unattested* token does not pass the gate either.
    let (unattested, _) = mint_client_token(
        &SIGNING_KEY,
        KIND_UNATTESTED,
        None,
        Tier::Pro,
        chrono::Duration::hours(1),
    )
    .unwrap();
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(&unattested), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("attestation_required")
    );

    // The unattested minting route is gated too, or it would defeat the flag.
    let response = app
        .clone()
        .oneshot(req("POST", "/api/entitlements/verify", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Attest, then the same create succeeds.
    let (minted, _ta) = attest_device(&app, None).await;
    let token = minted["client_token"].as_str().expect("client_token");
    assert_eq!(minted["tier"].as_str(), Some("free"));
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;

    // Reads stay open: no token needed to fetch the mailbox.
    let address = created["address"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/addresses/{address}"),
            None,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn attest_carries_the_purchase_tier() {
    let (app, pro) = test_app(attest_config(true));
    pro.grant("subscriber");
    let (minted, _) = attest_device(&app, Some("subscriber")).await;
    assert_eq!(minted["tier"].as_str(), Some("pro"));
    let (minted, _) = attest_device(&app, Some("stranger")).await;
    assert_eq!(minted["tier"].as_str(), Some("free"));
}

#[tokio::test]
async fn challenges_are_single_use_and_bad_attestations_reject() {
    let (app, _) = test_app(attest_config(false));

    // A well-formed but bogus attestation burns the challenge...
    let challenge = fetch_challenge(&app).await;
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/client/attest",
            None,
            None,
            Some(json!({ "key_id": "k", "attestation": "aGVsbG8=", "challenge": challenge })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("invalid_attestation")
    );

    // ...so even a valid attestation cannot reuse it.
    let ta = build_test_attestation(&challenge, APP_ID);
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/client/attest",
            None,
            None,
            Some(json!({
                "key_id": ta.key_id,
                "attestation": B64.encode(&ta.cbor),
                "challenge": challenge,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("invalid_challenge")
    );

    // Made-up challenges never validate.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/client/attest",
            None,
            None,
            Some(json!({ "key_id": "k", "attestation": "aGk=", "challenge": "invented" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("invalid_challenge")
    );

    // Oversized key ids are rejected before any crypto.
    let challenge = fetch_challenge(&app).await;
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/client/attest",
            None,
            None,
            Some(json!({
                "key_id": "x".repeat(65),
                "attestation": "aGk=",
                "challenge": challenge,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attestations_for_another_app_are_rejected() {
    let (app, _) = test_app(attest_config(false));
    let challenge = fetch_challenge(&app).await;
    let ta = build_test_attestation(&challenge, "OTHERTEAM0.com.other.app");
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/client/attest",
            None,
            None,
            Some(json!({
                "key_id": ta.key_id,
                "attestation": B64.encode(&ta.cbor),
                "challenge": challenge,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("invalid_attestation")
    );
}

#[tokio::test]
async fn assert_refreshes_and_the_counter_blocks_replay() {
    let (app, _) = test_app(attest_config(true));
    let (_, ta) = attest_device(&app, None).await;

    // First assertion: stored counter 0, device claims 1 -> fresh token.
    let response = submit_assertion(&app, &ta, 0).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert!(body["client_token"].as_str().is_some());
    assert_eq!(body["tier"].as_str(), Some("free"));

    // Replay at the same counter: the stored counter already advanced to 1,
    // so a device claiming 1 again is rejected.
    let response = submit_assertion(&app, &ta, 0).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("invalid_assertion")
    );

    // Advancing keeps working.
    let response = submit_assertion(&app, &ta, 1).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn asserting_an_unknown_key_requires_attestation() {
    let (app, _) = test_app(attest_config(true));
    // A key the server never saw (no prior attest).
    let challenge = fetch_challenge(&app).await;
    let ta = build_test_attestation(&challenge, APP_ID);
    // Burn a *different* challenge for the assertion itself.
    let response = submit_assertion(&app, &ta, 0).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("attestation_required")
    );
}

#[tokio::test]
async fn per_device_mailbox_cap_applies_to_attested_creates() {
    let config = Config {
        entitlements_enforced: true,
        free_tier: TierPolicy {
            active_mailboxes: 2,
            max_lifetime_seconds: 0,
            custom_local_parts: false,
            domain_count: 0,
            custom_domains: false,
        },
        ..attest_config(true)
    };
    let (app, _) = test_app(config);

    let (minted, _ta) = attest_device(&app, None).await;
    let token = minted["client_token"].as_str().unwrap();

    // Two creates fit the cap; remember one owner token for the delete below.
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let first = json_body(response).await;
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // The third hits the device cap.
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response).await["code"].as_str(),
        Some("mailbox_cap")
    );

    // Another device is capped independently.
    let (minted_b, _) = attest_device(&app, None).await;
    let token_b = minted_b["client_token"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token_b), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Deleting one frees a slot for the first device.
    let address = first["address"].as_str().unwrap();
    let owner = first["owner_token"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/addresses/{address}"),
            Some(owner),
            Some(token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, Some(token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn attestation_not_required_leaves_everything_open() {
    // Configured-but-optional: attest works, yet plain requests still write.
    let (app, _) = test_app(attest_config(false));
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let (minted, _) = attest_device(&app, None).await;
    assert!(minted["client_token"].as_str().is_some());
}
