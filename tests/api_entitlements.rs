//! Router-level tests for server-side entitlements (docs/10, phase 1):
//! token minting via `POST /api/entitlements/verify` (with a stub RevenueCat
//! verdict), the free/pro gates on create/extend/custom-domain claims, coded
//! 401/403 errors, and the capabilities policy block.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use anony_mail::api::{self, AppState};
use anony_mail::config::Config;
use anony_mail::custom_domains::DomainDns;
use anony_mail::entitlements::{KIND_UNATTESTED, ProVerifier, Tier, mint_client_token};
use anony_mail::events::EventBus;
use anony_mail::store::{MemoryStore, Store};

const SIGNING_KEY: [u8; 32] = [7u8; 32];

/// Scriptable [`ProVerifier`]: per-id verdicts, or a global outage.
#[derive(Default)]
struct FakePro {
    verdicts: Mutex<HashMap<String, bool>>,
    outage: AtomicBool,
}

impl FakePro {
    fn grant(&self, id: &str, pro: bool) {
        self.verdicts.lock().unwrap().insert(id.to_string(), pro);
    }

    fn set_outage(&self, down: bool) {
        self.outage.store(down, Ordering::SeqCst);
    }
}

#[async_trait]
impl ProVerifier for FakePro {
    async fn is_pro(&self, rc_app_user_id: &str) -> anyhow::Result<bool> {
        if self.outage.load(Ordering::SeqCst) {
            anyhow::bail!("revenuecat unreachable");
        }
        Ok(self
            .verdicts
            .lock()
            .unwrap()
            .get(rc_app_user_id)
            .copied()
            .unwrap_or(false))
    }
}

/// Scriptable DNS so a custom domain can be verified without the network.
#[derive(Default)]
struct FakeDns {
    txt: Mutex<HashMap<String, Vec<String>>>,
    mx: Mutex<HashMap<String, Vec<String>>>,
}

#[async_trait]
impl DomainDns for FakeDns {
    async fn txt_records(&self, name: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .txt
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default())
    }

    async fn mx_hosts(&self, name: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .mx
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
}

fn test_config() -> Config {
    Config {
        domains: vec!["example.com".to_string(), "premium.example".to_string()],
        smtp_hostname: "mx.example.com".to_string(),
        token_signing_key: Some(SIGNING_KEY.to_vec()),
        // Rate limiting is covered by its own tests.
        api_rate_limit_per_second: 0,
        create_rate_limit_per_minute: 0,
        max_addresses_per_ip_per_day: 0,
        max_custom_domains_per_ip_per_day: 0,
        custom_domain_verify_throttle: std::time::Duration::ZERO,
        ..Config::default()
    }
}

fn enforced_config() -> Config {
    Config {
        entitlements_enforced: true,
        ..test_config()
    }
}

fn test_app(config: Config) -> (Router, Arc<FakePro>, Arc<FakeDns>) {
    let pro = Arc::new(FakePro::default());
    let dns = Arc::new(FakeDns::default());
    let state = AppState::new(
        Arc::new(MemoryStore::new()) as Arc<dyn Store>,
        Arc::new(config),
        EventBus::new(16),
    )
    .with_dns(dns.clone())
    .with_pro_verifier(pro.clone());
    (api::router(state), pro, dns)
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
                "198.51.100.9:4242".parse().unwrap(),
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
    serde_json::from_slice(&bytes).unwrap()
}

/// Mint a token through the real endpoint, as the app would.
async fn fetch_token(app: &Router, rc_id: Option<&str>) -> (String, String) {
    let body = rc_id.map(|id| json!({ "rc_app_user_id": id }));
    let response = app
        .clone()
        .oneshot(req("POST", "/api/entitlements/verify", None, None, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    (
        body["client_token"].as_str().unwrap().to_string(),
        body["tier"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn verify_is_503_without_a_signing_key() {
    let (app, _, _) = test_app(Config {
        token_signing_key: None,
        ..test_config()
    });
    let response = app
        .oneshot(req("POST", "/api/entitlements/verify", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn verify_mints_tier_tokens_from_purchase_verdicts() {
    let (app, pro, _) = test_app(test_config());
    pro.grant("subscriber", true);
    pro.grant("lapsed", false);

    let (_, tier) = fetch_token(&app, Some("subscriber")).await;
    assert_eq!(tier, "pro");

    let (_, tier) = fetch_token(&app, Some("lapsed")).await;
    assert_eq!(tier, "free");

    // Unknown id, missing id, and missing body are all just free.
    let (_, tier) = fetch_token(&app, Some("never-seen")).await;
    assert_eq!(tier, "free");
    let (_, tier) = fetch_token(&app, None).await;
    assert_eq!(tier, "free");

    let response = app
        .oneshot(req("POST", "/api/entitlements/verify", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "bodyless request");
}

#[tokio::test]
async fn verify_surfaces_revenuecat_outage_as_503() {
    let (app, pro, _) = test_app(test_config());
    pro.set_outage(true);

    // With an id the upstream is consulted -> 503 so the client retries
    // later instead of silently dropping to free.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/entitlements/verify",
            None,
            None,
            Some(json!({ "rc_app_user_id": "subscriber" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Without an id nothing upstream is needed: free token, no error.
    let (_, tier) = fetch_token(&app, None).await;
    assert_eq!(tier, "free");
}

#[tokio::test]
async fn enforcement_off_gates_nothing() {
    let (app, _, _) = test_app(test_config());

    // Custom local part on the second domain, tokenless: fine.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            None,
            Some(json!({ "local_part": "myname", "domain": "premium.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;

    // Extend, tokenless: fine.
    let owner = created["owner_token"].as_str().unwrap();
    let address = created["address"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/addresses/{address}/extend"),
            Some(owner),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Claiming a custom domain, tokenless: fine.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            None,
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(req("GET", "/api/capabilities", None, None, None))
        .await
        .unwrap();
    let caps = json_body(response).await;
    assert_eq!(caps["entitlements"]["enforced"], json!(false));
}

#[tokio::test]
async fn free_tier_hits_the_gates_when_enforced() {
    let (app, _, _) = test_app(enforced_config());

    // Tokenless *is* the free tier — not an error, but gated.
    let cases = [
        (
            json!({ "local_part": "myname" }),
            "custom local part",
            "pro_required",
        ),
        (
            json!({ "domain": "premium.example" }),
            "second configured domain",
            "pro_required",
        ),
    ];
    for (body, what, code) in cases {
        let response = app
            .clone()
            .oneshot(req("POST", "/api/addresses", None, None, Some(body)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{what}");
        let body = json_body(response).await;
        assert_eq!(body["code"].as_str(), Some(code), "{what}");
    }

    // Random local part on the first domain stays free.
    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Explicitly-free token behaves exactly like no token.
    let (free_token, tier) = fetch_token(&app, None).await;
    assert_eq!(tier, "free");
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some(&free_token),
            Some(json!({ "local_part": "myname" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Claiming a custom domain is pro-only under the default policy.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            None,
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json_body(response).await;
    assert_eq!(body["code"].as_str(), Some("pro_required"));
}

#[tokio::test]
async fn pro_token_unlocks_the_gates() {
    let (app, pro, dns) = test_app(enforced_config());
    pro.grant("subscriber", true);
    let (token, tier) = fetch_token(&app, Some("subscriber")).await;
    assert_eq!(tier, "pro");

    // Custom local part on the second domain.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some(&token),
            Some(json!({ "local_part": "myname", "domain": "premium.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Claim + verify + mint a mailbox on a custom domain, sending both the
    // claim token (Authorization) and the tier token (X-Client-Token).
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            Some(&token),
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let claim = json_body(response).await;
    let claim_token = claim["claim_token"].as_str().unwrap().to_string();
    let txt_record = claim["txt_record"].as_str().unwrap().to_string();

    dns.txt
        .lock()
        .unwrap()
        .insert("_anonymail.corp.example".to_string(), vec![txt_record]);
    dns.mx.lock().unwrap().insert(
        "corp.example".to_string(),
        vec!["mx.example.com".to_string()],
    );
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains/corp.example/verify",
            Some(&claim_token),
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], json!("verified"));

    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            Some(&claim_token),
            Some(&token),
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn lifetime_ceiling_caps_free_extends_but_not_pro() {
    // Free ceiling below the default TTL: the very first extend must exceed
    // it deterministically (new lifetime ≈ 2×TTL-ish > ceiling).
    let mut config = enforced_config();
    config.free_tier.max_lifetime_seconds = config.default_ttl.as_secs() / 2;
    let (app, pro, _) = test_app(config);
    pro.grant("subscriber", true);

    let response = app
        .clone()
        .oneshot(req("POST", "/api/addresses", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    let owner = created["owner_token"].as_str().unwrap();
    let address = created["address"].as_str().unwrap();
    let extend_uri = format!("/api/addresses/{address}/extend");

    // Free (tokenless): over the ceiling -> coded 403.
    let response = app
        .clone()
        .oneshot(req("POST", &extend_uri, Some(owner), None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json_body(response).await;
    assert_eq!(body["code"].as_str(), Some("lifetime_cap"));

    // Pro: unlimited lifetime by default -> extend succeeds.
    let (token, _) = fetch_token(&app, Some("subscriber")).await;
    let response = app
        .clone()
        .oneshot(req("POST", &extend_uri, Some(owner), Some(&token), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn expired_and_forged_tokens_get_coded_401s() {
    let (app, _, _) = test_app(enforced_config());

    let (expired, _) = mint_client_token(
        &SIGNING_KEY,
        KIND_UNATTESTED,
        None,
        Tier::Pro,
        chrono::Duration::seconds(-120),
    )
    .unwrap();
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some(&expired),
            Some(json!({ "local_part": "myname" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["code"].as_str(), Some("client_token_expired"));

    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some("garbage.token.here"),
            Some(json!({ "local_part": "myname" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["code"].as_str(), Some("client_token_invalid"));
}

#[tokio::test]
async fn capabilities_reports_the_policy_numbers() {
    let (app, _, _) = test_app(enforced_config());
    let response = app
        .oneshot(req("GET", "/api/capabilities", None, None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let caps = json_body(response).await;

    assert_eq!(caps["attestation"]["supported"], json!(false));
    assert_eq!(caps["attestation"]["required"], json!(false));

    let entitlements = &caps["entitlements"];
    assert_eq!(entitlements["enforced"], json!(true));
    assert_eq!(entitlements["free"]["active_mailboxes"], json!(5));
    assert_eq!(entitlements["free"]["max_lifetime_seconds"], json!(86400));
    assert_eq!(entitlements["free"]["custom_local_parts"], json!(false));
    assert_eq!(entitlements["free"]["domain_count"], json!(1));
    assert_eq!(entitlements["free"]["custom_domains"], json!(false));
    assert_eq!(entitlements["pro"]["active_mailboxes"], json!(50));
    assert_eq!(entitlements["pro"]["max_lifetime_seconds"], json!(0));
    assert_eq!(entitlements["pro"]["custom_local_parts"], json!(true));
    assert_eq!(entitlements["pro"]["domain_count"], json!(0));
    assert_eq!(entitlements["pro"]["custom_domains"], json!(true));
}
