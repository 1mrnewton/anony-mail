//! Router-level tests for the custom-domain endpoints (docs/11), driven
//! through the real `api::router` with a stub DNS resolver — no network.
//! Covers the whole lifecycle: claim, verify (fail then pass), create a
//! mailbox on the domain, grace behavior on broken DNS, and release.

use std::collections::HashMap;
use std::net::SocketAddr;
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
use anony_mail::events::EventBus;
use anony_mail::store::{MemoryStore, Store};

/// Scriptable [`DomainDns`]: answers from in-memory maps, like a zone file.
#[derive(Default)]
struct FakeDns {
    txt: Mutex<HashMap<String, Vec<String>>>,
    mx: Mutex<HashMap<String, Vec<String>>>,
}

impl FakeDns {
    fn set_txt(&self, name: &str, values: &[&str]) {
        self.txt.lock().unwrap().insert(
            name.to_string(),
            values.iter().map(|s| s.to_string()).collect(),
        );
    }

    fn set_mx(&self, name: &str, hosts: &[&str]) {
        self.mx.lock().unwrap().insert(
            name.to_string(),
            hosts.iter().map(|s| s.to_string()).collect(),
        );
    }

    fn clear(&self) {
        self.txt.lock().unwrap().clear();
        self.mx.lock().unwrap().clear();
    }
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
        domains: vec!["example.com".to_string()],
        smtp_hostname: "mx.example.com".to_string(),
        // Rate limiting is covered by its own tests; disabled here so oneshot
        // requests don't need governor bookkeeping. The verify throttle is
        // re-enabled by the test that covers it.
        api_rate_limit_per_second: 0,
        create_rate_limit_per_minute: 0,
        max_addresses_per_ip_per_day: 0,
        max_custom_domains_per_ip_per_day: 0,
        custom_domain_verify_throttle: std::time::Duration::ZERO,
        ..Config::default()
    }
}

fn test_app(config: Config) -> (Router, Arc<FakeDns>, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let dns = Arc::new(FakeDns::default());
    let state = AppState::new(
        store.clone() as Arc<dyn Store>,
        Arc::new(config),
        EventBus::new(16),
    )
    .with_dns(dns.clone());
    (api::router(state), dns, store)
}

fn req(method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder =
        Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo::<SocketAddr>(
                "198.51.100.7:4242".parse().unwrap(),
            ));
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
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

#[tokio::test]
async fn full_lifecycle_claim_verify_create_mailbox_release() {
    let (app, dns, _) = test_app(test_config());

    // Claim (messy input normalizes) -> pending + records + one-time token.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            Some(json!({ "domain": " Corp.Example. " })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let claim = json_body(response).await;
    assert_eq!(claim["domain"], "corp.example");
    assert_eq!(claim["status"], "pending");
    assert_eq!(claim["mx_target"], "mx.example.com");
    let txt_record = claim["txt_record"].as_str().unwrap().to_string();
    assert!(txt_record.starts_with("anonymail-verify="));
    let token = claim["claim_token"].as_str().unwrap().to_string();
    assert!(token.starts_with("amd_"));

    // Claim-gated reads: no token / wrong token -> 401, right token -> 200.
    for bad in [None, Some("amd_wrong")] {
        let response = app
            .clone()
            .oneshot(req("GET", "/api/custom-domains/corp.example", bad, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{bad:?}");
    }
    let response = app
        .clone()
        .oneshot(req(
            "GET",
            "/api/custom-domains/corp.example",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got = json_body(response).await;
    assert_eq!(got["status"], "pending");
    assert!(
        got.get("claim_token").is_none(),
        "claim token is returned only on create"
    );

    // Mailboxes on a pending domain are refused even with the right token.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            Some(&token),
            Some(json!({ "domain": "corp.example", "local_part": "jane" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        json_body(response).await["error"]
            .as_str()
            .unwrap()
            .contains("not verified")
    );

    // Verify with no DNS published -> both checks fail, still pending.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains/corp.example/verify",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let outcome = json_body(response).await;
    assert_eq!(outcome["status"], "pending");
    let checks = outcome["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 2);
    assert_eq!(checks[0]["record"], "txt");
    assert_eq!(checks[0]["ok"], false);
    assert_eq!(checks[0]["found"], Value::Null);
    assert_eq!(checks[1]["record"], "mx");
    assert_eq!(checks[1]["ok"], false);

    // Publish both records (extra TXT noise and a trailing-dot MX are fine).
    dns.set_txt(
        "_anonymail.corp.example",
        &["some-other-service=xyz", &txt_record],
    );
    dns.set_mx("corp.example", &["backup.mx.other.com", "mx.example.com"]);

    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains/corp.example/verify",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let outcome = json_body(response).await;
    assert_eq!(outcome["status"], "verified");
    assert!(outcome["verified_at"].is_string());
    let checks = outcome["checks"].as_array().unwrap();
    assert_eq!(checks[0]["ok"], true);
    assert_eq!(checks[1]["ok"], true);

    // Now mailboxes can be created — but only with the claim token.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some(json!({ "domain": "corp.example", "local_part": "jane" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            Some("amd_wrong"),
            Some(json!({ "domain": "corp.example", "local_part": "jane" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            Some(&token),
            Some(json!({ "domain": "corp.example", "local_part": "jane" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let mailbox = json_body(response).await;
    assert_eq!(mailbox["address"], "jane@corp.example");
    assert!(mailbox["owner_token"].as_str().unwrap().starts_with("am_"));

    // Broken DNS within the grace window: checks fail but status holds.
    dns.clear();
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains/corp.example/verify",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let outcome = json_body(response).await;
    assert_eq!(
        outcome["status"], "verified",
        "a just-verified domain survives a bad check (48h grace)"
    );
    assert_eq!(outcome["checks"][0]["ok"], false);

    // Release: token-gated, idempotent via 404 afterwards.
    let response = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/custom-domains/corp.example",
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/custom-domains/corp.example",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/custom-domains/corp.example",
            Some(&token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // With the claim gone the domain is unknown to address creation again.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            Some(&token),
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn server_namespace_and_garbage_domains_are_rejected() {
    let (app, _, _) = test_app(test_config());

    for domain in [
        "example.com",     // a configured domain
        "sub.example.com", // subdomain of a configured domain
        "mx.example.com",  // the SMTP hostname
        "not a domain",    // garbage
        "nodots",          // no TLD
        "1.2.3.4",         // bare IP
        "-corp.example",   // bad label
    ] {
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/custom-domains",
                None,
                Some(json!({ "domain": domain })),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "claiming {domain:?} must be rejected"
        );
    }
}

#[tokio::test]
async fn duplicate_claim_answers_conflict() {
    let (app, _, _) = test_app(test_config());
    let claim = || {
        req(
            "POST",
            "/api/custom-domains",
            None,
            Some(json!({ "domain": "corp.example" })),
        )
    };

    let first = app.clone().oneshot(claim()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = app.clone().oneshot(claim()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn verify_is_throttled_per_domain() {
    let (app, _, _) = test_app(Config {
        custom_domain_verify_throttle: std::time::Duration::from_secs(10),
        ..test_config()
    });

    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    let token = json_body(response).await["claim_token"]
        .as_str()
        .unwrap()
        .to_string();

    let verify = || {
        req(
            "POST",
            "/api/custom-domains/corp.example/verify",
            Some(&token),
            None,
        )
    };
    let first = app.clone().oneshot(verify()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app.clone().oneshot(verify()).await.unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "back-to-back verify must be throttled"
    );
}

#[tokio::test]
async fn daily_domain_quota_is_enforced_per_ip() {
    let (app, _, _) = test_app(Config {
        max_custom_domains_per_ip_per_day: 2,
        ..test_config()
    });

    for (i, domain) in ["a.example", "b.example"].iter().enumerate() {
        let response = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/custom-domains",
                None,
                Some(json!({ "domain": domain })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED, "claim #{i}");
    }
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            Some(json!({ "domain": "c.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn disabled_feature_unmounts_routes_and_reports_capability() {
    let (app, _, _) = test_app(Config {
        custom_domains_enabled: false,
        ..test_config()
    });

    let response = app
        .clone()
        .oneshot(req("GET", "/api/capabilities", None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["custom_domains"], false);

    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/custom-domains",
            None,
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Address creation on a would-be custom domain is a plain bad request.
    let response = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/addresses",
            None,
            Some(json!({ "domain": "corp.example" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
