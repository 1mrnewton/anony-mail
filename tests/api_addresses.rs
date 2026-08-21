//! Handler-level integration tests for the address API against a real
//! (temp-file) SQLite database.
//!
//! Regression coverage for B1: creating the same custom address twice used to
//! surface as `500 Internal Server Error` on SQLite because the unique-
//! violation check only recognized the Postgres SQLSTATE. It must be a clean
//! `409 Conflict`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use std::net::SocketAddr;

use anony_mail::api::addresses::{CreateAddressRequest, create, delete, extend, rotate};
use anony_mail::api::{ApiError, AppState};
use anony_mail::config::Config;
use anony_mail::events::EventBus;
use anony_mail::store::SqliteStore;
use axum::Json;
use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};

fn peer() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:54321".parse().unwrap())
}

fn temp_db_path() -> PathBuf {
    // Tests in this binary start concurrently, so a timestamp alone can
    // collide; the counter makes each path unique within the process.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "anony-mail-api-test-{}-{seq}-{nanos}.db",
        std::process::id()
    ))
}

/// Removes the database file plus any WAL/SHM sidecars.
fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn test_config() -> Config {
    Config {
        domains: vec!["example.com".to_string()],
        database_url: "sqlite://unused-in-tests".to_string(),
        ..Config::default()
    }
}

async fn sqlite_app_state(path: &Path) -> AppState {
    let store = SqliteStore::connect(path.to_str().unwrap())
        .await
        .expect("open sqlite store");
    AppState::new(Arc::new(store), Arc::new(test_config()), EventBus::new(16))
}

#[tokio::test]
async fn duplicate_custom_address_returns_conflict_not_internal() {
    let path = temp_db_path();
    let state = sqlite_app_state(&path).await;

    let request = || CreateAddressRequest {
        local_part: Some("taken".to_string()),
        domain: Some("example.com".to_string()),
    };

    let Ok((status, Json(created))) = create(
        State(state.clone()),
        peer(),
        HeaderMap::new(),
        Some(Json(request())),
    )
    .await
    else {
        panic!("first create should succeed");
    };
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created.mailbox.address, "taken@example.com");
    assert!(
        created.owner_token.starts_with("am_"),
        "create must hand out the owner token"
    );

    match create(
        State(state),
        peer(),
        HeaderMap::new(),
        Some(Json(request())),
    )
    .await
    {
        Err(ApiError::Conflict(msg)) => {
            assert!(
                msg.contains("taken@example.com"),
                "unhelpful message: {msg}"
            )
        }
        Err(ApiError::Internal(e)) => {
            panic!("duplicate address surfaced as Internal (500) — the B1 bug: {e}")
        }
        Err(_) => panic!("duplicate address returned an unexpected error kind"),
        Ok(_) => panic!("duplicate address creation unexpectedly succeeded"),
    }

    cleanup(&path);
}

/// A1: role/domain-validation addresses must not be claimable, including via
/// the `RESERVED_LOCAL_PARTS`-style config extension.
#[tokio::test]
async fn reserved_local_parts_are_rejected() {
    let path = temp_db_path();
    let mut state = sqlite_app_state(&path).await;
    {
        let config = Arc::make_mut(&mut state.config);
        config
            .reserved_local_parts
            .insert("operator-extra".to_string());
    }

    for local in ["admin", "Postmaster", "SSLAdmin", "operator-extra"] {
        let req = CreateAddressRequest {
            local_part: Some(local.to_string()),
            domain: Some("example.com".to_string()),
        };
        match create(
            State(state.clone()),
            peer(),
            HeaderMap::new(),
            Some(Json(req)),
        )
        .await
        {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("reserved"), "unhelpful message: {msg}")
            }
            Ok(_) => panic!("reserved local part {local} was claimable"),
            Err(_) => panic!("reserved local part {local} returned the wrong error kind"),
        }
    }

    // Non-reserved names still work.
    let req = CreateAddressRequest {
        local_part: Some("adminx".to_string()),
        domain: None,
    };
    let created = create(State(state), peer(), HeaderMap::new(), Some(Json(req))).await;
    assert!(created.is_ok(), "non-reserved local part must be claimable");

    cleanup(&path);
}

/// A3: one IP can only create so many addresses per day.
#[tokio::test]
async fn daily_create_quota_returns_429() {
    let path = temp_db_path();
    let mut state = sqlite_app_state(&path).await;
    {
        let config = Arc::make_mut(&mut state.config);
        config.max_addresses_per_ip_per_day = 2;
    }
    // RuntimeLimits are derived from config at construction; rebuild.
    let state = AppState::new(
        Arc::clone(&state.store),
        Arc::clone(&state.config),
        state.events.clone(),
    );

    for _ in 0..2 {
        let res = create(State(state.clone()), peer(), HeaderMap::new(), None).await;
        assert!(res.is_ok(), "creates within quota must succeed");
    }
    match create(State(state), peer(), HeaderMap::new(), None).await {
        Err(ApiError::TooManyRequests(msg)) => {
            assert!(msg.contains("daily"), "unhelpful message: {msg}")
        }
        Ok(_) => panic!("create beyond daily quota must fail"),
        Err(_) => panic!("wrong error kind for daily quota"),
    }

    cleanup(&path);
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

async fn create_one(state: &AppState) -> (String, String) {
    let Ok((_, Json(created))) = create(State(state.clone()), peer(), HeaderMap::new(), None).await
    else {
        panic!("create should succeed");
    };
    (created.mailbox.address, created.owner_token)
}

/// A2: gated operations demand the owner token — missing and wrong tokens are
/// 401, the right one succeeds, and `extend` keeps the token valid.
#[tokio::test]
async fn gated_ops_require_owner_token() {
    let path = temp_db_path();
    let state = sqlite_app_state(&path).await;
    let (address, token) = create_one(&state).await;

    // Missing token → 401.
    match extend(
        State(state.clone()),
        AxumPath(address.clone()),
        HeaderMap::new(),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("extend without token must be 401"),
    }
    // Wrong token → 401.
    match delete(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer("am_wrong-token"),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("delete with wrong token must be 401"),
    }

    // Right token → extend works, and the token still works afterwards.
    let extended = extend(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer(&token),
    )
    .await;
    assert!(extended.is_ok(), "extend with valid token must succeed");
    let deleted = delete(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer(&token),
    )
    .await;
    assert!(
        deleted.is_ok(),
        "token must remain valid after extend (stable across extend)"
    );

    cleanup(&path);
}

/// A2: rotate reissues the token; the old one dies instantly.
#[tokio::test]
async fn rotate_invalidates_old_token() {
    let path = temp_db_path();
    let state = sqlite_app_state(&path).await;
    let (address, old_token) = create_one(&state).await;

    let Ok(Json(rotated)) = rotate(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer(&old_token),
    )
    .await
    else {
        panic!("rotate with valid token must succeed");
    };
    assert_ne!(rotated.owner_token, old_token);

    // Old token is dead...
    match extend(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer(&old_token),
    )
    .await
    {
        Err(ApiError::Unauthorized(_)) => {}
        _ => panic!("old token must be rejected after rotate"),
    }
    // ...the new one works.
    let extended = extend(
        State(state.clone()),
        AxumPath(address.clone()),
        bearer(&rotated.owner_token),
    )
    .await;
    assert!(extended.is_ok(), "new token must work after rotate");

    cleanup(&path);
}
