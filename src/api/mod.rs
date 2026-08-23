pub mod addresses;
pub mod auth;
pub mod client;
pub mod custom_domains;
pub mod docs;
pub mod entitlements;
pub mod legal;
pub mod limits;
pub mod messages;
pub mod push;
pub mod sse;

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use governor::middleware::NoOpMiddleware;
use serde_json::json;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::{GovernorError, GovernorLayer};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::attest::ChallengeStore;
use crate::config::Config;
use crate::custom_domains::{DomainDns, HickoryDns};
use crate::entitlements::{ProVerifier, RevenueCatVerifier};
use crate::events::EventBus;
use crate::store::Store;

use limits::RuntimeLimits;

/// Shared state handed to every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub config: Arc<Config>,
    pub events: EventBus,
    pub limits: Arc<RuntimeLimits>,
    /// DNS lookups for custom-domain verification (docs/11). The production
    /// resolver initializes lazily, so carrying it costs nothing when the
    /// feature is off; tests swap in a stub via [`Self::with_dns`].
    pub dns: Arc<dyn DomainDns>,
    /// Pro-entitlement lookups (docs/10). `None` when no RevenueCat key is
    /// configured — every verify then mints a free-tier token. Tests swap in
    /// a stub via [`Self::with_pro_verifier`].
    pub pro: Option<Arc<dyn ProVerifier>>,
    /// Single-use App Attest challenges (docs/09). Empty overhead when
    /// attestation is unconfigured.
    pub challenges: Arc<ChallengeStore>,
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, config: Arc<Config>, events: EventBus) -> Self {
        let limits = Arc::new(RuntimeLimits::from_config(&config));
        let pro = match &config.revenuecat_secret_key {
            Some(key) => {
                match RevenueCatVerifier::new(key.clone(), config.revenuecat_entitlement_id.clone())
                {
                    Ok(verifier) => Some(Arc::new(verifier) as Arc<dyn ProVerifier>),
                    Err(e) => {
                        error!(error = %e, "RevenueCat verifier failed to build; pro is unreachable");
                        None
                    }
                }
            }
            None => None,
        };
        Self {
            store,
            config,
            events,
            limits,
            dns: Arc::new(HickoryDns::new()),
            pro,
            challenges: Arc::new(ChallengeStore::default()),
        }
    }

    /// Replace the DNS resolver (tests).
    pub fn with_dns(mut self, dns: Arc<dyn DomainDns>) -> Self {
        self.dns = dns;
        self
    }

    /// Replace the pro verifier (tests).
    pub fn with_pro_verifier(mut self, pro: Arc<dyn ProVerifier>) -> Self {
        self.pro = Some(pro);
        self
    }
}

/// Build the application router with rate limiting, timeout, CORS, and
/// tracing middleware (A3).
pub fn router(state: AppState) -> Router {
    // The governor config is generic over its key extractor, so pick it once
    // here and build the rest generically.
    if state.config.api_trust_proxy_headers {
        build_router(state, SmartIpKeyExtractor)
    } else {
        build_router(state, PeerIpKeyExtractor)
    }
}

fn build_router<K>(state: AppState, key_extractor: K) -> Router
where
    K: KeyExtractor + Send + Sync + 'static,
    K::Key: Send + Sync + 'static,
{
    let config = Arc::clone(&state.config);
    let cors = build_cors(&config);

    // Address creation gets a stricter, dedicated per-IP budget: mailboxes
    // are real, spammable resources, unlike cheap reads. Custom-domain claims
    // share that budget (they are rarer and even more abusable), and so do
    // entitlement verification (it can trigger an upstream RevenueCat call)
    // and the App Attest flow (crypto-heavy, and challenges must not be
    // free to hoard). The client routes are always mounted and answer 503
    // when App Attest is unconfigured (docs/09 decision 2).
    let mut create_route = Router::new()
        .route("/api/addresses", post(addresses::create))
        .route("/api/entitlements/verify", post(entitlements::verify))
        .route("/api/client/challenge", post(client::challenge))
        .route("/api/client/attest", post(client::attest))
        .route("/api/client/assert", post(client::assert));
    if config.custom_domains_enabled {
        create_route = create_route.route("/api/custom-domains", post(custom_domains::create));
    }
    if config.create_rate_limit_per_minute > 0 && config.create_rate_limit_burst > 0 {
        let period = Duration::from_millis(60_000 / config.create_rate_limit_per_minute.max(1));
        create_route = create_route.layer(governor_layer(
            key_extractor.clone(),
            period,
            config.create_rate_limit_burst,
        ));
    }

    let mut non_sse = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/api/capabilities", get(capabilities))
        .route("/api/domains", get(addresses::list_domains))
        .route(
            "/api/addresses/{address}",
            get(addresses::get).delete(addresses::delete),
        )
        .route("/api/addresses/{address}/extend", post(addresses::extend))
        .route("/api/addresses/{address}/rotate", post(addresses::rotate))
        .route(
            "/api/addresses/{address}/messages",
            get(messages::list).delete(messages::clear),
        )
        .route(
            "/api/addresses/{address}/messages/{id}",
            get(messages::get).delete(messages::delete),
        )
        .route(
            "/api/addresses/{address}/messages/{id}/read",
            post(messages::mark_read),
        )
        .route(
            "/api/addresses/{address}/messages/{id}/raw",
            get(messages::get_raw),
        )
        .route(
            "/api/addresses/{address}/messages/{id}/attachments/{attachment_id}",
            get(messages::get_attachment),
        )
        .route("/api/push/config", get(push::config))
        .route("/api/push/vapid-public-key", get(push::vapid_public_key))
        .route(
            "/api/addresses/{address}/subscriptions",
            post(push::subscribe).delete(push::unsubscribe),
        )
        .merge(create_route);

    // Custom domains (docs/11): mounted only when enabled, so disabled
    // servers answer 404 — clients discover the feature via /api/capabilities.
    if config.custom_domains_enabled {
        non_sse = non_sse
            .route(
                "/api/custom-domains/{domain}",
                get(custom_domains::get).delete(custom_domains::delete),
            )
            .route(
                "/api/custom-domains/{domain}/verify",
                post(custom_domains::verify),
            );
    }

    // Docs routes are merged (not `.route(...)` here) so the OpenAPI drift
    // scrape does not treat `/docs` and `/openapi.json` as product API paths.
    if config.api_docs_enabled {
        non_sse = non_sse.merge(docs::router());
    }

    // Legal pages (`/tos`, `/privacy`) for the hosted deployment only.
    if config.legal_pages_enabled {
        non_sse = non_sse.merge(legal::router());
    }

    // Requests on non-SSE routes must finish within a bounded time; the SSE
    // route is intentionally excluded (streams are long-lived by design).
    if !config.api_request_timeout.is_zero() {
        non_sse = non_sse.layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.api_request_timeout,
        ));
    }

    let sse_route = Router::new().route("/api/addresses/{address}/events", get(sse::events));

    let mut app = non_sse.merge(sse_route);
    // General per-IP limit over everything, including SSE connection attempts.
    if config.api_rate_limit_per_second > 0 && config.api_rate_limit_burst > 0 {
        app = app.layer(governor_layer(
            key_extractor,
            Duration::from_millis(1_000 / config.api_rate_limit_per_second.max(1)),
            config.api_rate_limit_burst,
        ));
    }

    app.layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Build a per-IP token-bucket layer replenishing one request per `period`
/// with the given burst budget, and spawn its bookkeeping GC task.
fn governor_layer<K>(
    key_extractor: K,
    period: Duration,
    burst: u32,
) -> GovernorLayer<K, NoOpMiddleware<governor::clock::QuantaInstant>, Body>
where
    K: KeyExtractor + Send + Sync + 'static,
    K::Key: Send + Sync + 'static,
{
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(key_extractor)
            .period(period)
            .burst_size(burst)
            .finish()
            .expect("governor config: period and burst are validated non-zero"),
    );
    spawn_limiter_gc(Arc::clone(&config));
    GovernorLayer::new(config).error_handler(governor_error_response)
}

/// Periodically drop stale per-key limiter state so memory stays bounded.
fn spawn_limiter_gc<K>(
    config: Arc<GovernorConfig<K, NoOpMiddleware<governor::clock::QuantaInstant>>>,
) where
    K: KeyExtractor + Send + Sync + 'static,
    K::Key: Send + Sync + 'static,
{
    // Router construction can happen outside a runtime (e.g. in sync tests);
    // skip the GC task there.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            config.limiter().retain_recent();
        }
    });
}

/// Render governor rejections in the API's standard `{ "error": ... }` shape.
fn governor_error_response(e: GovernorError) -> Response<Body> {
    match e {
        GovernorError::TooManyRequests { wait_time, headers } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": format!("rate limit exceeded, retry in {wait_time}s")
                })),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&wait_time.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            if let Some(headers) = headers {
                response.headers_mut().extend(headers);
            }
            response
        }
        GovernorError::UnableToExtractKey => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "could not determine client address" })),
        )
            .into_response(),
        GovernorError::Other { code, msg, headers } => {
            let mut response = (
                code,
                Json(json!({
                    "error": msg.unwrap_or_else(|| "request rejected".to_string())
                })),
            )
                .into_response();
            if let Some(headers) = headers {
                response.headers_mut().extend(headers);
            }
            response
        }
    }
}

/// Liveness: the process is up. Never touches the database.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Feature discovery for clients: which optional server features this
/// instance has enabled, and the tier policy in force (docs/10). Absent keys
/// mean "unsupported" to tolerant clients, so this only ever grows. When
/// `entitlements.enforced` is false clients should unlock everything — the
/// self-host experience.
async fn capabilities(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "apns_push": state.config.apns_configured(),
        "web_push": state.config.push_configured(),
        "custom_domains": state.config.custom_domains_enabled,
        "attestation": {
            "supported": state.config.app_attest_configured(),
            "required": state.config.client_attestation_required,
        },
        "entitlements": {
            "enforced": state.config.entitlements_enforced,
            "free": state.config.free_tier,
            "pro": state.config.pro_tier,
        },
    }))
}

/// Readiness (P5): verifies the store can serve queries, so orchestrators
/// stop routing traffic when the database is down while `/healthz` still
/// reports the process alive.
async fn ready(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    if let Err(e) = state.store.ping().await {
        tracing::warn!(error = %e, "readiness probe failed: store unreachable");
        return Err(ApiError::ServiceUnavailable(
            "store unavailable".to_string(),
        ));
    }
    Ok(Json(json!({ "status": "ready" })))
}

fn build_cors(config: &Config) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers(Any);

    if config.cors_allow_any() {
        base.allow_origin(Any)
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        base.allow_origin(AllowOrigin::list(origins))
    }
}

/// Uniform error type for handlers, rendered as `{ "error": "..." }` JSON —
/// plus an optional machine-readable `code` for policy rejections (docs/10),
/// which existing clients simply ignore.
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Unauthorized(String),
    TooManyRequests(String),
    ServiceUnavailable(String),
    /// A coded rejection: `{ "error": message, "code": code }`.
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
    Internal(anyhow::Error),
}

impl ApiError {
    /// `403 { code: "pro_required" }` — the app maps this straight to its
    /// paywall.
    pub fn pro_required(message: impl Into<String>) -> Self {
        ApiError::Coded {
            status: StatusCode::FORBIDDEN,
            code: "pro_required",
            message: message.into(),
        }
    }

    /// `403 { code: "lifetime_cap" }` — extending would exceed the tier's
    /// max mailbox lifetime.
    pub fn lifetime_cap(message: impl Into<String>) -> Self {
        ApiError::Coded {
            status: StatusCode::FORBIDDEN,
            code: "lifetime_cap",
            message: message.into(),
        }
    }

    /// `403 { code: "mailbox_cap" }` — this device already holds the tier's
    /// maximum number of active mailboxes (docs/10 phase 2).
    pub fn mailbox_cap(message: impl Into<String>) -> Self {
        ApiError::Coded {
            status: StatusCode::FORBIDDEN,
            code: "mailbox_cap",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => {
                // Advertise the expected scheme per RFC 7235.
                let mut response =
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": m }))).into_response();
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                return response;
            }
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::Coded {
                status,
                code,
                message,
            } => {
                return (status, Json(json!({ "error": message, "code": code }))).into_response();
            }
            ApiError::Internal(e) => {
                error!(error = %e, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}

/// True if `e` wraps a database unique/primary-key violation, on any backend.
///
/// For SQL stores this uses sqlx's backend-agnostic
/// [`sqlx::error::DatabaseError::is_unique_violation`], which covers Postgres
/// (SQLSTATE `23505`) as well as SQLite's extended codes (`1555` primary key,
/// `2067` unique index) — matching on the raw Postgres code alone made SQLite
/// duplicates surface as 500s instead of 409s. Non-SQL stores raise the typed
/// [`crate::store::UniqueViolation`] marker instead.
pub fn is_unique_violation(e: &anyhow::Error) -> bool {
    if e.downcast_ref::<crate::store::UniqueViolation>().is_some() {
        return true;
    }
    e.downcast_ref::<sqlx::Error>()
        .and_then(|e| e.as_database_error())
        .is_some_and(|db| db.is_unique_violation())
}
