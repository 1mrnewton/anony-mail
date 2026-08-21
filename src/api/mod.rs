pub mod addresses;
pub mod auth;
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

use crate::config::Config;
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
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, config: Arc<Config>, events: EventBus) -> Self {
        let limits = Arc::new(RuntimeLimits::from_config(&config));
        Self {
            store,
            config,
            events,
            limits,
        }
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
    // are real, spammable resources, unlike cheap reads.
    let mut create_route = Router::new().route("/api/addresses", post(addresses::create));
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
        .route("/api/push/vapid-public-key", get(push::vapid_public_key))
        .route(
            "/api/addresses/{address}/subscriptions",
            post(push::subscribe).delete(push::unsubscribe),
        )
        .merge(create_route);

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

/// Uniform error type for handlers, rendered as `{ "error": "..." }` JSON.
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Unauthorized(String),
    TooManyRequests(String),
    ServiceUnavailable(String),
    Internal(anyhow::Error),
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
