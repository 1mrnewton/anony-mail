pub mod addresses;
pub mod messages;
pub mod sse;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::config::Config;
use crate::events::EventBus;
use crate::store::Store;

/// Shared state handed to every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub config: Arc<Config>,
    pub events: EventBus,
}

/// Build the application router with CORS + tracing middleware.
pub fn router(state: AppState) -> Router {
    let cors = build_cors(&state.config);

    Router::new()
        .route("/healthz", get(health))
        .route("/api/domains", get(addresses::list_domains))
        .route("/api/addresses", post(addresses::create))
        .route(
            "/api/addresses/{address}",
            get(addresses::get).delete(addresses::delete),
        )
        .route("/api/addresses/{address}/extend", post(addresses::extend))
        .route("/api/addresses/{address}/messages", get(messages::list))
        .route(
            "/api/addresses/{address}/messages/{id}",
            get(messages::get).delete(messages::delete),
        )
        .route(
            "/api/addresses/{address}/messages/{id}/attachments/{attachment_id}",
            get(messages::get_attachment),
        )
        .route("/api/addresses/{address}/events", get(sse::events))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
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
pub enum ApiError {
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
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

/// True if `e` wraps a Postgres unique-violation (SQLSTATE 23505).
pub fn is_unique_violation(e: &anyhow::Error) -> bool {
    e.downcast_ref::<sqlx::Error>()
        .and_then(|e| e.as_database_error())
        .and_then(|db| db.code())
        .as_deref()
        == Some("23505")
}
