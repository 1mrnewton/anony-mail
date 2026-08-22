//! Scalar API reference (`GET /docs`) and the OpenAPI document
//! (`GET /openapi.json`). Both are gated by `API_DOCS_ENABLED` (on by default).
//!
//! The spec is the hand-maintained `openapi.json` at the crate root, embedded
//! at compile time so the runtime image does not need a separate copy.

use axum::Router;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use super::AppState;

const OPENAPI_JSON: &str = include_str!("../../openapi.json");

const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <title>anony-mail API</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <div id="app"></div>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
    <script>
      Scalar.createApiReference('#app', {
        url: '/openapi.json',
        servers: [{ url: window.location.origin, description: 'This instance' }],
        agent: { disabled: true },
      });
    </script>
  </body>
</html>
"#;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/docs", get(docs))
        .route("/openapi.json", get(openapi))
}

async fn docs() -> Html<&'static str> {
    Html(DOCS_HTML)
}

async fn openapi() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        OPENAPI_JSON,
    )
        .into_response()
}
