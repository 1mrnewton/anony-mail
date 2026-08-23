//! Legal + support pages for the hosted deployment (`GET /tos`,
//! `GET /privacy`, `GET /support`) — the pages App Review requires links to.
//!
//! Gated by `LEGAL_PAGES_ENABLED` (off by default): the text names the
//! hosted service's operator, so self-hosted instances must not serve it.
//! The pages are embedded at compile time from `legal/` at the crate root.

use axum::Router;
use axum::response::Html;
use axum::routing::get;

use super::AppState;

const TOS_HTML: &str = include_str!("../../legal/tos.html");
const PRIVACY_HTML: &str = include_str!("../../legal/privacy.html");
const SUPPORT_HTML: &str = include_str!("../../legal/support.html");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tos", get(tos))
        .route("/privacy", get(privacy))
        .route("/support", get(support))
}

async fn tos() -> Html<&'static str> {
    Html(TOS_HTML)
}

async fn privacy() -> Html<&'static str> {
    Html(PRIVACY_HTML)
}

async fn support() -> Html<&'static str> {
    Html(SUPPORT_HTML)
}
