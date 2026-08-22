use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::{self, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::authorize_owner;
use super::{ApiError, AppState};
use crate::model::{MessageSummary, StoredMessage};

/// Default page size for inbox listings (P3).
const DEFAULT_PAGE_SIZE: u32 = 50;
/// Hard cap on `?limit=` — larger requests are clamped, not rejected.
const MAX_PAGE_SIZE: u32 = 200;

/// Query parameters for `GET .../messages` (P3 pagination).
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Max summaries to return (default 50, clamped to 1..=200).
    pub limit: Option<u32>,
    /// Keyset cursor: only messages strictly newer than this message id.
    /// Unknown/pruned ids are ignored (newest page is returned).
    pub since: Option<Uuid>,
}

/// `GET /api/addresses/{address}/messages` - inbox listing (newest first).
/// Supports `?limit=` + `?since=<message-uuid>` keyset pagination (P3).
pub async fn list(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<MessageSummary>>, ApiError> {
    let address = address.to_ascii_lowercase();
    // Distinguish "no such mailbox" (404) from "empty inbox" (200 []).
    if state.store.get_mailbox(&address).await?.is_none() {
        return Err(ApiError::NotFound("mailbox not found".to_string()));
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let messages = state
        .store
        .list_messages(&address, limit, query.since)
        .await?;
    Ok(Json(messages))
}

/// `GET /api/addresses/{address}/messages/{id}` - full message with bodies.
pub async fn get(
    State(state): State<AppState>,
    Path((address, id)): Path<(String, Uuid)>,
) -> Result<Json<StoredMessage>, ApiError> {
    let address = address.to_ascii_lowercase();
    match state.store.get_message(&address, id).await? {
        Some(msg) => Ok(Json(msg)),
        None => Err(ApiError::NotFound("message not found".to_string())),
    }
}

/// `POST /api/addresses/{address}/messages/{id}/read` - mark a message read
/// (U3). Open like the read endpoints: knowing the address already grants
/// full read access, so a read-marker needs no stronger proof.
pub async fn mark_read(
    State(state): State<AppState>,
    Path((address, id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let address = address.to_ascii_lowercase();
    if state.store.mark_seen(&address, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("message not found".to_string()))
    }
}

/// Body of the U3 clear-inbox response.
#[derive(Debug, Serialize)]
pub struct ClearInboxResponse {
    /// Number of messages that were deleted.
    pub deleted: u64,
}

/// `DELETE /api/addresses/{address}/messages` - delete every message in the
/// mailbox (U3 clear inbox). Owner-token gated (A2); the mailbox survives.
pub async fn clear(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ClearInboxResponse>, ApiError> {
    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;
    let deleted = state.store.delete_all_messages(&address).await?;
    Ok(Json(ClearInboxResponse { deleted }))
}

/// `DELETE /api/addresses/{address}/messages/{id}` - delete a single message.
/// Owner-token gated (A2).
pub async fn delete(
    State(state): State<AppState>,
    Path((address, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let address = address.to_ascii_lowercase();
    super::entitlements::attestation_gate(&state, &headers)?;
    authorize_owner(&state, &address, &headers).await?;
    if state.store.delete_message(&address, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("message not found".to_string()))
    }
}

/// `GET /api/addresses/{address}/messages/{id}/raw` - download the original
/// RFC 5322 bytes as a `.eml` file (U2). `404` when the message is missing
/// **or** raw retention (`STORE_RAW_MESSAGE`) was off when it was delivered.
pub async fn get_raw(
    State(state): State<AppState>,
    Path((address, id)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    let address = address.to_ascii_lowercase();
    let raw = state
        .store
        .get_raw_message(&address, id)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(
                "raw message not available (missing, or raw retention is disabled)".to_string(),
            )
        })?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("message/rfc822"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let disposition = format!("attachment; filename=\"{id}.eml\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    Ok((headers, raw))
}

/// `GET /api/addresses/{address}/messages/{id}/attachments/{attachment_id}`
/// - download raw attachment bytes.
///
/// A6 hardening: `X-Content-Type-Options: nosniff` on every response, and
/// browser-active types (HTML, SVG, XML) are served as
/// `application/octet-stream` so a crafted attachment can never execute on
/// the API origin. The real type stays in the message's attachment metadata.
pub async fn get_attachment(
    State(state): State<AppState>,
    Path((address, id, attachment_id)): Path<(String, Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    let address = address.to_ascii_lowercase();
    let att = state
        .store
        .get_attachment(&address, id, attachment_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("attachment not found".to_string()))?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let content_type = if forced_octet_stream(&att.content_type) {
        HeaderValue::from_static("application/octet-stream")
    } else {
        HeaderValue::from_str(&att.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
    };
    headers.insert(CONTENT_TYPE, content_type);
    if let Ok(value) = HeaderValue::from_str(&content_disposition(att.filename.as_deref())) {
        headers.insert(CONTENT_DISPOSITION, value);
    }

    Ok((headers, att.content))
}

/// A6: types a browser may execute/render actively when navigated to.
/// Matched on the media type's essence (parameters stripped, case-insensitive).
fn forced_octet_stream(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        essence.as_str(),
        "text/html" | "application/xhtml+xml" | "image/svg+xml" | "text/xml" | "application/xml"
    )
}

/// Build the `Content-Disposition` value: an ASCII-safe `filename="…"`
/// fallback always, plus an RFC 5987 `filename*=UTF-8''…` form when the
/// original name is non-ASCII so it survives for capable clients (A6/U-note).
fn content_disposition(name: Option<&str>) -> String {
    let mut value = format!("attachment; filename=\"{}\"", safe_filename(name));
    if let Some(raw) = name
        && !raw.is_ascii()
    {
        value.push_str("; filename*=UTF-8''");
        value.push_str(&rfc5987_encode(raw));
    }
    value
}

/// Percent-encode a filename per RFC 5987 `value-chars`: only `attr-char`
/// bytes stay literal, everything else (UTF-8 continuation bytes included)
/// becomes `%XX` — which also neutralizes header-injection attempts.
fn rfc5987_encode(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(name.len() * 3);
    for &b in name.as_bytes() {
        let attr_char = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            );
        if attr_char {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// Produce an ASCII-safe filename for the `Content-Disposition` header,
/// stripping quotes/control characters. Falls back to `attachment`.
fn safe_filename(name: Option<&str>) -> String {
    let cleaned: String = name
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\' && c.is_ascii())
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_types_are_forced_to_octet_stream() {
        assert!(forced_octet_stream("text/html"));
        assert!(forced_octet_stream("TEXT/HTML; charset=utf-8"));
        assert!(forced_octet_stream("image/svg+xml"));
        assert!(forced_octet_stream("application/xml"));
        assert!(forced_octet_stream("text/xml"));
        assert!(forced_octet_stream("application/xhtml+xml"));

        assert!(!forced_octet_stream("application/pdf"));
        assert!(!forced_octet_stream("image/png"));
        assert!(!forced_octet_stream("text/plain"));
    }

    #[test]
    fn ascii_names_get_plain_disposition() {
        assert_eq!(
            content_disposition(Some("invoice.pdf")),
            "attachment; filename=\"invoice.pdf\""
        );
        assert_eq!(
            content_disposition(None),
            "attachment; filename=\"attachment\""
        );
    }

    #[test]
    fn non_ascii_names_add_rfc5987_form() {
        let value = content_disposition(Some("naïve résumé.pdf"));
        assert!(value.starts_with("attachment; filename=\"nave rsum.pdf\""));
        assert!(value.ends_with("; filename*=UTF-8''na%C3%AFve%20r%C3%A9sum%C3%A9.pdf"));
        assert!(value.is_ascii(), "header value must stay ASCII");
    }

    #[test]
    fn rfc5987_encoding_is_injection_safe() {
        assert_eq!(rfc5987_encode("a\r\nb: c"), "a%0D%0Ab%3A%20c");
    }
}
