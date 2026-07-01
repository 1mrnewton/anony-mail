use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use uuid::Uuid;

use super::{ApiError, AppState};
use crate::model::{MessageSummary, StoredMessage};

/// `GET /api/addresses/{address}/messages` - inbox listing (newest first).
pub async fn list(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Vec<MessageSummary>>, ApiError> {
    let address = address.to_ascii_lowercase();
    // Distinguish "no such mailbox" (404) from "empty inbox" (200 []).
    if state.store.get_mailbox(&address).await?.is_none() {
        return Err(ApiError::NotFound("mailbox not found".to_string()));
    }
    let messages = state.store.list_messages(&address).await?;
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

/// `DELETE /api/addresses/{address}/messages/{id}` - delete a single message.
pub async fn delete(
    State(state): State<AppState>,
    Path((address, id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let address = address.to_ascii_lowercase();
    if state.store.delete_message(&address, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("message not found".to_string()))
    }
}

/// `GET /api/addresses/{address}/messages/{id}/attachments/{attachment_id}`
/// - download raw attachment bytes.
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
        CONTENT_TYPE,
        HeaderValue::from_str(&att.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    let disposition = format!(
        "attachment; filename=\"{}\"",
        safe_filename(att.filename.as_deref())
    );
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(CONTENT_DISPOSITION, value);
    }

    Ok((headers, att.content))
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
