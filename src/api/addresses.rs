use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, AppState, is_unique_violation};
use crate::model::Mailbox;

const LOCAL_PART_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const RANDOM_LOCAL_PART_LEN: usize = 10;
const MAX_LOCAL_PART_LEN: usize = 64;
const RANDOM_CREATE_ATTEMPTS: usize = 5;

#[derive(Debug, Default, Deserialize)]
pub struct CreateAddressRequest {
    /// Optional custom local part (the bit before `@`). Random if omitted.
    pub local_part: Option<String>,
    /// Optional domain; must be one of the configured domains. Defaults to the
    /// first configured domain.
    pub domain: Option<String>,
}

/// `GET /api/domains` - list the domains this server accepts mail for.
pub async fn list_domains(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "domains": state.config.domains }))
}

/// `POST /api/addresses` - create a disposable mailbox.
pub async fn create(
    State(state): State<AppState>,
    body: Option<Json<CreateAddressRequest>>,
) -> Result<(StatusCode, Json<Mailbox>), ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let domain = match req.domain {
        Some(d) => {
            let d = d.trim().to_ascii_lowercase();
            if !state.config.accepts_domain(&d) {
                return Err(ApiError::BadRequest(format!("unknown domain: {d}")));
            }
            d
        }
        None => state.config.domains[0].clone(),
    };

    let ttl = Duration::seconds(state.config.default_ttl.as_secs() as i64);
    let expires_at = Utc::now() + ttl;

    // Custom local part: validate and fail loudly on collision.
    if let Some(local_part) = req.local_part {
        let local = local_part.trim().to_ascii_lowercase();
        if !is_valid_local_part(&local) {
            return Err(ApiError::BadRequest(
                "local_part must be 1-64 chars of a-z, 0-9, '.', '_' or '-' and not start/end with a separator".to_string(),
            ));
        }
        let address = format!("{local}@{domain}");
        return match state
            .store
            .create_mailbox(&address, &domain, expires_at)
            .await
        {
            Ok(mb) => Ok((StatusCode::CREATED, Json(mb))),
            Err(e) if is_unique_violation(&e) => Err(ApiError::Conflict(format!(
                "address already exists: {address}"
            ))),
            Err(e) => Err(ApiError::Internal(e)),
        };
    }

    // Random local part: retry a few times on the (rare) collision.
    for _ in 0..RANDOM_CREATE_ATTEMPTS {
        let address = format!("{}@{}", random_local_part(), domain);
        match state
            .store
            .create_mailbox(&address, &domain, expires_at)
            .await
        {
            Ok(mb) => return Ok((StatusCode::CREATED, Json(mb))),
            Err(e) if is_unique_violation(&e) => continue,
            Err(e) => return Err(ApiError::Internal(e)),
        }
    }
    Err(ApiError::Internal(anyhow::anyhow!(
        "could not allocate a unique random address after {RANDOM_CREATE_ATTEMPTS} attempts"
    )))
}

/// `GET /api/addresses/{address}` - mailbox metadata / existence check.
pub async fn get(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Mailbox>, ApiError> {
    let address = address.to_ascii_lowercase();
    match state.store.get_mailbox(&address).await? {
        Some(mb) => Ok(Json(mb)),
        None => Err(ApiError::NotFound("mailbox not found".to_string())),
    }
}

/// `POST /api/addresses/{address}/extend` - push expiry back by the default TTL.
pub async fn extend(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Mailbox>, ApiError> {
    let address = address.to_ascii_lowercase();
    let ttl = Duration::seconds(state.config.default_ttl.as_secs() as i64);
    let new_expiry = Utc::now() + ttl;
    match state.store.extend_mailbox(&address, new_expiry).await? {
        Some(mb) => Ok(Json(mb)),
        None => Err(ApiError::NotFound("mailbox not found".to_string())),
    }
}

/// `DELETE /api/addresses/{address}` - delete a mailbox and all its messages.
pub async fn delete(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<StatusCode, ApiError> {
    let address = address.to_ascii_lowercase();
    if state.store.delete_mailbox(&address).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("mailbox not found".to_string()))
    }
}

fn random_local_part() -> String {
    let mut rng = rand::rng();
    (0..RANDOM_LOCAL_PART_LEN)
        .map(|_| {
            let idx = rng.random_range(0..LOCAL_PART_CHARSET.len());
            LOCAL_PART_CHARSET[idx] as char
        })
        .collect()
}

/// Validate a user-supplied local part: 1-64 chars from `[a-z0-9._-]`, and it
/// may not start or end with a separator (`.`, `_`, `-`).
fn is_valid_local_part(local: &str) -> bool {
    if local.is_empty() || local.len() > MAX_LOCAL_PART_LEN {
        return false;
    }
    let ok_chars = local
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if !ok_chars {
        return false;
    }
    let is_sep = |b: u8| matches!(b, b'.' | b'_' | b'-');
    let bytes = local.as_bytes();
    !is_sep(bytes[0]) && !is_sep(bytes[bytes.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_local_parts_are_well_formed() {
        for _ in 0..100 {
            let lp = random_local_part();
            assert_eq!(lp.len(), RANDOM_LOCAL_PART_LEN);
            assert!(
                is_valid_local_part(&lp),
                "generated invalid local part: {lp}"
            );
        }
    }

    #[test]
    fn validates_local_parts() {
        assert!(is_valid_local_part("john"));
        assert!(is_valid_local_part("john.doe"));
        assert!(is_valid_local_part("a1_b-c"));
        assert!(!is_valid_local_part(""));
        assert!(!is_valid_local_part(".john"));
        assert!(!is_valid_local_part("john."));
        assert!(!is_valid_local_part("John")); // uppercase not allowed (callers lowercase first)
        assert!(!is_valid_local_part("a b"));
        assert!(!is_valid_local_part("a@b"));
        assert!(!is_valid_local_part(&"x".repeat(65)));
    }
}
