//! Owner-token authentication (A2, design in `docs/08-authentication.md`).
//!
//! Opaque per-mailbox bearer token: 32 CSPRNG bytes, base64url, `am_` prefix.
//! Only its SHA-256 hex lives in the database, on the mailbox row — so the
//! token is valid exactly as long as the mailbox exists, survives `extend`,
//! and dies instantly on rotate or delete.

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use rand::RngExt;
use sha2::{Digest, Sha256};

use super::{ApiError, AppState};
use crate::model::Mailbox;

/// Greppable, obviously-a-secret prefix (like `sk_...`).
pub const TOKEN_PREFIX: &str = "am_";

/// Prefix for custom-domain claim tokens (docs/11), so the two credential
/// kinds are never mistaken for each other.
pub const DOMAIN_TOKEN_PREFIX: &str = "amd_";

/// Generate a fresh owner token. Returns `(token, sha256_hex_of_token)`; only
/// the hash may be persisted.
pub fn generate_owner_token() -> (String, String) {
    generate_token(TOKEN_PREFIX)
}

/// Generate a bearer token with the given prefix: 32 CSPRNG bytes, base64url.
/// Returns `(token, sha256_hex_of_token)`; only the hash may be persisted.
pub fn generate_token(prefix: &str) -> (String, String) {
    let bytes: [u8; 32] = rand::rng().random();
    let token = format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let hash = hash_token(&token);
    (token, hash)
}

/// True if `presented` hashes to `want_hash` (constant-time compare).
pub fn token_matches_hash(presented: &str, want_hash: &str) -> bool {
    constant_time_eq(hash_token(presented).as_bytes(), want_hash.as_bytes())
}

/// SHA-256 of the full token string (prefix included), lowercase hex.
pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Extract the token from an `Authorization: Bearer <token>` header.
/// The scheme is matched case-insensitively per RFC 7235.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// Authorize a gated operation on `address` (must already be lowercased).
///
/// `404` when the mailbox doesn't exist (existence is already discoverable via
/// the open read endpoints, so this leaks nothing new), `401` for a missing or
/// wrong token — including mailboxes created before tokens existed (`NULL`
/// hash), which can never pass and simply age out.
pub async fn authorize_owner(
    state: &AppState,
    address: &str,
    headers: &HeaderMap,
) -> Result<Mailbox, ApiError> {
    let mailbox = state
        .store
        .get_mailbox(address)
        .await?
        .ok_or_else(|| ApiError::NotFound("mailbox not found".to_string()))?;

    let presented = bearer_token(headers)
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".to_string()))?;

    let Some(want) = mailbox.owner_token_hash.as_deref() else {
        return Err(ApiError::Unauthorized(
            "mailbox has no owner token".to_string(),
        ));
    };

    if token_matches_hash(presented, want) {
        Ok(mailbox)
    } else {
        Err(ApiError::Unauthorized("invalid owner token".to_string()))
    }
}

/// Constant-time comparison. Strictly optional here (both sides are SHA-256
/// hashes of a 256-bit secret, so timing leaks nothing exploitable) but it is
/// best practice and costs nothing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_have_prefix_and_high_entropy_encoding() {
        let (token, hash) = generate_owner_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        // 32 bytes base64url unpadded = 43 chars.
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 43);
        assert_eq!(hash, hash_token(&token));
        assert_eq!(hash.len(), 64, "sha256 hex");

        let (token2, hash2) = generate_owner_token();
        assert_ne!(token, token2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn bearer_parsing_is_scheme_insensitive_and_strict() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None, "no header");

        headers.insert(header::AUTHORIZATION, "Bearer am_abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("am_abc"));

        headers.insert(header::AUTHORIZATION, "bearer am_abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("am_abc"), "lowercase scheme");

        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwdw==".parse().unwrap());
        assert_eq!(bearer_token(&headers), None, "wrong scheme");

        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&headers), None, "empty token");
    }
}
