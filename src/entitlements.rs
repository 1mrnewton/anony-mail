//! Server-side entitlements (docs/10, phase 1).
//!
//! Tier is proven by purchase, not identity: the app sends its anonymous
//! RevenueCat app-user id, the server checks the pro entitlement against the
//! RevenueCat API, and the result is embedded as the `tier` claim in a
//! short-lived signed client token (HS256). Requests carry the token in
//! `X-Client-Token`; no token simply means free tier. Everything is off by
//! default — self-hosted servers never mint or check tokens.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context as _, anyhow, bail};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// How long a minted client token stays valid. Renewal re-checks RevenueCat,
/// so a lapsed subscription degrades to free within this window.
pub const CLIENT_TOKEN_TTL_SECONDS: i64 = 12 * 3600;

/// `kind` claim for tokens minted without device attestation (phase 1).
pub const KIND_UNATTESTED: &str = "unattested";

/// `kind` claim for tokens minted through App Attest (docs/09). When
/// `CLIENT_ATTESTATION_REQUIRED` is on, only these pass the mutation gate.
pub const KIND_IOS: &str = "ios";

/// How long one RevenueCat verdict is reused before re-asking.
const RC_CACHE_TTL: StdDuration = StdDuration::from_secs(600);

/// A client's tier. The default for requests without a client token is
/// [`Tier::Free`]; [`Tier::Pro`] is only ever asserted by a signed token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Pro,
}

/// Claims inside a client token (docs/09 shape).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientClaims {
    /// Which verification path minted this token: `"unattested"` (doc 10
    /// phase 1) or `"ios"` (App Attest, doc 09).
    pub kind: String,
    /// The App Attest key id behind an attested token; its SHA-256 hex
    /// scopes per-device mailbox caps. Absent on unattested tokens (and on
    /// tokens minted before phase 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub tier: Tier,
    pub iat: i64,
    pub exp: i64,
}

impl ClientClaims {
    /// True when this token was minted through device attestation.
    pub fn is_attested(&self) -> bool {
        self.kind != KIND_UNATTESTED
    }
}

/// Sign a client token. Returns `(token, expires_at)`.
pub fn mint_client_token(
    signing_key: &[u8],
    kind: &str,
    kid: Option<&str>,
    tier: Tier,
    ttl: Duration,
) -> anyhow::Result<(String, DateTime<Utc>)> {
    let now = Utc::now();
    let expires_at = now + ttl;
    let claims = ClientClaims {
        kind: kind.to_string(),
        kid: kid.map(String::from),
        tier,
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
    };
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_key),
    )
    .context("signing client token")?;
    Ok((token, expires_at))
}

/// Why a presented client token was rejected. The two cases get distinct
/// error codes so the app knows "refresh and retry" from "start over".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Expired,
    Invalid,
}

/// Verify a client token's signature and expiry and return its claims.
pub fn verify_client_token(signing_key: &[u8], token: &str) -> Result<ClientClaims, TokenError> {
    let mut validation = Validation::new(Algorithm::HS256);
    // Default leeway is 60s, which would make freshly-expired tokens pass;
    // keep just enough slack for clock skew between replicas.
    validation.leeway = 5;
    match jsonwebtoken::decode::<ClientClaims>(
        token,
        &DecodingKey::from_secret(signing_key),
        &validation,
    ) {
        Ok(data) => Ok(data.claims),
        Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) => {
            Err(TokenError::Expired)
        }
        Err(_) => Err(TokenError::Invalid),
    }
}

/// Answers "does this purchase id have the pro entitlement right now?".
/// A trait so tests stub the verdict without HTTP.
#[async_trait]
pub trait ProVerifier: Send + Sync {
    async fn is_pro(&self, rc_app_user_id: &str) -> anyhow::Result<bool>;
}

/// Production [`ProVerifier`]: RevenueCat's
/// `GET /v1/subscribers/{app_user_id}` with the secret key, verdicts cached
/// for [`RC_CACHE_TTL`] so token refreshes don't hammer RC.
pub struct RevenueCatVerifier {
    http: reqwest::Client,
    base_url: String,
    secret_key: String,
    entitlement_id: String,
    cache: Mutex<HashMap<String, (bool, Instant)>>,
}

impl RevenueCatVerifier {
    pub fn new(secret_key: String, entitlement_id: String) -> anyhow::Result<Self> {
        Self::with_base_url(secret_key, entitlement_id, "https://api.revenuecat.com")
    }

    /// Point at a different API root (tests).
    pub fn with_base_url(
        secret_key: String,
        entitlement_id: String,
        base_url: &str,
    ) -> anyhow::Result<Self> {
        // reqwest is built with `rustls-no-provider`; install the ring
        // provider process-wide (a no-op Err if something already did).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(10))
            .build()
            .context("building RevenueCat HTTP client")?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            secret_key,
            entitlement_id,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn cached(&self, id: &str) -> Option<bool> {
        let cache = self.cache.lock().expect("rc cache lock");
        cache
            .get(id)
            .filter(|(_, at)| at.elapsed() < RC_CACHE_TTL)
            .map(|(pro, _)| *pro)
    }

    fn remember(&self, id: &str, pro: bool) {
        let mut cache = self.cache.lock().expect("rc cache lock");
        // Ids are attacker-suppliable, so keep the map bounded.
        if cache.len() >= 10_000 {
            cache.retain(|_, (_, at)| at.elapsed() < RC_CACHE_TTL);
        }
        cache.insert(id.to_string(), (pro, Instant::now()));
    }
}

#[async_trait]
impl ProVerifier for RevenueCatVerifier {
    async fn is_pro(&self, rc_app_user_id: &str) -> anyhow::Result<bool> {
        if let Some(pro) = self.cached(rc_app_user_id) {
            return Ok(pro);
        }

        // Path-segment push percent-encodes the id (RC anonymous ids contain
        // `$` and `:`).
        let mut url = reqwest::Url::parse(&self.base_url).context("parsing RevenueCat base url")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("RevenueCat base url cannot be a base"))?
            .extend(["v1", "subscribers", rc_app_user_id]);

        let response = self
            .http
            .get(url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .context("calling RevenueCat")?;
        let status = response.status();
        if !status.is_success() {
            bail!("RevenueCat returned {status}");
        }
        let body: SubscriberResponse = response
            .json()
            .await
            .context("parsing RevenueCat response")?;

        let pro = entitlement_active(&body, &self.entitlement_id, Utc::now());
        self.remember(rc_app_user_id, pro);
        Ok(pro)
    }
}

/// The slice of RevenueCat's subscriber payload we care about.
#[derive(Debug, Deserialize)]
struct SubscriberResponse {
    subscriber: Subscriber,
}

#[derive(Debug, Deserialize)]
struct Subscriber {
    #[serde(default)]
    entitlements: HashMap<String, Entitlement>,
}

#[derive(Debug, Deserialize)]
struct Entitlement {
    /// `null` for lifetime purchases, otherwise the moment it lapses.
    expires_date: Option<DateTime<Utc>>,
}

fn entitlement_active(body: &SubscriberResponse, entitlement_id: &str, now: DateTime<Utc>) -> bool {
    body.subscriber
        .entitlements
        .get(entitlement_id)
        .is_some_and(|e| e.expires_date.is_none_or(|d| d > now))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = &[7u8; 32];

    #[test]
    fn mint_verify_roundtrip_carries_tier_and_kind() {
        let (token, expires_at) =
            mint_client_token(KEY, KIND_UNATTESTED, None, Tier::Pro, Duration::hours(12)).unwrap();
        assert!(expires_at > Utc::now());

        let claims = verify_client_token(KEY, &token).unwrap();
        assert_eq!(claims.tier, Tier::Pro);
        assert_eq!(claims.kind, KIND_UNATTESTED);
        assert_eq!(claims.kid, None);
        assert!(!claims.is_attested());
        assert_eq!(claims.exp, expires_at.timestamp());
    }

    #[test]
    fn attested_tokens_carry_the_key_id() {
        let (token, _) = mint_client_token(
            KEY,
            KIND_IOS,
            Some("key-123"),
            Tier::Free,
            Duration::hours(1),
        )
        .unwrap();
        let claims = verify_client_token(KEY, &token).unwrap();
        assert_eq!(claims.kind, KIND_IOS);
        assert_eq!(claims.kid.as_deref(), Some("key-123"));
        assert!(claims.is_attested());
    }

    #[test]
    fn expired_and_forged_tokens_are_distinguished() {
        let (expired, _) = mint_client_token(
            KEY,
            KIND_UNATTESTED,
            None,
            Tier::Pro,
            Duration::seconds(-120),
        )
        .unwrap();
        assert_eq!(verify_client_token(KEY, &expired), Err(TokenError::Expired));

        let (token, _) =
            mint_client_token(KEY, KIND_UNATTESTED, None, Tier::Pro, Duration::hours(1)).unwrap();
        let wrong_key = [8u8; 32];
        assert_eq!(
            verify_client_token(&wrong_key, &token),
            Err(TokenError::Invalid)
        );
        assert_eq!(
            verify_client_token(KEY, "not-a-jwt"),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn tier_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Tier::Free).unwrap(), "\"free\"");
        assert_eq!(serde_json::from_str::<Tier>("\"pro\"").unwrap(), Tier::Pro);
    }

    #[test]
    fn revenuecat_payload_activity_rules() {
        let parse = |json: &str| serde_json::from_str::<SubscriberResponse>(json).unwrap();
        let now = Utc::now();

        let active = parse(
            r#"{"subscriber":{"entitlements":{"Anony Mail Pro":{"expires_date":"2999-01-01T00:00:00Z"}}}}"#,
        );
        assert!(entitlement_active(&active, "Anony Mail Pro", now));

        let lifetime =
            parse(r#"{"subscriber":{"entitlements":{"Anony Mail Pro":{"expires_date":null}}}}"#);
        assert!(entitlement_active(&lifetime, "Anony Mail Pro", now));

        let lapsed = parse(
            r#"{"subscriber":{"entitlements":{"Anony Mail Pro":{"expires_date":"2001-01-01T00:00:00Z"}}}}"#,
        );
        assert!(!entitlement_active(&lapsed, "Anony Mail Pro", now));

        let other = parse(
            r#"{"subscriber":{"entitlements":{"Other":{"expires_date":null}},"first_seen":"x"}}"#,
        );
        assert!(!entitlement_active(&other, "Anony Mail Pro", now));

        let none = parse(r#"{"subscriber":{"original_app_user_id":"abc"}}"#);
        assert!(!entitlement_active(&none, "Anony Mail Pro", now));
    }
}
