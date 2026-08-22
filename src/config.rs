use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;

use crate::store::MailboxQuotas;

/// Connection string used when `DATABASE_URL` is unset: a SQLite file in a
/// `data/` directory relative to the working directory.
pub const DEFAULT_SQLITE_URL: &str = "sqlite://data/anony-mail.db";

/// Local parts that can never be claimed through the API (A1): RFC 2142 role
/// addresses, the CA/Browser-Forum domain-validation set, and common
/// operator/system names. Operators can extend the set (never shrink it) via
/// the `RESERVED_LOCAL_PARTS` env var.
const BUILTIN_RESERVED_LOCAL_PARTS: &[&str] = &[
    // RFC 2142 role addresses
    "postmaster",
    "abuse",
    "hostmaster",
    "webmaster",
    "noc",
    "security",
    "info",
    "marketing",
    "sales",
    "support",
    // CA/Browser-Forum domain-validation addresses
    "admin",
    "administrator",
    "ssladmin",
    "ssladministrator",
    "sysadmin",
    // Operator / system
    "root",
    "mailer-daemon",
    "noreply",
    "no-reply",
    "daemon",
];

/// Which storage backend a [`Config`] selects, derived from `DATABASE_URL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
}

/// What one tier is allowed to do (docs/10). Serialized verbatim into
/// `GET /api/capabilities` so clients drive their gates and paywall copy from
/// the server's numbers instead of hardcoded constants.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierPolicy {
    /// Active-mailbox cap per attested device. `0` = unlimited. Enforced only
    /// for requests that prove which device they come from (attested token).
    pub active_mailboxes: u32,
    /// Ceiling on `expires_at - created_at`, including extends. `0` =
    /// unlimited.
    pub max_lifetime_seconds: u64,
    /// May pick the local part instead of getting a random one.
    pub custom_local_parts: bool,
    /// How many of the configured domains are usable, counted from the front
    /// of `DOMAINS`. `0` = all.
    pub domain_count: u32,
    /// May claim bring-your-own domains.
    pub custom_domains: bool,
}

/// Runtime configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the SMTP receiver listens on (e.g. `0.0.0.0:25`).
    pub smtp_bind_addr: SocketAddr,
    /// Address the HTTP API listens on (e.g. `0.0.0.0:8080`).
    pub api_bind_addr: SocketAddr,
    /// Domains this server accepts mail for. Always lowercased.
    pub domains: Vec<String>,
    /// Database connection string. `sqlite://<path>` (the default) selects the
    /// embedded SQLite backend; `postgres://…` selects PostgreSQL.
    pub database_url: String,
    /// Max connections in the database pool. 0 keeps the backend default
    /// (PostgreSQL 10, SQLite 5).
    pub db_max_connections: u32,
    /// How long a freshly created mailbox lives before it expires.
    pub default_ttl: Duration,
    /// Largest message (raw bytes) accepted during the SMTP DATA phase.
    pub max_message_size: usize,
    /// Max recipients accepted per SMTP transaction.
    pub max_recipients: usize,
    /// Max simultaneously open SMTP connections across the whole server.
    pub max_connections: usize,
    /// Idle/session timeout for a single SMTP connection.
    pub smtp_session_timeout: Duration,
    /// Max new SMTP connections allowed from a single IP within a 60s window.
    pub per_ip_connections_per_min: usize,
    /// How often the background task purges expired mailboxes.
    pub cleanup_interval: Duration,
    /// Allowed CORS origins. A single `*` entry means "any origin".
    pub cors_allowed_origins: Vec<String>,
    /// Hostname this server announces in SMTP banners/EHLO.
    pub smtp_hostname: String,
    /// Optional STARTTLS configuration.
    pub tls: Option<TlsConfig>,
    /// Local parts that cannot be claimed via the API (built-in + env extras).
    /// All lowercase.
    pub reserved_local_parts: HashSet<String>,
    /// General per-IP API rate limit: sustained requests/second (0 disables).
    pub api_rate_limit_per_second: u64,
    /// Burst budget for the general per-IP API rate limit.
    pub api_rate_limit_burst: u32,
    /// Address creation per-IP rate limit: sustained creates/minute (0 disables).
    pub create_rate_limit_per_minute: u64,
    /// Burst budget for the address-creation rate limit.
    pub create_rate_limit_burst: u32,
    /// Request timeout for non-SSE HTTP routes (0 disables).
    pub api_request_timeout: Duration,
    /// Trust `X-Forwarded-For`/`X-Real-IP`/`Forwarded` for the client IP.
    /// Enable only behind a reverse proxy that always sets them.
    pub api_trust_proxy_headers: bool,
    /// Serve Scalar at `/docs` and the OpenAPI document at `/openapi.json`.
    /// On by default; set `API_DOCS_ENABLED=false` to disable both.
    pub api_docs_enabled: bool,
    /// Max concurrent SSE event streams server-wide (0 disables the cap).
    pub sse_max_concurrent: usize,
    /// Max concurrent SSE event streams per client IP (0 disables the cap).
    pub sse_max_per_ip: usize,
    /// Max addresses a single IP may create per UTC day (0 disables).
    pub max_addresses_per_ip_per_day: u32,
    /// Max messages kept per mailbox; oldest dropped first (0 disables).
    pub max_messages_per_mailbox: u32,
    /// Max stored raw bytes per mailbox; oldest dropped first (0 disables).
    pub max_mailbox_bytes: u64,
    /// Refuse SMTP `DATA` when the database volume has less free space than
    /// this (bytes). SQLite backend only; 0 disables.
    pub min_free_disk_bytes: u64,
    /// VAPID public key (base64url, uncompressed P-256 point) handed to
    /// clients for Web Push subscription. Push is disabled unless both keys
    /// are set.
    pub vapid_public_key: Option<String>,
    /// VAPID private key (base64url raw bytes). Secret — env/file only.
    pub vapid_private_key: Option<String>,
    /// VAPID `sub` claim, a contact URI for push-service operators. Defaults
    /// to `mailto:postmaster@<first domain>`.
    pub vapid_subject: String,
    /// Max push subscriptions per mailbox, all kinds combined (0 disables the
    /// cap).
    pub max_subscriptions_per_mailbox: u32,
    /// APNs: Apple Developer Team ID (native iOS push). APNs is enabled only
    /// when team ID, key ID, signing key, and topic are all set.
    pub apns_team_id: Option<String>,
    /// APNs: the 10-character key ID of the `.p8` signing key.
    pub apns_key_id: Option<String>,
    /// APNs: PEM contents of the `.p8` token-signing key, loaded from
    /// `APNS_KEY_PATH` (file) or `APNS_KEY_BASE64` (inline). Secret.
    pub apns_private_key: Option<String>,
    /// APNs: the topic notifications are sent under — the app's bundle ID.
    pub apns_topic: Option<String>,
    /// APNs: send through the sandbox environment (Xcode/dev builds of the
    /// app). Default: production.
    pub apns_sandbox: bool,
    /// Auto-create a default-TTL mailbox when mail arrives for an unknown
    /// local part on an accepted domain (U1). Never applies to reserved local
    /// parts. Off by default.
    pub catch_all_enabled: bool,
    /// Custom domains (docs/11): let clients claim their own domain, prove it
    /// via DNS (TXT + MX), and receive mail on it. On by default.
    pub custom_domains_enabled: bool,
    /// Max custom-domain claims a single IP may create per UTC day (0
    /// disables).
    pub max_custom_domains_per_ip_per_day: u32,
    /// Min spacing between DNS verification runs for one custom domain (0
    /// disables the throttle).
    pub custom_domain_verify_throttle: Duration,
    /// U2: retain the original RFC 5322 bytes of each delivered message and
    /// serve them via `GET .../messages/{id}/raw`. Off by default (roughly
    /// doubles per-message storage; the A4 byte quota already counts
    /// `raw_size`, so quotas need no adjustment).
    pub store_raw_message: bool,
    /// Enforce free/pro tiers server-side (docs/10). Off by default: the
    /// self-host experience is everything-on with no tokens required.
    pub entitlements_enforced: bool,
    /// Key for signing client tokens (HS256), decoded from the base64
    /// `TOKEN_SIGNING_KEY`. Required when entitlements are enforced; also the
    /// availability switch for `POST /api/entitlements/verify`.
    pub token_signing_key: Option<Vec<u8>>,
    /// RevenueCat secret API key. Enables pro verification; without it every
    /// client is free tier.
    pub revenuecat_secret_key: Option<String>,
    /// RevenueCat entitlement identifier that marks a subscriber as pro.
    pub revenuecat_entitlement_id: String,
    /// Require an attested client token (App Attest, docs/09) on every
    /// mutating route. Off by default: self-hosted servers stay fully open.
    pub client_attestation_required: bool,
    /// Apple Developer Team ID for App Attest (e.g. `FR82ZG29F6`). App Attest
    /// is configured only when team ID and bundle ID are both set.
    pub app_attest_team_id: Option<String>,
    /// The app's bundle ID for App Attest (e.g. `com.scytheralpha.anonymail`).
    pub app_attest_bundle_id: Option<String>,
    /// PEM of the root CA that attestation cert chains must anchor to,
    /// loaded from `APP_ATTEST_ROOT_CA_PATH`. `None` uses the Apple App
    /// Attestation Root CA embedded at build time (valid to 2045); the
    /// override exists for rotation and for tests, which anchor to a
    /// synthetic CA.
    pub app_attest_root_pem: Option<Vec<u8>>,
    /// What free-tier clients may do when enforcement is on.
    pub free_tier: TierPolicy,
    /// What pro-tier clients may do. Pro caps are abuse ceilings, not sales
    /// gates.
    pub pro_tier: TierPolicy,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for Config {
    /// The same defaults `from_env` applies with no environment set, plus a
    /// placeholder domain. Primarily useful for tests and local tinkering.
    fn default() -> Self {
        Self {
            smtp_bind_addr: "0.0.0.0:25".parse().expect("valid default bind addr"),
            api_bind_addr: "0.0.0.0:8080".parse().expect("valid default bind addr"),
            domains: vec!["example.com".to_string()],
            database_url: DEFAULT_SQLITE_URL.to_string(),
            db_max_connections: 0,
            default_ttl: Duration::from_secs(3600),
            max_message_size: 26_214_400, // 25 MiB
            max_recipients: 10,
            max_connections: 1024,
            smtp_session_timeout: Duration::from_secs(60),
            per_ip_connections_per_min: 60,
            cleanup_interval: Duration::from_secs(300),
            cors_allowed_origins: vec!["*".to_string()],
            smtp_hostname: "example.com".to_string(),
            tls: None,
            reserved_local_parts: builtin_reserved_local_parts(),
            api_rate_limit_per_second: 20,
            api_rate_limit_burst: 50,
            create_rate_limit_per_minute: 30,
            create_rate_limit_burst: 10,
            api_request_timeout: Duration::from_secs(30),
            api_trust_proxy_headers: false,
            api_docs_enabled: true,
            sse_max_concurrent: 512,
            sse_max_per_ip: 8,
            max_addresses_per_ip_per_day: 200,
            max_messages_per_mailbox: 50,
            max_mailbox_bytes: 41_943_040,    // 40 MiB
            min_free_disk_bytes: 268_435_456, // 256 MiB
            vapid_public_key: None,
            vapid_private_key: None,
            vapid_subject: "mailto:postmaster@example.com".to_string(),
            max_subscriptions_per_mailbox: 5,
            apns_team_id: None,
            apns_key_id: None,
            apns_private_key: None,
            apns_topic: None,
            apns_sandbox: false,
            catch_all_enabled: false,
            custom_domains_enabled: true,
            max_custom_domains_per_ip_per_day: 5,
            custom_domain_verify_throttle: Duration::from_secs(10),
            store_raw_message: false,
            entitlements_enforced: false,
            token_signing_key: None,
            revenuecat_secret_key: None,
            revenuecat_entitlement_id: "Anony Mail Pro".to_string(),
            client_attestation_required: false,
            app_attest_team_id: None,
            app_attest_bundle_id: None,
            app_attest_root_pem: None,
            free_tier: TierPolicy {
                active_mailboxes: 5,
                max_lifetime_seconds: 86_400, // 24h
                custom_local_parts: false,
                domain_count: 1,
                custom_domains: false,
            },
            pro_tier: TierPolicy {
                active_mailboxes: 50,
                max_lifetime_seconds: 0,
                custom_local_parts: true,
                domain_count: 0,
                custom_domains: true,
            },
        }
    }
}

impl Config {
    /// Build a [`Config`] from environment variables, applying sensible
    /// defaults for everything except `DATABASE_URL` and `DOMAINS`.
    pub fn from_env() -> Result<Self> {
        let base = Self::default();

        let domains = parse_list(&env_or("DOMAINS", ""))
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if domains.is_empty() {
            bail!("DOMAINS must be set to a comma-separated list of accepted domains");
        }

        // Defaults to a local SQLite file so the service runs with zero external
        // dependencies. Set a `postgres://` URL to switch backends.
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(base.database_url);

        let db_max_connections = parse_env("DB_MAX_CONNECTIONS", base.db_max_connections)?;

        let smtp_bind_addr = parse_env("SMTP_BIND_ADDR", base.smtp_bind_addr)?;
        let api_bind_addr = parse_env("API_BIND_ADDR", base.api_bind_addr)?;
        let default_ttl = Duration::from_secs(parse_env(
            "DEFAULT_TTL_SECONDS",
            base.default_ttl.as_secs(),
        )?);
        let max_message_size = parse_env("MAX_MESSAGE_SIZE_BYTES", base.max_message_size)?;
        let max_recipients = parse_env("MAX_RECIPIENTS", base.max_recipients)?;
        let max_connections = parse_env("MAX_CONNECTIONS", base.max_connections)?;
        let smtp_session_timeout = Duration::from_secs(parse_env(
            "SMTP_SESSION_TIMEOUT_SECONDS",
            base.smtp_session_timeout.as_secs(),
        )?);
        let per_ip_connections_per_min = parse_env(
            "SMTP_PER_IP_CONNECTIONS_PER_MIN",
            base.per_ip_connections_per_min,
        )?;
        let cleanup_interval = Duration::from_secs(parse_env(
            "CLEANUP_INTERVAL_SECONDS",
            base.cleanup_interval.as_secs(),
        )?);

        let cors_allowed_origins = {
            let raw = env_or("CORS_ALLOWED_ORIGINS", "*");
            parse_list(&raw)
        };

        let smtp_hostname = std::env::var("SMTP_HOSTNAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| domains[0].clone());

        let tls = match (
            std::env::var("TLS_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty()),
        ) {
            (Some(cert_path), Some(key_path)) => Some(TlsConfig {
                cert_path,
                key_path,
            }),
            (None, None) => None,
            _ => bail!("TLS_CERT_PATH and TLS_KEY_PATH must both be set, or both be unset"),
        };

        let reserved_local_parts = {
            let mut set = builtin_reserved_local_parts();
            set.extend(
                parse_list(&env_or("RESERVED_LOCAL_PARTS", ""))
                    .into_iter()
                    .map(|s| s.to_ascii_lowercase()),
            );
            set
        };

        let api_rate_limit_per_second =
            parse_env("API_RATE_LIMIT_PER_SECOND", base.api_rate_limit_per_second)?;
        let api_rate_limit_burst = parse_env("API_RATE_LIMIT_BURST", base.api_rate_limit_burst)?;
        let create_rate_limit_per_minute = parse_env(
            "API_CREATE_RATE_LIMIT_PER_MINUTE",
            base.create_rate_limit_per_minute,
        )?;
        let create_rate_limit_burst =
            parse_env("API_CREATE_RATE_LIMIT_BURST", base.create_rate_limit_burst)?;
        let api_request_timeout = Duration::from_secs(parse_env(
            "API_REQUEST_TIMEOUT_SECONDS",
            base.api_request_timeout.as_secs(),
        )?);
        let api_trust_proxy_headers =
            parse_env("API_TRUST_PROXY_HEADERS", base.api_trust_proxy_headers)?;
        let api_docs_enabled = parse_env("API_DOCS_ENABLED", base.api_docs_enabled)?;
        let sse_max_concurrent = parse_env("SSE_MAX_CONCURRENT", base.sse_max_concurrent)?;
        let sse_max_per_ip = parse_env("SSE_MAX_PER_IP", base.sse_max_per_ip)?;
        let max_addresses_per_ip_per_day = parse_env(
            "MAX_ADDRESSES_PER_IP_PER_DAY",
            base.max_addresses_per_ip_per_day,
        )?;
        let max_messages_per_mailbox =
            parse_env("MAX_MESSAGES_PER_MAILBOX", base.max_messages_per_mailbox)?;
        let max_mailbox_bytes = parse_env("MAX_MAILBOX_BYTES", base.max_mailbox_bytes)?;
        let min_free_disk_bytes = parse_env("MIN_FREE_DISK_BYTES", base.min_free_disk_bytes)?;

        let vapid_public_key = std::env::var("VAPID_PUBLIC_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let vapid_private_key = std::env::var("VAPID_PRIVATE_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if vapid_public_key.is_some() != vapid_private_key.is_some() {
            bail!("VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY must both be set, or both be unset");
        }
        let vapid_subject = std::env::var("VAPID_SUBJECT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("mailto:postmaster@{}", domains[0]));
        let max_subscriptions_per_mailbox = parse_env(
            "MAX_SUBSCRIPTIONS_PER_MAILBOX",
            base.max_subscriptions_per_mailbox,
        )?;

        let apns_team_id = non_empty_env("APNS_TEAM_ID");
        let apns_key_id = non_empty_env("APNS_KEY_ID");
        let apns_topic = non_empty_env("APNS_TOPIC");
        let apns_private_key = match (
            non_empty_env("APNS_KEY_PATH"),
            non_empty_env("APNS_KEY_BASE64"),
        ) {
            (Some(_), Some(_)) => {
                bail!("set only one of APNS_KEY_PATH and APNS_KEY_BASE64");
            }
            (Some(path), None) => Some(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("reading APNS_KEY_PATH ({path})"))?,
            ),
            (None, Some(b64)) => {
                let compact: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(compact.as_bytes())
                    .context("APNS_KEY_BASE64 is not valid base64")?;
                Some(
                    String::from_utf8(bytes)
                        .context("APNS_KEY_BASE64 does not decode to PEM text")?,
                )
            }
            (None, None) => None,
        };
        let apns_parts = [
            apns_team_id.is_some(),
            apns_key_id.is_some(),
            apns_private_key.is_some(),
            apns_topic.is_some(),
        ];
        if apns_parts.iter().any(|&set| set) && !apns_parts.iter().all(|&set| set) {
            bail!(
                "APNs requires APNS_TEAM_ID, APNS_KEY_ID, APNS_TOPIC, and a key \
                 (APNS_KEY_PATH or APNS_KEY_BASE64) together — set all or none"
            );
        }
        let apns_sandbox = parse_env("APNS_SANDBOX", base.apns_sandbox)?;

        let catch_all_enabled = parse_env("CATCH_ALL_ENABLED", base.catch_all_enabled)?;
        let custom_domains_enabled =
            parse_env("CUSTOM_DOMAINS_ENABLED", base.custom_domains_enabled)?;
        let max_custom_domains_per_ip_per_day = parse_env(
            "MAX_CUSTOM_DOMAINS_PER_IP_PER_DAY",
            base.max_custom_domains_per_ip_per_day,
        )?;
        let custom_domain_verify_throttle = Duration::from_secs(parse_env(
            "CUSTOM_DOMAIN_VERIFY_THROTTLE_SECONDS",
            base.custom_domain_verify_throttle.as_secs(),
        )?);
        let store_raw_message = parse_env("STORE_RAW_MESSAGE", base.store_raw_message)?;

        // Entitlements (docs/10). Defaults keep the self-host deployment fully
        // open; the hosted instance opts in via env.
        let entitlements_enforced = parse_env("ENTITLEMENTS_ENFORCED", base.entitlements_enforced)?;
        let token_signing_key = match non_empty_env("TOKEN_SIGNING_KEY") {
            Some(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .context("TOKEN_SIGNING_KEY is not valid base64")?;
                if bytes.len() < 32 {
                    bail!(
                        "TOKEN_SIGNING_KEY must decode to at least 32 bytes (got {})",
                        bytes.len()
                    );
                }
                Some(bytes)
            }
            None => None,
        };
        let revenuecat_secret_key = non_empty_env("REVENUECAT_SECRET_KEY");
        let revenuecat_entitlement_id =
            non_empty_env("REVENUECAT_ENTITLEMENT_ID").unwrap_or(base.revenuecat_entitlement_id);
        if entitlements_enforced && token_signing_key.is_none() {
            bail!("ENTITLEMENTS_ENFORCED=true requires TOKEN_SIGNING_KEY (base64, >=32 bytes)");
        }
        if revenuecat_secret_key.is_some() && token_signing_key.is_none() {
            bail!("REVENUECAT_SECRET_KEY requires TOKEN_SIGNING_KEY to mint client tokens");
        }

        // App Attest (docs/09). Same all-or-none convention as APNS_*/VAPID_*.
        let client_attestation_required = parse_env(
            "CLIENT_ATTESTATION_REQUIRED",
            base.client_attestation_required,
        )?;
        let app_attest_team_id = non_empty_env("APP_ATTEST_TEAM_ID");
        let app_attest_bundle_id = non_empty_env("APP_ATTEST_BUNDLE_ID");
        if app_attest_team_id.is_some() != app_attest_bundle_id.is_some() {
            bail!("APP_ATTEST_TEAM_ID and APP_ATTEST_BUNDLE_ID must both be set, or both be unset");
        }
        if app_attest_team_id.is_some() && token_signing_key.is_none() {
            bail!("APP_ATTEST_* requires TOKEN_SIGNING_KEY to mint client tokens");
        }
        if client_attestation_required && app_attest_team_id.is_none() {
            bail!(
                "CLIENT_ATTESTATION_REQUIRED=true requires APP_ATTEST_TEAM_ID and \
                 APP_ATTEST_BUNDLE_ID (and TOKEN_SIGNING_KEY)"
            );
        }
        let app_attest_root_pem = match non_empty_env("APP_ATTEST_ROOT_CA_PATH") {
            Some(path) => Some(
                std::fs::read(&path)
                    .with_context(|| format!("reading APP_ATTEST_ROOT_CA_PATH ({path})"))?,
            ),
            None => None,
        };
        let free_tier = TierPolicy {
            active_mailboxes: parse_env("FREE_ACTIVE_MAILBOXES", base.free_tier.active_mailboxes)?,
            max_lifetime_seconds: parse_env(
                "FREE_MAX_LIFETIME_SECONDS",
                base.free_tier.max_lifetime_seconds,
            )?,
            custom_local_parts: parse_env(
                "FREE_CUSTOM_LOCAL_PARTS",
                base.free_tier.custom_local_parts,
            )?,
            domain_count: parse_env("FREE_DOMAIN_COUNT", base.free_tier.domain_count)?,
            custom_domains: parse_env("FREE_CUSTOM_DOMAINS", base.free_tier.custom_domains)?,
        };
        let pro_tier = TierPolicy {
            active_mailboxes: parse_env("PRO_ACTIVE_MAILBOXES", base.pro_tier.active_mailboxes)?,
            max_lifetime_seconds: parse_env(
                "PRO_MAX_LIFETIME_SECONDS",
                base.pro_tier.max_lifetime_seconds,
            )?,
            ..base.pro_tier
        };

        Ok(Self {
            smtp_bind_addr,
            api_bind_addr,
            domains,
            database_url,
            db_max_connections,
            default_ttl,
            max_message_size,
            max_recipients,
            max_connections,
            smtp_session_timeout,
            per_ip_connections_per_min,
            cleanup_interval,
            cors_allowed_origins,
            smtp_hostname,
            tls,
            reserved_local_parts,
            api_rate_limit_per_second,
            api_rate_limit_burst,
            create_rate_limit_per_minute,
            create_rate_limit_burst,
            api_request_timeout,
            api_trust_proxy_headers,
            api_docs_enabled,
            sse_max_concurrent,
            sse_max_per_ip,
            max_addresses_per_ip_per_day,
            max_messages_per_mailbox,
            max_mailbox_bytes,
            min_free_disk_bytes,
            vapid_public_key,
            vapid_private_key,
            vapid_subject,
            max_subscriptions_per_mailbox,
            apns_team_id,
            apns_key_id,
            apns_private_key,
            apns_topic,
            apns_sandbox,
            catch_all_enabled,
            custom_domains_enabled,
            max_custom_domains_per_ip_per_day,
            custom_domain_verify_throttle,
            store_raw_message,
            entitlements_enforced,
            token_signing_key,
            revenuecat_secret_key,
            revenuecat_entitlement_id,
            client_attestation_required,
            app_attest_team_id,
            app_attest_bundle_id,
            app_attest_root_pem,
            free_tier,
            pro_tier,
        })
    }

    /// True when Web Push is enabled (a VAPID keypair is configured).
    pub fn push_configured(&self) -> bool {
        self.vapid_public_key.is_some() && self.vapid_private_key.is_some()
    }

    /// True when APNs (native iOS push) is enabled: team ID, key ID, signing
    /// key, and topic are all configured.
    pub fn apns_configured(&self) -> bool {
        self.apns_team_id.is_some()
            && self.apns_key_id.is_some()
            && self.apns_private_key.is_some()
            && self.apns_topic.is_some()
    }

    /// True when at least one push channel is enabled.
    pub fn any_push_configured(&self) -> bool {
        self.push_configured() || self.apns_configured()
    }

    /// True when the server can mint client tokens — the availability switch
    /// for `POST /api/entitlements/verify` (503 otherwise, like the push
    /// routes).
    pub fn entitlements_supported(&self) -> bool {
        self.token_signing_key.is_some()
    }

    /// True when App Attest verification is configured (docs/09) — the
    /// availability switch for the `POST /api/client/*` routes. Boot
    /// validation guarantees a signing key exists alongside.
    pub fn app_attest_configured(&self) -> bool {
        self.app_attest_team_id.is_some() && self.app_attest_bundle_id.is_some()
    }

    /// The App Attest app identifier (`TEAMID.bundle.id`) attestations must
    /// bind to, when configured.
    pub fn app_attest_app_id(&self) -> Option<String> {
        match (&self.app_attest_team_id, &self.app_attest_bundle_id) {
            (Some(team), Some(bundle)) => Some(format!("{team}.{bundle}")),
            _ => None,
        }
    }

    /// The policy for one tier (docs/10).
    pub fn tier_policy(&self, tier: crate::entitlements::Tier) -> &TierPolicy {
        match tier {
            crate::entitlements::Tier::Free => &self.free_tier,
            crate::entitlements::Tier::Pro => &self.pro_tier,
        }
    }

    /// Selects the storage backend from the `DATABASE_URL` scheme. Anything
    /// that is not a `postgres://`/`postgresql://` URL is treated as SQLite.
    pub fn db_backend(&self) -> DbBackend {
        let url = self.database_url.trim();
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            DbBackend::Postgres
        } else {
            DbBackend::Sqlite
        }
    }

    /// Returns true if `domain` (case-insensitive) is one this server accepts.
    pub fn accepts_domain(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.domains.iter().any(|d| d == &domain)
    }

    /// True if every origin is allowed (CORS wildcard).
    pub fn cors_allow_any(&self) -> bool {
        self.cors_allowed_origins.iter().any(|o| o == "*")
    }

    /// True if `local` may not be claimed via the API. Callers must pass a
    /// lowercased local part.
    pub fn is_reserved_local_part(&self, local: &str) -> bool {
        self.reserved_local_parts.contains(local)
    }

    /// Per-mailbox storage quotas for the store layer (A4).
    pub fn mailbox_quotas(&self) -> MailboxQuotas {
        MailboxQuotas {
            max_messages: self.max_messages_per_mailbox,
            max_bytes: self.max_mailbox_bytes,
        }
    }

    /// Filesystem path of the SQLite database file, when the SQLite backend is
    /// selected. Tolerates the common `sqlite:`, `sqlite://`, and `sqlite:///`
    /// prefixes and strips any `?query` parameters.
    pub fn sqlite_path(&self) -> Option<String> {
        if self.db_backend() != DbBackend::Sqlite {
            return None;
        }
        let raw = self.database_url.trim();
        let without_scheme = raw
            .strip_prefix("sqlite://")
            .or_else(|| raw.strip_prefix("sqlite:"))
            .unwrap_or(raw);
        Some(
            without_scheme
                .split('?')
                .next()
                .unwrap_or(without_scheme)
                .to_string(),
        )
    }
}

fn builtin_reserved_local_parts() -> HashSet<String> {
    BUILTIN_RESERVED_LOCAL_PARTS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse an env var into `T`, falling back to `default` when unset or blank.
/// A trimmed, non-empty environment variable, or `None`.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_env<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid value for {key} ({raw:?}): {e}")),
        _ => Ok(default),
    }
}

fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_reserved_names_are_flagged() {
        let config = Config::default();
        for name in ["admin", "postmaster", "ssladmin", "root", "mailer-daemon"] {
            assert!(
                config.is_reserved_local_part(name),
                "{name} must be reserved"
            );
        }
        assert!(!config.is_reserved_local_part("john"));
        assert!(!config.is_reserved_local_part("adminx"));
        assert!(config.api_docs_enabled, "docs on by default");
    }
}
