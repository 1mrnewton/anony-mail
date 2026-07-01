use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, bail};

/// Connection string used when `DATABASE_URL` is unset: a SQLite file in a
/// `data/` directory relative to the working directory.
pub const DEFAULT_SQLITE_URL: &str = "sqlite://data/anony-mail.db";

/// Which storage backend a [`Config`] selects, derived from `DATABASE_URL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
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
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Config {
    /// Build a [`Config`] from environment variables, applying sensible
    /// defaults for everything except `DATABASE_URL` and `DOMAINS`.
    pub fn from_env() -> Result<Self> {
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
            .unwrap_or_else(|| DEFAULT_SQLITE_URL.to_string());

        let smtp_bind_addr = parse_env("SMTP_BIND_ADDR", "0.0.0.0:25")?;
        let api_bind_addr = parse_env("API_BIND_ADDR", "0.0.0.0:8080")?;
        let default_ttl = Duration::from_secs(parse_env("DEFAULT_TTL_SECONDS", "3600")?);
        let max_message_size = parse_env("MAX_MESSAGE_SIZE_BYTES", "26214400")?; // 25 MiB
        let max_recipients = parse_env("MAX_RECIPIENTS", "100")?;
        let max_connections = parse_env("MAX_CONNECTIONS", "1024")?;
        let smtp_session_timeout =
            Duration::from_secs(parse_env("SMTP_SESSION_TIMEOUT_SECONDS", "60")?);
        let per_ip_connections_per_min = parse_env("SMTP_PER_IP_CONNECTIONS_PER_MIN", "60")?;
        let cleanup_interval = Duration::from_secs(parse_env("CLEANUP_INTERVAL_SECONDS", "300")?);

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

        Ok(Self {
            smtp_bind_addr,
            api_bind_addr,
            domains,
            database_url,
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
        })
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
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T>(key: &str, default: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env_or(key, default);
    raw.parse::<T>()
        .map_err(|e| anyhow::anyhow!("invalid value for {key} ({raw:?}): {e}"))
}

fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
