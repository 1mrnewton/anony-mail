//! Custom sender domains (docs/11): receive mail at a domain you own.
//!
//! Flow: claim the domain via `POST /api/custom-domains` (returns a one-time
//! `amd_…` claim token plus the DNS records to publish), prove control by
//! publishing a TXT challenge at `_anonymail.<domain>` and an MX record
//! pointing at this server, then hit the verify endpoint. Once `verified`,
//! the SMTP listener accepts mail for the domain and mailboxes on it can be
//! created with the claim token.
//!
//! Verified domains are re-checked daily; a domain whose DNS stays broken past
//! a 48h grace window flips to `failed` (mail and creates stop), and a later
//! successful verify restores it. No catch-all ever applies to custom domains:
//! only explicitly created mailboxes receive mail, so a lapsed domain cannot
//! be farmed by strangers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use rand::RngExt;
use serde::Serialize;
use tokio::sync::OnceCell;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::model::{CustomDomain, CustomDomainStatus};
use crate::store::Store;

/// DNS label the TXT challenge lives under: `_anonymail.<domain>`.
pub const TXT_LABEL: &str = "_anonymail";
/// Prefix of the TXT challenge value: `anonymail-verify=<token>`.
pub const TXT_VALUE_PREFIX: &str = "anonymail-verify=";

/// How long a previously verified domain keeps working after its last
/// successful check before failing re-verification flips it to `failed`.
/// Generous on purpose: DNS hiccups and expired-but-renewed zones should not
/// kill mail flow instantly.
const GRACE_HOURS: i64 = 48;

/// How often the background task scans for domains due a re-check.
const RECHECK_SCAN_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// A verified/failed domain is re-checked once its last check is older than
/// this.
const RECHECK_AFTER_HOURS: i64 = 24;

/// The full TXT record value the owner must publish.
pub fn txt_value(txt_token: &str) -> String {
    format!("{TXT_VALUE_PREFIX}{txt_token}")
}

/// The DNS name the TXT record must live at.
pub fn txt_host(domain: &str) -> String {
    format!("{TXT_LABEL}.{domain}")
}

/// Random TXT challenge token: 16 CSPRNG bytes as lowercase hex. It is
/// published in public DNS, so it is a domain-control proof, not a secret.
pub fn generate_txt_token() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Normalize and validate a domain a client wants to claim. Returns the
/// lowercase form, or a human-readable rejection reason.
///
/// Rejected: syntactically invalid names, the server's own configured domains
/// (and their subdomains — those are first-party namespace), and the SMTP
/// hostname itself (a domain whose MX must point at this host cannot *be*
/// this host's mail name).
pub fn validate_claimable(config: &Config, raw: &str) -> Result<String, String> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !is_valid_domain(&domain) {
        return Err(format!("not a valid domain name: {raw}"));
    }
    for served in &config.domains {
        if &domain == served || domain.ends_with(&format!(".{served}")) {
            return Err(format!("domain is reserved by this server: {domain}"));
        }
    }
    if domain == config.smtp_hostname.to_ascii_lowercase() {
        return Err(format!("domain is reserved by this server: {domain}"));
    }
    Ok(domain)
}

/// Syntactic validity per RFC 1035 preferred name syntax (lowercase input):
/// 2+ labels of 1-63 chars from `[a-z0-9-]`, no leading/trailing hyphen, an
/// alphabetic TLD of 2+ chars, 253 chars total max.
fn is_valid_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let valid_label = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    if !labels.iter().all(valid_label) {
        return false;
    }
    // Alphabetic TLD also rules out bare IPv4 addresses.
    let tld = labels.last().expect("at least two labels");
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_lowercase())
}

/// One DNS check result, serialized into verify responses as
/// `{"record": "txt", "ok": true, "expected": ..., "found": ...}`.
#[derive(Debug, Clone, Serialize)]
pub struct DnsCheck {
    /// `"txt"` or `"mx"`.
    pub record: &'static str,
    pub ok: bool,
    /// The value the owner is expected to publish.
    pub expected: String,
    /// What DNS actually returned (comma-joined when multiple), `null` when
    /// nothing resolved.
    pub found: Option<String>,
}

/// The minimal async DNS surface verification needs; a trait so tests can
/// stub answers without a live resolver.
#[async_trait]
pub trait DomainDns: Send + Sync + 'static {
    /// TXT record values at `name` (character-strings of each record
    /// concatenated, per RFC 7208 §3.3 conventions). Missing name or no
    /// records is `Ok(vec![])`; only transport/server failures are `Err`.
    async fn txt_records(&self, name: &str) -> Result<Vec<String>>;

    /// MX exchange hostnames at `name`, lowercased without the trailing dot.
    /// Missing name or no records is `Ok(vec![])`.
    async fn mx_hosts(&self, name: &str) -> Result<Vec<String>>;
}

/// Production [`DomainDns`] backed by hickory-resolver using the system
/// configuration (`/etc/resolv.conf`). Built lazily on first use so
/// constructing it is sync and infallible (no runtime required).
#[derive(Default)]
pub struct HickoryDns {
    resolver: OnceCell<TokioResolver>,
}

impl HickoryDns {
    pub fn new() -> Self {
        Self::default()
    }

    async fn resolver(&self) -> Result<&TokioResolver> {
        self.resolver
            .get_or_try_init(|| async { Ok(Resolver::builder_tokio()?.build()?) })
            .await
    }

    /// Queries are sent as FQDNs (trailing dot) so resolv.conf search domains
    /// never rewrite them.
    fn fqdn(name: &str) -> String {
        format!("{}.", name.trim_end_matches('.'))
    }
}

#[async_trait]
impl DomainDns for HickoryDns {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>> {
        let resolver = self.resolver().await?;
        match resolver.txt_lookup(Self::fqdn(name)).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn mx_hosts(&self, name: &str) -> Result<Vec<String>> {
        let resolver = self.resolver().await?;
        match resolver.mx_lookup(Self::fqdn(name)).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(mx) => Some(
                        mx.exchange
                            .to_utf8()
                            .trim_end_matches('.')
                            .to_ascii_lowercase(),
                    ),
                    _ => None,
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Run both DNS checks for `domain` concurrently. Returns the per-record
/// results and whether every check passed. Resolver failures (SERVFAIL,
/// timeouts) count as not-ok rather than erroring out, so callers always get
/// a renderable answer — the grace window absorbs transient blips.
pub async fn run_checks(
    dns: &dyn DomainDns,
    config: &Config,
    domain: &CustomDomain,
) -> (Vec<DnsCheck>, bool) {
    let expected_txt = txt_value(&domain.txt_token);
    let expected_mx = config
        .smtp_hostname
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let txt_name = txt_host(&domain.domain);
    let (txt_result, mx_result) =
        tokio::join!(dns.txt_records(&txt_name), dns.mx_hosts(&domain.domain));

    let txt = match txt_result {
        Ok(values) => {
            let ok = values.iter().any(|v| v.trim() == expected_txt);
            DnsCheck {
                record: "txt",
                ok,
                expected: expected_txt,
                found: summarize(values),
            }
        }
        Err(e) => {
            warn!(domain = %domain.domain, error = %e, "TXT lookup failed");
            DnsCheck {
                record: "txt",
                ok: false,
                expected: expected_txt,
                found: None,
            }
        }
    };

    let mx = match mx_result {
        Ok(hosts) => {
            let ok = hosts.iter().any(|h| h == &expected_mx);
            DnsCheck {
                record: "mx",
                ok,
                expected: expected_mx,
                found: summarize(hosts),
            }
        }
        Err(e) => {
            warn!(domain = %domain.domain, error = %e, "MX lookup failed");
            DnsCheck {
                record: "mx",
                ok: false,
                expected: expected_mx,
                found: None,
            }
        }
    };

    let all_ok = txt.ok && mx.ok;
    (vec![txt, mx], all_ok)
}

fn summarize(values: Vec<String>) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// Compute the status transition after a check run. `verified_at` is the
/// last-success anchor: refreshed on success, kept as-is on failure so the
/// grace window measures time since DNS last looked right.
pub fn next_status(
    current: &CustomDomain,
    all_ok: bool,
    now: DateTime<Utc>,
) -> (CustomDomainStatus, Option<DateTime<Utc>>) {
    if all_ok {
        return (CustomDomainStatus::Verified, Some(now));
    }
    match current.status {
        CustomDomainStatus::Pending => (CustomDomainStatus::Pending, current.verified_at),
        CustomDomainStatus::Failed => (CustomDomainStatus::Failed, current.verified_at),
        CustomDomainStatus::Verified => {
            let anchor = current.verified_at.unwrap_or(current.created_at);
            if now - anchor > chrono::Duration::hours(GRACE_HOURS) {
                (CustomDomainStatus::Failed, current.verified_at)
            } else {
                (CustomDomainStatus::Verified, current.verified_at)
            }
        }
    }
}

/// Run the DNS checks for `domain`, apply the status transition, and persist
/// it. Returns the checks plus the resulting status/anchor.
pub async fn check_and_record(
    store: &dyn Store,
    dns: &dyn DomainDns,
    config: &Config,
    domain: &CustomDomain,
) -> Result<(Vec<DnsCheck>, CustomDomainStatus, Option<DateTime<Utc>>)> {
    let (checks, all_ok) = run_checks(dns, config, domain).await;
    let now = Utc::now();
    let (status, verified_at) = next_status(domain, all_ok, now);
    store
        .record_custom_domain_check(&domain.domain, status, verified_at, now)
        .await?;
    if status != domain.status {
        info!(
            domain = %domain.domain,
            from = domain.status.as_str(),
            to = status.as_str(),
            "custom domain status changed"
        );
    }
    Ok((checks, status, verified_at))
}

/// Background task: hourly, re-check every verified/failed domain whose last
/// check is older than a day. Keeps `verified` honest after the owner drops
/// their DNS records, and lets a `failed` domain heal without manual action.
pub async fn reverify_loop(store: Arc<dyn Store>, dns: Arc<dyn DomainDns>, config: Arc<Config>) {
    let mut ticker = tokio::time::interval(RECHECK_SCAN_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let cutoff = Utc::now() - chrono::Duration::hours(RECHECK_AFTER_HOURS);
        let due = match store.list_custom_domains_to_recheck(cutoff).await {
            Ok(due) => due,
            Err(e) => {
                error!(error = %e, "could not list custom domains for re-verification");
                continue;
            }
        };
        for domain in due {
            if let Err(e) = check_and_record(store.as_ref(), dns.as_ref(), &config, &domain).await {
                warn!(domain = %domain.domain, error = %e, "custom domain re-check failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            domains: vec!["anonymail.example".to_string()],
            smtp_hostname: "mx.anonymail.example".to_string(),
            ..Config::default()
        }
    }

    fn claim(status: CustomDomainStatus, verified_at: Option<DateTime<Utc>>) -> CustomDomain {
        CustomDomain {
            domain: "mail.corp.example".to_string(),
            status,
            claim_token_hash: "hash".to_string(),
            txt_token: "tok".to_string(),
            created_at: Utc::now() - chrono::Duration::days(30),
            verified_at,
            last_checked_at: None,
        }
    }

    #[test]
    fn validates_and_normalizes_domains() {
        let config = config();
        assert_eq!(
            validate_claimable(&config, " Mail.Corp.Example. "),
            Ok("mail.corp.example".to_string())
        );
        for bad in [
            "",
            "nodots",
            "-bad.example",
            "bad-.example",
            "under_score.example",
            "spaces in.example",
            "1.2.3.4",
            "single-char-tld.e",
        ] {
            assert!(validate_claimable(&config, bad).is_err(), "{bad:?}");
        }
        // The server's own namespace is off limits.
        assert!(validate_claimable(&config, "anonymail.example").is_err());
        assert!(validate_claimable(&config, "sub.anonymail.example").is_err());
        assert!(validate_claimable(&config, "mx.anonymail.example").is_err());
        // But unrelated lookalikes are fine.
        assert!(validate_claimable(&config, "notanonymail.example").is_ok());
    }

    #[test]
    fn txt_helpers_compose_the_published_record() {
        assert_eq!(txt_host("corp.example"), "_anonymail.corp.example");
        assert_eq!(txt_value("abc"), "anonymail-verify=abc");
        let token = generate_txt_token();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn success_always_verifies_and_refreshes_anchor() {
        let now = Utc::now();
        for status in [
            CustomDomainStatus::Pending,
            CustomDomainStatus::Verified,
            CustomDomainStatus::Failed,
        ] {
            let (next, anchor) = next_status(&claim(status, None), true, now);
            assert_eq!(next, CustomDomainStatus::Verified);
            assert_eq!(anchor, Some(now));
        }
    }

    #[test]
    fn failure_respects_grace_window() {
        let now = Utc::now();

        // Pending stays pending; failed stays failed.
        let (next, _) = next_status(&claim(CustomDomainStatus::Pending, None), false, now);
        assert_eq!(next, CustomDomainStatus::Pending);
        let (next, _) = next_status(&claim(CustomDomainStatus::Failed, None), false, now);
        assert_eq!(next, CustomDomainStatus::Failed);

        // Verified within grace survives a bad check.
        let recent = Some(now - chrono::Duration::hours(GRACE_HOURS - 1));
        let (next, anchor) = next_status(&claim(CustomDomainStatus::Verified, recent), false, now);
        assert_eq!(next, CustomDomainStatus::Verified);
        assert_eq!(anchor, recent, "anchor not refreshed on failure");

        // Verified past grace flips to failed.
        let stale = Some(now - chrono::Duration::hours(GRACE_HOURS + 1));
        let (next, _) = next_status(&claim(CustomDomainStatus::Verified, stale), false, now);
        assert_eq!(next, CustomDomainStatus::Failed);
    }
}
