//! In-process HTTP abuse limits that complement the router-level rate
//! limiting (A3): concurrent-SSE caps and a per-IP daily address-creation
//! quota. All state is in-memory and resets on restart, which is acceptable
//! for abuse control (an attacker gains nothing durable from a restart).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use chrono::NaiveDate;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Config;

/// Shared counters/limits owned by [`super::AppState`].
pub struct RuntimeLimits {
    /// Server-wide concurrent SSE stream cap; `None` when disabled.
    sse_global: Option<Arc<Semaphore>>,
    /// Per-IP concurrent SSE stream cap; 0 disables.
    sse_per_ip_cap: usize,
    sse_per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Per-IP daily address creation cap; 0 disables.
    daily_create_cap: u32,
    created_today: Mutex<HashMap<IpAddr, (NaiveDate, u32)>>,
}

impl RuntimeLimits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            sse_global: (config.sse_max_concurrent > 0)
                .then(|| Arc::new(Semaphore::new(config.sse_max_concurrent))),
            sse_per_ip_cap: config.sse_max_per_ip,
            sse_per_ip: Arc::new(Mutex::new(HashMap::new())),
            daily_create_cap: config.max_addresses_per_ip_per_day,
            created_today: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve an SSE slot for `ip`. Returns `None` when either the global or
    /// the per-IP cap is exhausted; the returned guard frees the slot on drop.
    pub fn try_acquire_sse(&self, ip: IpAddr) -> Option<SseGuard> {
        let permit = match &self.sse_global {
            Some(sem) => Some(Arc::clone(sem).try_acquire_owned().ok()?),
            None => None,
        };

        let tracked_ip = if self.sse_per_ip_cap > 0 {
            let mut per_ip = self.sse_per_ip.lock().expect("sse per-ip mutex poisoned");
            let count = per_ip.entry(ip).or_insert(0);
            if *count >= self.sse_per_ip_cap {
                // `permit` drops here, releasing the global slot.
                return None;
            }
            *count += 1;
            Some(ip)
        } else {
            None
        };

        Some(SseGuard {
            _permit: permit,
            ip: tracked_ip,
            per_ip: Arc::clone(&self.sse_per_ip),
        })
    }

    /// Record an address-creation attempt from `ip` on `today` (UTC). Returns
    /// false when the daily quota is exhausted.
    pub fn note_address_created(&self, ip: IpAddr, today: NaiveDate) -> bool {
        if self.daily_create_cap == 0 {
            return true;
        }
        let mut created = self
            .created_today
            .lock()
            .expect("daily create mutex poisoned");
        // Bound memory: drop stale entries once the table grows large.
        if created.len() > 100_000 {
            created.retain(|_, (day, _)| *day == today);
        }
        let entry = created.entry(ip).or_insert((today, 0));
        if entry.0 != today {
            *entry = (today, 0);
        }
        if entry.1 >= self.daily_create_cap {
            false
        } else {
            entry.1 += 1;
            true
        }
    }
}

/// RAII guard for one active SSE stream; releases the global permit and the
/// per-IP slot when the stream ends.
pub struct SseGuard {
    _permit: Option<OwnedSemaphorePermit>,
    ip: Option<IpAddr>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            let mut per_ip = self.per_ip.lock().expect("sse per-ip mutex poisoned");
            if let Some(count) = per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_ip.remove(&ip);
                }
            }
        }
    }
}

/// Resolve the client IP for quota/cap purposes.
///
/// Mirrors `tower_governor`'s `SmartIpKeyExtractor` precedence when proxy
/// headers are trusted (`X-Forwarded-For` first parseable entry, then
/// `X-Real-IP`), falling back to the socket peer address.
pub fn client_ip(headers: &HeaderMap, peer: IpAddr, trust_proxy_headers: bool) -> IpAddr {
    if !trust_proxy_headers {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').find_map(|part| part.trim().parse().ok()))
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse().ok())
        })
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn limits(global: usize, per_ip: usize, daily: u32) -> RuntimeLimits {
        RuntimeLimits::from_config(&Config {
            sse_max_concurrent: global,
            sse_max_per_ip: per_ip,
            max_addresses_per_ip_per_day: daily,
            ..Config::default()
        })
    }

    #[test]
    fn sse_per_ip_cap_enforced_and_released() {
        let limits = limits(10, 2, 0);
        let g1 = limits.try_acquire_sse(ip(1)).expect("first stream");
        let _g2 = limits.try_acquire_sse(ip(1)).expect("second stream");
        assert!(
            limits.try_acquire_sse(ip(1)).is_none(),
            "third stream from same IP must be rejected"
        );
        // Other IPs unaffected.
        assert!(limits.try_acquire_sse(ip(2)).is_some());
        // Releasing one slot lets the IP connect again.
        drop(g1);
        assert!(limits.try_acquire_sse(ip(1)).is_some());
    }

    #[test]
    fn sse_global_cap_enforced() {
        let limits = limits(2, 0, 0);
        let _g1 = limits.try_acquire_sse(ip(1)).unwrap();
        let _g2 = limits.try_acquire_sse(ip(2)).unwrap();
        assert!(limits.try_acquire_sse(ip(3)).is_none(), "global cap");
    }

    #[test]
    fn zero_caps_disable_sse_limits() {
        let limits = limits(0, 0, 0);
        let guards: Vec<_> = (0..100)
            .map(|_| limits.try_acquire_sse(ip(1)).expect("unlimited"))
            .collect();
        assert_eq!(guards.len(), 100);
    }

    #[test]
    fn daily_create_quota_enforced_per_ip_and_day() {
        let limits = limits(0, 0, 2);
        let today = Utc::now().date_naive();
        assert!(limits.note_address_created(ip(1), today));
        assert!(limits.note_address_created(ip(1), today));
        assert!(
            !limits.note_address_created(ip(1), today),
            "third create today must be rejected"
        );
        // Other IPs have their own budget.
        assert!(limits.note_address_created(ip(2), today));
        // A new day resets the counter.
        let tomorrow = today.succ_opt().unwrap();
        assert!(limits.note_address_created(ip(1), tomorrow));
    }

    #[test]
    fn client_ip_honors_trust_flag() {
        let peer: IpAddr = ip(9);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(
            client_ip(&headers, peer, false),
            peer,
            "untrusted: peer wins"
        );
        assert_eq!(
            client_ip(&headers, peer, true),
            "203.0.113.7".parse::<IpAddr>().unwrap(),
            "trusted: first XFF entry wins"
        );
        let empty = HeaderMap::new();
        assert_eq!(client_ip(&empty, peer, true), peer, "fallback to peer");
    }
}
