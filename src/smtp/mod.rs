pub mod commands;
pub mod session;
pub mod tls;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub use session::SmtpContext;

/// Bind the SMTP listener and serve connections until the process exits.
///
/// Applies two hygiene limits at the connection layer: a global concurrency cap
/// (semaphore) and a per-IP new-connection rate limit.
pub async fn serve(ctx: SmtpContext) -> Result<()> {
    let addr = ctx.config.smtp_bind_addr;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding SMTP listener on {addr}"))?;
    info!(%addr, tls = ctx.tls_acceptor.is_some(), "SMTP receiver listening");

    let semaphore = Arc::new(Semaphore::new(ctx.config.max_connections));
    let limiter = Arc::new(RateLimiter::new(
        Duration::from_secs(60),
        ctx.config.per_ip_connections_per_min,
    ));

    loop {
        let (mut socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "failed to accept SMTP connection");
                continue;
            }
        };
        let _ = socket.set_nodelay(true);

        if !limiter.check(peer.ip()) {
            // Log at most one WARN per IP per window so a connection flood
            // cannot amplify itself into a log flood (B2). Every rejection is
            // still visible at debug level.
            match limiter.note_rejection(peer.ip()) {
                Some(rejections) => {
                    warn!(%peer, rejections_since_last_report = rejections,
                        "per-IP connection rate limit exceeded")
                }
                None => debug!(%peer, "per-IP connection rate limit exceeded"),
            }
            let _ = reject(&mut socket, "421 4.7.0 Too many connections from your host").await;
            continue;
        }

        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(%peer, "max concurrent connections reached");
                let _ = reject(&mut socket, "421 4.7.0 Server busy, try again later").await;
                continue;
            }
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the task ends
            if let Err(e) = session::handle(socket, peer, ctx).await {
                debug!(%peer, error = %e, "SMTP session ended with error");
            }
        });
    }
}

/// Send a single rejection line and close, ignoring errors.
async fn reject(socket: &mut TcpStream, line: &str) -> std::io::Result<()> {
    socket.write_all(line.as_bytes()).await?;
    socket.write_all(b"\r\n").await?;
    socket.flush().await?;
    socket.shutdown().await
}

/// Sliding-window per-IP connection rate limiter.
struct RateLimiter {
    window: Duration,
    max: usize,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    rejections: Mutex<HashMap<IpAddr, RejectionLog>>,
}

/// Per-IP bookkeeping for throttled rejection logging.
struct RejectionLog {
    /// When the last WARN for this IP was emitted.
    last_logged: Instant,
    /// Rejections seen since `last_logged` that have not been reported yet.
    unreported: u64,
}

impl RateLimiter {
    fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(HashMap::new()),
            rejections: Mutex::new(HashMap::new()),
        }
    }

    /// Record a connection attempt from `ip`; returns true if it is allowed.
    fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut hits = self.hits.lock().expect("rate limiter mutex poisoned");

        // Bound memory: if the table grows large, drop entries with no recent hits.
        if hits.len() > 10_000 {
            hits.retain(|_, times| times.iter().any(|t| now.duration_since(*t) < self.window));
        }

        let times = hits.entry(ip).or_default();
        times.retain(|t| now.duration_since(*t) < self.window);
        if times.len() >= self.max {
            false
        } else {
            times.push(now);
            true
        }
    }

    /// Record that a connection from `ip` was rejected, purely for log
    /// throttling; the rejection itself has already happened.
    ///
    /// Returns `Some(n)` when the caller should log — at most once per IP per
    /// `window` — where `n` counts the rejections from this IP since the last
    /// logged one, including this one. Returns `None` while within the window
    /// of the last logged line.
    fn note_rejection(&self, ip: IpAddr) -> Option<u64> {
        self.note_rejection_at(ip, Instant::now())
    }

    fn note_rejection_at(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        use std::collections::hash_map::Entry;

        let mut rejections = self.rejections.lock().expect("rate limiter mutex poisoned");

        // Bound memory the same way as `hits`; dropping a stale entry only
        // costs an uncounted tail in the next report.
        if rejections.len() > 10_000 {
            rejections.retain(|_, r| now.duration_since(r.last_logged) < self.window);
        }

        match rejections.entry(ip) {
            Entry::Vacant(v) => {
                v.insert(RejectionLog {
                    last_logged: now,
                    unreported: 0,
                });
                Some(1)
            }
            Entry::Occupied(mut o) => {
                let r = o.get_mut();
                if now.duration_since(r.last_logged) < self.window {
                    r.unreported += 1;
                    None
                } else {
                    let count = r.unreported + 1;
                    r.last_logged = now;
                    r.unreported = 0;
                    Some(count)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    #[test]
    fn rate_limiter_enforces_per_ip_sliding_window() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 2);
        let now = Instant::now();

        assert!(limiter.check_at(ip(1), now));
        assert!(limiter.check_at(ip(1), now));
        assert!(!limiter.check_at(ip(1), now), "third hit must be rejected");

        // Other IPs are unaffected.
        assert!(limiter.check_at(ip(2), now));

        // Once the window slides past the earlier hits, the IP is allowed again.
        assert!(limiter.check_at(ip(1), now + Duration::from_secs(61)));
    }

    #[test]
    fn rejection_logging_is_throttled_to_once_per_ip_per_window() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 1);
        let now = Instant::now();

        // The first rejection logs immediately.
        assert_eq!(limiter.note_rejection_at(ip(1), now), Some(1));

        // A flood inside the window is suppressed (the incident log had 82
        // back-to-back WARNs; these would all be silent now)...
        for _ in 0..81 {
            assert_eq!(
                limiter.note_rejection_at(ip(1), now + Duration::from_secs(1)),
                None
            );
        }

        // ...and rolled up into the next logged line after the window passes.
        assert_eq!(
            limiter.note_rejection_at(ip(1), now + Duration::from_secs(61)),
            Some(82)
        );

        // Other IPs report independently of each other.
        assert_eq!(limiter.note_rejection_at(ip(2), now), Some(1));
    }
}
