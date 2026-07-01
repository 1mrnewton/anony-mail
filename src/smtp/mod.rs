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
            warn!(%peer, "per-IP connection rate limit exceeded");
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
}

impl RateLimiter {
    fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record a connection attempt from `ip`; returns true if it is allowed.
    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
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
}
