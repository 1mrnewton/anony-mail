pub mod api;
pub mod cleanup;
pub mod config;
pub mod events;
pub mod mime;
pub mod model;
pub mod smtp;
pub mod store;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::ServiceExt;
use axum::extract::Request;
use sqlx::postgres::PgPoolOptions;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::{Config, DbBackend};
use crate::events::EventBus;
use crate::smtp::SmtpContext;
use crate::store::{PostgresStore, SqliteStore, Store};

/// Boot the whole service: load config, connect + migrate the configured
/// database, then run the SMTP receiver, HTTP API, and cleanup task until
/// shutdown.
pub async fn run() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Arc::new(Config::from_env().context("loading configuration")?);
    info!(
        domains = ?config.domains,
        smtp = %config.smtp_bind_addr,
        api = %config.api_bind_addr,
        "starting anony-mail"
    );

    let store = build_store(&config).await?;
    let events = EventBus::new(1024);

    let tls_acceptor = match &config.tls {
        Some(tls) => {
            info!("STARTTLS enabled");
            Some(smtp::tls::build_acceptor(tls).context("building TLS acceptor")?)
        }
        None => {
            info!("STARTTLS disabled (no certificate configured)");
            None
        }
    };

    let smtp_ctx = SmtpContext {
        store: Arc::clone(&store),
        config: Arc::clone(&config),
        events: events.clone(),
        tls_acceptor,
    };

    let app_state = api::AppState {
        store: Arc::clone(&store),
        config: Arc::clone(&config),
        events: events.clone(),
    };

    let api_addr = config.api_bind_addr;
    let listener = tokio::net::TcpListener::bind(api_addr)
        .await
        .with_context(|| format!("binding HTTP API listener on {api_addr}"))?;
    // Axum 0.8 removed implicit trailing-slash redirects. Trim it *before*
    // routing (NormalizePathLayer must wrap the whole router) so `/api/addresses/`
    // is treated the same as `/api/addresses`.
    let router = api::router(app_state);
    let app = NormalizePathLayer::trim_trailing_slash().layer(router);

    let smtp_task = tokio::spawn(async move { smtp::serve(smtp_ctx).await });
    let cleanup_task = {
        let store = Arc::clone(&store);
        let interval = config.cleanup_interval;
        tokio::spawn(async move { cleanup::run(store, interval).await })
    };
    let api_task = tokio::spawn(async move {
        info!(%api_addr, "HTTP API listening");
        axum::serve(listener, ServiceExt::<Request>::into_make_service(app))
            .await
            .context("serving HTTP API")
    });

    // Any of the long-running tasks exiting is unexpected; ctrl-c is graceful.
    tokio::select! {
        res = smtp_task => match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(error = %e, "SMTP server stopped with error"),
            Err(e) => error!(error = %e, "SMTP task join error"),
        },
        res = api_task => match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(error = %e, "HTTP API stopped with error"),
            Err(e) => error!(error = %e, "API task join error"),
        },
        res = cleanup_task => {
            if let Err(e) = res {
                error!(error = %e, "cleanup task join error");
            }
        },
        _ = shutdown_signal() => info!("shutdown signal received, exiting"),
    }

    Ok(())
}

/// Connect to the configured database, run its migrations, and return the
/// matching [`Store`] behind a trait object so the rest of the app is backend-
/// agnostic.
async fn build_store(config: &Config) -> Result<Arc<dyn Store>> {
    match config.db_backend() {
        DbBackend::Postgres => {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(&config.database_url)
                .await
                .context("connecting to PostgreSQL")?;
            sqlx::migrate!("./migrations/postgres")
                .run(&pool)
                .await
                .context("running PostgreSQL migrations")?;
            info!("storage backend: PostgreSQL");
            Ok(Arc::new(PostgresStore::new(pool)))
        }
        DbBackend::Sqlite => {
            let path = sqlite_file_path(&config.database_url);
            let store = SqliteStore::connect(&path).await?;
            info!(path = %path, "storage backend: SQLite");
            Ok(Arc::new(store))
        }
    }
}

/// Extracts the filesystem path from a `sqlite:` connection string, tolerating
/// the common `sqlite:`, `sqlite://`, and `sqlite:///` prefixes and stripping
/// any `?query` parameters.
fn sqlite_file_path(url: &str) -> String {
    let raw = url.trim();
    let without_scheme = raw
        .strip_prefix("sqlite://")
        .or_else(|| raw.strip_prefix("sqlite:"))
        .unwrap_or(raw);
    without_scheme
        .split('?')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,anony_mail=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
