pub mod api;
pub mod cleanup;
pub mod config;
pub mod events;
pub mod mime;
pub mod model;
pub mod otp;
pub mod push;
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

    let app_state = api::AppState::new(Arc::clone(&store), Arc::clone(&config), events.clone());

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

    // Web Push worker: only when a VAPID keypair is configured.
    if config.push_configured() {
        match push::WebPushSender::from_config(&config) {
            Some(sender) => {
                let store = Arc::clone(&store);
                let events = events.clone();
                tokio::spawn(async move {
                    push::run(store, events, Arc::new(sender)).await;
                });
                info!("web push enabled");
            }
            None => error!("web push mis-configured; continuing without it"),
        }
    } else {
        info!("web push disabled (no VAPID keypair configured)");
    }
    let api_task = tokio::spawn(async move {
        info!(%api_addr, "HTTP API listening");
        // Connect info exposes the peer address to rate limiting and quotas.
        axum::serve(
            listener,
            ServiceExt::<Request>::into_make_service_with_connect_info::<std::net::SocketAddr>(app),
        )
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
    let quotas = config.mailbox_quotas();
    match config.db_backend() {
        DbBackend::Postgres => {
            let max_connections = if config.db_max_connections == 0 {
                10
            } else {
                config.db_max_connections
            };
            let pool = PgPoolOptions::new()
                .max_connections(max_connections)
                .connect(&config.database_url)
                .await
                .context("connecting to PostgreSQL")?;
            sqlx::migrate!("./migrations/postgres")
                .run(&pool)
                .await
                .context("running PostgreSQL migrations")?;
            info!(max_connections, "storage backend: PostgreSQL");
            Ok(Arc::new(PostgresStore::new(pool).with_quotas(quotas)))
        }
        DbBackend::Sqlite => {
            let path = config
                .sqlite_path()
                .expect("sqlite backend implies a sqlite path");
            let store = SqliteStore::connect_with(&path, config.db_max_connections)
                .await?
                .with_quotas(quotas);
            info!(path = %path, "storage backend: SQLite");
            Ok(Arc::new(store))
        }
    }
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
