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
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::events::EventBus;
use crate::smtp::SmtpContext;
use crate::store::{PostgresStore, Store};

/// Boot the whole service: load config, connect + migrate Postgres, then run
/// the SMTP receiver, HTTP API, and cleanup task until shutdown.
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

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .context("connecting to PostgreSQL")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running database migrations")?;

    let store: Arc<dyn Store> = Arc::new(PostgresStore::new(pool));
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
    let router = api::router(app_state);

    let smtp_task = tokio::spawn(async move { smtp::serve(smtp_ctx).await });
    let cleanup_task = {
        let store = Arc::clone(&store);
        let interval = config.cleanup_interval;
        tokio::spawn(async move { cleanup::run(store, interval).await })
    };
    let api_task = tokio::spawn(async move {
        info!(%api_addr, "HTTP API listening");
        axum::serve(listener, router)
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
