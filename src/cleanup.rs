use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};

use crate::store::Store;

/// Periodically delete expired mailboxes (their messages/attachments cascade).
///
/// Runs forever; the first tick fires immediately so expired data is cleared
/// promptly on startup.
pub async fn run(store: Arc<dyn Store>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        match store.purge_expired(Utc::now()).await {
            Ok(0) => {}
            Ok(count) => info!(count, "purged expired mailboxes"),
            Err(e) => error!(error = %e, "failed to purge expired mailboxes"),
        }
    }
}
