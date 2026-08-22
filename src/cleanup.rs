use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};

use crate::store::Store;

/// Attested devices (docs/09) idle longer than this are pruned; the device
/// simply re-attests on its next contact.
const DEVICE_IDLE_WINDOW: chrono::Duration = chrono::Duration::days(180);

/// Periodically delete expired mailboxes (their messages/attachments cascade)
/// and long-idle attested devices, then run backend storage maintenance
/// (e.g. SQLite incremental vacuum) so freed pages actually return to the
/// filesystem.
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
        match store
            .prune_attested_devices(Utc::now() - DEVICE_IDLE_WINDOW)
            .await
        {
            Ok(0) => {}
            Ok(count) => info!(count, "pruned idle attested devices"),
            Err(e) => error!(error = %e, "failed to prune attested devices"),
        }
        if let Err(e) = store.run_maintenance().await {
            error!(error = %e, "storage maintenance failed");
        }
    }
}
