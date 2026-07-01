use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::model::StoredMessage;

/// Broadcast to every SSE subscriber whenever a new message is stored.
///
/// Carries enough data to render a list entry immediately, but clients should
/// still treat their REST inbox listing as authoritative (e.g. to recover
/// events missed while disconnected).
#[derive(Debug, Clone, Serialize)]
pub struct MailEvent {
    pub address: String,
    pub id: Uuid,
    pub mail_from: String,
    pub subject: Option<String>,
    pub received_at: DateTime<Utc>,
    pub has_attachments: bool,
}

impl MailEvent {
    pub fn from_stored(address: impl Into<String>, msg: &StoredMessage) -> Self {
        Self {
            address: address.into(),
            id: msg.id,
            mail_from: msg.mail_from.clone(),
            subject: msg.subject.clone(),
            received_at: msg.received_at,
            has_attachments: !msg.attachments.is_empty(),
        }
    }
}

/// Cloneable handle used to publish [`MailEvent`]s to all subscribers.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<MailEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event. Errors (no active subscribers) are intentionally
    /// ignored: delivery is best-effort and clients reconcile over REST.
    pub fn publish(&self, event: MailEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MailEvent> {
        self.tx.subscribe()
    }
}
