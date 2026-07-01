pub mod memory;
pub mod postgres;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::model::{Attachment, Mailbox, MessageSummary, NewMessage, StoredMessage};

pub use memory::MemoryStore;
pub use postgres::PostgresStore;

/// Persistence abstraction for mailboxes, messages, and attachments.
///
/// Kept as a trait so the SMTP handler and HTTP API depend only on this
/// interface, allowing an alternative (e.g. in-memory) implementation in tests.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Create a new mailbox. Fails if the address already exists.
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Mailbox>;

    /// Fetch a mailbox by address, if it exists (regardless of expiry).
    async fn get_mailbox(&self, address: &str) -> anyhow::Result<Option<Mailbox>>;

    /// True if the mailbox exists and has not yet expired as of `now`.
    /// Used to validate SMTP `RCPT TO`.
    async fn mailbox_is_active(&self, address: &str, now: DateTime<Utc>) -> anyhow::Result<bool>;

    /// Push a mailbox's expiry to `new_expires_at`. Returns the updated
    /// mailbox, or `None` if it does not exist.
    async fn extend_mailbox(
        &self,
        address: &str,
        new_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<Mailbox>>;

    /// Delete a mailbox and everything in it. Returns true if a row was removed.
    async fn delete_mailbox(&self, address: &str) -> anyhow::Result<bool>;

    /// Persist a parsed message (and its attachments) into a mailbox.
    async fn save_message(
        &self,
        address: &str,
        message: NewMessage,
    ) -> anyhow::Result<StoredMessage>;

    /// List message summaries for a mailbox, newest first.
    async fn list_messages(&self, address: &str) -> anyhow::Result<Vec<MessageSummary>>;

    /// Fetch a single full message (with attachment metadata) scoped to a mailbox.
    async fn get_message(&self, address: &str, id: Uuid) -> anyhow::Result<Option<StoredMessage>>;

    /// Fetch raw attachment bytes, scoped to a mailbox + message.
    async fn get_attachment(
        &self,
        address: &str,
        message_id: Uuid,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<Attachment>>;

    /// Delete a single message. Returns true if a row was removed.
    async fn delete_message(&self, address: &str, id: Uuid) -> anyhow::Result<bool>;

    /// Delete all mailboxes that expired on or before `now`. Returns the count.
    async fn purge_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64>;
}
