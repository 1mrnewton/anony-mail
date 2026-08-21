pub mod memory;
pub mod postgres;
pub mod sqlite;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::model::{
    Attachment, Mailbox, MessageSummary, NewMessage, PushSubscription, StoredMessage,
    SubscriptionKind,
};

pub use memory::MemoryStore;
pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

/// Backend-agnostic marker error for unique/primary-key conflicts, raised by
/// non-SQL backends. SQL backends surface `sqlx` errors carrying the same
/// semantics; `crate::api::is_unique_violation` recognizes both, so the API
/// maps duplicates to `409 Conflict` regardless of the configured store.
#[derive(Debug, thiserror::Error)]
#[error("unique constraint violation: {0}")]
pub struct UniqueViolation(pub String);

/// Typed marker raised by `add_subscription` when a mailbox already holds the
/// maximum number of push subscriptions. Handlers downcast it to answer `429`
/// instead of `500`.
#[derive(Debug, thiserror::Error)]
#[error("push subscription limit reached ({0} per mailbox)")]
pub struct SubscriptionLimit(pub u32);

/// Per-mailbox storage quotas enforced inside `save_message` (A4). When a new
/// message would exceed a cap, the **oldest** messages are dropped: for OTP /
/// signup flows the newest mail is the valuable one.
///
/// A value of `0` disables that cap. The just-saved message itself is never
/// dropped, even if it alone exceeds `max_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxQuotas {
    /// Max messages kept per mailbox.
    pub max_messages: u32,
    /// Max total stored raw bytes per mailbox (sum of `raw_size`).
    pub max_bytes: u64,
}

impl MailboxQuotas {
    pub const UNLIMITED: Self = Self {
        max_messages: 0,
        max_bytes: 0,
    };
}

impl Default for MailboxQuotas {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

/// Persistence abstraction for mailboxes, messages, and attachments.
///
/// Kept as a trait so the SMTP handler and HTTP API depend only on this
/// interface, allowing an alternative (e.g. in-memory) implementation in tests.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Create a new mailbox. Fails if the address already exists.
    /// `owner_token_hash` is the SHA-256 hex of the owner bearer token (A2);
    /// `None` creates an ownerless mailbox that can never pass gated ops.
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
        owner_token_hash: Option<&str>,
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

    /// Replace the mailbox's owner-token hash (A2 rotate). The old token is
    /// dead the moment this commits. Returns false if the mailbox is missing.
    async fn rotate_owner_token(&self, address: &str, new_hash: &str) -> anyhow::Result<bool>;

    /// Persist a parsed message (and its attachments) into a mailbox.
    async fn save_message(
        &self,
        address: &str,
        message: NewMessage,
    ) -> anyhow::Result<StoredMessage>;

    /// List message summaries for a mailbox, newest first (P3/P4: ordered by
    /// `(received_at, id)` descending — the id tiebreak keeps the order stable
    /// and the cursor exact).
    ///
    /// `limit` caps the result (`0` = unlimited). `since` is a keyset cursor:
    /// only messages strictly newer than that message (in the same ordering)
    /// are returned. A `since` id that no longer exists (pruned by quota,
    /// deleted, or bogus) is ignored, returning the newest page — safe for
    /// pollers, which simply refetch.
    async fn list_messages(
        &self,
        address: &str,
        limit: u32,
        since: Option<Uuid>,
    ) -> anyhow::Result<Vec<MessageSummary>>;

    /// Fetch a single full message (with attachment metadata) scoped to a mailbox.
    async fn get_message(&self, address: &str, id: Uuid) -> anyhow::Result<Option<StoredMessage>>;

    /// Fetch the original RFC 5322 bytes of a message (U2). `None` when the
    /// message doesn't exist **or** raw retention was off at delivery time.
    async fn get_raw_message(&self, address: &str, id: Uuid) -> anyhow::Result<Option<Vec<u8>>>;

    /// Fetch raw attachment bytes, scoped to a mailbox + message.
    async fn get_attachment(
        &self,
        address: &str,
        message_id: Uuid,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<Attachment>>;

    /// Delete a single message. Returns true if a row was removed.
    async fn delete_message(&self, address: &str, id: Uuid) -> anyhow::Result<bool>;

    /// Mark a message as read (U3). Idempotent; returns true if the message
    /// exists.
    async fn mark_seen(&self, address: &str, id: Uuid) -> anyhow::Result<bool>;

    /// Delete every message in a mailbox (U3 clear-inbox). The mailbox itself
    /// survives. Returns the number of messages removed.
    async fn delete_all_messages(&self, address: &str) -> anyhow::Result<u64>;

    /// Delete all mailboxes that expired on or before `now`. Returns the count.
    async fn purge_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64>;

    /// Register (or refresh) a push subscription for a mailbox. Upserts on
    /// `(mailbox_address, endpoint)`, so re-subscribing from the same client
    /// is idempotent (and may switch the `kind`). For `apns` subscriptions the
    /// `endpoint` is the device token and the key fields are empty. Fails with
    /// [`SubscriptionLimit`] when the mailbox already has `max_per_mailbox`
    /// other subscriptions (0 = unlimited).
    async fn add_subscription(
        &self,
        address: &str,
        kind: SubscriptionKind,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        max_per_mailbox: u32,
    ) -> anyhow::Result<PushSubscription>;

    /// All push subscriptions registered for a mailbox.
    async fn list_subscriptions(&self, address: &str) -> anyhow::Result<Vec<PushSubscription>>;

    /// Remove a subscription by endpoint. Returns true if a row was removed.
    /// Also used by the push worker to prune endpoints that answer 404/410.
    async fn delete_subscription(&self, address: &str, endpoint: &str) -> anyhow::Result<bool>;

    /// Backend-specific storage maintenance, invoked periodically by the
    /// cleanup task after purging (e.g. SQLite incremental vacuum). Default:
    /// no-op.
    async fn run_maintenance(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Readiness probe (P5): verify the backend can actually serve queries
    /// (SQL stores run `SELECT 1`). Powers `GET /readyz`. Default: always
    /// ready (memory store).
    async fn ping(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
