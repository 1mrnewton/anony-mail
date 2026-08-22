use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use uuid::Uuid;

use super::{MailboxQuotas, Store, SubscriptionLimit};
use crate::model::{
    Attachment, AttachmentMeta, AttestedDevice, CustomDomain, CustomDomainStatus, Mailbox,
    MessageSummary, NewMessage, PushSubscription, StoredMessage, SubscriptionKind,
};

/// SQLite-backed [`Store`] implementation using `sqlx`.
///
/// UUIDs and timestamps are generated in Rust (SQLite lacks native types for
/// both): ids are stored as TEXT and datetimes as ISO-8601 TEXT via `sqlx`'s
/// `chrono` support. Uses runtime-checked queries so no live DB is needed to
/// build.
#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    quotas: MailboxQuotas,
}

impl SqliteStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            quotas: MailboxQuotas::UNLIMITED,
        }
    }

    /// Set the per-mailbox quotas enforced by `save_message`.
    pub fn with_quotas(mut self, quotas: MailboxQuotas) -> Self {
        self.quotas = quotas;
        self
    }

    /// Default pool size when `DB_MAX_CONNECTIONS` is unset (P5).
    const DEFAULT_MAX_CONNECTIONS: u32 = 5;

    /// [`Self::connect_with`] using the default pool size.
    pub async fn connect(path: &str) -> Result<Self> {
        Self::connect_with(path, 0).await
    }

    /// Open (creating if needed) a SQLite database at the given filesystem
    /// `path`, apply migrations, and return a ready store. `max_connections`
    /// sizes the pool (0 = default).
    ///
    /// The connection is configured for server use: WAL journaling with
    /// `synchronous=NORMAL` (readers run concurrently with the single writer),
    /// foreign keys enforced (so `ON DELETE CASCADE` works), a busy timeout
    /// to absorb brief write contention, and incremental auto-vacuum so purged
    /// mail actually shrinks the file (see `run_maintenance`). The parent
    /// directory is created if missing, since `create_if_missing` only creates
    /// the file itself.
    pub async fn connect_with(path: &str, max_connections: u32) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating SQLite data directory {}", parent.display()))?;
        }

        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .busy_timeout(Duration::from_secs(5));

        let max_connections = if max_connections == 0 {
            Self::DEFAULT_MAX_CONNECTIONS
        } else {
            max_connections
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(opts)
            .await
            .with_context(|| format!("opening SQLite database at {path}"))?;

        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .context("running SQLite migrations")?;

        // `auto_vacuum` only takes effect on fresh databases; pre-existing
        // files need a one-time VACUUM to rebuild with it enabled. The mode is
        // persistent, so this runs at most once per database file.
        let mode: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
            .fetch_one(&pool)
            .await
            .context("querying auto_vacuum mode")?;
        if mode != 2 {
            sqlx::query("VACUUM")
                .execute(&pool)
                .await
                .context("one-time VACUUM to enable incremental auto_vacuum")?;
        }

        Ok(Self::new(pool))
    }
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).with_context(|| format!("invalid uuid stored in database: {s}"))
}

// --- Row types (kept local so the model layer stays storage-agnostic) ---

#[derive(sqlx::FromRow)]
struct MailboxRow {
    address: String,
    domain: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    owner_token_hash: Option<String>,
    creator_device_hash: Option<String>,
}

impl From<MailboxRow> for Mailbox {
    fn from(r: MailboxRow) -> Self {
        Mailbox {
            address: r.address,
            domain: r.domain,
            created_at: r.created_at,
            expires_at: r.expires_at,
            owner_token_hash: r.owner_token_hash,
            creator_device_hash: r.creator_device_hash,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AttestedDeviceRow {
    key_id: String,
    public_key: Vec<u8>,
    counter: i64,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

impl From<AttestedDeviceRow> for AttestedDevice {
    fn from(r: AttestedDeviceRow) -> Self {
        AttestedDevice {
            key_id: r.key_id,
            public_key: r.public_key,
            counter: r.counter,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    id: String,
    mail_from: String,
    subject: Option<String>,
    received_at: DateTime<Utc>,
    has_attachments: bool,
    seen: bool,
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: String,
    mailbox_address: String,
    mail_from: String,
    subject: Option<String>,
    message_date: Option<DateTime<Utc>>,
    text_body: Option<String>,
    html_body: Option<String>,
    raw_size: i32,
    received_at: DateTime<Utc>,
    seen: bool,
}

#[derive(sqlx::FromRow)]
struct AttachmentMetaRow {
    id: String,
    filename: Option<String>,
    content_type: String,
    size: i32,
}

#[derive(sqlx::FromRow)]
struct PushSubscriptionRow {
    id: String,
    mailbox_address: String,
    kind: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    created_at: DateTime<Utc>,
}

impl TryFrom<PushSubscriptionRow> for PushSubscription {
    type Error = anyhow::Error;

    fn try_from(r: PushSubscriptionRow) -> Result<Self> {
        Ok(PushSubscription {
            id: parse_uuid(&r.id)?,
            mailbox_address: r.mailbox_address,
            kind: r.kind.parse()?,
            endpoint: r.endpoint,
            p256dh: r.p256dh,
            auth: r.auth,
            created_at: r.created_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CustomDomainRow {
    domain: String,
    claim_token_hash: String,
    txt_token: String,
    status: String,
    created_at: DateTime<Utc>,
    verified_at: Option<DateTime<Utc>>,
    last_checked_at: Option<DateTime<Utc>>,
}

impl TryFrom<CustomDomainRow> for CustomDomain {
    type Error = anyhow::Error;

    fn try_from(r: CustomDomainRow) -> Result<Self> {
        Ok(CustomDomain {
            domain: r.domain,
            status: r.status.parse()?,
            claim_token_hash: r.claim_token_hash,
            txt_token: r.txt_token,
            created_at: r.created_at,
            verified_at: r.verified_at,
            last_checked_at: r.last_checked_at,
        })
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
        owner_token_hash: Option<&str>,
        creator_device_hash: Option<&str>,
    ) -> Result<Mailbox> {
        let created_at = Utc::now();
        sqlx::query(
            "INSERT INTO mailboxes
                 (address, domain, created_at, expires_at, owner_token_hash,
                  creator_device_hash)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(address)
        .bind(domain)
        .bind(created_at)
        .bind(expires_at)
        .bind(owner_token_hash)
        .bind(creator_device_hash)
        .execute(&self.pool)
        .await?;

        Ok(Mailbox {
            address: address.to_string(),
            domain: domain.to_string(),
            created_at,
            expires_at,
            owner_token_hash: owner_token_hash.map(String::from),
            creator_device_hash: creator_device_hash.map(String::from),
        })
    }

    async fn get_mailbox(&self, address: &str) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            "SELECT address, domain, created_at, expires_at, owner_token_hash,
                    creator_device_hash
             FROM mailboxes WHERE address = ?",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn mailbox_is_active(&self, address: &str, now: DateTime<Utc>) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM mailboxes WHERE address = ? AND expires_at > ?
             )",
        )
        .bind(address)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    async fn extend_mailbox(
        &self,
        address: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Option<Mailbox>> {
        let res = sqlx::query("UPDATE mailboxes SET expires_at = ? WHERE address = ?")
            .bind(new_expires_at)
            .bind(address)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        self.get_mailbox(address).await
    }

    async fn delete_mailbox(&self, address: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM mailboxes WHERE address = ?")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn rotate_owner_token(&self, address: &str, new_hash: &str) -> Result<bool> {
        let res = sqlx::query("UPDATE mailboxes SET owner_token_hash = ? WHERE address = ?")
            .bind(new_hash)
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn save_message(&self, address: &str, message: NewMessage) -> Result<StoredMessage> {
        let mut tx = self.pool.begin().await?;

        let id = Uuid::new_v4();
        let received_at = Utc::now();
        sqlx::query(
            "INSERT INTO messages
                 (id, mailbox_address, mail_from, subject, message_date,
                  text_body, html_body, raw_size, received_at, raw_content)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(address)
        .bind(&message.mail_from)
        .bind(&message.subject)
        .bind(message.message_date)
        .bind(&message.text_body)
        .bind(&message.html_body)
        .bind(message.raw_size)
        .bind(received_at)
        .bind(&message.raw_content)
        .execute(&mut *tx)
        .await?;

        let mut attachments = Vec::with_capacity(message.attachments.len());
        for att in &message.attachments {
            let att_id = Uuid::new_v4();
            let size = att.content.len() as i32;
            sqlx::query(
                "INSERT INTO attachments (id, message_id, filename, content_type, size, content)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(att_id.to_string())
            .bind(id.to_string())
            .bind(&att.filename)
            .bind(&att.content_type)
            .bind(size)
            .bind(&att.content[..])
            .execute(&mut *tx)
            .await?;

            attachments.push(AttachmentMeta {
                id: att_id,
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                size,
            });
        }

        // A4 quotas: drop the oldest messages beyond the caps, atomically with
        // the insert. `(received_at, id)` ordering matches the listing order.
        if self.quotas.max_messages > 0 {
            sqlx::query(
                "DELETE FROM messages WHERE mailbox_address = ? AND id NOT IN (
                     SELECT id FROM messages WHERE mailbox_address = ?
                     ORDER BY received_at DESC, id DESC LIMIT ?
                 )",
            )
            .bind(address)
            .bind(address)
            .bind(self.quotas.max_messages as i64)
            .execute(&mut *tx)
            .await?;
        }
        if self.quotas.max_bytes > 0 {
            // Keep the newest messages whose running total fits the budget;
            // never drop the message just saved.
            sqlx::query(
                "DELETE FROM messages WHERE mailbox_address = ? AND id IN (
                     SELECT id FROM (
                         SELECT id,
                                SUM(raw_size) OVER (ORDER BY received_at DESC, id DESC)
                                    AS running
                         FROM messages WHERE mailbox_address = ?
                     ) t WHERE t.running > ? AND t.id <> ?
                 )",
            )
            .bind(address)
            .bind(address)
            .bind(self.quotas.max_bytes as i64)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(StoredMessage {
            id,
            mailbox_address: address.to_string(),
            mail_from: message.mail_from,
            subject: message.subject,
            message_date: message.message_date,
            text_body: message.text_body,
            html_body: message.html_body,
            raw_size: message.raw_size,
            received_at,
            seen: false,
            attachments,
        })
    }

    async fn list_messages(
        &self,
        address: &str,
        limit: u32,
        since: Option<Uuid>,
    ) -> Result<Vec<MessageSummary>> {
        // Keyset cursor resolved in-SQL so timestamps never round-trip through
        // chrono (SQLite stores them as TEXT; re-encoding could break the
        // equality arm). A vanished anchor disables the filter (newest page).
        let rows = sqlx::query_as::<_, SummaryRow>(
            "SELECT m.id, m.mail_from, m.subject, m.received_at, m.seen,
                    EXISTS(SELECT 1 FROM attachments a WHERE a.message_id = m.id)
                        AS has_attachments
             FROM messages m
             WHERE m.mailbox_address = ?1
               AND (?3 IS NULL
                    OR NOT EXISTS(SELECT 1 FROM messages s
                                  WHERE s.mailbox_address = ?1 AND s.id = ?3)
                    OR (m.received_at, m.id) >
                       (SELECT s.received_at, s.id FROM messages s
                        WHERE s.mailbox_address = ?1 AND s.id = ?3))
             ORDER BY m.received_at DESC, m.id DESC
             LIMIT ?2",
        )
        .bind(address)
        .bind(if limit == 0 { -1 } else { limit as i64 })
        .bind(since.map(|u| u.to_string()))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                Ok(MessageSummary {
                    id: parse_uuid(&r.id)?,
                    mail_from: r.mail_from,
                    subject: r.subject,
                    received_at: r.received_at,
                    has_attachments: r.has_attachments,
                    seen: r.seen,
                })
            })
            .collect()
    }

    async fn get_message(&self, address: &str, id: Uuid) -> Result<Option<StoredMessage>> {
        let row = sqlx::query_as::<_, MessageRow>(
            "SELECT id, mailbox_address, mail_from, subject, message_date,
                    text_body, html_body, raw_size, received_at, seen
             FROM messages
             WHERE mailbox_address = ? AND id = ?",
        )
        .bind(address)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let attachments = sqlx::query_as::<_, AttachmentMetaRow>(
            "SELECT id, filename, content_type, size
             FROM attachments WHERE message_id = ? ORDER BY id",
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| {
            Ok::<_, anyhow::Error>(AttachmentMeta {
                id: parse_uuid(&r.id)?,
                filename: r.filename,
                content_type: r.content_type,
                size: r.size,
            })
        })
        .collect::<Result<Vec<_>>>()?;

        Ok(Some(StoredMessage {
            id: parse_uuid(&row.id)?,
            mailbox_address: row.mailbox_address,
            mail_from: row.mail_from,
            subject: row.subject,
            message_date: row.message_date,
            text_body: row.text_body,
            html_body: row.html_body,
            raw_size: row.raw_size,
            received_at: row.received_at,
            seen: row.seen,
            attachments,
        }))
    }

    async fn get_raw_message(&self, address: &str, id: Uuid) -> Result<Option<Vec<u8>>> {
        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT raw_content FROM messages WHERE mailbox_address = ? AND id = ?")
                .bind(address)
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(raw,)| raw))
    }

    async fn get_attachment(
        &self,
        address: &str,
        message_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Option<Attachment>> {
        let row = sqlx::query_as::<_, (Option<String>, String, Vec<u8>)>(
            "SELECT a.filename, a.content_type, a.content
             FROM attachments a
             JOIN messages m ON m.id = a.message_id
             WHERE m.mailbox_address = ? AND a.message_id = ? AND a.id = ?",
        )
        .bind(address)
        .bind(message_id.to_string())
        .bind(attachment_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(filename, content_type, content)| Attachment {
            filename,
            content_type,
            content,
        }))
    }

    async fn delete_message(&self, address: &str, id: Uuid) -> Result<bool> {
        let res = sqlx::query("DELETE FROM messages WHERE mailbox_address = ? AND id = ?")
            .bind(address)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn mark_seen(&self, address: &str, id: Uuid) -> Result<bool> {
        let res = sqlx::query("UPDATE messages SET seen = 1 WHERE mailbox_address = ? AND id = ?")
            .bind(address)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_all_messages(&self, address: &str) -> Result<u64> {
        let res = sqlx::query("DELETE FROM messages WHERE mailbox_address = ?")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let res = sqlx::query("DELETE FROM mailboxes WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Hand freed pages back to the filesystem (requires the incremental
    /// auto-vacuum mode configured in `connect`).
    async fn run_maintenance(&self) -> Result<()> {
        sqlx::query("PRAGMA incremental_vacuum")
            .execute(&self.pool)
            .await
            .context("running SQLite incremental_vacuum")?;
        Ok(())
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    async fn add_subscription(
        &self,
        address: &str,
        kind: SubscriptionKind,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        max_per_mailbox: u32,
    ) -> Result<PushSubscription> {
        let mut tx = self.pool.begin().await?;

        // Upsert: refreshing an existing endpoint replaces its kind and keys
        // and does not count against the cap.
        let existing: Option<PushSubscriptionRow> = sqlx::query_as(
            "SELECT id, mailbox_address, kind, endpoint, p256dh, auth, created_at
             FROM push_subscriptions WHERE mailbox_address = ? AND endpoint = ?",
        )
        .bind(address)
        .bind(endpoint)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            sqlx::query(
                "UPDATE push_subscriptions SET kind = ?, p256dh = ?, auth = ? WHERE id = ?",
            )
            .bind(kind.as_str())
            .bind(p256dh)
            .bind(auth)
            .bind(&row.id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(PushSubscription {
                kind,
                p256dh: p256dh.to_string(),
                auth: auth.to_string(),
                ..row.try_into()?
            });
        }

        if max_per_mailbox > 0 {
            let (count,): (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM push_subscriptions WHERE mailbox_address = ?")
                    .bind(address)
                    .fetch_one(&mut *tx)
                    .await?;
            if count >= max_per_mailbox as i64 {
                return Err(SubscriptionLimit(max_per_mailbox).into());
            }
        }

        let id = Uuid::new_v4();
        let created_at = Utc::now();
        sqlx::query(
            "INSERT INTO push_subscriptions (id, mailbox_address, kind, endpoint, p256dh, auth, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(address)
        .bind(kind.as_str())
        .bind(endpoint)
        .bind(p256dh)
        .bind(auth)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(PushSubscription {
            id,
            mailbox_address: address.to_string(),
            kind,
            endpoint: endpoint.to_string(),
            p256dh: p256dh.to_string(),
            auth: auth.to_string(),
            created_at,
        })
    }

    async fn create_custom_domain(
        &self,
        domain: &str,
        claim_token_hash: &str,
        txt_token: &str,
    ) -> Result<CustomDomain> {
        let created_at = Utc::now();
        sqlx::query(
            "INSERT INTO custom_domains (domain, claim_token_hash, txt_token, status, created_at)
             VALUES (?, ?, ?, 'pending', ?)",
        )
        .bind(domain)
        .bind(claim_token_hash)
        .bind(txt_token)
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        Ok(CustomDomain {
            domain: domain.to_string(),
            status: CustomDomainStatus::Pending,
            claim_token_hash: claim_token_hash.to_string(),
            txt_token: txt_token.to_string(),
            created_at,
            verified_at: None,
            last_checked_at: None,
        })
    }

    async fn get_custom_domain(&self, domain: &str) -> Result<Option<CustomDomain>> {
        let row: Option<CustomDomainRow> = sqlx::query_as(
            "SELECT domain, claim_token_hash, txt_token, status,
                    created_at, verified_at, last_checked_at
             FROM custom_domains WHERE domain = ?",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn delete_custom_domain(&self, domain: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM custom_domains WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn custom_domain_is_verified(&self, domain: &str) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM custom_domains WHERE domain = ? AND status = 'verified'
             )",
        )
        .bind(domain)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    async fn record_custom_domain_check(
        &self,
        domain: &str,
        status: CustomDomainStatus,
        verified_at: Option<DateTime<Utc>>,
        checked_at: DateTime<Utc>,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE custom_domains
             SET status = ?, verified_at = ?, last_checked_at = ?
             WHERE domain = ?",
        )
        .bind(status.as_str())
        .bind(verified_at)
        .bind(checked_at)
        .bind(domain)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_custom_domains_to_recheck(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<CustomDomain>> {
        let rows: Vec<CustomDomainRow> = sqlx::query_as(
            "SELECT domain, claim_token_hash, txt_token, status,
                    created_at, verified_at, last_checked_at
             FROM custom_domains
             WHERE status IN ('verified', 'failed')
               AND (last_checked_at IS NULL OR last_checked_at <= ?)",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_subscriptions(&self, address: &str) -> Result<Vec<PushSubscription>> {
        let rows: Vec<PushSubscriptionRow> = sqlx::query_as(
            "SELECT id, mailbox_address, kind, endpoint, p256dh, auth, created_at
             FROM push_subscriptions WHERE mailbox_address = ? ORDER BY created_at",
        )
        .bind(address)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn delete_subscription(&self, address: &str, endpoint: &str) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM push_subscriptions WHERE mailbox_address = ? AND endpoint = ?",
        )
        .bind(address)
        .bind(endpoint)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn upsert_attested_device(
        &self,
        key_id: &str,
        public_key: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AttestedDevice> {
        // Re-attesting a known key keeps the stored counter (resetting it
        // would reopen the replay window) and refreshes last_seen_at.
        let row: AttestedDeviceRow = sqlx::query_as(
            "INSERT INTO attested_devices
                 (key_id, public_key, counter, created_at, last_seen_at)
             VALUES (?, ?, 0, ?, ?)
             ON CONFLICT(key_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
             RETURNING key_id, public_key, counter, created_at, last_seen_at",
        )
        .bind(key_id)
        .bind(public_key)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    async fn get_attested_device(&self, key_id: &str) -> Result<Option<AttestedDevice>> {
        let row: Option<AttestedDeviceRow> = sqlx::query_as(
            "SELECT key_id, public_key, counter, created_at, last_seen_at
             FROM attested_devices WHERE key_id = ?",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn advance_attested_device_counter(
        &self,
        key_id: &str,
        counter: i64,
        seen_at: DateTime<Utc>,
    ) -> Result<bool> {
        // The strictly-greater guard makes the database the serialization
        // point: of two concurrent assertions carrying the same counter,
        // exactly one wins.
        let res = sqlx::query(
            "UPDATE attested_devices SET counter = ?, last_seen_at = ?
             WHERE key_id = ? AND counter < ?",
        )
        .bind(counter)
        .bind(seen_at)
        .bind(key_id)
        .bind(counter)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn prune_attested_devices(&self, idle_before: DateTime<Utc>) -> Result<u64> {
        let res = sqlx::query("DELETE FROM attested_devices WHERE last_seen_at < ?")
            .bind(idle_before)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn count_active_mailboxes_by_device(
        &self,
        creator_device_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mailboxes
             WHERE creator_device_hash = ? AND expires_at > ?",
        )
        .bind(creator_device_hash)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.max(0) as u64)
    }
}
