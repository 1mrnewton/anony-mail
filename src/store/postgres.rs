use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::{MailboxQuotas, Store, SubscriptionLimit};
use crate::model::{
    Attachment, AttachmentMeta, Mailbox, MessageSummary, NewMessage, PushSubscription,
    StoredMessage,
};

/// Postgres-backed [`Store`] implementation using `sqlx`.
///
/// Uses runtime-checked queries (`query_as`/`query_scalar` with `.bind`) rather
/// than the compile-time macros so the project builds without a live database.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    quotas: MailboxQuotas,
}

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
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
}

// --- Row types (kept local so the model layer stays storage-agnostic) ---

#[derive(sqlx::FromRow)]
struct MailboxRow {
    address: String,
    domain: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    owner_token_hash: Option<String>,
}

impl From<MailboxRow> for Mailbox {
    fn from(r: MailboxRow) -> Self {
        Mailbox {
            address: r.address,
            domain: r.domain,
            created_at: r.created_at,
            expires_at: r.expires_at,
            owner_token_hash: r.owner_token_hash,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    id: Uuid,
    mail_from: String,
    subject: Option<String>,
    received_at: DateTime<Utc>,
    has_attachments: bool,
    seen: bool,
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: Uuid,
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
    id: Uuid,
    filename: Option<String>,
    content_type: String,
    size: i32,
}

impl From<AttachmentMetaRow> for AttachmentMeta {
    fn from(r: AttachmentMetaRow) -> Self {
        AttachmentMeta {
            id: r.id,
            filename: r.filename,
            content_type: r.content_type,
            size: r.size,
        }
    }
}

#[async_trait]
impl Store for PostgresStore {
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
        owner_token_hash: Option<&str>,
    ) -> Result<Mailbox> {
        let row = sqlx::query_as::<_, MailboxRow>(
            "INSERT INTO mailboxes (address, domain, expires_at, owner_token_hash)
             VALUES ($1, $2, $3, $4)
             RETURNING address, domain, created_at, expires_at, owner_token_hash",
        )
        .bind(address)
        .bind(domain)
        .bind(expires_at)
        .bind(owner_token_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    async fn get_mailbox(&self, address: &str) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            "SELECT address, domain, created_at, expires_at, owner_token_hash
             FROM mailboxes WHERE address = $1",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn mailbox_is_active(&self, address: &str, now: DateTime<Utc>) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM mailboxes WHERE address = $1 AND expires_at > $2
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
        let row = sqlx::query_as::<_, MailboxRow>(
            "UPDATE mailboxes SET expires_at = $2 WHERE address = $1
             RETURNING address, domain, created_at, expires_at, owner_token_hash",
        )
        .bind(address)
        .bind(new_expires_at)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn delete_mailbox(&self, address: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM mailboxes WHERE address = $1")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn rotate_owner_token(&self, address: &str, new_hash: &str) -> Result<bool> {
        let res = sqlx::query("UPDATE mailboxes SET owner_token_hash = $2 WHERE address = $1")
            .bind(address)
            .bind(new_hash)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn save_message(&self, address: &str, message: NewMessage) -> Result<StoredMessage> {
        let mut tx = self.pool.begin().await?;

        let (id, received_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO messages
                 (mailbox_address, mail_from, subject, message_date,
                  text_body, html_body, raw_size, raw_content)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, received_at",
        )
        .bind(address)
        .bind(&message.mail_from)
        .bind(&message.subject)
        .bind(message.message_date)
        .bind(&message.text_body)
        .bind(&message.html_body)
        .bind(message.raw_size)
        .bind(&message.raw_content)
        .fetch_one(&mut *tx)
        .await?;

        let mut attachments = Vec::with_capacity(message.attachments.len());
        for att in &message.attachments {
            let size = att.content.len() as i32;
            let att_id: Uuid = sqlx::query_scalar(
                "INSERT INTO attachments (message_id, filename, content_type, size, content)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id",
            )
            .bind(id)
            .bind(&att.filename)
            .bind(&att.content_type)
            .bind(size)
            .bind(&att.content[..])
            .fetch_one(&mut *tx)
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
                "DELETE FROM messages WHERE mailbox_address = $1 AND id NOT IN (
                     SELECT id FROM messages WHERE mailbox_address = $1
                     ORDER BY received_at DESC, id DESC LIMIT $2
                 )",
            )
            .bind(address)
            .bind(self.quotas.max_messages as i64)
            .execute(&mut *tx)
            .await?;
        }
        if self.quotas.max_bytes > 0 {
            // Keep the newest messages whose running total fits the budget;
            // never drop the message just saved.
            sqlx::query(
                "DELETE FROM messages WHERE mailbox_address = $1 AND id IN (
                     SELECT id FROM (
                         SELECT id,
                                SUM(raw_size) OVER (ORDER BY received_at DESC, id DESC)
                                    AS running
                         FROM messages WHERE mailbox_address = $1
                     ) t WHERE t.running > $2 AND t.id <> $3
                 )",
            )
            .bind(address)
            .bind(self.quotas.max_bytes as i64)
            .bind(id)
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
        // Keyset cursor resolved in-SQL (see the SQLite twin). `LIMIT NULL`
        // means no limit in Postgres; a vanished anchor disables the filter.
        let rows = sqlx::query_as::<_, SummaryRow>(
            "SELECT m.id, m.mail_from, m.subject, m.received_at, m.seen,
                    EXISTS(SELECT 1 FROM attachments a WHERE a.message_id = m.id)
                        AS has_attachments
             FROM messages m
             WHERE m.mailbox_address = $1
               AND ($3 IS NULL
                    OR NOT EXISTS(SELECT 1 FROM messages s
                                  WHERE s.mailbox_address = $1 AND s.id = $3)
                    OR (m.received_at, m.id) >
                       (SELECT s.received_at, s.id FROM messages s
                        WHERE s.mailbox_address = $1 AND s.id = $3))
             ORDER BY m.received_at DESC, m.id DESC
             LIMIT $2",
        )
        .bind(address)
        .bind(if limit == 0 { None } else { Some(limit as i64) })
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| MessageSummary {
                id: r.id,
                mail_from: r.mail_from,
                subject: r.subject,
                received_at: r.received_at,
                has_attachments: r.has_attachments,
                seen: r.seen,
            })
            .collect())
    }

    async fn get_message(&self, address: &str, id: Uuid) -> Result<Option<StoredMessage>> {
        let row = sqlx::query_as::<_, MessageRow>(
            "SELECT id, mailbox_address, mail_from, subject, message_date,
                    text_body, html_body, raw_size, received_at, seen
             FROM messages
             WHERE mailbox_address = $1 AND id = $2",
        )
        .bind(address)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let attachments = sqlx::query_as::<_, AttachmentMetaRow>(
            "SELECT id, filename, content_type, size
             FROM attachments WHERE message_id = $1 ORDER BY id",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

        Ok(Some(StoredMessage {
            id: row.id,
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
        let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT raw_content FROM messages WHERE mailbox_address = $1 AND id = $2",
        )
        .bind(address)
        .bind(id)
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
             WHERE m.mailbox_address = $1 AND a.message_id = $2 AND a.id = $3",
        )
        .bind(address)
        .bind(message_id)
        .bind(attachment_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(filename, content_type, content)| Attachment {
            filename,
            content_type,
            content,
        }))
    }

    async fn delete_message(&self, address: &str, id: Uuid) -> Result<bool> {
        let res = sqlx::query("DELETE FROM messages WHERE mailbox_address = $1 AND id = $2")
            .bind(address)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn mark_seen(&self, address: &str, id: Uuid) -> Result<bool> {
        let res =
            sqlx::query("UPDATE messages SET seen = TRUE WHERE mailbox_address = $1 AND id = $2")
                .bind(address)
                .bind(id)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_all_messages(&self, address: &str) -> Result<u64> {
        let res = sqlx::query("DELETE FROM messages WHERE mailbox_address = $1")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let res = sqlx::query("DELETE FROM mailboxes WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    async fn add_subscription(
        &self,
        address: &str,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        max_per_mailbox: u32,
    ) -> Result<PushSubscription> {
        let mut tx = self.pool.begin().await?;

        // Cap check first; the upsert below refreshes existing rows without
        // consuming quota (count only rows with a *different* endpoint).
        if max_per_mailbox > 0 {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM push_subscriptions
                 WHERE mailbox_address = $1 AND endpoint <> $2",
            )
            .bind(address)
            .bind(endpoint)
            .fetch_one(&mut *tx)
            .await?;
            if count >= max_per_mailbox as i64 {
                return Err(SubscriptionLimit(max_per_mailbox).into());
            }
        }

        let row: PushSubscriptionRow = sqlx::query_as(
            "INSERT INTO push_subscriptions (mailbox_address, endpoint, p256dh, auth)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (mailbox_address, endpoint)
             DO UPDATE SET p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth
             RETURNING id, mailbox_address, endpoint, p256dh, auth, created_at",
        )
        .bind(address)
        .bind(endpoint)
        .bind(p256dh)
        .bind(auth)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    async fn list_subscriptions(&self, address: &str) -> Result<Vec<PushSubscription>> {
        let rows: Vec<PushSubscriptionRow> = sqlx::query_as(
            "SELECT id, mailbox_address, endpoint, p256dh, auth, created_at
             FROM push_subscriptions WHERE mailbox_address = $1 ORDER BY created_at",
        )
        .bind(address)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_subscription(&self, address: &str, endpoint: &str) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM push_subscriptions WHERE mailbox_address = $1 AND endpoint = $2",
        )
        .bind(address)
        .bind(endpoint)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

#[derive(sqlx::FromRow)]
struct PushSubscriptionRow {
    id: Uuid,
    mailbox_address: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    created_at: DateTime<Utc>,
}

impl From<PushSubscriptionRow> for PushSubscription {
    fn from(r: PushSubscriptionRow) -> Self {
        PushSubscription {
            id: r.id,
            mailbox_address: r.mailbox_address,
            endpoint: r.endpoint,
            p256dh: r.p256dh,
            auth: r.auth,
            created_at: r.created_at,
        }
    }
}
