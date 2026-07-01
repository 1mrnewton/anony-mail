use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use uuid::Uuid;

use super::Store;
use crate::model::{
    Attachment, AttachmentMeta, Mailbox, MessageSummary, NewMessage, StoredMessage,
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
}

impl SqliteStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Open (creating if needed) a SQLite database at the given filesystem
    /// `path`, apply migrations, and return a ready store.
    ///
    /// The connection is configured for server use: WAL journaling with
    /// `synchronous=NORMAL` (readers run concurrently with the single writer),
    /// foreign keys enforced (so `ON DELETE CASCADE` works), and a busy timeout
    /// to absorb brief write contention. The parent directory is created if
    /// missing, since `create_if_missing` only creates the file itself.
    pub async fn connect(path: &str) -> Result<Self> {
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
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .with_context(|| format!("opening SQLite database at {path}"))?;

        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .context("running SQLite migrations")?;

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
}

impl From<MailboxRow> for Mailbox {
    fn from(r: MailboxRow) -> Self {
        Mailbox {
            address: r.address,
            domain: r.domain,
            created_at: r.created_at,
            expires_at: r.expires_at,
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
}

#[derive(sqlx::FromRow)]
struct AttachmentMetaRow {
    id: String,
    filename: Option<String>,
    content_type: String,
    size: i32,
}

#[async_trait]
impl Store for SqliteStore {
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Mailbox> {
        let created_at = Utc::now();
        sqlx::query(
            "INSERT INTO mailboxes (address, domain, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(address)
        .bind(domain)
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(Mailbox {
            address: address.to_string(),
            domain: domain.to_string(),
            created_at,
            expires_at,
        })
    }

    async fn get_mailbox(&self, address: &str) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            "SELECT address, domain, created_at, expires_at
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

    async fn save_message(&self, address: &str, message: NewMessage) -> Result<StoredMessage> {
        let mut tx = self.pool.begin().await?;

        let id = Uuid::new_v4();
        let received_at = Utc::now();
        sqlx::query(
            "INSERT INTO messages
                 (id, mailbox_address, mail_from, subject, message_date,
                  text_body, html_body, raw_size, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            attachments,
        })
    }

    async fn list_messages(&self, address: &str) -> Result<Vec<MessageSummary>> {
        let rows = sqlx::query_as::<_, SummaryRow>(
            "SELECT m.id, m.mail_from, m.subject, m.received_at,
                    EXISTS(SELECT 1 FROM attachments a WHERE a.message_id = m.id)
                        AS has_attachments
             FROM messages m
             WHERE m.mailbox_address = ?
             ORDER BY m.received_at DESC",
        )
        .bind(address)
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
                })
            })
            .collect()
    }

    async fn get_message(&self, address: &str, id: Uuid) -> Result<Option<StoredMessage>> {
        let row = sqlx::query_as::<_, MessageRow>(
            "SELECT id, mailbox_address, mail_from, subject, message_date,
                    text_body, html_body, raw_size, received_at
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
            attachments,
        }))
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

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let res = sqlx::query("DELETE FROM mailboxes WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}
