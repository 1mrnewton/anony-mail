use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A disposable inbox.
#[derive(Debug, Clone, Serialize)]
pub struct Mailbox {
    pub address: String,
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Lightweight message representation for inbox listings (no bodies).
#[derive(Debug, Clone, Serialize)]
pub struct MessageSummary {
    pub id: Uuid,
    pub mail_from: String,
    pub subject: Option<String>,
    pub received_at: DateTime<Utc>,
    pub has_attachments: bool,
}

/// Attachment metadata returned alongside a full message (content omitted).
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentMeta {
    pub id: Uuid,
    pub filename: Option<String>,
    pub content_type: String,
    pub size: i32,
}

/// A fully materialised stored message including bodies and attachment metadata.
#[derive(Debug, Clone, Serialize)]
pub struct StoredMessage {
    pub id: Uuid,
    pub mailbox_address: String,
    pub mail_from: String,
    pub subject: Option<String>,
    pub message_date: Option<DateTime<Utc>>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub raw_size: i32,
    pub received_at: DateTime<Utc>,
    pub attachments: Vec<AttachmentMeta>,
}

/// Raw attachment bytes plus the metadata needed to serve a download.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: Option<String>,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// A parsed inbound message ready to be persisted. Produced by the MIME
/// parser from raw SMTP `DATA` bytes and consumed by [`crate::store::Store::save_message`].
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub mail_from: String,
    pub subject: Option<String>,
    pub message_date: Option<DateTime<Utc>>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub raw_size: i32,
    pub attachments: Vec<NewAttachment>,
}

/// A parsed attachment awaiting persistence.
#[derive(Debug, Clone)]
pub struct NewAttachment {
    pub filename: Option<String>,
    pub content_type: String,
    pub content: Vec<u8>,
}
