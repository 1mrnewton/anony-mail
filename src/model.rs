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
    /// SHA-256 hex of the owner bearer token (A2). Never serialized; the raw
    /// token is returned exactly once, from create/rotate responses.
    #[serde(skip)]
    pub owner_token_hash: Option<String>,
}

/// Lightweight message representation for inbox listings (no bodies).
#[derive(Debug, Clone, Serialize)]
pub struct MessageSummary {
    pub id: Uuid,
    pub mail_from: String,
    pub subject: Option<String>,
    pub received_at: DateTime<Utc>,
    pub has_attachments: bool,
    /// U3: true once the client marked the message read.
    pub seen: bool,
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
    /// U3: true once the client marked the message read.
    pub seen: bool,
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
    /// U2: the original RFC 5322 bytes, retained only when
    /// `STORE_RAW_MESSAGE` is enabled (the SMTP session sets this; the parser
    /// leaves it `None`). Served via `GET .../messages/{id}/raw`.
    pub raw_content: Option<Vec<u8>>,
    pub attachments: Vec<NewAttachment>,
}

/// A parsed attachment awaiting persistence.
#[derive(Debug, Clone)]
pub struct NewAttachment {
    pub filename: Option<String>,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// A Web Push subscription registered for a mailbox (docs/06). Internal only —
/// the endpoint and keys are client credentials and are never serialized out.
#[derive(Debug, Clone)]
pub struct PushSubscription {
    pub id: Uuid,
    pub mailbox_address: String,
    pub endpoint: String,
    /// Client public key (base64url), from `PushSubscription.getKey('p256dh')`.
    pub p256dh: String,
    /// Client auth secret (base64url), from `PushSubscription.getKey('auth')`.
    pub auth: String,
    pub created_at: DateTime<Utc>,
}
