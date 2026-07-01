use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::Store;
use crate::model::{
    Attachment, AttachmentMeta, Mailbox, MessageSummary, NewMessage, StoredMessage,
};

/// In-memory [`Store`], primarily for tests and local development without a
/// database. Not durable: everything is lost when the process exits.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    mailboxes: HashMap<String, Mailbox>,
    messages: Vec<Entry>,
}

struct Entry {
    message: StoredMessage,
    /// Attachment id -> raw bytes.
    contents: Vec<(Uuid, Vec<u8>)>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Mailbox> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mailboxes.contains_key(address) {
            bail!("mailbox already exists: {address}");
        }
        let mailbox = Mailbox {
            address: address.to_string(),
            domain: domain.to_string(),
            created_at: Utc::now(),
            expires_at,
        };
        inner.mailboxes.insert(address.to_string(), mailbox.clone());
        Ok(mailbox)
    }

    async fn get_mailbox(&self, address: &str) -> Result<Option<Mailbox>> {
        Ok(self.inner.lock().unwrap().mailboxes.get(address).cloned())
    }

    async fn mailbox_is_active(&self, address: &str, now: DateTime<Utc>) -> Result<bool> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .mailboxes
            .get(address)
            .is_some_and(|m| m.expires_at > now))
    }

    async fn extend_mailbox(
        &self,
        address: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Option<Mailbox>> {
        let mut inner = self.inner.lock().unwrap();
        match inner.mailboxes.get_mut(address) {
            Some(mb) => {
                mb.expires_at = new_expires_at;
                Ok(Some(mb.clone()))
            }
            None => Ok(None),
        }
    }

    async fn delete_mailbox(&self, address: &str) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let existed = inner.mailboxes.remove(address).is_some();
        inner
            .messages
            .retain(|e| e.message.mailbox_address != address);
        Ok(existed)
    }

    async fn save_message(&self, address: &str, message: NewMessage) -> Result<StoredMessage> {
        let mut metas = Vec::new();
        let mut contents = Vec::new();
        for att in message.attachments {
            let aid = Uuid::new_v4();
            let size = att.content.len() as i32;
            metas.push(AttachmentMeta {
                id: aid,
                filename: att.filename,
                content_type: att.content_type,
                size,
            });
            contents.push((aid, att.content));
        }

        let stored = StoredMessage {
            id: Uuid::new_v4(),
            mailbox_address: address.to_string(),
            mail_from: message.mail_from,
            subject: message.subject,
            message_date: message.message_date,
            text_body: message.text_body,
            html_body: message.html_body,
            raw_size: message.raw_size,
            received_at: Utc::now(),
            attachments: metas,
        };

        self.inner.lock().unwrap().messages.push(Entry {
            message: stored.clone(),
            contents,
        });
        Ok(stored)
    }

    async fn list_messages(&self, address: &str) -> Result<Vec<MessageSummary>> {
        let inner = self.inner.lock().unwrap();
        let mut summaries: Vec<MessageSummary> = inner
            .messages
            .iter()
            .filter(|e| e.message.mailbox_address == address)
            .map(|e| MessageSummary {
                id: e.message.id,
                mail_from: e.message.mail_from.clone(),
                subject: e.message.subject.clone(),
                received_at: e.message.received_at,
                has_attachments: !e.message.attachments.is_empty(),
            })
            .collect();
        summaries.sort_by(|a, b| b.received_at.cmp(&a.received_at).then(b.id.cmp(&a.id)));
        Ok(summaries)
    }

    async fn get_message(&self, address: &str, id: Uuid) -> Result<Option<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .messages
            .iter()
            .find(|e| e.message.mailbox_address == address && e.message.id == id)
            .map(|e| e.message.clone()))
    }

    async fn get_attachment(
        &self,
        address: &str,
        message_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Option<Attachment>> {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner
            .messages
            .iter()
            .find(|e| e.message.mailbox_address == address && e.message.id == message_id)
        else {
            return Ok(None);
        };
        let Some(meta) = entry
            .message
            .attachments
            .iter()
            .find(|a| a.id == attachment_id)
        else {
            return Ok(None);
        };
        let Some((_, content)) = entry.contents.iter().find(|(id, _)| *id == attachment_id) else {
            return Ok(None);
        };
        Ok(Some(Attachment {
            filename: meta.filename.clone(),
            content_type: meta.content_type.clone(),
            content: content.clone(),
        }))
    }

    async fn delete_message(&self, address: &str, id: Uuid) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.messages.len();
        inner
            .messages
            .retain(|e| !(e.message.mailbox_address == address && e.message.id == id));
        Ok(inner.messages.len() != before)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        let expired: Vec<String> = inner
            .mailboxes
            .values()
            .filter(|m| m.expires_at <= now)
            .map(|m| m.address.clone())
            .collect();
        for addr in &expired {
            inner.mailboxes.remove(addr);
        }
        inner
            .messages
            .retain(|e| !expired.contains(&e.message.mailbox_address));
        Ok(expired.len() as u64)
    }
}
