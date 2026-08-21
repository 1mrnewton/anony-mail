use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{MailboxQuotas, Store, SubscriptionLimit, UniqueViolation};
use crate::model::{
    Attachment, AttachmentMeta, Mailbox, MessageSummary, NewMessage, PushSubscription,
    StoredMessage,
};

/// In-memory [`Store`], primarily for tests and local development without a
/// database. Not durable: everything is lost when the process exits.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
    quotas: MailboxQuotas,
}

#[derive(Default)]
struct Inner {
    mailboxes: HashMap<String, Mailbox>,
    messages: Vec<Entry>,
    subscriptions: Vec<PushSubscription>,
}

struct Entry {
    message: StoredMessage,
    /// Attachment id -> raw bytes.
    contents: Vec<(Uuid, Vec<u8>)>,
    /// U2: original RFC 5322 bytes, when raw retention was enabled.
    raw: Option<Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the per-mailbox quotas enforced by `save_message`.
    pub fn with_quotas(mut self, quotas: MailboxQuotas) -> Self {
        self.quotas = quotas;
        self
    }
}

/// Drop-oldest quota enforcement, mirroring the SQL stores' semantics: keep
/// the newest `max_messages`, then walk newest-first dropping messages once
/// the running byte total exceeds `max_bytes` — but never the new message.
fn enforce_quotas(inner: &mut Inner, address: &str, new_id: Uuid, quotas: MailboxQuotas) {
    if quotas == MailboxQuotas::UNLIMITED {
        return;
    }

    // This mailbox's messages, newest first (received_at, id) — the same
    // ordering the listing endpoints use.
    let mut newest_first: Vec<(DateTime<Utc>, Uuid, u64)> = inner
        .messages
        .iter()
        .filter(|e| e.message.mailbox_address == address)
        .map(|e| {
            (
                e.message.received_at,
                e.message.id,
                e.message.raw_size.max(0) as u64,
            )
        })
        .collect();
    newest_first.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));

    let mut drop: HashSet<Uuid> = HashSet::new();
    if quotas.max_messages > 0 {
        for &(_, id, _) in newest_first.iter().skip(quotas.max_messages as usize) {
            drop.insert(id);
        }
    }
    if quotas.max_bytes > 0 {
        let mut running: u64 = 0;
        for &(_, id, size) in &newest_first {
            running = running.saturating_add(size);
            if running > quotas.max_bytes && id != new_id {
                drop.insert(id);
            }
        }
    }
    if !drop.is_empty() {
        inner.messages.retain(|e| !drop.contains(&e.message.id));
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn create_mailbox(
        &self,
        address: &str,
        domain: &str,
        expires_at: DateTime<Utc>,
        owner_token_hash: Option<&str>,
    ) -> Result<Mailbox> {
        let mut inner = self.inner.lock().unwrap();
        if inner.mailboxes.contains_key(address) {
            return Err(UniqueViolation(format!("mailbox already exists: {address}")).into());
        }
        let mailbox = Mailbox {
            address: address.to_string(),
            domain: domain.to_string(),
            created_at: Utc::now(),
            expires_at,
            owner_token_hash: owner_token_hash.map(String::from),
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
        inner.subscriptions.retain(|s| s.mailbox_address != address);
        Ok(existed)
    }

    async fn rotate_owner_token(&self, address: &str, new_hash: &str) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner.mailboxes.get_mut(address) {
            Some(mb) => {
                mb.owner_token_hash = Some(new_hash.to_string());
                Ok(true)
            }
            None => Ok(false),
        }
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
            seen: false,
            attachments: metas,
        };

        let mut inner = self.inner.lock().unwrap();
        inner.messages.push(Entry {
            message: stored.clone(),
            contents,
            raw: message.raw_content,
        });
        enforce_quotas(&mut inner, address, stored.id, self.quotas);
        Ok(stored)
    }

    async fn list_messages(
        &self,
        address: &str,
        limit: u32,
        since: Option<Uuid>,
    ) -> Result<Vec<MessageSummary>> {
        let inner = self.inner.lock().unwrap();
        // Resolve the keyset anchor; a vanished anchor means "no cursor".
        let anchor = since.and_then(|id| {
            inner
                .messages
                .iter()
                .find(|e| e.message.mailbox_address == address && e.message.id == id)
                .map(|e| (e.message.received_at, e.message.id))
        });
        let mut summaries: Vec<MessageSummary> = inner
            .messages
            .iter()
            .filter(|e| e.message.mailbox_address == address)
            .filter(|e| {
                anchor.is_none_or(|(ts, id)| (e.message.received_at, e.message.id) > (ts, id))
            })
            .map(|e| MessageSummary {
                id: e.message.id,
                mail_from: e.message.mail_from.clone(),
                subject: e.message.subject.clone(),
                received_at: e.message.received_at,
                has_attachments: !e.message.attachments.is_empty(),
                seen: e.message.seen,
            })
            .collect();
        summaries.sort_by(|a, b| b.received_at.cmp(&a.received_at).then(b.id.cmp(&a.id)));
        if limit > 0 {
            summaries.truncate(limit as usize);
        }
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

    async fn get_raw_message(&self, address: &str, id: Uuid) -> Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .messages
            .iter()
            .find(|e| e.message.mailbox_address == address && e.message.id == id)
            .and_then(|e| e.raw.clone()))
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

    async fn mark_seen(&self, address: &str, id: Uuid) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        match inner
            .messages
            .iter_mut()
            .find(|e| e.message.mailbox_address == address && e.message.id == id)
        {
            Some(e) => {
                e.message.seen = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_all_messages(&self, address: &str) -> Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.messages.len();
        inner
            .messages
            .retain(|e| e.message.mailbox_address != address);
        Ok((before - inner.messages.len()) as u64)
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
        inner
            .subscriptions
            .retain(|s| !expired.contains(&s.mailbox_address));
        Ok(expired.len() as u64)
    }

    async fn add_subscription(
        &self,
        address: &str,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        max_per_mailbox: u32,
    ) -> Result<PushSubscription> {
        let mut inner = self.inner.lock().unwrap();
        // Upsert: refreshing an existing endpoint replaces its keys and does
        // not count against the cap.
        if let Some(existing) = inner
            .subscriptions
            .iter_mut()
            .find(|s| s.mailbox_address == address && s.endpoint == endpoint)
        {
            existing.p256dh = p256dh.to_string();
            existing.auth = auth.to_string();
            return Ok(existing.clone());
        }
        let count = inner
            .subscriptions
            .iter()
            .filter(|s| s.mailbox_address == address)
            .count();
        if max_per_mailbox > 0 && count >= max_per_mailbox as usize {
            return Err(SubscriptionLimit(max_per_mailbox).into());
        }
        let sub = PushSubscription {
            id: Uuid::new_v4(),
            mailbox_address: address.to_string(),
            endpoint: endpoint.to_string(),
            p256dh: p256dh.to_string(),
            auth: auth.to_string(),
            created_at: Utc::now(),
        };
        inner.subscriptions.push(sub.clone());
        Ok(sub)
    }

    async fn list_subscriptions(&self, address: &str) -> Result<Vec<PushSubscription>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .subscriptions
            .iter()
            .filter(|s| s.mailbox_address == address)
            .cloned()
            .collect())
    }

    async fn delete_subscription(&self, address: &str, endpoint: &str) -> Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.subscriptions.len();
        inner
            .subscriptions
            .retain(|s| !(s.mailbox_address == address && s.endpoint == endpoint));
        Ok(inner.subscriptions.len() != before)
    }
}
