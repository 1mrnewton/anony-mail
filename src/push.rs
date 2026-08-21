//! Web Push delivery worker (docs/06).
//!
//! Subscribes to the same [`EventBus`] the SSE handler uses, so push and SSE
//! share one publish point and stay consistent — and push I/O never blocks the
//! SMTP hot path. Sends are best-effort (matching the SSE philosophy): dead
//! endpoints (`404`/`410`) are pruned, transient failures are dropped.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, info, warn};
use web_push::{
    ContentEncoding, HyperWebPushClient, PartialVapidSignatureBuilder, SubscriptionInfo,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

use crate::config::Config;
use crate::events::{EventBus, MailEvent};
use crate::model::PushSubscription;
use crate::store::Store;

/// What became of one push send. Decides whether the subscription survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Delivered,
    /// The push service says this endpoint no longer exists (404/410) —
    /// the subscription must be pruned.
    Gone,
    /// Anything else (throttling, 5xx, network). Dropped without retry in v1.
    TransientFailure,
}

/// Minimal lock-screen payload: enough to be useful, not enough to leak the
/// whole message. Clients fetch the rest over REST if the user taps in. The
/// extracted OTP (docs/05 §1) is the star: for most users the notification
/// **is** the workflow.
#[derive(Debug, Serialize)]
struct PushPayload<'a> {
    address: &'a str,
    id: uuid::Uuid,
    from: &'a str,
    subject: Option<&'a str>,
    code: Option<&'a str>,
}

/// Abstraction over the actual Web Push protocol so the worker can be tested
/// with a mock sender (no crypto or network).
#[async_trait]
pub trait PushSender: Send + Sync + 'static {
    async fn send(&self, subscription: &PushSubscription, payload: &[u8]) -> PushOutcome;
}

/// Real VAPID Web Push sender backed by the `web-push` crate.
pub struct WebPushSender {
    client: HyperWebPushClient,
    signature_builder: PartialVapidSignatureBuilder,
    subject: String,
}

impl WebPushSender {
    /// Build from config. Returns `None` (with a log) when push is not
    /// configured or the private key fails to parse.
    pub fn from_config(config: &Config) -> Option<Self> {
        let private_key = config.vapid_private_key.as_deref()?;
        let signature_builder = match VapidSignatureBuilder::from_base64_no_sub(private_key) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "VAPID_PRIVATE_KEY is not a valid base64url P-256 key; push disabled");
                return None;
            }
        };
        Some(Self {
            client: HyperWebPushClient::new(),
            signature_builder,
            subject: config.vapid_subject.clone(),
        })
    }
}

#[async_trait]
impl PushSender for WebPushSender {
    async fn send(&self, subscription: &PushSubscription, payload: &[u8]) -> PushOutcome {
        let sub_info = SubscriptionInfo::new(
            subscription.endpoint.clone(),
            subscription.p256dh.clone(),
            subscription.auth.clone(),
        );

        let mut sig_builder = self.signature_builder.clone().add_sub_info(&sub_info);
        sig_builder.add_claim("sub", self.subject.as_str());
        let signature = match sig_builder.build() {
            Ok(sig) => sig,
            Err(e) => {
                // Signing fails for malformed endpoints/keys — never recoverable.
                debug!(error = %e, endpoint = %subscription.endpoint, "VAPID signing failed");
                return PushOutcome::Gone;
            }
        };

        let mut builder = WebPushMessageBuilder::new(&sub_info);
        builder.set_vapid_signature(signature);
        builder.set_payload(ContentEncoding::Aes128Gcm, payload);
        let message = match builder.build() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, endpoint = %subscription.endpoint, "building push message failed");
                return PushOutcome::Gone;
            }
        };

        match self.client.send(message).await {
            Ok(()) => PushOutcome::Delivered,
            Err(WebPushError::EndpointNotFound(_) | WebPushError::EndpointNotValid(_)) => {
                PushOutcome::Gone
            }
            Err(e) => {
                debug!(error = %e, endpoint = %subscription.endpoint, "push send failed");
                PushOutcome::TransientFailure
            }
        }
    }
}

/// Run the push worker until the event bus closes. Spawned from `run()` like
/// the cleanup task.
pub async fn run(store: Arc<dyn Store>, events: EventBus, sender: Arc<dyn PushSender>) {
    let mut rx = events.subscribe();
    info!("push worker started");
    loop {
        match rx.recv().await {
            Ok(event) => deliver(&store, &sender, &event).await,
            // Skipped events are fine: push is a nudge, clients reconcile
            // over REST exactly as SSE consumers do.
            Err(RecvError::Lagged(skipped)) => {
                warn!(skipped, "push worker lagged behind the event bus");
            }
            Err(RecvError::Closed) => break,
        }
    }
}

/// Send one event to every subscription of its mailbox and prune dead ones.
/// Concurrency is naturally bounded by the per-mailbox subscription cap.
pub async fn deliver(store: &Arc<dyn Store>, sender: &Arc<dyn PushSender>, event: &MailEvent) {
    let subscriptions = match store.list_subscriptions(&event.address).await {
        Ok(subs) => subs,
        Err(e) => {
            warn!(error = %e, address = %event.address, "failed to load push subscriptions");
            return;
        }
    };
    if subscriptions.is_empty() {
        return;
    }

    let payload = match serde_json::to_vec(&PushPayload {
        address: &event.address,
        id: event.id,
        from: &event.mail_from,
        subject: event.subject.as_deref(),
        code: event.code.as_deref(),
    }) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to encode push payload");
            return;
        }
    };

    let results = futures::future::join_all(subscriptions.iter().map(|sub| {
        let payload = &payload;
        async move { (sub, sender.send(sub, payload).await) }
    }))
    .await;

    for (sub, outcome) in results {
        if outcome == PushOutcome::Gone {
            match store
                .delete_subscription(&sub.mailbox_address, &sub.endpoint)
                .await
            {
                Ok(true) => debug!(endpoint = %sub.endpoint, "pruned dead push subscription"),
                Ok(false) => {}
                Err(e) => warn!(error = %e, "failed to prune dead push subscription"),
            }
        }
    }
}
