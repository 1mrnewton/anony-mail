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
use crate::model::{PushSubscription, SubscriptionKind};
use crate::store::Store;

/// What became of one push send. Decides whether the subscription survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Delivered,
    /// The push service says this endpoint/token no longer exists (Web Push
    /// 404/410, APNs `Unregistered`/`BadDeviceToken`) — the subscription must
    /// be pruned.
    Gone,
    /// Anything else (throttling, 5xx, network). Dropped without retry in v1.
    TransientFailure,
}

/// Minimal lock-screen payload: enough to be useful, not enough to leak the
/// whole message. Clients fetch the rest over REST if the user taps in. The
/// extracted OTP (docs/05 §1) is the star: for most users the notification
/// **is** the workflow. Web Push sends it as the raw JSON body; APNs carries
/// it as custom data under the `anonymail` key.
#[derive(Debug, Serialize)]
pub struct PushPayload<'a> {
    pub address: &'a str,
    pub id: uuid::Uuid,
    pub from: &'a str,
    pub subject: Option<&'a str>,
    pub code: Option<&'a str>,
}

impl PushPayload<'_> {
    /// The human-visible alert for channels that display server-composed text
    /// (APNs). Returns `(title, body)`.
    pub fn alert(&self) -> (String, String) {
        let title = self
            .subject
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("New mail")
            .to_string();
        let body = match self.code {
            Some(code) => format!("Code {code} — {}", self.from),
            None => format!("From {}", self.from),
        };
        (title, body)
    }
}

/// Abstraction over one push protocol so the worker can be tested with mock
/// senders (no crypto or network).
#[async_trait]
pub trait PushSender: Send + Sync + 'static {
    async fn send(&self, subscription: &PushSubscription, payload: &PushPayload<'_>)
    -> PushOutcome;
}

/// The configured sender for each subscription kind. Either may be absent;
/// subscriptions of an unconfigured kind are skipped.
#[derive(Clone, Default)]
pub struct Senders {
    pub webpush: Option<Arc<dyn PushSender>>,
    pub apns: Option<Arc<dyn PushSender>>,
}

impl Senders {
    pub fn for_kind(&self, kind: SubscriptionKind) -> Option<&Arc<dyn PushSender>> {
        match kind {
            SubscriptionKind::WebPush => self.webpush.as_ref(),
            SubscriptionKind::Apns => self.apns.as_ref(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.webpush.is_none() && self.apns.is_none()
    }
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
    async fn send(
        &self,
        subscription: &PushSubscription,
        payload: &PushPayload<'_>,
    ) -> PushOutcome {
        let payload = match serde_json::to_vec(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to encode web push payload");
                return PushOutcome::TransientFailure;
            }
        };
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
        builder.set_payload(ContentEncoding::Aes128Gcm, &payload);
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

/// APNs sender for native iOS/macOS apps, backed by the `a2` crate with
/// token-based (`.p8`) authentication.
pub struct ApnsSender {
    client: a2::Client,
    topic: String,
}

impl ApnsSender {
    /// Build from config. Returns `None` (with a log) when APNs is not
    /// configured or the signing key fails to parse.
    pub fn from_config(config: &Config) -> Option<Self> {
        let key = config.apns_private_key.as_deref()?;
        let key_id = config.apns_key_id.as_deref()?;
        let team_id = config.apns_team_id.as_deref()?;
        let topic = config.apns_topic.as_deref()?;

        let endpoint = if config.apns_sandbox {
            a2::Endpoint::Sandbox
        } else {
            a2::Endpoint::Production
        };
        let client = match a2::Client::token(
            std::io::Cursor::new(key.as_bytes().to_vec()),
            key_id,
            team_id,
            a2::ClientConfig::new(endpoint),
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "APNs key rejected (check APNS_KEY_PATH/APNS_KEY_BASE64); APNs disabled");
                return None;
            }
        };
        Some(Self {
            client,
            topic: topic.to_string(),
        })
    }
}

#[async_trait]
impl PushSender for ApnsSender {
    async fn send(
        &self,
        subscription: &PushSubscription,
        payload: &PushPayload<'_>,
    ) -> PushOutcome {
        use a2::NotificationBuilder as _;

        let (title, body) = payload.alert();
        let builder = a2::DefaultNotificationBuilder::new()
            .set_title(&title)
            .set_body(&body)
            .set_sound("default");

        let collapse = payload.id.to_string();
        let options = apns_notification_options(&self.topic, &collapse);
        let mut apns_payload = builder.build(&subscription.endpoint, options);
        // Custom data mirrors the Web Push JSON so the app can deep-link and
        // copy the code without fetching first.
        if let Err(e) = apns_payload.add_custom_data("anonymail", payload) {
            warn!(error = %e, "failed to attach APNs custom data");
            return PushOutcome::TransientFailure;
        }

        match self.client.send(apns_payload).await {
            Ok(_) => PushOutcome::Delivered,
            Err(a2::Error::ResponseError(response)) => {
                let reason = response.error.as_ref().map(|e| &e.reason);
                if matches!(
                    reason,
                    Some(a2::ErrorReason::Unregistered | a2::ErrorReason::BadDeviceToken)
                ) {
                    warn!(
                        status = response.code,
                        ?reason,
                        address = %payload.address,
                        "APNs token gone; pruning subscription"
                    );
                    PushOutcome::Gone
                } else {
                    warn!(
                        status = response.code,
                        ?reason,
                        address = %payload.address,
                        "APNs rejected notification"
                    );
                    PushOutcome::TransientFailure
                }
            }
            Err(e) => {
                warn!(error = %e, address = %payload.address, "APNs send failed");
                PushOutcome::TransientFailure
            }
        }
    }
}

/// Run the push worker until the event bus closes. Spawned from `run()` like
/// the cleanup task.
pub async fn run(store: Arc<dyn Store>, events: EventBus, senders: Senders) {
    let mut rx = events.subscribe();
    info!("push worker started");
    loop {
        match rx.recv().await {
            Ok(event) => deliver(&store, &senders, &event).await,
            // Skipped events are fine: push is a nudge, clients reconcile
            // over REST exactly as SSE consumers do.
            Err(RecvError::Lagged(skipped)) => {
                warn!(skipped, "push worker lagged behind the event bus");
            }
            Err(RecvError::Closed) => break,
        }
    }
}

/// Headers Apple requires on token-authenticated HTTP/2 alerts. Omitting
/// `apns-push-type` is rejected with `400 MissingPushType` (a2 0.10 does not
/// even deserialize that reason, so the failure used to look like a bare 400).
fn apns_notification_options<'a>(
    topic: &'a str,
    collapse_id: &'a str,
) -> a2::NotificationOptions<'a> {
    a2::NotificationOptions {
        apns_topic: Some(topic),
        apns_push_type: Some(a2::PushType::Alert),
        apns_collapse_id: a2::CollapseId::new(collapse_id).ok(),
        ..Default::default()
    }
}

/// Send one event to every subscription of its mailbox and prune dead ones.
/// Each subscription is routed to the sender for its kind; kinds without a
/// configured sender are skipped. Concurrency is naturally bounded by the
/// per-mailbox subscription cap.
pub async fn deliver(store: &Arc<dyn Store>, senders: &Senders, event: &MailEvent) {
    let subscriptions = match store.list_subscriptions(&event.address).await {
        Ok(subs) => subs,
        Err(e) => {
            warn!(error = %e, address = %event.address, "failed to load push subscriptions");
            return;
        }
    };
    if subscriptions.is_empty() {
        debug!(address = %event.address, "no push subscriptions; skipping");
        return;
    }

    let payload = PushPayload {
        address: &event.address,
        id: event.id,
        from: &event.mail_from,
        subject: event.subject.as_deref(),
        code: event.code.as_deref(),
    };

    let results = futures::future::join_all(subscriptions.iter().filter_map(|sub| {
        let sender = match senders.for_kind(sub.kind) {
            Some(s) => s,
            None => {
                debug!(kind = sub.kind.as_str(), endpoint = %sub.endpoint,
                       "skipping subscription: kind not configured");
                return None;
            }
        };
        let payload = &payload;
        Some(async move { (sub, sender.send(sub, payload).await) })
    }))
    .await;

    for (sub, outcome) in results {
        info!(
            address = %event.address,
            kind = sub.kind.as_str(),
            ?outcome,
            "push send"
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn payload<'a>(
        subject: Option<&'a str>,
        code: Option<&'a str>,
        from: &'a str,
    ) -> PushPayload<'a> {
        PushPayload {
            address: "inbox@example.com",
            id: uuid::Uuid::nil(),
            from,
            subject,
            code,
        }
    }

    #[test]
    fn alert_leads_with_the_code_when_present() {
        let (title, body) =
            payload(Some("Verify your account"), Some("483920"), "noreply@a.com").alert();
        assert_eq!(title, "Verify your account");
        assert_eq!(body, "Code 483920 — noreply@a.com");
    }

    #[test]
    fn alert_falls_back_to_sender_without_code() {
        let (title, body) = payload(Some("Hello"), None, "friend@b.com").alert();
        assert_eq!(title, "Hello");
        assert_eq!(body, "From friend@b.com");
    }

    #[test]
    fn alert_handles_missing_or_blank_subject() {
        let (title, _) = payload(None, None, "x@y.z").alert();
        assert_eq!(title, "New mail");
        let (title, _) = payload(Some("   "), None, "x@y.z").alert();
        assert_eq!(title, "New mail");
    }

    #[test]
    fn apns_options_declare_alert_push_type_and_topic() {
        let id = "7b1e9f6a-6e0f-4bb0-a7d1-555555555555";
        let opts = apns_notification_options("com.scytheralpha.anonymail", id);
        assert_eq!(opts.apns_push_type, Some(a2::PushType::Alert));
        assert_eq!(opts.apns_topic, Some("com.scytheralpha.anonymail"));
        assert_eq!(
            opts.apns_collapse_id.as_ref().map(|c| c.value),
            Some(id),
            "collapse id groups retries of the same message"
        );
    }
}
