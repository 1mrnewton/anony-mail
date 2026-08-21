//! Push worker behavior (docs/06) against a mock sender: a send fires per
//! subscription on new mail, payloads carry the event data, and endpoints
//! answering 404/410 are pruned.

use std::sync::{Arc, Mutex};

use anony_mail::events::MailEvent;
use anony_mail::model::PushSubscription;
use anony_mail::push::{PushOutcome, PushSender, deliver};
use anony_mail::store::{MemoryStore, Store};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Records every send and answers with a per-endpoint scripted outcome.
struct MockSender {
    sends: Mutex<Vec<(String, Vec<u8>)>>,
    gone_endpoints: Vec<String>,
}

impl MockSender {
    fn new(gone_endpoints: &[&str]) -> Self {
        Self {
            sends: Mutex::new(Vec::new()),
            gone_endpoints: gone_endpoints.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[async_trait]
impl PushSender for MockSender {
    async fn send(&self, subscription: &PushSubscription, payload: &[u8]) -> PushOutcome {
        self.sends
            .lock()
            .unwrap()
            .push((subscription.endpoint.clone(), payload.to_vec()));
        if self.gone_endpoints.contains(&subscription.endpoint) {
            PushOutcome::Gone
        } else {
            PushOutcome::Delivered
        }
    }
}

fn event_for(address: &str) -> MailEvent {
    MailEvent {
        address: address.to_string(),
        id: Uuid::new_v4(),
        mail_from: "sender@remote.test".to_string(),
        subject: Some("Your verification code".to_string()),
        received_at: Utc::now(),
        has_attachments: false,
        code: Some("483920".to_string()),
    }
}

#[tokio::test]
async fn delivers_to_every_subscription_with_minimal_payload() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let addr = "inbox@example.com";
    store
        .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
        .await
        .unwrap();
    store
        .add_subscription(addr, "https://push.example/a", "k1", "a1", 0)
        .await
        .unwrap();
    store
        .add_subscription(addr, "https://push.example/b", "k2", "a2", 0)
        .await
        .unwrap();

    let sender = Arc::new(MockSender::new(&[]));
    let event = event_for(addr);
    deliver(&store, &(sender.clone() as Arc<dyn PushSender>), &event).await;

    let sends = sender.sends.lock().unwrap();
    assert_eq!(sends.len(), 2, "one send per subscription");

    let payload: serde_json::Value = serde_json::from_slice(&sends[0].1).unwrap();
    assert_eq!(payload["address"], addr);
    assert_eq!(payload["id"], event.id.to_string());
    assert_eq!(payload["from"], "sender@remote.test");
    assert_eq!(payload["subject"], "Your verification code");
    assert_eq!(payload["code"], "483920", "extracted OTP rides along");
    assert!(
        payload.get("text_body").is_none() && payload.get("html_body").is_none(),
        "payload must stay minimal"
    );
}

#[tokio::test]
async fn gone_endpoints_are_pruned_others_survive() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let addr = "inbox@example.com";
    store
        .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
        .await
        .unwrap();
    store
        .add_subscription(addr, "https://push.example/dead", "k1", "a1", 0)
        .await
        .unwrap();
    store
        .add_subscription(addr, "https://push.example/alive", "k2", "a2", 0)
        .await
        .unwrap();

    let sender = Arc::new(MockSender::new(&["https://push.example/dead"]));
    deliver(
        &store,
        &(sender.clone() as Arc<dyn PushSender>),
        &event_for(addr),
    )
    .await;

    let remaining = store.list_subscriptions(addr).await.unwrap();
    assert_eq!(remaining.len(), 1, "410 endpoint must be pruned");
    assert_eq!(remaining[0].endpoint, "https://push.example/alive");

    // Next event only reaches the survivor.
    sender.sends.lock().unwrap().clear();
    deliver(
        &store,
        &(sender.clone() as Arc<dyn PushSender>),
        &event_for(addr),
    )
    .await;
    let sends = sender.sends.lock().unwrap();
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].0, "https://push.example/alive");
}

#[tokio::test]
async fn no_subscriptions_means_no_sends() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let addr = "empty@example.com";
    store
        .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
        .await
        .unwrap();

    let sender = Arc::new(MockSender::new(&[]));
    deliver(
        &store,
        &(sender.clone() as Arc<dyn PushSender>),
        &event_for(addr),
    )
    .await;
    assert!(sender.sends.lock().unwrap().is_empty());
}
