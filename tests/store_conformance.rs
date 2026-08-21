//! Cross-backend `Store` conformance suite (U4).
//!
//! Every test runs against **all** locally testable backends — `MemoryStore`
//! and a real temp-file `SqliteStore` — so behavioral contracts (duplicate
//! handling, ordering, cascade, purge) cannot silently diverge between them.
//! The Postgres store shares its SQL shape with SQLite and is exercised in
//! deployments; it needs a live server, so it is not part of this suite.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anony_mail::api::is_unique_violation;
use anony_mail::model::{NewAttachment, NewMessage};
use anony_mail::store::{MailboxQuotas, MemoryStore, SqliteStore, Store, SubscriptionLimit};
use chrono::{Duration, Utc};

fn temp_db_path() -> PathBuf {
    // Tests start concurrently, so a timestamp alone can collide; the counter
    // makes each path unique within the process.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "anony-mail-conformance-{}-{seq}-{nanos}.db",
        std::process::id()
    ))
}

/// A store under test; removes any on-disk artifacts when dropped.
struct TestStore {
    name: &'static str,
    store: Arc<dyn Store>,
    db_path: Option<PathBuf>,
}

impl Drop for TestStore {
    fn drop(&mut self) {
        if let Some(path) = &self.db_path {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        }
    }
}

async fn all_stores() -> Vec<TestStore> {
    all_stores_with_quotas(MailboxQuotas::UNLIMITED).await
}

async fn all_stores_with_quotas(quotas: MailboxQuotas) -> Vec<TestStore> {
    let sqlite_path = temp_db_path();
    let sqlite = SqliteStore::connect(sqlite_path.to_str().unwrap())
        .await
        .expect("open sqlite store")
        .with_quotas(quotas);
    vec![
        TestStore {
            name: "memory",
            store: Arc::new(MemoryStore::new().with_quotas(quotas)),
            db_path: None,
        },
        TestStore {
            name: "sqlite",
            store: Arc::new(sqlite),
            db_path: Some(sqlite_path),
        },
    ]
}

fn sample_message(subject: &str) -> NewMessage {
    NewMessage {
        mail_from: "sender@somewhere.test".to_string(),
        subject: Some(subject.to_string()),
        message_date: Some(Utc::now()),
        text_body: Some(format!("body of {subject}")),
        html_body: None,
        raw_size: 42,
        raw_content: None,
        attachments: vec![],
    }
}

#[tokio::test]
async fn mailbox_lifecycle_create_get_extend_delete() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        let expires = Utc::now() + Duration::hours(1);

        let created = store
            .create_mailbox(addr, "example.com", expires, None)
            .await
            .unwrap_or_else(|e| panic!("[{}] create failed: {e}", ts.name));
        assert_eq!(created.address, addr, "[{}]", ts.name);
        assert!(
            store.mailbox_is_active(addr, Utc::now()).await.unwrap(),
            "[{}] fresh mailbox must be active",
            ts.name
        );

        let fetched = store.get_mailbox(addr).await.unwrap();
        assert!(fetched.is_some(), "[{}] get after create", ts.name);

        let later = Utc::now() + Duration::hours(2);
        let extended = store.extend_mailbox(addr, later).await.unwrap();
        assert!(extended.is_some(), "[{}] extend existing", ts.name);
        // Compare with tolerance: SQLite round-trips through ISO-8601 text.
        let got = extended.unwrap().expires_at;
        assert!(
            (got - later).num_seconds().abs() < 1,
            "[{}] expiry should be pushed back",
            ts.name
        );

        assert!(
            store
                .extend_mailbox("ghost@example.com", later)
                .await
                .unwrap()
                .is_none(),
            "[{}] extend missing mailbox is None",
            ts.name
        );

        assert!(store.delete_mailbox(addr).await.unwrap(), "[{}]", ts.name);
        assert!(
            !store.delete_mailbox(addr).await.unwrap(),
            "[{}] double delete is false",
            ts.name
        );
        assert!(
            store.get_mailbox(addr).await.unwrap().is_none(),
            "[{}] gone after delete",
            ts.name
        );
    }
}

/// Regression for B1: duplicate creation must surface as a recognizable unique
/// violation on every backend (SQLite reports 1555/2067, not the Postgres
/// SQLSTATE; the memory store raises a typed marker) so the API can map it to
/// `409 Conflict` instead of `500`.
#[tokio::test]
async fn duplicate_mailbox_is_a_unique_violation() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "taken@example.com";
        let expires = Utc::now() + Duration::hours(1);

        store
            .create_mailbox(addr, "example.com", expires, None)
            .await
            .unwrap();
        let err = store
            .create_mailbox(addr, "example.com", expires, None)
            .await
            .err()
            .unwrap_or_else(|| panic!("[{}] second create of the same address must fail", ts.name));
        assert!(
            is_unique_violation(&err),
            "[{}] duplicate error not recognized as unique violation: {err}",
            ts.name
        );
    }
}

#[tokio::test]
async fn message_round_trip_and_cascade_on_mailbox_delete() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        let mut msg = sample_message("hello");
        msg.attachments.push(NewAttachment {
            filename: Some("a.txt".to_string()),
            content_type: "text/plain".to_string(),
            content: b"file-bytes".to_vec(),
        });
        let stored = store.save_message(addr, msg).await.unwrap();
        assert_eq!(stored.attachments.len(), 1, "[{}]", ts.name);

        let list = store.list_messages(addr, 0, None).await.unwrap();
        assert_eq!(list.len(), 1, "[{}]", ts.name);
        assert_eq!(list[0].id, stored.id, "[{}]", ts.name);
        assert!(list[0].has_attachments, "[{}]", ts.name);

        let fetched = store
            .get_message(addr, stored.id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("[{}] message must exist", ts.name));
        assert_eq!(fetched.subject.as_deref(), Some("hello"), "[{}]", ts.name);
        assert_eq!(fetched.attachments.len(), 1, "[{}]", ts.name);

        let att_id = fetched.attachments[0].id;
        let att = store
            .get_attachment(addr, stored.id, att_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("[{}] attachment must exist", ts.name));
        assert_eq!(att.content, b"file-bytes", "[{}]", ts.name);
        assert_eq!(att.content_type, "text/plain", "[{}]", ts.name);

        // Scoping: another mailbox must not see this message.
        store
            .create_mailbox(
                "other@example.com",
                "example.com",
                Utc::now() + Duration::hours(1),
                None,
            )
            .await
            .unwrap();
        assert!(
            store
                .get_message("other@example.com", stored.id)
                .await
                .unwrap()
                .is_none(),
            "[{}] messages are scoped to their mailbox",
            ts.name
        );

        // Deleting the mailbox must cascade to messages + attachments (for
        // SQLite this relies on `PRAGMA foreign_keys = ON`).
        assert!(store.delete_mailbox(addr).await.unwrap(), "[{}]", ts.name);
        assert!(
            store.get_message(addr, stored.id).await.unwrap().is_none(),
            "[{}] cascade removes messages",
            ts.name
        );
        assert!(
            store.list_messages(addr, 0, None).await.unwrap().is_empty(),
            "[{}]",
            ts.name
        );
    }
}

#[tokio::test]
async fn delete_single_message() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();
        let stored = store
            .save_message(addr, sample_message("bye"))
            .await
            .unwrap();

        // Wrong mailbox must not delete it.
        assert!(
            !store
                .delete_message("other@example.com", stored.id)
                .await
                .unwrap(),
            "[{}] delete is mailbox-scoped",
            ts.name
        );
        assert!(
            store.delete_message(addr, stored.id).await.unwrap(),
            "[{}]",
            ts.name
        );
        assert!(
            !store.delete_message(addr, stored.id).await.unwrap(),
            "[{}] double delete is false",
            ts.name
        );
    }
}

#[tokio::test]
async fn purge_removes_only_expired_mailboxes() {
    for ts in all_stores().await {
        let store = &ts.store;
        store
            .create_mailbox(
                "old@example.com",
                "example.com",
                Utc::now() - Duration::minutes(5),
                None,
            )
            .await
            .unwrap();
        store
            .create_mailbox(
                "fresh@example.com",
                "example.com",
                Utc::now() + Duration::hours(1),
                None,
            )
            .await
            .unwrap();
        store
            .save_message("old@example.com", sample_message("stale"))
            .await
            .unwrap();

        let purged = store.purge_expired(Utc::now()).await.unwrap();
        assert_eq!(purged, 1, "[{}]", ts.name);
        assert!(
            store
                .get_mailbox("old@example.com")
                .await
                .unwrap()
                .is_none(),
            "[{}]",
            ts.name
        );
        assert!(
            store
                .get_mailbox("fresh@example.com")
                .await
                .unwrap()
                .is_some(),
            "[{}]",
            ts.name
        );
        assert!(
            store
                .list_messages("old@example.com", 0, None)
                .await
                .unwrap()
                .is_empty(),
            "[{}] purge cascades to messages",
            ts.name
        );
    }
}

/// A2: the owner-token hash round-trips through create/get/extend and can be
/// rotated; rotation on a missing mailbox reports false.
#[tokio::test]
async fn owner_token_hash_roundtrip_and_rotate() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        let expires = Utc::now() + Duration::hours(1);

        let created = store
            .create_mailbox(addr, "example.com", expires, Some("hash-v1"))
            .await
            .unwrap();
        assert_eq!(
            created.owner_token_hash.as_deref(),
            Some("hash-v1"),
            "[{}]",
            ts.name
        );

        let fetched = store.get_mailbox(addr).await.unwrap().unwrap();
        assert_eq!(fetched.owner_token_hash.as_deref(), Some("hash-v1"));

        // Extend must not touch the hash (token stable across extend).
        let extended = store
            .extend_mailbox(addr, expires + Duration::hours(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            extended.owner_token_hash.as_deref(),
            Some("hash-v1"),
            "[{}] extend must preserve the token hash",
            ts.name
        );

        assert!(store.rotate_owner_token(addr, "hash-v2").await.unwrap());
        let rotated = store.get_mailbox(addr).await.unwrap().unwrap();
        assert_eq!(rotated.owner_token_hash.as_deref(), Some("hash-v2"));

        assert!(
            !store
                .rotate_owner_token("ghost@example.com", "x")
                .await
                .unwrap(),
            "[{}] rotating a missing mailbox must report false",
            ts.name
        );
    }
}

/// Push (docs/06): subscription CRUD — upsert semantics, per-mailbox cap, and
/// cascade when the mailbox goes away.
#[tokio::test]
async fn push_subscription_crud_cap_and_cascade() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        // Register two endpoints (cap = 2).
        let s1 = store
            .add_subscription(addr, "https://push.example/ep1", "key1", "auth1", 2)
            .await
            .unwrap();
        store
            .add_subscription(addr, "https://push.example/ep2", "key2", "auth2", 2)
            .await
            .unwrap();

        // Same endpoint again: upsert (keys refreshed, same logical sub, no
        // cap consumption).
        let s1b = store
            .add_subscription(addr, "https://push.example/ep1", "key1-new", "auth1-new", 2)
            .await
            .unwrap();
        assert_eq!(s1.id, s1b.id, "[{}] upsert must keep identity", ts.name);
        assert_eq!(s1b.p256dh, "key1-new", "[{}]", ts.name);

        // A third distinct endpoint busts the cap with the typed error.
        let err = store
            .add_subscription(addr, "https://push.example/ep3", "key3", "auth3", 2)
            .await
            .expect_err("cap must be enforced");
        assert!(
            err.downcast_ref::<SubscriptionLimit>().is_some(),
            "[{}] expected SubscriptionLimit, got: {err}",
            ts.name
        );

        let listed = store.list_subscriptions(addr).await.unwrap();
        assert_eq!(listed.len(), 2, "[{}]", ts.name);

        // Unsubscribe one; double-delete reports false.
        assert!(
            store
                .delete_subscription(addr, "https://push.example/ep2")
                .await
                .unwrap()
        );
        assert!(
            !store
                .delete_subscription(addr, "https://push.example/ep2")
                .await
                .unwrap()
        );

        // Deleting the mailbox cascades away the remaining subscription.
        store.delete_mailbox(addr).await.unwrap();
        let after = store.list_subscriptions(addr).await.unwrap();
        assert!(after.is_empty(), "[{}] cascade must clear subs", ts.name);
    }
}

/// Push: purging an expired mailbox also removes its subscriptions.
#[tokio::test]
async fn purge_removes_push_subscriptions() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "doomed@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() - Duration::minutes(1), None)
            .await
            .unwrap();
        store
            .add_subscription(addr, "https://push.example/ep", "k", "a", 0)
            .await
            .unwrap();

        store.purge_expired(Utc::now()).await.unwrap();
        assert!(
            store.list_subscriptions(addr).await.unwrap().is_empty(),
            "[{}] purge must remove subscriptions",
            ts.name
        );
    }
}

/// A4: the message-count quota keeps only the newest N messages.
#[tokio::test]
async fn message_count_quota_drops_oldest() {
    let quotas = MailboxQuotas {
        max_messages: 2,
        max_bytes: 0,
    };
    for ts in all_stores_with_quotas(quotas).await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        for i in 0..4 {
            store
                .save_message(addr, sample_message(&format!("msg-{i}")))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let list = store.list_messages(addr, 0, None).await.unwrap();
        assert_eq!(list.len(), 2, "[{}] quota keeps only 2", ts.name);
        assert_eq!(list[0].subject.as_deref(), Some("msg-3"), "[{}]", ts.name);
        assert_eq!(list[1].subject.as_deref(), Some("msg-2"), "[{}]", ts.name);
    }
}

/// A4: the byte quota drops oldest messages once the running total exceeds the
/// cap, but never the just-saved message.
#[tokio::test]
async fn mailbox_byte_quota_drops_oldest_but_keeps_newest() {
    let quotas = MailboxQuotas {
        max_messages: 0,
        max_bytes: 100,
    };
    for ts in all_stores_with_quotas(quotas).await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        let sized = |subject: &str, raw_size: i32| {
            let mut m = sample_message(subject);
            m.raw_size = raw_size;
            m
        };

        // 40 + 40 fits; +40 more exceeds 100 => oldest goes.
        store.save_message(addr, sized("a", 40)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        store.save_message(addr, sized("b", 40)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        store.save_message(addr, sized("c", 40)).await.unwrap();

        let list = store.list_messages(addr, 0, None).await.unwrap();
        let subjects: Vec<_> = list.iter().filter_map(|m| m.subject.as_deref()).collect();
        assert_eq!(subjects, ["c", "b"], "[{}] oldest dropped", ts.name);

        // A message bigger than the whole budget still survives (alone).
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        store.save_message(addr, sized("huge", 500)).await.unwrap();
        let list = store.list_messages(addr, 0, None).await.unwrap();
        let subjects: Vec<_> = list.iter().filter_map(|m| m.subject.as_deref()).collect();
        assert_eq!(
            subjects,
            ["huge"],
            "[{}] oversized newest survives alone",
            ts.name
        );
    }
}

#[tokio::test]
async fn list_messages_newest_first() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "inbox@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        for i in 0..3 {
            store
                .save_message(addr, sample_message(&format!("msg-{i}")))
                .await
                .unwrap();
            // Ensure strictly increasing received_at even on coarse clocks.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let list = store.list_messages(addr, 0, None).await.unwrap();
        assert_eq!(list.len(), 3, "[{}]", ts.name);
        assert_eq!(list[0].subject.as_deref(), Some("msg-2"), "[{}]", ts.name);
        assert_eq!(list[2].subject.as_deref(), Some("msg-0"), "[{}]", ts.name);
        assert!(
            list.windows(2)
                .all(|w| w[0].received_at >= w[1].received_at),
            "[{}] newest first",
            ts.name
        );
    }
}

/// U2: raw bytes round-trip when provided, and stay absent when not.
#[tokio::test]
async fn raw_message_roundtrip() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "raw@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        let mut with_raw = sample_message("kept");
        with_raw.raw_content = Some(b"Subject: kept\r\n\r\noriginal bytes".to_vec());
        let kept = store.save_message(addr, with_raw).await.unwrap();
        let without_raw = store
            .save_message(addr, sample_message("dropped"))
            .await
            .unwrap();

        assert_eq!(
            store
                .get_raw_message(addr, kept.id)
                .await
                .unwrap()
                .as_deref(),
            Some(b"Subject: kept\r\n\r\noriginal bytes".as_slice()),
            "[{}] raw bytes round-trip",
            ts.name
        );
        assert!(
            store
                .get_raw_message(addr, without_raw.id)
                .await
                .unwrap()
                .is_none(),
            "[{}] no raw stored means None",
            ts.name
        );
        assert!(
            store
                .get_raw_message(addr, uuid::Uuid::new_v4())
                .await
                .unwrap()
                .is_none(),
            "[{}] missing message means None",
            ts.name
        );
    }
}

/// P5: a healthy store answers the readiness ping.
#[tokio::test]
async fn ping_succeeds_on_healthy_store() {
    for ts in all_stores().await {
        ts.store
            .ping()
            .await
            .unwrap_or_else(|e| panic!("[{}] ping failed: {e}", ts.name));
    }
}

/// U3: messages start unseen; `mark_seen` flips the flag idempotently and is
/// visible in both summaries and full messages; missing ids report false.
#[tokio::test]
async fn mark_seen_roundtrip() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "seen@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();
        let saved = store
            .save_message(addr, sample_message("unread"))
            .await
            .unwrap();
        assert!(!saved.seen, "[{}] fresh message starts unseen", ts.name);

        let list = store.list_messages(addr, 0, None).await.unwrap();
        assert!(!list[0].seen, "[{}] summary starts unseen", ts.name);

        assert!(
            store.mark_seen(addr, saved.id).await.unwrap(),
            "[{}] mark existing",
            ts.name
        );
        // Idempotent: marking again still reports the message exists.
        assert!(
            store.mark_seen(addr, saved.id).await.unwrap(),
            "[{}] mark twice",
            ts.name
        );

        let list = store.list_messages(addr, 0, None).await.unwrap();
        assert!(list[0].seen, "[{}] summary shows seen", ts.name);
        let full = store.get_message(addr, saved.id).await.unwrap().unwrap();
        assert!(full.seen, "[{}] full message shows seen", ts.name);

        assert!(
            !store.mark_seen(addr, uuid::Uuid::new_v4()).await.unwrap(),
            "[{}] missing message is false",
            ts.name
        );
        assert!(
            !store
                .mark_seen("ghost@example.com", saved.id)
                .await
                .unwrap(),
            "[{}] wrong mailbox is false",
            ts.name
        );
    }
}

/// U3: clear-inbox removes every message (and their attachments) but leaves
/// the mailbox itself alive.
#[tokio::test]
async fn delete_all_messages_clears_inbox_keeps_mailbox() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "clear@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        let mut with_attachment = sample_message("with-attachment");
        with_attachment.attachments.push(NewAttachment {
            filename: Some("a.txt".to_string()),
            content_type: "text/plain".to_string(),
            content: b"hello".to_vec(),
        });
        let saved = store.save_message(addr, with_attachment).await.unwrap();
        let att_id = saved.attachments[0].id;
        store
            .save_message(addr, sample_message("plain"))
            .await
            .unwrap();

        assert_eq!(
            store.delete_all_messages(addr).await.unwrap(),
            2,
            "[{}] clears both",
            ts.name
        );
        assert!(
            store.list_messages(addr, 0, None).await.unwrap().is_empty(),
            "[{}] inbox empty",
            ts.name
        );
        assert!(
            store
                .get_attachment(addr, saved.id, att_id)
                .await
                .unwrap()
                .is_none(),
            "[{}] attachments cascade",
            ts.name
        );
        assert!(
            store.get_mailbox(addr).await.unwrap().is_some(),
            "[{}] mailbox survives",
            ts.name
        );
        assert_eq!(
            store.delete_all_messages(addr).await.unwrap(),
            0,
            "[{}] second clear is zero",
            ts.name
        );
    }
}

/// P3: `limit` caps the page; `since` returns only strictly-newer messages in
/// the `(received_at, id)` keyset order; a vanished cursor falls back to the
/// newest page. Assertions compare against the store's own full listing, so
/// they hold even when timestamps collide and the id tiebreak (P4) decides.
#[tokio::test]
async fn pagination_limit_and_since_cursor() {
    for ts in all_stores().await {
        let store = &ts.store;
        let addr = "page@example.com";
        store
            .create_mailbox(addr, "example.com", Utc::now() + Duration::hours(1), None)
            .await
            .unwrap();

        for i in 0..5 {
            store
                .save_message(addr, sample_message(&format!("msg-{i}")))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let full = store.list_messages(addr, 0, None).await.unwrap();
        assert_eq!(full.len(), 5, "[{}]", ts.name);
        let full_ids: Vec<_> = full.iter().map(|m| m.id).collect();

        // limit caps from the newest end.
        let page = store.list_messages(addr, 2, None).await.unwrap();
        let page_ids: Vec<_> = page.iter().map(|m| m.id).collect();
        assert_eq!(page_ids, full_ids[..2], "[{}] limit=2", ts.name);

        // since=third-newest returns exactly the two newer ones.
        let newer = store
            .list_messages(addr, 0, Some(full_ids[2]))
            .await
            .unwrap();
        let newer_ids: Vec<_> = newer.iter().map(|m| m.id).collect();
        assert_eq!(newer_ids, full_ids[..2], "[{}] since cursor", ts.name);

        // since=newest returns nothing new.
        assert!(
            store
                .list_messages(addr, 0, Some(full_ids[0]))
                .await
                .unwrap()
                .is_empty(),
            "[{}] since newest is empty",
            ts.name
        );

        // limit + since combine (newest end of the newer set).
        let one = store
            .list_messages(addr, 1, Some(full_ids[3]))
            .await
            .unwrap();
        assert_eq!(one.len(), 1, "[{}]", ts.name);
        assert_eq!(one[0].id, full_ids[0], "[{}] limit+since", ts.name);

        // A cursor that no longer exists (pruned/bogus) is ignored.
        let ghost = store
            .list_messages(addr, 0, Some(uuid::Uuid::new_v4()))
            .await
            .unwrap();
        assert_eq!(
            ghost.len(),
            5,
            "[{}] vanished cursor = newest page",
            ts.name
        );
    }
}
