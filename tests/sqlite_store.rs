//! Integration tests for the SQLite `Store` backend against a real (temp-file)
//! database, covering the round-trip of messages/attachments, foreign-key
//! cascade on mailbox deletion, and expiry purging.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anony_mail::model::{NewAttachment, NewMessage};
use anony_mail::store::{SqliteStore, Store};
use chrono::Utc;

fn temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("anony-mail-test-{}-{nanos}.db", std::process::id()))
}

/// Removes the database file plus any WAL/SHM sidecars.
fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

#[tokio::test]
async fn round_trips_messages_and_cascades_on_delete() {
    let path = temp_db_path();
    let store = SqliteStore::connect(path.to_str().unwrap())
        .await
        .expect("open sqlite store");

    let addr = "inbox@example.com";
    store
        .create_mailbox(addr, "example.com", Utc::now() + chrono::Duration::hours(1))
        .await
        .unwrap();
    assert!(store.mailbox_is_active(addr, Utc::now()).await.unwrap());

    let stored = store
        .save_message(
            addr,
            NewMessage {
                mail_from: "sender@somewhere.test".to_string(),
                subject: Some("hello".to_string()),
                message_date: Some(Utc::now()),
                text_body: Some("body text".to_string()),
                html_body: None,
                raw_size: 42,
                attachments: vec![NewAttachment {
                    filename: Some("a.txt".to_string()),
                    content_type: "text/plain".to_string(),
                    content: b"file-bytes".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(stored.attachments.len(), 1);

    let list = store.list_messages(addr).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, stored.id);
    assert!(list[0].has_attachments);

    let fetched = store
        .get_message(addr, stored.id)
        .await
        .unwrap()
        .expect("message exists");
    assert_eq!(fetched.subject.as_deref(), Some("hello"));
    assert_eq!(fetched.text_body.as_deref(), Some("body text"));
    assert_eq!(fetched.attachments.len(), 1);

    let att_id = fetched.attachments[0].id;
    let att = store
        .get_attachment(addr, stored.id, att_id)
        .await
        .unwrap()
        .expect("attachment exists");
    assert_eq!(att.content, b"file-bytes");
    assert_eq!(att.content_type, "text/plain");

    // Deleting the mailbox must cascade to messages + attachments, which relies
    // on `PRAGMA foreign_keys = ON` being set on the connection.
    assert!(store.delete_mailbox(addr).await.unwrap());
    assert!(store.get_message(addr, stored.id).await.unwrap().is_none());
    assert!(store.list_messages(addr).await.unwrap().is_empty());

    cleanup(&path);
}

#[tokio::test]
async fn purges_only_expired_mailboxes() {
    let path = temp_db_path();
    let store = SqliteStore::connect(path.to_str().unwrap())
        .await
        .expect("open sqlite store");

    store
        .create_mailbox(
            "old@example.com",
            "example.com",
            Utc::now() - chrono::Duration::minutes(5),
        )
        .await
        .unwrap();
    store
        .create_mailbox(
            "fresh@example.com",
            "example.com",
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    let purged = store.purge_expired(Utc::now()).await.unwrap();
    assert_eq!(purged, 1);
    assert!(
        store
            .get_mailbox("old@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_mailbox("fresh@example.com")
            .await
            .unwrap()
            .is_some()
    );

    cleanup(&path);
}
