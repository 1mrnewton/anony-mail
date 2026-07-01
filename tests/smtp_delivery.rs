//! End-to-end test: drive a real SMTP conversation over a TCP socket against
//! the session handler and assert the message is retrievable via the `Store`.
//! Uses the in-memory store so no database is required.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use tempmail_backend::config::Config;
use tempmail_backend::events::EventBus;
use tempmail_backend::smtp::SmtpContext;
use tempmail_backend::store::{MemoryStore, Store};

fn test_config() -> Config {
    Config {
        smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
        api_bind_addr: "127.0.0.1:0".parse().unwrap(),
        domains: vec!["test.local".to_string()],
        database_url: String::new(),
        default_ttl: Duration::from_secs(3600),
        max_message_size: 1024 * 1024,
        max_recipients: 100,
        max_connections: 64,
        smtp_session_timeout: Duration::from_secs(10),
        per_ip_connections_per_min: 1000,
        cleanup_interval: Duration::from_secs(300),
        cors_allowed_origins: vec!["*".to_string()],
        smtp_hostname: "mx.test.local".to_string(),
        tls: None,
    }
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, line: &str) {
    w.write_all(line.as_bytes()).await.unwrap();
    w.write_all(b"\r\n").await.unwrap();
    w.flush().await.unwrap();
}

/// Read a (possibly multi-line) SMTP reply, returning the full text. The reply
/// ends at the first line whose 4th byte is a space (per RFC 5321).
async fn read_reply<R: AsyncBufRead + Unpin>(r: &mut R) -> String {
    let mut reply = String::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await.unwrap();
        assert!(n > 0, "server closed the connection unexpectedly");
        let is_last = line.as_bytes().get(3).map(|&b| b == b' ').unwrap_or(true);
        reply.push_str(&line);
        if is_last {
            break;
        }
    }
    reply
}

#[tokio::test]
async fn delivers_message_to_valid_recipient() {
    let config = Arc::new(test_config());
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);

    // A valid, active mailbox to receive the message.
    store
        .create_mailbox(
            "user@test.local",
            "test.local",
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    let ctx = SmtpContext {
        store: (store.clone() as Arc<dyn Store>),
        config,
        events: events.clone(),
        tls_acceptor: None,
    };

    // Subscribe before delivery so we can assert the SSE event fires.
    let mut event_rx = events.subscribe();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        tempmail_backend::smtp::session::handle(socket, peer, ctx)
            .await
            .unwrap();
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));

    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    // Unknown mailbox on our domain -> 550.
    send(&mut write_half, "RCPT TO:<nobody@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    // Domain we don't serve -> 550 (no relaying).
    send(&mut write_half, "RCPT TO:<user@notours.example>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    // Valid recipient -> 250.
    send(&mut write_half, "RCPT TO:<user@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));

    for line in [
        "From: Sender Person <sender@elsewhere.test>",
        "Subject: Integration test",
        "Content-Type: text/plain",
        "",
        "Hello inbound world!",
        ".",
    ] {
        send(&mut write_half, line).await;
    }
    assert!(read_reply(&mut reader).await.starts_with("250"));

    send(&mut write_half, "QUIT").await;
    assert!(read_reply(&mut reader).await.starts_with("221"));

    // The message must now be retrievable through the store.
    let summaries = store.list_messages("user@test.local").await.unwrap();
    assert_eq!(summaries.len(), 1, "expected exactly one delivered message");
    let summary = &summaries[0];
    assert_eq!(summary.subject.as_deref(), Some("Integration test"));

    let full = store
        .get_message("user@test.local", summary.id)
        .await
        .unwrap()
        .expect("message should exist");
    assert!(full.mail_from.contains("sender@elsewhere.test"));
    assert!(full.text_body.unwrap().contains("Hello inbound world!"));

    // And an SSE event should have been published for it.
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event should arrive promptly")
        .expect("event channel should deliver");
    assert_eq!(event.address, "user@test.local");
    assert_eq!(event.id, summary.id);

    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server task should finish after QUIT")
        .unwrap();
}

#[tokio::test]
async fn rejects_message_with_no_valid_recipients() {
    let config = Arc::new(test_config());
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);

    let ctx = SmtpContext {
        store: (store.clone() as Arc<dyn Store>),
        config,
        events,
        tls_acceptor: None,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        let _ = tempmail_backend::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "RCPT TO:<ghost@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    // DATA with no accepted recipients must be refused.
    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("554"));

    send(&mut write_half, "QUIT").await;
    assert!(read_reply(&mut reader).await.starts_with("221"));

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
