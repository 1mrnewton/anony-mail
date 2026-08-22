//! End-to-end test: drive a real SMTP conversation over a TCP socket against
//! the session handler and assert the message is retrievable via the `Store`.
//! Uses the in-memory store so no database is required.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use anony_mail::config::Config;
use anony_mail::events::EventBus;
use anony_mail::smtp::SmtpContext;
use anony_mail::store::{MemoryStore, Store};

fn test_config() -> Config {
    Config {
        smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
        api_bind_addr: "127.0.0.1:0".parse().unwrap(),
        domains: vec!["test.local".to_string()],
        database_url: String::new(),
        max_message_size: 1024 * 1024,
        max_recipients: 100,
        max_connections: 64,
        smtp_session_timeout: Duration::from_secs(10),
        per_ip_connections_per_min: 1000,
        smtp_hostname: "mx.test.local".to_string(),
        ..Config::default()
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
            // Ownerless is fine here; SMTP delivery ignores tokens.
            None,
            None,
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
        anony_mail::smtp::session::handle(socket, peer, ctx)
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
    let summaries = store
        .list_messages("user@test.local", 0, None)
        .await
        .unwrap();
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

/// U4: oversize DATA is refused with `552`, nothing is stored, and the
/// session stays usable for the next transaction.
#[tokio::test]
async fn oversize_data_rejected_with_552_and_not_stored() {
    let mut config = test_config();
    config.max_message_size = 512;
    let config = Arc::new(config);
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);
    store
        .create_mailbox(
            "user@test.local",
            "test.local",
            Utc::now() + chrono::Duration::hours(1),
            None,
            None,
        )
        .await
        .unwrap();

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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "RCPT TO:<user@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));

    send(&mut write_half, "Subject: big").await;
    send(&mut write_half, "").await;
    let filler = "x".repeat(100);
    for _ in 0..10 {
        send(&mut write_half, &filler).await;
    }
    send(&mut write_half, ".").await;
    let reply = read_reply(&mut reader).await;
    assert!(reply.starts_with("552"), "expected 552, got: {reply}");

    // The transaction was reset, not the connection: NOOP still answers.
    send(&mut write_half, "NOOP").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "QUIT").await;
    assert!(read_reply(&mut reader).await.starts_with("221"));

    assert!(
        store
            .list_messages("user@test.local", 0, None)
            .await
            .unwrap()
            .is_empty(),
        "oversize message must not be stored"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

/// U4: dot-stuffed lines (RFC 5321 §4.5.2) are unstuffed exactly once, and a
/// lone `..` line survives as `.` content instead of terminating DATA early.
#[tokio::test]
async fn dot_stuffed_lines_are_unstuffed_in_stored_body() {
    let config = Arc::new(test_config());
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);
    store
        .create_mailbox(
            "user@test.local",
            "test.local",
            Utc::now() + chrono::Duration::hours(1),
            None,
            None,
        )
        .await
        .unwrap();

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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "RCPT TO:<user@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));

    for line in [
        "Subject: dots",
        "Content-Type: text/plain",
        "",
        "..leading dot line",
        "..",
        "normal line",
        ".",
    ] {
        send(&mut write_half, line).await;
    }
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "QUIT").await;
    let _ = read_reply(&mut reader).await;

    let id = store
        .list_messages("user@test.local", 0, None)
        .await
        .unwrap()[0]
        .id;
    let body = store
        .get_message("user@test.local", id)
        .await
        .unwrap()
        .unwrap()
        .text_body
        .expect("text body");
    assert!(
        body.contains(".leading dot line"),
        "one leading dot must be stripped: {body:?}"
    );
    assert!(
        !body.contains("..leading dot line"),
        "stuffed dot must not survive: {body:?}"
    );
    assert!(
        body.contains("normal line"),
        "later lines still present: {body:?}"
    );
    // The lone `..` line unstuffs to a single-dot content line.
    assert!(
        body.lines().any(|l| l.trim_end() == "."),
        "`..` line must unstuff to `.`: {body:?}"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

/// U2: with `STORE_RAW_MESSAGE` on, the original bytes come back verbatim
/// (dot-unstuffed, CRLF line endings); by default nothing is retained.
#[tokio::test]
async fn raw_bytes_retained_only_when_enabled() {
    for enabled in [true, false] {
        let mut config = test_config();
        config.store_raw_message = enabled;
        let config = Arc::new(config);
        let store = Arc::new(MemoryStore::new());
        let events = EventBus::new(16);
        store
            .create_mailbox(
                "user@test.local",
                "test.local",
                Utc::now() + chrono::Duration::hours(1),
                None,
                None,
            )
            .await
            .unwrap();

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
            let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);

        assert!(read_reply(&mut reader).await.starts_with("220"));
        send(&mut write_half, "EHLO client.test").await;
        assert!(read_reply(&mut reader).await.starts_with("250"));
        send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
        assert!(read_reply(&mut reader).await.starts_with("250"));
        send(&mut write_half, "RCPT TO:<user@test.local>").await;
        assert!(read_reply(&mut reader).await.starts_with("250"));
        send(&mut write_half, "DATA").await;
        assert!(read_reply(&mut reader).await.starts_with("354"));
        for line in ["Subject: raw check", "", "body line", "."] {
            send(&mut write_half, line).await;
        }
        assert!(read_reply(&mut reader).await.starts_with("250"));
        send(&mut write_half, "QUIT").await;
        let _ = read_reply(&mut reader).await;

        let id = store
            .list_messages("user@test.local", 0, None)
            .await
            .unwrap()[0]
            .id;
        let raw = store.get_raw_message("user@test.local", id).await.unwrap();
        if enabled {
            let raw = raw.expect("raw bytes must be retained when enabled");
            let text = String::from_utf8(raw).unwrap();
            assert!(text.starts_with("Subject: raw check\r\n"));
            assert!(text.contains("\r\nbody line\r\n"));
            assert!(!text.contains("\r\n.\r\n"), "terminator must not be stored");
        } else {
            assert!(raw.is_none(), "raw bytes must not be retained by default");
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}

/// U1: `user+tag@` must deliver into `user@`'s mailbox.
#[tokio::test]
async fn plus_addressed_mail_lands_in_base_mailbox() {
    let config = Arc::new(test_config());
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);
    store
        .create_mailbox(
            "user@test.local",
            "test.local",
            Utc::now() + chrono::Duration::hours(1),
            None,
            None,
        )
        .await
        .unwrap();

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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "RCPT TO:<user+newsletter@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));
    for line in ["Subject: tagged", "", "hi", "."] {
        send(&mut write_half, line).await;
    }
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "QUIT").await;
    let _ = read_reply(&mut reader).await;

    let summaries = store
        .list_messages("user@test.local", 0, None)
        .await
        .unwrap();
    assert_eq!(summaries.len(), 1, "tagged mail must land in base mailbox");
    assert_eq!(summaries[0].subject.as_deref(), Some("tagged"));

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

/// U1 catch-all: unknown local parts get a mailbox auto-created — except
/// reserved ones, which must stay rejected.
#[tokio::test]
async fn catch_all_creates_mailboxes_but_refuses_reserved() {
    let mut config = test_config();
    config.catch_all_enabled = true;
    let config = Arc::new(config);
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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    // Unknown local part: accepted via catch-all.
    send(&mut write_half, "RCPT TO:<brand-new@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    // Reserved local part: still refused, even with catch-all on.
    send(&mut write_half, "RCPT TO:<admin@test.local>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));
    for line in ["Subject: caught", "", "hello", "."] {
        send(&mut write_half, line).await;
    }
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "QUIT").await;
    let _ = read_reply(&mut reader).await;

    // The catch-all mailbox exists and holds the message.
    let mb = store
        .get_mailbox("brand-new@test.local")
        .await
        .unwrap()
        .expect("catch-all mailbox must exist");
    assert!(mb.expires_at > Utc::now(), "fresh TTL");
    let summaries = store
        .list_messages("brand-new@test.local", 0, None)
        .await
        .unwrap();
    assert_eq!(summaries.len(), 1);

    // The reserved one must NOT have been conjured.
    assert!(
        store
            .get_mailbox("admin@test.local")
            .await
            .unwrap()
            .is_none(),
        "catch-all must never create reserved mailboxes"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
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

/// Custom domains (docs/11): RCPT accepts mail for a *verified* custom
/// domain's existing mailboxes only — no catch-all even when it is enabled
/// for the server's own domains, and unverified claims stay foreign.
#[tokio::test]
async fn custom_domain_recipients_gated_on_verification() {
    use anony_mail::model::CustomDomainStatus;

    let mut config = test_config();
    // Catch-all ON, to prove it never applies to custom domains.
    config.catch_all_enabled = true;
    let config = Arc::new(config);
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);

    // corp.example: verified claim with one explicitly created mailbox.
    let now = Utc::now();
    store
        .create_custom_domain("corp.example", "hash", "tok")
        .await
        .unwrap();
    store
        .record_custom_domain_check("corp.example", CustomDomainStatus::Verified, Some(now), now)
        .await
        .unwrap();
    store
        .create_mailbox(
            "jane@corp.example",
            "corp.example",
            now + chrono::Duration::hours(1),
            None,
            None,
        )
        .await
        .unwrap();
    // pending.example: claimed but never verified.
    store
        .create_custom_domain("pending.example", "hash2", "tok2")
        .await
        .unwrap();

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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    // Existing mailbox on a verified custom domain -> accepted.
    send(&mut write_half, "RCPT TO:<jane@corp.example>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));

    // Unknown local part on the custom domain -> refused (catch-all is on,
    // but must not conjure mailboxes on someone's own domain).
    send(&mut write_half, "RCPT TO:<stranger@corp.example>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    // Unverified claim -> treated as a foreign domain.
    send(&mut write_half, "RCPT TO:<jane@pending.example>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    send(&mut write_half, "DATA").await;
    assert!(read_reply(&mut reader).await.starts_with("354"));
    for line in [
        "From: Sender <sender@elsewhere.test>",
        "Subject: To a custom domain",
        "",
        "Hello custom domain!",
        ".",
    ] {
        send(&mut write_half, line).await;
    }
    assert!(read_reply(&mut reader).await.starts_with("250"));

    send(&mut write_half, "QUIT").await;
    assert!(read_reply(&mut reader).await.starts_with("221"));
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    let summaries = store
        .list_messages("jane@corp.example", 0, None)
        .await
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].subject.as_deref(), Some("To a custom domain"));
    // The catch-all must not have created the stranger mailbox.
    assert!(
        store
            .get_mailbox("stranger@corp.example")
            .await
            .unwrap()
            .is_none()
    );
}

/// With `CUSTOM_DOMAINS_ENABLED=false`, even a verified claim in the store
/// is ignored by RCPT.
#[tokio::test]
async fn custom_domains_disabled_rejects_verified_claims() {
    use anony_mail::model::CustomDomainStatus;

    let mut config = test_config();
    config.custom_domains_enabled = false;
    let config = Arc::new(config);
    let store = Arc::new(MemoryStore::new());
    let events = EventBus::new(16);

    let now = Utc::now();
    store
        .create_custom_domain("corp.example", "hash", "tok")
        .await
        .unwrap();
    store
        .record_custom_domain_check("corp.example", CustomDomainStatus::Verified, Some(now), now)
        .await
        .unwrap();
    store
        .create_mailbox(
            "jane@corp.example",
            "corp.example",
            now + chrono::Duration::hours(1),
            None,
            None,
        )
        .await
        .unwrap();

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
        let _ = anony_mail::smtp::session::handle(socket, peer, ctx).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    assert!(read_reply(&mut reader).await.starts_with("220"));
    send(&mut write_half, "EHLO client.test").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "MAIL FROM:<sender@elsewhere.test>").await;
    assert!(read_reply(&mut reader).await.starts_with("250"));
    send(&mut write_half, "RCPT TO:<jane@corp.example>").await;
    assert!(read_reply(&mut reader).await.starts_with("550"));

    send(&mut write_half, "QUIT").await;
    assert!(read_reply(&mut reader).await.starts_with("221"));
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
