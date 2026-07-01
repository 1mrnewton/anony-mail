-- SQLite schema. UUIDs are stored as TEXT and timestamps as ISO-8601 TEXT
-- (both generated in Rust, since SQLite has no native UUID/timestamp types).
-- ON DELETE CASCADE requires `PRAGMA foreign_keys = ON`, which the app sets on
-- every connection via SqliteConnectOptions::foreign_keys(true).

CREATE TABLE mailboxes (
    address     TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

-- Supports the cleanup task's "expired on or before now" scan.
CREATE INDEX idx_mailboxes_expires_at ON mailboxes (expires_at);

CREATE TABLE messages (
    id               TEXT PRIMARY KEY,
    mailbox_address  TEXT NOT NULL REFERENCES mailboxes (address) ON DELETE CASCADE,
    mail_from        TEXT NOT NULL,
    subject          TEXT,
    message_date     TEXT,
    text_body        TEXT,
    html_body        TEXT,
    raw_size         INTEGER NOT NULL,
    received_at      TEXT NOT NULL
);

-- Supports listing a mailbox's messages newest-first.
CREATE INDEX idx_messages_mailbox ON messages (mailbox_address, received_at DESC);

CREATE TABLE attachments (
    id            TEXT PRIMARY KEY,
    message_id    TEXT NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    filename      TEXT,
    content_type  TEXT NOT NULL,
    size          INTEGER NOT NULL,
    content       BLOB NOT NULL
);

CREATE INDEX idx_attachments_message ON attachments (message_id);
