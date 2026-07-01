-- Disposable inboxes. The address is the natural primary key.
CREATE TABLE mailboxes (
    address     TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

-- Supports the cleanup task's "expired on or before now" scan.
CREATE INDEX idx_mailboxes_expires_at ON mailboxes (expires_at);

CREATE TABLE messages (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_address  TEXT NOT NULL REFERENCES mailboxes (address) ON DELETE CASCADE,
    mail_from        TEXT NOT NULL,
    subject          TEXT,
    message_date     TIMESTAMPTZ,
    text_body        TEXT,
    html_body        TEXT,
    raw_size         INTEGER NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Supports listing a mailbox's messages newest-first.
CREATE INDEX idx_messages_mailbox ON messages (mailbox_address, received_at DESC);

CREATE TABLE attachments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id    UUID NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    filename      TEXT,
    content_type  TEXT NOT NULL,
    size          INTEGER NOT NULL,
    content       BYTEA NOT NULL
);

CREATE INDEX idx_attachments_message ON attachments (message_id);
