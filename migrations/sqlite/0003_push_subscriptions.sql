-- Web Push subscriptions (docs/06). One row per device/browser registration,
-- cascaded off the mailbox so purge/delete removes them for free.
CREATE TABLE push_subscriptions (
    id               TEXT PRIMARY KEY,
    mailbox_address  TEXT NOT NULL REFERENCES mailboxes (address) ON DELETE CASCADE,
    endpoint         TEXT NOT NULL,
    p256dh           TEXT NOT NULL,
    auth             TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    UNIQUE (mailbox_address, endpoint)
);

CREATE INDEX idx_push_sub_mailbox ON push_subscriptions (mailbox_address);
