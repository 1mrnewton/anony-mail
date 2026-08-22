-- App Attest device registry (docs/09). One row per attested hardware key;
-- assertions must present a strictly increasing counter. Rows idle longer
-- than the prune window are deleted by the cleanup task — devices simply
-- re-attest.
CREATE TABLE attested_devices (
    key_id        TEXT PRIMARY KEY,
    public_key    BYTEA NOT NULL,
    counter       BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL
);

-- Supports pruning idle devices.
CREATE INDEX idx_attested_devices_last_seen ON attested_devices (last_seen_at);

-- Per-device active-mailbox caps (docs/10 phase 2): mailboxes remember the
-- SHA-256 of the attested key id that created them. NULL for unattested
-- creates and SMTP catch-all.
ALTER TABLE mailboxes ADD COLUMN creator_device_hash TEXT;

-- Supports counting a device's live mailboxes at create time.
CREATE INDEX idx_mailboxes_creator_device ON mailboxes (creator_device_hash)
    WHERE creator_device_hash IS NOT NULL;
