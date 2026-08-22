-- Custom sender domains (docs/11). A row is claimed via the API, proven by
-- DNS (TXT + MX), and once verified the SMTP listener accepts mail for it.
-- Mailboxes on the domain are ordinary `mailboxes` rows; deleting the domain
-- does not cascade — existing mailboxes live out their TTL.
CREATE TABLE custom_domains (
    domain            TEXT PRIMARY KEY,
    claim_token_hash  TEXT NOT NULL,
    txt_token         TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMPTZ NOT NULL,
    verified_at       TIMESTAMPTZ,
    last_checked_at   TIMESTAMPTZ
);

-- Supports the periodic re-verification scan.
CREATE INDEX idx_custom_domains_status ON custom_domains (status, last_checked_at);
