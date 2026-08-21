-- Owner tokens (A2, docs/08): SHA-256 hex of the bearer token, never the raw
-- token. Nullable so pre-existing mailboxes keep working; a NULL hash simply
-- cannot pass gated operations and ages out on its normal TTL.
ALTER TABLE mailboxes ADD COLUMN owner_token_hash TEXT;
