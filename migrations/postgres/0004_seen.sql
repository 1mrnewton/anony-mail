-- U3: read/unread state.
ALTER TABLE messages ADD COLUMN seen BOOLEAN NOT NULL DEFAULT FALSE;
