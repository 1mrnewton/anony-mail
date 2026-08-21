-- U3: read/unread state. INTEGER because SQLite has no BOOLEAN type;
-- sqlx maps Rust bool <-> 0/1.
ALTER TABLE messages ADD COLUMN seen INTEGER NOT NULL DEFAULT 0;
