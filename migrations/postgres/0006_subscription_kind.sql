-- Push channel per subscription: 'webpush' (endpoint + encryption keys) or
-- 'apns' (endpoint column holds the APNs device token, key columns empty).
ALTER TABLE push_subscriptions ADD COLUMN kind TEXT NOT NULL DEFAULT 'webpush';
