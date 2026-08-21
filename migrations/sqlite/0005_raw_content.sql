-- U2: optional retention of the original RFC 5322 bytes (.eml download).
-- NULL when STORE_RAW_MESSAGE was off at delivery time.
ALTER TABLE messages ADD COLUMN raw_content BLOB;
