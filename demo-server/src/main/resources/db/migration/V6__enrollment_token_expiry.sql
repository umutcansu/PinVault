-- audit M-1: enrollment tokens previously never expired and were only 48 bits.
-- Add an expiry column. Legacy rows (created before this migration) get NULL
-- and are treated as non-expiring for backward compatibility; every token
-- created from now on is stamped with expires_at and rejected by validate()
-- once it is past. Token randomness/length is hardened in EnrollmentTokenStore.
ALTER TABLE enrollment_tokens ADD COLUMN expires_at TEXT;
