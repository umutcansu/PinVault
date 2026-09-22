-- audit N-8: enrollment tokens were stored in plaintext. The `token` column now
-- holds SHA-256(plaintext) as lowercase hex; the plaintext is shown exactly once,
-- at creation, the same way vault access tokens already work.
--
-- `token_prefix` keeps the first 8 characters so the admin list can still tell
-- rows apart without being a credential store.
ALTER TABLE enrollment_tokens ADD COLUMN token_prefix TEXT;

-- Every row that exists at migration time holds a PLAINTEXT token, and
-- validate() now only ever compares hashes — a plaintext row could never match
-- again. Mark them used rather than leaving dead rows that look pending in the
-- admin UI. Enrollment tokens are single-use and short-lived, so re-minting is
-- the intended migration path.
UPDATE enrollment_tokens SET used = 1 WHERE token_prefix IS NULL;
