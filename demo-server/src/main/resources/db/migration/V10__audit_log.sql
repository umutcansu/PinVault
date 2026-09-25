-- Who changed what, when. Append-only: nothing in the server updates or
-- deletes these rows (unlike pin_history, which is trimmed to 100 rows and
-- wiped with its Config API).
--
-- Tamper evidence: every row stores the SHA-256 of the previous row's hash
-- plus its own fields (see AuditLogStore.chainHash). Editing or deleting a
-- row breaks the chain from that row on; GET /api/v1/audit-log/verify finds
-- the first broken link. Someone with write access to the database can
-- rewrite the whole chain, which is why security events are also pushed out
-- to a webhook (NOTIFY_WEBHOOK_URL) as they happen.
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    config_api_id TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    source_ip     TEXT NOT NULL DEFAULT '',
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);

-- Append-only at the database level too: the server never updates or deletes
-- audit rows, and these triggers make any code path (or console session)
-- that tries fail instead of silently rewriting history.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
