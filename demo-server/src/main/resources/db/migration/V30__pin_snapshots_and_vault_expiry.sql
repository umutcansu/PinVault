-- Pin snapshots (2.9.0): the whole pin set of a Config API after every save,
-- so a published set can be brought back with one click. A restore is a NEW
-- version with the old pins (devices refuse version downgrades), never the
-- old version itself. Kept per scope (the newest 200); content_hash lets a
-- save that changed nothing skip the row.
CREATE TABLE IF NOT EXISTS pin_snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id  TEXT NOT NULL,
    taken_at       TEXT NOT NULL,
    actor          TEXT NOT NULL DEFAULT 'system',
    content_hash   TEXT NOT NULL,
    config_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pin_snapshots_scope ON pin_snapshots(config_api_id, id);

-- Vault files may carry a date they stop being valid (a licence, a model,
-- a certificate bundle): the expiry monitor warns ahead of it like it does
-- for host certificates. Null = no expiry.
ALTER TABLE vault_files ADD COLUMN expires_at TEXT;
