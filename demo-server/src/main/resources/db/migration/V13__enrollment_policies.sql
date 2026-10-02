-- Enrollment policies: one code that many devices enroll with, within a
-- device limit and an end date, optionally only after an administrator
-- approves each device. The code itself is never stored, only its SHA-256.
CREATE TABLE IF NOT EXISTS enrollment_policies (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    code_hash        TEXT NOT NULL UNIQUE,
    code_prefix      TEXT NOT NULL,
    max_devices      INTEGER NOT NULL,
    -- Devices issued a certificate, plus approved ones not yet picked up.
    used_count       INTEGER NOT NULL DEFAULT 0,
    require_approval INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    created_by       TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL,
    stopped_at       TEXT
);

-- One row per device key that came with a policy code. The device is
-- recognised by its key (spki_sha256): it asks again with a CSR signed by
-- that key, never with a secret of its own.
-- status: pending | approved | rejected | issued
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id            TEXT PRIMARY KEY,
    policy_id     TEXT NOT NULL,
    client_id     TEXT NOT NULL UNIQUE,
    spki_sha256   TEXT NOT NULL,
    status        TEXT NOT NULL,
    config_api_id TEXT NOT NULL DEFAULT '',
    device_alias  TEXT,
    device_uid    TEXT,
    source_ip     TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    decided_at    TEXT,
    decided_by    TEXT,
    issued_at     TEXT,
    UNIQUE (policy_id, spki_sha256)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status ON enrollment_requests (status);
