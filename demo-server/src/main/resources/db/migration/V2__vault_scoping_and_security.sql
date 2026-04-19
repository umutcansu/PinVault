-- PinVault 2.0 — Multi-Config-API + Vault Scoping + Per-File Security
--
-- Problems addressed:
--   1. vault_files had no config_api_id → TLS and mTLS Config APIs shared one
--      global vault pool (privilege bypass).
--   2. Vault content stored plain — no at-rest or end-to-end encryption.
--   3. Vault download endpoint effectively public (no per-device/per-file auth).
--
-- Per user decision (plan: token-based granular access, blanket "enrolled_device"
-- policy omitted). Existing vault_files + vault_distributions are intentionally
-- dropped (fresh start per decision 2B in plan).

-- ── Config API: vault toggle ─────────────────────────────────────────────
ALTER TABLE config_apis ADD COLUMN vault_enabled INTEGER NOT NULL DEFAULT 1;

-- ── vault_files: scoping + per-file policy ───────────────────────────────
-- Access model: default 'token' (least-privilege). Admin issues a token per
-- (device, file). Blanket "all enrolled devices can read all files" is NOT a
-- valid policy — every file requires explicit grant.
DROP TABLE IF EXISTS vault_files;
CREATE TABLE vault_files (
    config_api_id  TEXT    NOT NULL,
    key            TEXT    NOT NULL,
    content        BLOB    NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    access_policy  TEXT    NOT NULL DEFAULT 'token',
                   -- public     : demo/test only (no auth)
                   -- api_key    : X-API-Key header (admin tooling)
                   -- token      : per-device token (default; least-privilege)
                   -- token_mtls : token + mTLS client cert (highest)
    encryption     TEXT    NOT NULL DEFAULT 'plain',
                   -- plain | at_rest | end_to_end
    updated_at     TEXT    NOT NULL,
    PRIMARY KEY (config_api_id, key),
    FOREIGN KEY (config_api_id) REFERENCES config_apis(id)
);

-- ── vault_distributions: scoping ─────────────────────────────────────────
DROP TABLE IF EXISTS vault_distributions;
CREATE TABLE vault_distributions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id        TEXT    NOT NULL,
    vault_key            TEXT    NOT NULL,
    version              INTEGER NOT NULL,
    device_id            TEXT    NOT NULL,
    device_manufacturer  TEXT,
    device_model         TEXT,
    enrollment_label     TEXT,
    status               TEXT    NOT NULL,
    timestamp            TEXT    NOT NULL,
    device_alias         TEXT
);

CREATE INDEX idx_vault_distributions_scope
    ON vault_distributions(config_api_id, vault_key);
CREATE INDEX idx_vault_distributions_device
    ON vault_distributions(config_api_id, device_id);

-- ── vault_file_tokens: per-device, per-file access tokens ────────────────
-- token_hash stores SHA-256 of the plaintext token (never stored plaintext).
-- UNIQUE(config_api_id, vault_key, device_id) enforces "one active token per
-- device+file"; reissuing replaces the previous row (handled in application).
CREATE TABLE vault_file_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id  TEXT    NOT NULL,
    vault_key      TEXT    NOT NULL,
    device_id      TEXT    NOT NULL,
    token_hash     TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0,
    UNIQUE(config_api_id, vault_key, device_id)
);

CREATE INDEX idx_vault_file_tokens_lookup
    ON vault_file_tokens(config_api_id, vault_key, device_id);

-- ── device_public_keys: RSA public keys for E2E encryption ───────────────
-- Each device registers its public key once per Config API (init time).
-- Server uses this key to wrap AES session keys in RSA-OAEP-SHA256 for
-- end_to_end encrypted files. Device decrypts with its Android-Keystore-held
-- private key.
CREATE TABLE device_public_keys (
    device_id       TEXT NOT NULL,
    config_api_id   TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'RSA-OAEP-SHA256',
    registered_at   TEXT NOT NULL,
    PRIMARY KEY (device_id, config_api_id)
);

-- ── device_host_acl: per-device pin scoping ──────────────────────────────
-- When a device fetches /api/v1/certificate-config, server intersects the
-- client's requested hosts (from wantPinsFor DSL) with the device's allowed
-- hosts. Only the intersection is returned; unauthorized hosts are logged.
CREATE TABLE device_host_acl (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id  TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    hostname       TEXT NOT NULL,
    granted_at     TEXT NOT NULL,
    UNIQUE(config_api_id, device_id, hostname)
);

CREATE INDEX idx_device_host_acl_lookup
    ON device_host_acl(config_api_id, device_id);

-- ── default_host_acl: fallback per-Config-API defaults ───────────────────
-- Devices without explicit ACL entries receive this default set. Useful for
-- "newly enrolled devices get baseline access to X, Y, Z" policies.
CREATE TABLE default_host_acl (
    config_api_id  TEXT NOT NULL,
    hostname       TEXT NOT NULL,
    PRIMARY KEY (config_api_id, hostname)
);
