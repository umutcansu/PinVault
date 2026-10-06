-- Attestation (ATTESTATION.md): per-Config-API rejection policies, the
-- devices that attested with their key and last verdict, the HS256 secrets
-- behind PinVault-Token, and hourly verdict counters for the stats endpoint.

-- One policy per Config API; none stored = the server defaults
-- (ATTESTATION_POLICY_DEFAULT). `version` grows with every PUT and travels
-- in the token's `pol` claim.
CREATE TABLE attestation_policies (
    config_api_id TEXT PRIMARY KEY,
    version       INTEGER NOT NULL DEFAULT 1,
    -- The policy as PUT accepted it (flags, revealReasons, tokenTtlSeconds, attestIntervalSeconds).
    policy_json   TEXT NOT NULL,
    updated_by    TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL
);

-- A device that attested (or that an administrator annotated before it did:
-- spki_sha256 NULL = no key registered yet). The key is what the server
-- registers; the device id is what it indexes by.
CREATE TABLE attested_devices (
    config_api_id          TEXT NOT NULL,
    device_id              TEXT NOT NULL,
    -- SHA-256 (lowercase hex) of the DER SubjectPublicKeyInfo of the device key; NULL = unregistered.
    spki_sha256            TEXT,
    -- The key itself, Base64 DER, for the dashboard.
    public_key             TEXT,
    -- What Android Key Attestation said when the key was registered.
    key_attested           INTEGER NOT NULL DEFAULT 0,
    key_security_level     TEXT,
    key_attestation_reason TEXT,
    first_seen             TEXT NOT NULL,
    last_seen              TEXT NOT NULL,
    -- The last verdict: pass | reject, its ARC, reasons and warnings (JSON arrays).
    last_result            TEXT,
    last_arc               TEXT,
    last_reasons           TEXT NOT NULL DEFAULT '[]',
    last_warnings          TEXT NOT NULL DEFAULT '[]',
    -- The last report, trimmed to its app, device and signals blocks (JSON).
    last_report            TEXT,
    last_policy_version    INTEGER,
    last_sdk_version       TEXT,
    attest_count           INTEGER NOT NULL DEFAULT 0,
    -- Operator overrides and the free-form annotations the token carries (`anno`).
    force_pass             INTEGER NOT NULL DEFAULT 0,
    force_fail             INTEGER NOT NULL DEFAULT 0,
    annotations            TEXT NOT NULL DEFAULT '[]',
    -- Attestations signed with a key other than the registered one (a reinstall, or someone else).
    key_mismatches         INTEGER NOT NULL DEFAULT 0,
    last_key_mismatch_at   TEXT,
    -- A second opinion the app plugged in (Play Integrity): stored, not verified here.
    verdict_provider       TEXT,
    verdict_token          TEXT,
    PRIMARY KEY (config_api_id, device_id)
);
CREATE INDEX idx_attested_devices_result ON attested_devices (config_api_id, last_result);

-- HS256 secrets of PinVault-Token: 32 random bytes each, encrypted at rest
-- under VAULT_AT_REST_PASSWORD. One active at a time; the previous ones stay
-- for verification until an operator deletes them. `kid` names the secret in
-- the token header.
CREATE TABLE attestation_token_secrets (
    kid        TEXT PRIMARY KEY,
    secret     BLOB NOT NULL,
    active     INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT ''
);

-- Verdicts per Config API and hour: results (pass / reject), rejection
-- reasons and warnings. Kept 30 days; the stats endpoint sums 24 h and 7 d.
CREATE TABLE attestation_verdict_counts (
    config_api_id TEXT NOT NULL,
    -- Epoch hours (ms / 3600000).
    hour          INTEGER NOT NULL,
    -- result | reason | warning
    kind          TEXT NOT NULL,
    -- pass / reject, or the flag name.
    name          TEXT NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (config_api_id, hour, kind, name)
);
