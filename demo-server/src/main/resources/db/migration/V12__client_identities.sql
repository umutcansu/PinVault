-- CSR-enrolled device identities. The device keeps one permanent signing key
-- in its Android Keystore; the certificate over it is short-lived and renewed
-- by signing a CSR with that key. This row is what a renewal is checked
-- against: the registered key (spki_sha256) and the revoked flag — never the
-- truststore, which only holds the client CA from now on.
CREATE TABLE IF NOT EXISTS client_identities (
    client_id         TEXT PRIMARY KEY,
    config_api_id     TEXT NOT NULL DEFAULT '',
    spki_sha256       TEXT NOT NULL,
    serial            TEXT NOT NULL,
    not_before        TEXT NOT NULL,
    not_after         TEXT NOT NULL,
    key_registered_at TEXT NOT NULL,
    last_renewed_at   TEXT,
    renew_count       INTEGER NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    device_alias      TEXT,
    device_uid        TEXT
);
CREATE INDEX IF NOT EXISTS idx_client_identities_spki ON client_identities (spki_sha256);
