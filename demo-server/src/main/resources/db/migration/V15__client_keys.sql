-- Every key a client id enrolled with, and when it was retired.
--
-- The mTLS listeners trust every certificate the client CA issued until it
-- expires; revocation is checked per request by client id. Forgetting a
-- revoked identity — so that its client id can enroll again — deletes its
-- rows, so the keys it ever used are retired here first: a certificate over a
-- retired key is refused on every request, and a retired key never gets a
-- certificate again.
CREATE TABLE IF NOT EXISTS client_keys (
    client_id     TEXT NOT NULL,
    spki_sha256   TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    retired_at    TEXT,
    PRIMARY KEY (client_id, spki_sha256)
);
CREATE INDEX IF NOT EXISTS idx_client_keys_spki ON client_keys (spki_sha256);

-- The keys of the identities enrolled so far.
INSERT OR IGNORE INTO client_keys (client_id, spki_sha256, registered_at)
    SELECT client_id, spki_sha256, key_registered_at FROM client_identities;
