-- Signing-key sets: lists of config-signing keys, each signed OFFLINE by the
-- operator's recovery key(s) and relayed unchanged to devices inside every
-- signed config response. A device that has seen a set trusts exactly the
-- keys it lists, which is how a signing key is rotated or revoked without an
-- app update. The server cannot mint a set itself: it holds no recovery key.
--
-- Append-only, keyed by the set's own version; the highest version is served.
CREATE TABLE IF NOT EXISTS signing_key_sets (
    version     INTEGER PRIMARY KEY,
    payload     TEXT NOT NULL,
    signatures  TEXT NOT NULL,
    uploaded_by TEXT NOT NULL DEFAULT '',
    uploaded_at TEXT NOT NULL
);
