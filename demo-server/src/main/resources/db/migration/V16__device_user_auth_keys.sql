-- A device's USER-AUTH key: an RSA key whose private half the phone's
-- hardware uses only after the user passed the screen lock or biometric.
-- Files with encryption = 'user_auth' are wrapped with it, so a rooted
-- device calling the download API without the user gets ciphertext only.
--
-- Kept apart from the E2E key (device_public_keys): the two are registered
-- separately and neither may overwrite the other. Same columns, same rules.
CREATE TABLE IF NOT EXISTS device_user_auth_keys (
    device_id       TEXT NOT NULL,
    config_api_id   TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'RSA-OAEP-SHA256',
    registered_at   TEXT NOT NULL,
    PRIMARY KEY (device_id, config_api_id)
);

-- Revocation looks devices up by id: every device-bound vault download asks
-- whether its X-Device-Id belongs to a revoked identity, and revoking a
-- device revokes its tokens in every Config API.
CREATE INDEX IF NOT EXISTS idx_client_certs_device_uid ON client_certs (device_uid);
CREATE INDEX IF NOT EXISTS idx_client_identities_device_uid ON client_identities (device_uid);
CREATE INDEX IF NOT EXISTS idx_vault_file_tokens_device ON vault_file_tokens (device_id);
