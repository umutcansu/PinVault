-- What Android Key Attestation said about each user-auth key
-- (USER_AUTH_ATTESTATION). NULL attested = not checked (mode off, or a key
-- registered before this column existed); 0 = no attestation or a failing one
-- (accepted under warn, trust on first use); 1 = the chain verified to a
-- Google root and the key needs the user, in TEE or StrongBox.
ALTER TABLE device_user_auth_keys ADD COLUMN attested INTEGER;
-- tee | strongbox | software; NULL when unknown.
ALTER TABLE device_user_auth_keys ADD COLUMN attestation_security_level TEXT;
-- ok, or why it failed (chain_missing, challenge_mismatch, device_unlocked, ...).
ALTER TABLE device_user_auth_keys ADD COLUMN attestation_reason TEXT;

-- Device ids an identity PROVED it acts for, beyond its own client id: a
-- device key registered over its certificate, a vault token of the device
-- used over its certificate, or an administrator cascading a revocation to a
-- device id the identity only claimed. Revocation cuts these devices off the
-- vault and blocks their downloads; the device_uid an enrolling party sent is
-- not proof (anyone can name a victim's device id), so it alone is never
-- enough.
CREATE TABLE IF NOT EXISTS identity_devices (
    client_id    TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    proof        TEXT NOT NULL,
    recorded_at  TEXT NOT NULL,
    PRIMARY KEY (client_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_identity_devices_device ON identity_devices (device_id);
