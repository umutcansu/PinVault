-- What Android Key Attestation said about the key a device enrolled with
-- (ENROLLMENT_ATTESTATION). Same meaning as on device_user_auth_keys:
-- NULL attested = not checked (mode off, a server-made P12 key, or a row
-- older than this column); 0 = no chain or a failing one (accepted under
-- warn); 1 = the chain verified to a Google root, the key is a signing key
-- generated in TEE or StrongBox by the app on a locked, verified device.
ALTER TABLE client_identities ADD COLUMN attested INTEGER;
ALTER TABLE client_identities ADD COLUMN attestation_security_level TEXT;
ALTER TABLE client_identities ADD COLUMN attestation_reason TEXT;

-- The same verdict on a request waiting for approval, so the approver sees
-- "hardware-attested" or "not attested" before letting the device in.
ALTER TABLE enrollment_requests ADD COLUMN attested INTEGER;
ALTER TABLE enrollment_requests ADD COLUMN attestation_security_level TEXT;
ALTER TABLE enrollment_requests ADD COLUMN attestation_reason TEXT;

-- How a user-auth key asks for the user, read from its attestation:
-- per_use (every use) or time_bound (auth_timeout_seconds after an unlock),
-- and whether only a biometric unlocks it. NULL = not known (no passing
-- attestation, or registered before this column existed).
ALTER TABLE device_user_auth_keys ADD COLUMN key_kind TEXT;
ALTER TABLE device_user_auth_keys ADD COLUMN auth_timeout_seconds INTEGER;
ALTER TABLE device_user_auth_keys ADD COLUMN biometric_only INTEGER;
