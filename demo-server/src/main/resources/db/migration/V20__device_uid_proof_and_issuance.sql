-- Whether the device id an identity enrolled with (client_certs.device_uid)
-- is more than the enrolling party's word: 1 when an Android Key Attestation
-- with the app binding vouched for it (the challenge is SHA-256 of the device
-- id), when an administrator bound the enrollment token to that device id, or
-- when the client id is the device id itself. Only a proven device id lets a
-- certificate replace the device's E2E key, open its token_mtls files, take
-- its host client certificates and lift its revocation block. Existing rows
-- start unproven: their device ids were claims.
ALTER TABLE client_certs ADD COLUMN device_uid_proven INTEGER NOT NULL DEFAULT 0;

-- The device id an administrator bound a one-time token to when minting it
-- (POST /api/v1/enrollment-tokens/generate {"deviceUid": ...}); NULL = none.
-- An enrollment with that token must name this device id.
ALTER TABLE enrollment_tokens ADD COLUMN device_uid TEXT;

-- SHA-256 (Base64) of the last CSR a renewal accepted for the identity: the
-- same signed request sent again is a replay, not a renewal.
ALTER TABLE client_identities ADD COLUMN last_renewal_csr_sha256 TEXT;

-- The certificate (PEM, leaf) last issued over the identity's key: a device
-- asking again with the same key while it is valid gets this one back
-- instead of a new signature, audit entry and webhook per request.
ALTER TABLE client_identities ADD COLUMN cert_pem TEXT;
