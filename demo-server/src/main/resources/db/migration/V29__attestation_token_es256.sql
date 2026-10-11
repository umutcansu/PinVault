-- PinVault-Token signing keys (2.4.2): ES256 by default. `alg` names what a row
-- is: HS256 (secret = the shared 32-byte secret) or ES256 (secret = the PKCS#8
-- private key, sealed like the secrets; public_key = its X.509 SubjectPublicKeyInfo,
-- what backends get from GET /api/v1/attestation/jwks). Rows written before are HS256.
ALTER TABLE attestation_token_secrets ADD COLUMN alg TEXT NOT NULL DEFAULT 'HS256';
ALTER TABLE attestation_token_secrets ADD COLUMN public_key BLOB;
