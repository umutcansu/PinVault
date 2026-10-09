-- Token anomalies (ATTESTATION.md §5.2): a backend that counts how a device's
-- PinVault-Tokens are used (the reference verifier with PINVAULT_TOKEN_ANOMALY,
-- or any backend through POST …/attestation/devices/{deviceId}/anomaly) reports
-- a device whose tokens came from too many addresses or at a rate no person
-- makes. `anomaly_at` (ISO instant) and `anomaly_reason` hold the last report;
-- the device's rounds raise `token_anomaly` for ATTESTATION_ANOMALY_TTL_SECONDS
-- after it, or until an administrator clears it (DELETE …/anomaly).
ALTER TABLE attested_devices ADD COLUMN anomaly_at TEXT;
ALTER TABLE attested_devices ADD COLUMN anomaly_reason TEXT;
