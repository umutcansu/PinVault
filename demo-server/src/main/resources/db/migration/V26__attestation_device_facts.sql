-- What the server keeps about a device beyond its last verdict (ATTESTATION.md §3).
--
-- `key_facts`: what the registration's Android Key Attestation chain said
-- about the device, kept only from a chain that verified up to a trusted
-- root at the TEE or StrongBox level (JSON: securityLevel, deviceLocked,
-- verifiedBootState, verifiedBootKey, osVersion, osPatchLevel,
-- vendorPatchLevel, bootPatchLevel, chainSerials). Kept even when the chain
-- was refused for another reason (an unlocked bootloader under
-- ATTESTATION_KEY_POLICY=warn). NULL = no such chain (none sent, a
-- software-level one, an iPhone). Every round raises `bootloader_unlocked`,
-- `boot_not_verified`, `key_revoked` and `report_mismatch` from it; the
-- serials are looked up in the attestation revocation list every round.
--
-- `config_watermark`: the highest `currentIssuedAt` the device reported
-- (Unix ms), and `config_watermark_key_set` the version of the server's
-- signing-key set when it was stored. A lower report from the same key
-- raises `config_rollback`; a newer key set starts the watermark again.
ALTER TABLE attested_devices ADD COLUMN key_facts TEXT;
ALTER TABLE attested_devices ADD COLUMN config_watermark INTEGER;
ALTER TABLE attested_devices ADD COLUMN config_watermark_key_set INTEGER;
