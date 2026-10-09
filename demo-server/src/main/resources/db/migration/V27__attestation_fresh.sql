-- Periodic fresh Android Key Attestation (ATTESTATION.md §3.1).
--
-- A key's attestation chain is made once, when the key is generated, so the
-- registration's chain (`key_facts`, V26) says what the device was then. With
-- ATTESTATION_FRESH_INTERVAL_SECONDS the server asks the device, every that
-- many seconds, for the chain of a short-lived key made for one round only
-- (challenge: the round's nonce, the device id and the registered key).
--
-- `fresh_facts`: what that chain said (same JSON as `key_facts`), kept only
-- from a hardware-level chain that verified up to a trusted root; the
-- per-round flags read the RootOfTrust and patch levels from here when it is
-- set, and the serials of both chains are looked up in the revocation list.
-- `fresh_attested_at`: when the last fresh chain that counted arrived (ISO
-- instant); NULL = never, the registration (`first_seen`) is the start.
-- `fresh_result`: `ok`, or why the last fresh chain did not count.
ALTER TABLE attested_devices ADD COLUMN fresh_facts TEXT;
ALTER TABLE attested_devices ADD COLUMN fresh_attested_at TEXT;
ALTER TABLE attested_devices ADD COLUMN fresh_result TEXT;
