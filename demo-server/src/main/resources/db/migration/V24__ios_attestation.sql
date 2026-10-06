-- iOS devices (ATTESTATION.md §3, §12).
--
-- `platform`: what the last report said it ran on (`ios`), `android` for a
-- report that names none (the Android library sends no platform).
--
-- Apple App Attest, verified on this server with Apple's App Attestation
-- Root CA: the key an attestation registered for the device (`app_attest_key_id`
-- Base64 SHA-256 of the key, `app_attest_public_key` Base64 DER SPKI), the
-- authenticator counter its last assertion carried (each one must be
-- higher), and the last verdict — `app_attest_result` pass | fail,
-- `app_attest_at` when it was verified, `app_attest` a JSON summary (reason,
-- attestation or assertion, app id, environment). A device whose last
-- verified verdict is older than APP_ATTEST_MAX_AGE_SECONDS raises
-- `app_attest_missing` until it sends a fresh one. Forgetting the device
-- forgets its App Attest key too: the app attests a new one.
ALTER TABLE attested_devices ADD COLUMN platform TEXT;
ALTER TABLE attested_devices ADD COLUMN app_attest_key_id TEXT;
ALTER TABLE attested_devices ADD COLUMN app_attest_public_key TEXT;
ALTER TABLE attested_devices ADD COLUMN app_attest_counter INTEGER;
ALTER TABLE attested_devices ADD COLUMN app_attest_result TEXT;
ALTER TABLE attested_devices ADD COLUMN app_attest_at TEXT;
ALTER TABLE attested_devices ADD COLUMN app_attest TEXT;
