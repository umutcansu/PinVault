-- Play Integrity (ATTESTATION.md §11): the last verdict Google gave about a
-- device, verified on this server with the Play Console response keys.
-- `play_integrity_result` is pass | fail; `play_integrity_at` when it was
-- verified; `play_integrity` a JSON summary of what the token said (device
-- verdicts, app verdict, licensing, package, reason). A device whose last
-- verified verdict is older than PLAY_INTEGRITY_MAX_AGE_SECONDS raises
-- `play_integrity_missing` until it sends a fresh token.
ALTER TABLE attested_devices ADD COLUMN play_integrity_result TEXT;
ALTER TABLE attested_devices ADD COLUMN play_integrity_at TEXT;
ALTER TABLE attested_devices ADD COLUMN play_integrity TEXT;
