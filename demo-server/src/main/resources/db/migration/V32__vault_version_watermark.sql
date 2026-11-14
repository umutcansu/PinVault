-- Per-file version high-water mark, per Config API scope (review 2026-11-14).
-- It survives the file's deletion and the Config API's, so a file that is
-- removed and uploaded again continues its version sequence instead of
-- restarting at 1. Devices refuse a signed vault file older than the newest
-- version they ever verified (2.11.0 libraries keep that floor across
-- clearFile and wipes): a re-uploaded file starting over at v1 would be
-- refused by every device that saw the old versions until the counter caught
-- up again. The same rule as host_version_watermark (V7).
CREATE TABLE IF NOT EXISTS vault_version_watermark (
    config_api_id TEXT NOT NULL,
    key           TEXT NOT NULL,
    max_version   INTEGER NOT NULL,
    PRIMARY KEY (config_api_id, key)
);

-- Seed from the files there are today.
INSERT OR IGNORE INTO vault_version_watermark (config_api_id, key, max_version)
SELECT config_api_id, key, version FROM vault_files;
