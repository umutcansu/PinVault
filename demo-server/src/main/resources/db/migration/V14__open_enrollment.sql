-- Applications without a code: the dashboard's "code-less applications"
-- switch. One policy row with open_applications = 1 collects the devices
-- that ask without a token; every one of them waits for an administrator.
-- `accepting` = 0 turns new applications away while the ones already waiting
-- can still be decided. Its code_hash is random and was never shown.
ALTER TABLE enrollment_policies ADD COLUMN open_applications INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrollment_policies ADD COLUMN accepting INTEGER NOT NULL DEFAULT 1;

-- Waiting requests are matched by device id to flag a device asking twice.
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_device_uid ON enrollment_requests (device_uid);
