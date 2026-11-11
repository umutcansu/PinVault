-- Key material this server made (config signing key, client CA, TLS
-- keystore, server CA): a start that finds a recorded file missing refuses to
-- run instead of making a new key every device would refuse
-- (service/KeyMaterialGuard.kt, review 2026-11-11 C-10).
CREATE TABLE IF NOT EXISTS key_material (
    name         TEXT PRIMARY KEY,
    recorded_at  INTEGER NOT NULL
);
