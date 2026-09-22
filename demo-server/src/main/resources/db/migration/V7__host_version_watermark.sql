-- Per-host version high-water mark, per Config API scope. It survives host
-- deletion, so a host that is removed and later re-added continues its
-- version sequence instead of restarting at 1. Clients reject per-host
-- version downgrades; a re-added host starting over at v1 would have every
-- client that saw the old versions refuse its updates until the counter
-- caught up again.
CREATE TABLE IF NOT EXISTS host_version_watermark (
    config_api_id TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    max_version   INTEGER NOT NULL,
    PRIMARY KEY (config_api_id, hostname)
);

-- Seed from what is known today: current pins and the (trimmed) history.
INSERT OR IGNORE INTO host_version_watermark (config_api_id, hostname, max_version)
SELECT config_api_id, hostname, MAX(version)
FROM (
    SELECT config_api_id, hostname, version FROM pin_hashes
    UNION ALL
    SELECT config_api_id, hostname, version FROM pin_history WHERE hostname <> ''
)
GROUP BY config_api_id, hostname;
