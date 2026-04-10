-- PinVault Database Schema Baseline
-- All tables as of initial production release

CREATE TABLE IF NOT EXISTS config_apis (
    id TEXT PRIMARY KEY,
    port INTEGER NOT NULL,
    mode TEXT NOT NULL DEFAULT 'tls',
    auto_start INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pin_config (
    config_api_id TEXT PRIMARY KEY,
    force_update INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pin_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id TEXT NOT NULL DEFAULT 'default-tls',
    hostname TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    force_update INTEGER NOT NULL DEFAULT 0,
    mtls INTEGER NOT NULL DEFAULT 0,
    client_cert_version INTEGER
);

CREATE TABLE IF NOT EXISTS pin_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id TEXT NOT NULL DEFAULT 'default-tls',
    hostname TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    event TEXT NOT NULL,
    pin_prefix TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    hostname TEXT NOT NULL,
    config_api_id TEXT NOT NULL DEFAULT 'default-tls',
    keystore_path TEXT,
    cert_valid_until TEXT,
    mock_server_port INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (hostname, config_api_id)
);

CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'web',
    hostname TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    http_code INTEGER,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    server_cert_pin TEXT,
    stored_pin TEXT,
    pin_matched INTEGER,
    pin_version INTEGER,
    device_manufacturer TEXT,
    device_model TEXT
);

CREATE TABLE IF NOT EXISTS client_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_manufacturer TEXT,
    device_model TEXT,
    pin_version INTEGER NOT NULL DEFAULT 0,
    last_status TEXT NOT NULL DEFAULT 'unknown',
    last_seen TEXT NOT NULL,
    UNIQUE(hostname, device_id)
);

CREATE TABLE IF NOT EXISTS client_certs (
    id TEXT PRIMARY KEY,
    common_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    device_alias TEXT,
    device_uid TEXT
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS host_client_certs (
    hostname TEXT NOT NULL,
    config_api_id TEXT NOT NULL DEFAULT 'default-tls',
    p12_bytes BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    common_name TEXT,
    fingerprint TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (hostname, config_api_id)
);

CREATE TABLE IF NOT EXISTS vault_files (
    key TEXT PRIMARY KEY,
    content BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_distributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    device_manufacturer TEXT,
    device_model TEXT,
    enrollment_label TEXT,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    device_alias TEXT
);
