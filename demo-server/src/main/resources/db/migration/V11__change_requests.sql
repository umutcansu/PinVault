-- Two-person approval (PIN_CHANGE_APPROVALS >= 2). A pin-affecting request
-- is stored here instead of being executed; once enough OTHER admins approve
-- it, the server replays the exact request (method, path, query, body) through
-- its own management API.
CREATE TABLE IF NOT EXISTS change_requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    method         TEXT NOT NULL,
    path           TEXT NOT NULL,
    query          TEXT NOT NULL DEFAULT '',
    content_type   TEXT NOT NULL DEFAULT '',
    body           BLOB,
    config_api_id  TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL,
    approved_by    TEXT NOT NULL DEFAULT '',
    decided_by     TEXT,
    decided_at     TEXT,
    reason         TEXT,
    result_status  INTEGER,
    result_body    TEXT
);
CREATE INDEX IF NOT EXISTS idx_change_requests_status ON change_requests (status);
