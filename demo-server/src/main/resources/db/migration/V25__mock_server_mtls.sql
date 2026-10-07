-- Whether a host's mock listener was started with client-certificate auth
-- (`start-mock` with "mtls": true). The listeners are started again when the
-- server starts; without this an mTLS mock came back as a plain TLS one and
-- accepted every caller.
ALTER TABLE hosts ADD COLUMN mock_server_mtls INTEGER NOT NULL DEFAULT 0;
