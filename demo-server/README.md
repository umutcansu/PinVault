# Reference server

The PinVault server the libraries, samples and tests run against: Config
APIs (TLS and mTLS), enrollment and renewal, vault files, attestation and the
dashboard. Overview and the client side: the [main README](../README.md).
The API contract for a server of your own:
[SERVER_IMPLEMENTATION_GUIDE.md](../SERVER_IMPLEMENTATION_GUIDE.md). A
ready-to-run Docker setup for phones on the LAN: [`sample-host/`](../sample-host).

## Run it

```bash
cd demo-server
API_KEY=your-secret SIGNING_KEY_PASSWORD=second-secret KEYSTORE_PASSWORD=third-secret \
  VAULT_AT_REST_PASSWORD=fourth-secret docker compose up
```

Dashboard: `http://localhost:8080`
API docs (Swagger): `http://localhost:8080/docs`
Config API (TLS): `https://localhost:8081`

Data lives under `demo-server/data/` (`db/`, `certs/`, `keys/signing-key.pem`).
The compose file passes through the variables in the two tables below; add any
other one to its `environment:` list. Upgrading from a checkout that mounted
`./data/signing-key.pem`: move that file to `./data/keys/signing-key.pem`
before starting, or the server generates a new key and every device rejects
its configs.

## Required env vars

| Variable | Required? | Purpose |
|---|---|---|
| `API_KEY` | Required | X-API-Key header value for management endpoints. Server refuses to start when unset — pass `ALLOW_ANONYMOUS_ADMIN=true` to opt out (dev only). *(2.2)* At least 16 characters (`openssl rand -hex 24`) unless `ALLOW_DEMO_SECRETS=true`. |

## Optional env vars

| Variable | Default | Purpose |
|---|---|---|
| `SIGNING_KEY_PASSWORD` | unset | AES-256-GCM encrypts the ECDSA signing key on disk (PBKDF2-SHA256). When unset, the key is written plaintext + chmod 600 + warning logged. Existing plaintext keys are auto-migrated on startup. |
| `KEYSTORE_PASSWORD` | `changeit` | Protects the server's own keystores (TLS key, backup keys, truststore, stored host client certs). Never leaves the server. **Set it in production** — the default is public. |
| `KEYSTORE_PASSWORD_PREVIOUS` | unset | Old password when changing `KEYSTORE_PASSWORD`: keystores are re-encrypted at startup. Remove afterwards. |
| `VAULT_AT_REST_PASSWORD` | demo key | Encrypts uploaded vault files on disk. Unset uses a key that is in the source code, so the encryption is cosmetic. `VAULT_AT_REST_PASSWORD_PREVIOUS` re-encrypts after a change. |
| `CLIENT_P12_PASSWORD` | `changeit` | Password on device P12s for clients that don't negotiate a one-off one (`X-PinVault-Features: p12password`, library 2.1+). |
| `CONFIG_TTL_SECONDS` | `86400` (24h) | How long a signed config response stays valid before clients reject it as replayed. Lower = tighter replay window; too low risks rejecting cached configs from offline devices. |
| `ENROLLMENT_MODE` | `token` | `token` (production) requires an enrollment token; `open` allows deviceId-only enrollment (demo only). |
| `ENROLLMENT_TOKEN_TTL_SECONDS` | `86400` | Lifetime of a one-time enrollment token. |
| `ENROLLMENT_REQUEST_TTL_HOURS` | `24` | How long a device's request may wait for approval (enrollment codes and applications without a code); unanswered, it lapses and the device is told `410`. 1–720. |
| `OPEN_ENROLLMENT_RATE_LIMIT` | `20` | New applications without a code one source address may make per 10 minutes (`429` beyond it). Behind one NAT or proxy every device shares it; `0` turns it off. |
| `OPEN_ENROLLMENT_MAX_PENDING` | `50` | Most applications without a code waiting at once (`429` beyond it). |
| `CLIENT_CERT_TTL_DAYS` | `90` | Lifetime of certificates issued over device-held keys (CSR enrollment, library 2.1+). They renew themselves at a third of the lifetime; `KEYSTORE_PASSWORD` also protects the client CA (`client-ca.jks`). |
| `RECOVERY_PORT` | `PORT+3` | Certificate-renewal door for devices whose client certificate expired: TLS without client auth, serves only `POST /api/v1/client-certs/renew` and `/health`. Its certificate is signed by the server CA (`server-ca.jks` + `server-ca.backup.jks`) and reissued 30 days before expiry. `0` turns it off. In Docker it is 8083. |
| `ALLOW_TEST_HOOKS` | unset | `true` enables `POST /api/v1/test-hooks/client-cert-ttl` (API key), which arms a short lifetime for a client id's next certificate so tests can watch it expire. Never in production. |
| `DEVICE_KEY_RATE_LIMIT` | `30` | E2E keys a source address may write per 10 minutes over a TLS Config API, where key registration asks for no credential (`429` beyond it; a device repeating its own key is not counted). The address is the TCP peer: behind a reverse proxy, or Docker Desktop's port forwarding, every device shares one quota. Raise it for a first rollout behind one NAT or proxy; `0` turns it off. |
| `DEVICE_KEY_LIMIT` | `100000` | Most E2E keys one Config API stores; a new device beyond it gets `503`, known devices keep working. |
| `EXTRA_CERT_SANS` | unset | Comma-separated IPv4 addresses / DNS names added to every TLS certificate the server generates. Set it to the Docker host's LAN IP when running in a container — the server only sees the container's own address, and Android clients reject a certificate that does not name the IP they connect to. Applies when a certificate is (re)generated. |
| `CERT_EXPIRY_WARN_DAYS` | `30` | When `/api/v1/cert-expiry` and the dashboard start warning. |
| `MANAGEMENT_HTTPS_PORT` | unset | Also serve the management API over TLS with the Config API's certificate (the one apps already pin), so device reports and remote admins don't cross the network in the clear. Not in the compose file — add it and a port mapping. |
| `PORT` / `HTTPS_PORT` | `8080` / `PORT+1` | Management HTTP / Config API TLS ports. In Docker, change the host side instead (`PORT=9000 docker compose up`). |
| `DB_PATH` | `pinvault.db` (Docker image: `/data/db/pinvault.db`) | The SQLite database. Settings saved from the setup wizard (`server-settings.json`) are kept next to it. |
| `CERTS_DIR` | `certs` (Docker image: `/data/certs`) | Directory of the server's keystores: TLS and backup keys, host keystores, the client truststore, the client and server CAs. |
| `SIGNING_KEY_PATH` | `signing-key.pem` (Docker image: `/data/keys/signing-key.pem`; a key left at `/data/signing-key.pem` by an older image is moved there at start) | The local config-signing key file (`CONFIG_SIGNERS=local`; generated when missing). A named local signer reads `SIGNING_KEY_PATH_<NAME>`, default `signing-key-<name>.pem` in the same directory. |
| `ALLOW_ANONYMOUS_ADMIN` | unset | Set to `true` to allow startup with no `API_KEY` (anonymous admin). Logs a warning. Do not use on any network you don't control. *(2.2)* Anonymous admin answers only on the management port, only to connections from this machine, and never on a Config API port (`403 admin_key_required`). |
| `ANONYMOUS_ADMIN_PEERS` | unset | *(2.2)* Comma-separated IPs or CIDRs that count as "this machine" for anonymous admin, e.g. a container's gateway (`172.17.0.1`; Docker Desktop: `192.168.65.0/24`). Others get `403 peer_not_allowed`. |
| `ADMIN_AUTH_FAILURE_LIMIT` | `30` | *(2.2)* Invalid admin keys one address may send per 10 minutes before `429`. Correct keys are never counted; `0` turns it off. |
| `ADMIN_KEYS_FILE` | unset | A file of named admin keys, one `name:sha256hex` per line (`#` starts a comment), read in addition to `ADMIN_KEYS` — keeps the hashes out of the environment. See [SECURE_OPERATIONS.md](../SECURE_OPERATIONS.md). |
| `ADMIN_UPLOAD_MAX_BYTES` | `1048576` (1 MB) | Largest admin JSON body or upload (keystore, certificate) the server reads; `413` beyond it. 1024 bytes–64 MB. Vault files have their own cap, `VAULT_MAX_FILE_BYTES`. |
| `APPROVAL_TTL_HOURS` | `24` | How long a change request waits for a second admin under `PIN_CHANGE_APPROVALS`; unapproved by then, it expires. At least 1. |
| `PIN_LIVE_CHECK_ALLOW_OVERRIDE` | `true` | `false`: under `PIN_LIVE_CHECK=enforce` a pin set the live host fails cannot be published with `liveCheckOverride=<reason>` either. |
| `LIVE_CHECK_TIMEOUT_MS` | `5000` | Connect and read timeout of one live-certificate check (`PIN_LIVE_CHECK`); the whole handshake gets twice this. |
| `ISSUANCE_RATE_LIMIT` | `10` | *(2.2)* Certificates issued per client id per 10 minutes (open mode, enrollment codes). A device asking again with the same key within half its certificate's lifetime gets the same certificate back. |
| `KEY_REPLACEMENT_RATE_LIMIT` | `10` | *(2.2)* End-to-end / screen-lock key replacements one client id may make over its certificate per 10 minutes. |
| `PICKUP_RATE_LIMIT` / `PICKUP_SOURCE_RATE_LIMIT` | `120` / `600` | *(2.2)* How often a waiting request may be asked about, per request and per address, per 10 minutes. |
| `VAULT_DOWNLOAD_CONCURRENCY` | `4` | *(2.2)* Vault downloads one address may run at once (`429` beyond it). |
| `VAULT_DOWNLOAD_CONCURRENCY_TOTAL` | `16` | *(2.3)* Vault downloads served at once in total, across addresses and listeners (`429` beyond it; `0` = unlimited). Each download holds the whole file in memory, so the per-address cap alone let a few addresses fill the heap with one large `public` file. The Docker images start the JVM with `-XX:MaxRAMPercentage=60`. |
| `CONFIG_API_ADMIN_ROUTES` | `on` | *(2.3)* `off`: the Config API listeners — the ports devices reach — answer device endpoints only; every admin route gets `403 admin_routes_disabled` there, with or without a key, and administration happens on the management port alone. A leaked `API_KEY` is then useless from the internet-facing ports. The production profile sets `off`. |
| `ATTESTATION_ENABLED` | `true` | *(2.3)* Serves `GET /api/v1/attest/challenge` and `POST /api/v1/attest` on the Config API ports ([ATTESTATION.md](../ATTESTATION.md)): the app measures itself and the device, signs the report with its Keystore key, and gets a verdict, a `PinVault-Token` (HS256 JWT, 5 min) and — when it is behind — the signed pin config. |
| `ATTESTATION_KEY_POLICY` | `warn` | *(2.3)* What a device key's **first** registration must show: `off` trusts on first use; `warn` checks the Android Key Attestation chain when there is one and stores the outcome (`key_unattested` becomes a signal); `enforce` registers no key without a passing chain (`403 attestation_required` / `attestation_invalid`) and needs `ATTESTATION_PACKAGE_NAMES` + `ATTESTATION_SIGNER_SHA256` to start. The production profile sets `enforce`. A registered key is never re-attested; a device that comes with another key is `403 key_mismatch` until an operator forgets it. |
| `ATTESTATION_POLICY_DEFAULT` | `strict` | *(2.3)* The policy of a Config API without a stored one: `strict` rejects `rooted`, `emulator`, `debugger`, `debuggable`, `hooking_framework`, `app_integrity`, `cloner`, warns on `unknown_installer`, `software_key`, `key_unattested`, `old_patch_level`, `play_integrity`, `play_integrity_missing` and ignores `adb_enabled`; `lenient` warns on everything (measure the fleet first). Per Config API in the dashboard or `PUT /api/v1/config-apis/{id}/attestation/policy`. |
| `ATTESTATION_TOKEN_TTL_SECONDS` / `ATTESTATION_INTERVAL_SECONDS` | `300` / `300` | *(2.3)* Token lifetime and `nextAttestIn` when a policy has none (30–86400 / 60–86400). |
| `ATTESTATION_NONCE_TTL_SECONDS` | `120` | *(2.3)* How long a challenge nonce may be presented. Nonces are HMAC-stamped with a key made at start-up (a restart invalidates those in flight; the library asks for a new one) and remembered once accepted. |
| `ATTESTATION_RATE_LIMIT` / `ATTESTATION_DEVICE_RATE_LIMIT` | `60` / `30` | *(2.3)* Attestations per source address and per device id per 10 minutes (`0` = off); the challenge has twice the address quota. The device is counted once its signature verified with the registered key, so a stranger cannot spend a device's quota. |
| `ATTESTATION_DEVICE_LIMIT` | `100000` | *(2.3)* Most registered attestation devices one Config API holds (`0` = unlimited); a new device beyond it gets `503 device_limit_reached`, known devices keep attesting. |
| `ATTESTATION_REVEAL_REASONS` | `false` | *(2.3)* Default for a policy's `revealReasons`: whether a rejected device is told its `rejectionReasons` (the 8-hex ARC is always sent and resolves to them in the dashboard). |
| `PLAY_INTEGRITY_DECRYPTION_KEY` / `PLAY_INTEGRITY_VERIFICATION_KEY` | unset | *(2.3)* The Play Console response keys (Base64, both or neither). Set, the server verifies the `play-integrity` verdict a report carries ([ATTESTATION.md §11](../ATTESTATION.md#11-play-integrity-optional)) and raises `play_integrity` / `play_integrity_missing`; unset, the token is only stored. `PLAY_INTEGRITY_ENABLED=false` turns it off with the keys in place. |
| `PLAY_INTEGRITY_PACKAGE_NAMES` / `PLAY_INTEGRITY_DEVICE_LEVEL` / `PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED` | `ATTESTATION_PACKAGE_NAMES` / `device` / `true` | *(2.3)* What a verdict must say: the package, the least `deviceRecognitionVerdict` (`basic`, `device`, `strong`), whether the app must be `PLAY_RECOGNIZED`. |
| `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` / `PLAY_INTEGRITY_MAX_AGE_SECONDS` | `600` / `86400` | *(2.3)* How old a token may be; how long a verified verdict covers the device's later rounds (the client sends a token every few hours, not every round). |
| `PLAY_INTEGRITY_STALE_PASS_SECONDS` | `PLAY_INTEGRITY_MAX_AGE_SECONDS` | *(2.4)* How long a stored **pass** covers rounds without a token (60–2592000); a stored fail keeps `play_integrity` raised for the max age. Set it a little above the app's provider interval (6 h by default) so a dropped token turns into `play_integrity_missing` within hours. |
| `PLAY_INTEGRITY_REQUIRE_V2` / `PLAY_INTEGRITY_REQUIRE_LICENSED` | `false` / `false` | *(2.4)* Refuse a token asked with the round's bare nonce (v1; the v2 nonce also binds the device id, ATTESTATION.md §11) — off, it passes with the warning `play_integrity_v1`; require `appLicensingVerdict` `LICENSED`. |
| `APP_ATTEST_REQUIRE_V2` | `false` | *(2.4)* Refuse an App Attest round verdict made with the v1 client data hash (nonce and device id, not the report; ATTESTATION.md §12) — off, it passes with the warning `app_attest_v1`. |
| `ATTESTATION_TRUSTED_BOOT_KEYS` | unset | *(2.4)* `verifiedBootKey` digests (64 hex, comma-separated) of operating systems accepted with a `SelfSigned` boot on a locked bootloader (GrapheneOS, CalyxOS): verified for `ATTESTATION_REQUIRE_VERIFIED_BOOT` and `boot_not_verified`. |
| `ATTESTATION_FRESH_INTERVAL_SECONDS` / `ATTESTATION_FRESH_GRACE_SECONDS` | `0` (off) / `259200` | *(2.4)* Ask every Android device this often for the chain of a key made for one round (ATTESTATION.md §3.1): the hardware's facts are refreshed; a hardware-attested device without one for interval + grace raises `fresh_attestation_overdue`. |
| `PINVAULT_TOKEN_ANOMALY` / `_MAX_ADDRESSES` / `_MAX_REQUESTS` / `_WINDOW_SECONDS` | `off` / `8` / `1200` / `600` | *(2.4)* With `MOCK_HOST_REQUIRE_TOKEN`: the mock hosts count each device's token use per window and report a device over a limit (`warn`), or also refuse it with `429 token_anomaly` (`refuse`) (ATTESTATION.md §5.2). |
| `ATTESTATION_ANOMALY_TTL_SECONDS` | `3600` | *(2.4)* How long a reported device's rounds raise `token_anomaly`. |
| `PINVAULT_TOKEN_REQUIRE_PROOF` | `true` | *(2.4; on by default since 2.4.2, `false` turns it off)* With `MOCK_HOST_REQUIRE_TOKEN`: every request also carries a `PinVault-Proof` (DPoP, RFC 9449) for its method and URL, signed by the key the token's `cnf.jkt` names (ATTESTATION.md §5.1). |
| `PINVAULT_TOKEN_REQUIRE_CERT_BINDING` | `false` | *(2.4)* With `MOCK_HOST_REQUIRE_TOKEN`: a token counts only over mTLS with the client certificate its `cnf.x5t#S256` names (ATTESTATION.md §5). |
| `PINVAULT_TOKEN_PUBLIC_ORIGIN` | *(request origin)* | *(2.4)* The public origin (`scheme://host[:port]`, no path) a client's `PinVault-Proof` `htu` names, set behind a proxy/load balancer so the expected URL is not built from each request's `Host` header. Set it when several token-verifying backends share the same token secrets but answer under different Host names. |
| `MOCK_HOST_REQUIRE_TOKEN` | `false` | *(2.3)* The mock TLS/mTLS hosts refuse requests without a valid `PinVault-Token` (`401` with `WWW-Authenticate: PinVault-Token …`), as an app's own API would — the reference verifier is `plugin/PinVaultTokenAuth.kt`; backends load the secrets from `GET /api/v1/attestation/token-secrets` (requester-run under two-person approval). |
| `HOST_CLIENT_CERT_REQUIRE_GRANT` | `true` | *(2.3; on by default since 2.4.2)* A host's client certificate — one private key the whole fleet shares — is handed only to devices the device host ACL names; a scope with no ACL serves it to nobody (`403 host_not_allowed`). `false`: a scope without an ACL serves it to every enrolled device (so a device enrolled with a shared enrollment code, or a phone compromised before its revocation, could collect every host's key). |
| `CLIENT_DEVICES_MAX` | `20000` | *(2.2)* Most rows the device list (connection reports) keeps; the oldest go first. |
| `INTEGRITY_VERIFICATION` | `off` | *(2.3)* `off` \| `warn` \| `enforce`: the `integrityToken` of an enrollment (see [Bypass protection](../GUIDE.md#10-bypass-protection-23)). `enforce`: `403 integrity_required` / `integrity_invalid` before anything is spent, and no server-made keys. Needs `INTEGRITY_VERIFIER_COMMAND`. |
| `INTEGRITY_VERIFIER_COMMAND` | unset | *(2.3)* Decodes the token: stdin `{"token","requestHash","deviceId"}`, stdout `{"passed","reason","summary"}`. For Play Integrity: `scripts/play-integrity-verify.sh` with `INTEGRITY_PLAY_PACKAGE` and `INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE`. Gets `PATH`, `HOME`, `LANG`, `TZ`, `INTEGRITY_*` and `INTEGRITY_PASS_ENV`, never a server secret. `INTEGRITY_VERIFIER_TIMEOUT_MS` (default 10000). |
| `SIGNER_PUBLIC_KEY_FILE` | unset | `CONFIG_SIGNERS=command`: a file holding the signer's public key, in place of `SIGNER_PUBLIC_KEY` (one of the two is required). Like every `SIGNER_*` variable, a named signer reads it with a `_<NAME>` suffix. |
| `SIGNER_INPUT` | `payload` | `CONFIG_SIGNERS=command`: what `SIGNER_COMMAND` gets on stdin — `payload` (the bytes to sign) or `digest` (their SHA-256, for a KMS that signs a pre-computed digest, such as AWS KMS with `--message-type DIGEST`). |
| `SIGNER_TIMEOUT_MS` | `10000` | `CONFIG_SIGNERS=command`: how long one run of `SIGNER_COMMAND` may take. |
| `SETUP_PUBLIC_HOST` / `SETUP_PUBLIC_PORTS` | unset | *(2.3)* What the dashboard's setup wizard writes into the app's configuration when the server sits behind Docker or a proxy: the address phones reach it at, and `listen:published` port pairs (`8081:6651,8092:6652,8083:6656`). Unset: the dashboard's own address and the listening ports. The sample host fills both from `HOST_LAN_IP` and its port mapping. |
| `PINVAULT_RESTART_ON_EXIT` | unset | *(2.3)* `true`: something (Docker's `restart: unless-stopped`) starts the server again when it exits, so the setup wizard's "Restart now" may exit it to apply saved settings. Settings saved from the wizard live in `server-settings.json` next to the database and fill in what the environment leaves empty; a value set here in the environment is locked in the panel. |

**Setup wizard** *(2.3)*. The dashboard's *Setup Wizard* lists what a
production server still lacks — admin keys, approvals, signers, attestation,
integrity, demo secrets and the rest — with the `.env` lines to change (it
reads the environment, never writes it, and never shows a secret), then
writes the app's PinVault configuration in Kotlin or Java from this server's
own bootstrap pins, signing keys, client CA pin and ports.

The optional signing and governance layers — named admins (`ADMIN_KEYS`),
two-person approval (`PIN_CHANGE_APPROVALS`), live-certificate check
(`PIN_LIVE_CHECK`), webhooks (`NOTIFY_WEBHOOK_URL`), HSM/KMS signers
(`CONFIG_SIGNERS`, `PKCS11_*`, `SIGNER_*`), signature cache and signing-key
sets (`RECOVERY_PUBLIC_KEYS`) — are all off by default and documented with
their variables in [SECURE_OPERATIONS.md](../SECURE_OPERATIONS.md).
