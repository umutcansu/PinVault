# PinVault — Secure Operations

Pins are public: anyone can read a server's certificate. What has to be protected is **what devices trust** (the keys that sign configs), **who can change pins**, and **availability** (a wrong pin set locks every device out of a host). PinVault ships layers for each of these. Every layer is optional and off by default, so a team enables what its infrastructure and staffing can carry. None of them changes anything for clients or servers that don't use it.

## Security levels

Pick the highest level you can operate reliably. A layer you can't run well, such as an HSM nobody knows how to restore or approvals nobody answers at night, is worse than no layer at all.

**Level 0: default.** One signing key file on the server and one shared admin key (`API_KEY`). Devices verify every config (signature, freshness, replay, per-host downgrade).

**Level 1: no extra infrastructure.**

| Layer | Enable with | Protects against |
|---|---|---|
| Signing key encrypted at rest | `SIGNING_KEY_PASSWORD` (required, like the two passwords below; see *Required secrets*) | A copied data directory yielding the key |
| Management API off the network | sample host: plain HTTP bound to `127.0.0.1`, `MANAGEMENT_HTTPS_PORT` for devices and remote admins | The admin key crossing the network in the clear; read or forged device reports |
| Keystores under a real password | `KEYSTORE_PASSWORD` (required; the sample host's `setup.sh` generates one) | A copied data directory yielding TLS, backup and client keys |
| Vault files under a real password | `VAULT_AT_REST_PASSWORD` (required; the sample host's `setup.sh` generates one) | A copied database yielding at_rest and per-device vault files |
| Offline backup signing key in the app | client `signaturePublicKeys(primary, backup)` | Lost or stolen primary → switch without an app update |
| Named admins + audit log | `ADMIN_KEYS=alice:<sha256>,…` (log is always on) | "Who changed this pin?" having no answer |
| Webhook notifications | `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET` (`NOTIFY_EVENTS=*` sends every event but the routine `device_key_registered`, `device_key_attested` and `attestation_rejected`, which are sent only when named; deliveries are signed with a timestamp, see *Webhook receivers*) | Changes nobody notices; a DB-only rewrite of the audit log going unseen |
| Live certificate check, warn | `PIN_LIVE_CHECK=warn` | Typos and wrong-host pins (flagged, still stored) |
| User-auth key attestation, warn (default) | `USER_AUTH_ATTESTATION=warn` | Root code on the phone swapping in a software key of its own for a registered user-auth key (a replacement needs a passing Android Key Attestation) |
| Enrollment key attestation, warn (default) | `ENROLLMENT_ATTESTATION=warn` | Approving or keeping a device without knowing whether its key lives in its hardware (the verdict is shown next to every waiting request and certificate) |

**Level 2: an offline key and a second person.**

| Layer | Enable with | Protects against |
|---|---|---|
| Signing-key sets | client `recoveryPublicKeys(r1[, r2])`; server `RECOVERY_PUBLIC_KEYS` | A stolen signing key staying trusted until every app is updated |
| Two-person approval | `PIN_CHANGE_APPROVALS=2` (needs `ADMIN_KEYS`; the shared `API_KEY` can neither request nor approve a change) | One phished admin key or one insider publishing pins, trusting a certificate, letting devices enroll or replacing a vault file (see *What waits for a second admin*) |
| Live certificate check, enforce | `PIN_LIVE_CHECK=enforce` | Publishing a set that the live host fails |
| User-auth key attestation, enforce | `USER_AUTH_ATTESTATION=enforce` + `ATTESTATION_PACKAGE_NAMES` (+ `ATTESTATION_SIGNER_SHA256`) | A first user-auth key that is not a hardware key needing the user, made by your app on a locked phone |
| Per-use user-auth keys only | `USER_AUTH_REQUIRE_PER_USE=true` | Root running as the app registering a key that works for seconds after any unlock, on Android 7–10 too (Android 11+ refuses those always) |
| Enrollment key attestation, enforce | `ENROLLMENT_ATTESTATION=enforce` + the same app binding | A client certificate issued over a key that is not a hardware key made by your app on a locked, verified phone (an emulator, a rooted phone, a key copied off a device) |
| No server-made keys | `ENROLLMENT_P12=off` | A private key made on the server and sent over the network; a device identity nobody can attest |
| A current revocation list | `ATTESTATION_REVOKED_SERIALS_FILE` + a cron job (`demo-server/scripts/fetch-attestation-status.sh`) + `ATTESTATION_STATUS_MAX_AGE_HOURS` | Chains from attestation keys Google revoked (leaked from a phone model) passing; a fetch job that stopped going unnoticed; with the attestation endpoint, a device that registered before the revocation (`key_revoked` on its next round) |
| Verdicts bound to the round's data | `APP_ATTEST_REQUIRE_V2=true`, `PLAY_INTEGRITY_REQUIRE_V2=true` (once every supported app version sends v2) | Apple's verdict paired with a report it was not made for; a Play Integrity token minted for another device id |
| The hardware's word, refreshed | `ATTESTATION_FRESH_INTERVAL_SECONDS=86400` (production profile), `fresh_attestation_*` at `reject` once every app version in use sends fresh chains | A keybox revoked after registration going unnoticed until re-enrollment, patch levels frozen at registration, an identity key lifted to software or a server that never sees the device's hardware again (ATTESTATION.md §3.1) |
| Abused tokens noticed | `PINVAULT_TOKEN_ANOMALY=warn` on the reference verifier (production profile), or your backend counting per device and calling `POST …/attestation/devices/{id}/anomaly`; `token_anomaly` at `reject` | One device's tokens (lifted, or signed for others by a rooted phone) used from many addresses or by a script, unnoticed (ATTESTATION.md §5.2) |
| Tokens proven per request | blocks with `proofOfPossession()` + your API with `PinVaultTokenAuth { requireProof = true }` or a DPoP library (`PINVAULT_TOKEN_REQUIRE_PROOF=true` on the mock hosts; on in the sample host's production profile) | A `PinVault-Token` lifted off a device and replayed from elsewhere, also behind a proxy or CDN that ends TLS (ATTESTATION.md §5.1) |
| Tokens bound to the device's certificate | your API behind mTLS with the attesting identity + `PinVaultTokenAuth { requireCertBinding = true }` (`PINVAULT_TOKEN_REQUIRE_CERT_BINDING=true` on the mock hosts) | A `PinVault-Token` lifted off a device and replayed from elsewhere within its lifetime |

**Level 3: HSM/KMS and no single point.**

| Layer | Enable with | Protects against |
|---|---|---|
| Key inside an HSM (never extractable) | `CONFIG_SIGNERS=pkcs11` + `PKCS11_*` | The signing key ever being copied off the server |
| KMS / remote signer | `CONFIG_SIGNERS=command` + `SIGNER_COMMAND`, `SIGNER_PUBLIC_KEY` | Same, with the provider's own access policy and audit (see *Signer isolation* for what the command can and cannot be kept from) |
| Sign once per publish | `CONFIG_SIGNATURE_CACHE=true` (always on with a `pkcs11` or `command` signer) | HSM/KMS called on every poll; unaccountable signatures; anyone who reaches a device port running the signer at will |
| m-of-n signatures | server `CONFIG_SIGNERS=a,b` + client `requiredSignatures(2)` | A compromised server (or one team) publishing pins alone |

m-of-n is the only layer that holds against a fully compromised config server. An HSM keeps the key from being stolen, but whoever controls the server can still ask the HSM to sign. With two signers whose keys sit with different teams or systems, and each signer checking what it signs, neither one alone can produce a config devices accept.

### Production values for device identity and attestation

The defaults keep older apps and test phones working. In production, with an app on library 2.2.0 or later:

```
ENROLLMENT_ATTESTATION=enforce          # every CSR enrollment carries a passing attestation
ENROLLMENT_P12=off                      # no private key is ever made on the server
USER_AUTH_ATTESTATION=enforce           # user-auth keys: hardware, needs the user, your app
USER_AUTH_REQUIRE_PER_USE=true          # no time-bound user-auth key, on any Android version
ATTESTATION_PACKAGE_NAMES=com.example.app
ATTESTATION_SIGNER_SHA256=<SHA-256 of the release signing certificate>   # apksigner verify --print-certs app.apk
ATTESTATION_REVOKED_SERIALS_FILE=/data/attestation-status.json
ATTESTATION_STATUS_MAX_AGE_HOURS=48     # with the fetch job every 6 h: two days of outage before nothing passes
ATTESTATION_MIN_PATCH_LEVEL=            # optional, YYYYMM: refuse phones behind on security patches
```

For the attestation endpoint (ATTESTATION.md), in addition:

```
ATTESTATION_KEY_POLICY=enforce          # a first registration needs a passing chain (or App Attest)
ATTESTATION_POLICY_DEFAULT=strict       # rejects bootloader_unlocked, boot_not_verified, key_revoked,
                                        # report_mismatch, config_rollback (and the client probes' root, hooks, …)
APP_ATTEST_REQUIRE_V2=true              # App Attest verdicts bound to the report (iOS app on the current library)
PLAY_INTEGRITY_REQUIRE_V2=true          # Play Integrity tokens bound to the device id (Android provider on the current library)
PLAY_INTEGRITY_STALE_PASS_SECONDS=25200 # a stored pass covers 7 h of rounds without a token (provider asks every 6 h)
PLAY_INTEGRITY_DEVICE_LEVEL=strong      # optional: hardware-backed, recent patch
PLAY_INTEGRITY_REQUIRE_LICENSED=true    # optional: apps distributed only through Play
ATTESTATION_TRUSTED_BOOT_KEYS=          # optional: verifiedBootKey digests of GrapheneOS / CalyxOS builds you allow
```

**The policy for a production Config API.** `strict` already rejects what a stock, locked phone never shows (the five flags the server raises from the registration's hardware chain and the device's config watermark) and leaves the second opinions on `warn`, because rejecting them before every app build ships the provider rejects the fleet. Once the dashboard's stats show the fleet attesting with them, set — per Config API, `PUT /api/v1/config-apis/{id}/attestation/policy` or the panel — `app_attest`, `app_attest_missing`, `play_integrity` and `play_integrity_missing` to `reject`. Without them a hidden root on a phone whose registration chain was not hardware-level (no chain, under `warn`) and an iPhone without App Attest are judged by the client's own probes only. An iOS-only or Android-only fleet sets only its own pair (`play_integrity_missing` is never raised on an iPhone with App Attest configured, `app_attest_missing` never on Android). `ATTESTATION_POLICY_DEFAULT=production` starts every Config API with those four at `reject` and holds `rooted`, `emulator`, `debuggable`, `hooking_framework`, `app_integrity` and `software_key` at `reject` in code: a stored policy cannot lower them, and a PUT that does needs a second admin's approval (`403 two_person_approval_required` without it, even with approvals off or the operation exempted). The sample host's production profile fixes `ATTESTATION_POLICY_DEFAULT=production`, `MOCK_HOST_REQUIRE_TOKEN=true` and the two `*_REQUIRE_V2` switches. A token only cuts access where the backend requires it: every endpoint you protect must refuse a request without a valid `PinVault-Token`.

Both `enforce` modes refuse to start without the package and signer. They also mean emulators and phones with an unlocked bootloader cannot enroll or register a user-auth key: keep a test host on `warn`. `USER_AUTH_REQUIRE_PER_USE=true` locks out `user_auth` files on Android 7–10 phones without a strong fingerprint (the library gives those a 10-second key); if you must serve them, leave it off — Android 11 and later refuse time-bound keys regardless.

## Client configuration

```kotlin
PinVaultConfig.Builder()
    .configApi("prod", "https://config.example.com/") {
        bootstrapPins(listOf(HostPin("config.example.com", listOf(pin1, pin2))))
        signaturePublicKeys(SERVER_KEY, OFFLINE_BACKUP_KEY)   // any one may sign
        requiredSignatures(1)                                 // 2 = m-of-n
        recoveryPublicKeys(RECOVERY_KEY_1, RECOVERY_KEY_2)    // enables key sets
        requiredRecoverySignatures(1)                         // 2 = both recovery holders
    }
    .build()

PinVault.signingStatus()   // trusted key ids, key-set version, who signed the last config
```

Key ids are Base64 SHA-256 of the key's SubjectPublicKeyInfo, the same value `GET /api/v1/signing-key` and the dashboard show.

## Keys and where they live

- **Signing keys** sign configs and vault files. They are online: server file, HSM or KMS.
- **Backup signing key.** Its public half is compiled into the app and its private half is kept offline. Use it when the primary is lost.
- **Recovery keys** sign key sets and nothing else. They are offline (an air-gapped machine or a hardware token), ideally two, held by different people. They can never be signing keys, and a key set may not list one.
- **Admin keys** are personal. The server stores only their SHA-256.
- **The client CA** (`certs/client-ca.jks`, under `KEYSTORE_PASSWORD`, re-keyed with the other keystores; every server keystore is PKCS12 since 2.3.0 — the `.jks` names stay, a legacy JKS file is rewritten at start-up) signs every device certificate issued over a device-held key. Its certificate is the only thing the mTLS listeners trust for those devices; the database (`client_identities`) says which device keys are still allowed to renew.
- **The server CA** (`certs/server-ca.jks`, with a backup key in `server-ca.backup.jks`, both under `KEYSTORE_PASSWORD`) signs the recovery door's TLS certificate and nothing else. Apps pin both keys for `<host>:RECOVERY_PORT` only. Ten years; move the backup off the server once the app ships with its pin. If it is stolen, the thief can impersonate the recovery door — which issues nothing secret and whose answers the device checks against its own client CA — so the damage is blocked renewals, not stolen identities.
- **Device identity keys** are generated in each device's Android Keystore and never leave it. The server keeps their SPKI hash; a certificate is a 90-day credential over the key, renewed by a CSR the key signs.

The sample host's `scripts/signing-keys.sh` generates keys, builds and signs key sets, uploads them and installs a key for the local signer. `scripts/add-admin.sh` creates admin keys, and `scripts/softhsm-init.sh` prepares a SoftHSM token for the PKCS#11 signer.

## Operating the admin side

### What waits for a second admin

With `PIN_CHANGE_APPROVALS=2` a gated request is stored and answered `202`; nothing happens until another named admin approves it in the dashboard's Approvals tab. Gated, each under the operation name the approval card shows:

| What | Operations |
|---|---|
| Pins and what devices verify | `pins_update`, `force_on`, `force_off`, `host_add`, `host_cert`, `bootstrap_pins`, `signing_key`, `signing_keyset`, `host_acl`, `config_api_lifecycle`, `config_api_delete` |
| Who the mTLS listeners let in | `client_cert_upload`, `client_cert_generate`, `enrollment_policy_create`, `enrollment_open` (turning code-less applications on), `enrollment_token` |
| What the vault hands out | `vault_upload` (new file or replacement), `vault_delete`, `vault_policy` (access rule or encryption), `vault_token_issue`, `vault_token_revoke`, `device_key_reset` (E2E and user-auth keys), `vault_enabled` |
| Which devices attest and what backends trust | `attestation_policy`, `attestation_device` (a device override set or removed), `attestation_token_secrets` (reading the `PinVault-Token` secrets), `attestation_token_secret_rotate`, `attestation_token_secret_delete` |
| How the server runs | `server_settings` (settings saved from the setup wizard: approvals themselves, the live check, enrollment and attestation modes — one admin must not turn the two-person rule off alone) |

Not gated, on purpose: revoking and forgetting a device, stopping an enrollment code and turning code-less applications **off** (emergencies take effect at once), approving or rejecting a device that asked to enroll (that decision is already a second person's), and the setup wizard's "Restart now" (it applies only settings already saved, and approved). The full list, with the reason for each, is in the server's `GateCoverageTest`: a new admin write that is neither gated nor listed there fails the build.

**Letting a device in is the second person's act.** With `PIN_CHANGE_APPROVALS` 2 or more, approving a waiting enrollment request needs a personal key (`ADMIN_KEYS`, not the shared `API_KEY`: `409 named_admin_required`), and not the key of the admin who created the enrollment code (`409 own_enrollment_code`) — otherwise one admin could make a code and let their own device in, an mTLS identity minted alone. A code-less application has no creator to compare with (turning the switch on was itself approved by two): any personal key approves it. The approver is recorded in the audit entry (`approvedBy`, with `policyCreatedBy`). Rejecting stays open to any admin. With approvals off nothing changes.

Three things the approver can rely on:

- **A certificate change is fixed when it is requested.** For a generated, uploaded, rotated or fetched certificate — a host's or the Config API's own — the server works out the pins, the certificate's subject and validity and the Config APIs whose pins change at request time, shows them on the approval card and in the confirmation, and stores them. Approving installs exactly that: the URL is not read again and no key is generated again. If the pins of that Config API changed in the meantime, the request is stale and has to be made again.
- **An answer that carries a secret goes to the requester only.** A client P12, an enrollment token, an enrollment code, a vault token and the `PinVault-Token` secrets (`attestation_token_secrets`) are not produced by the approval. The request becomes *approved*, and the admin who asked repeats the same action; it then runs once and the result is shown to them. Nothing of it is stored with the request or reaches the approver.
- **What cannot be described is refused.** A certificate upload that is a CA, a vault upload with an unknown access rule, a malformed body: the requester gets the error, nobody is asked to approve it.

An uploaded client certificate must be one end-entity certificate. A CA (or any certificate allowed to sign certificates), one without the client-authentication usage, an expired one: all refused, with or without approvals. Neither upload nor generation brings a revoked client id back; forget the identity first, or use another id. An upload never replaces what an id already is: an active identity or another truststore entry under the same name (keystore aliases ignore case) is `409 client_id_in_use`. The names the server keeps for itself — `client-ca`, `server-ca`, `server`, `backup`, in any case — are no client id anywhere (`400 reserved_client_id`: upload, generate, tokens, open enrollment, revoke, forget); revoking or uploading `client-ca` used to remove or replace the CA every CSR identity chains to.

A host's client P12 (`POST /api/v1/hosts/{h}/upload-client-cert`) must hold exactly one private key; that entry is what the approval card shows, what is recorded and the only thing stored. A file with several keys is refused (`400`): which one a device's TLS stack would pick was not what the approver saw.

Starting or stopping a Config API takes an `id` of identifier shape and a `mode` of `tls` or `mtls` (`400` otherwise). The approval card for a start names the mode and, when another API holds the port, that the start **stops** it and the port then serves the new scope's pins.

#### Taking an operation out of the rule

`APPROVAL_EXEMPT_OPERATIONS=enrollment_token,vault_token_revoke` lets those operations run at once for any admin; an unknown name stops the server at start-up, and the exemptions are printed there. The trade-off is exactly the one the rule exists for: every exempt operation is something one phished key or one insider can do alone. `enrollment_token` exempt means one admin can enroll a device of their own; `vault_token_issue` exempt means one admin can read any token-protected file; `vault_token_revoke` exempt buys instant revocation at the price of one admin being able to cut devices off a file. Exempt what your on-call really needs at night, and nothing from the first table.

### Vault administration is on the management listener only

The device-facing Config API ports serve the download, the download report and device-key registration. Upload, delete, access rule, tokens, distributions and key resets are served only under `/api/v1/config-apis/{configApiId}/vault/…` on the management listener. Scripts that used `/api/v1/vault/…` on a Config API port for administration have to move.

A device that asks for a file that does not exist is told so (`404`) only when it showed an admin key or a client certificate. Anyone else gets the answer a token-protected file gives (`401`), so file names cannot be collected by asking. A mistyped key in an app therefore shows up as `401` on a TLS listener.

### Browser protections

The dashboard and the admin API are reachable from the administrator's browser, and so is every other page that browser has open.

- A state-changing admin request whose `Origin` is not the server's own, or whose `Sec-Fetch-Site` is `cross-site` or `same-site`, is refused (`403`). Behind a reverse proxy that changes the `Host` header, name the origin admins use in `ADMIN_ALLOWED_ORIGINS`.
- An admin write must be `application/json` or carry `X-API-Key` or `X-PinVault-Admin` (`415` otherwise): a form on another site can send neither.
- The dashboard keeps the admin key in the tab's session storage: it is gone when the tab is closed. A key an earlier version left in local storage is moved once and deleted.
- **Without admin keys** (`ALLOW_ANONYMOUS_ADMIN=true`, local development) nothing but the network protects the API, so the management listener binds `127.0.0.1` only, and every admin request, reads included, must be addressed to `localhost`, `127.0.0.1` or `[::1]` with the listener's port. That is what stops a web page from reaching it through a name pointed at 127.0.0.1 (DNS rebinding). `MANAGEMENT_BIND` chooses another address (a container needs `0.0.0.0` inside, with the port published on the host's loopback only), `MANAGEMENT_ALLOWED_HOSTS` adds `host:port` names. Device endpoints on that listener are not restricted by name. The `Host` header is the client's word, so every admin request must also come **from** this machine: the socket's peer is loopback, or one of `ANONYMOUS_ADMIN_PEERS` (IPs or CIDRs — through a container's port publish the peer is the bridge gateway, e.g. `172.17.0.1`; `403 peer_not_allowed` otherwise). **The Config API listeners serve no admin route at all without keys** (`403 admin_key_required`): they bind every interface for devices, and used to accept `PUT /api/v1/certificate-config` from anyone on the LAN. Device endpoints there are unchanged.
- **Wrong admin keys are cut off.** After `ADMIN_AUTH_FAILURE_LIMIT` (30) invalid keys in 10 minutes a source address gets `429` (`Retry-After: 600`) on every admin request, a right key included, on every listener. `0` turns it off. Correct keys are never counted; behind one NAT address a key-guessing neighbour locks the admins on that address out for the window.
- **`ping-remote` is a GET that opens connections**, so it asks what an admin write asks: no `Sec-Fetch-Site: cross-site|same-site`, and `X-PinVault-Admin` or `X-API-Key` (the dashboard sends both).

Refused requests are audited as `admin_request_refused`, one entry a minute at most.

### Required secrets

The server does not start while `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD` or `SIGNING_KEY_PASSWORD` is unset (the last one only when a local key file signs; each named local signer may have its own `SIGNING_KEY_PASSWORD_<NAME>`). They used to fall back to `changeit`, to a key printed in the source code, and to no encryption. `ALLOW_DEMO_SECRETS=true` brings those fallbacks back for local development and prints a warning; do not set it where real devices enroll. Nor with an `API_KEY` shorter than 16 characters (`openssl rand -hex 24`); `ALLOW_DEMO_SECRETS=true` accepts a short one with a warning (the Espresso server's `admin-key-123`).

A change waiting for approval keeps its request until it is decided — an uploaded P12 and its password, a generated keystore with its private key. Its body and plan are stored under `VAULT_AT_REST_PASSWORD` (AES-GCM, as vault files); requests stored before this release are read as they are. A request still waiting across a `VAULT_AT_REST_PASSWORD` change opens with `VAULT_AT_REST_PASSWORD_PREVIOUS`; without it, request it again.

The signing keys of `PinVault-Token` (ES256 private keys, or HS256 secrets) are sealed under the same password. At start-up every key must open with it: one that no password opens stops the server with a message naming `VAULT_AT_REST_PASSWORD` (it used to start and sign tokens with the ciphertext), one that only `VAULT_AT_REST_PASSWORD_PREVIOUS` opens is re-sealed under the current one.

The reference `docker-compose.yml` publishes the management port on `127.0.0.1` and runs the server as uid 10001, not root. Give it its data directories once (`chown -R 10001:10001 data`), or run it as yourself with `PINVAULT_UID`/`PINVAULT_GID`. Reach the dashboard from another machine through an SSH tunnel or a TLS reverse proxy.

### Signer isolation

With `CONFIG_SIGNERS=command` the server runs `SIGNER_COMMAND` to sign.

- **Its environment is an allowlist.** The command gets `PATH`, `HOME`, `LANG`, `TZ`, every `SIGNER_*` variable and what `SIGNER_PASS_ENV` names (for example `AWS_PROFILE,AWS_REGION`). Nothing else: no admin keys, no keystore, vault or signing-key passwords (or their `_PREVIOUS` values), no client P12 password, no webhook URL or secret. A server secret is not passed even if `SIGNER_PASS_ENV` names it.
- **That is not isolation.** The command runs as the server's own user. It can read every file the server can — the database, the keystores, a local signing key — and on Linux the server's whole environment through `/proc/<pid>/environ`. If the signer must not be able to read what the server holds (which is the point of m-of-n), run it as another user (`sudo -u signer /usr/local/bin/sign`, with the server's files unreadable to that user), in another container, or make the command a thin client of a socket or HTTPS service on another host. The same goes the other way round: the server's user must not be able to read the signer's key.
- **It is never run per request.** With any `command` or `pkcs11` signer the signature cache is on whatever `CONFIG_SIGNATURE_CACHE` says, and every client gets the cached envelope: one signing per distinct config (and per vault file version), however many requests ask. At most `SIGNER_MAX_CONCURRENT` (2) documents are at the signer at once and `SIGNER_MAX_QUEUE` (8) wait; beyond that a request gets `503` at once. Apps older than 2.1 treat a repeated envelope as a replay while nothing changed and keep the config they have.

### Webhook receivers

With `NOTIFY_WEBHOOK_SECRET` every delivery carries `X-PinVault-Timestamp` (Unix seconds) and `X-PinVault-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<body>` under the secret. A receiver should recompute the signature over the raw body, refuse a timestamp more than five minutes from its own clock, and refuse an `auditId` it has already accepted. A captured delivery can then not be sent again later. (Before this the signature covered the body alone: receivers that verify it have to add the timestamp.)

### Certificate fetches

"Add a host from a URL", "fetch this host's certificate", the live check (`PIN_LIVE_CHECK`, its dry run `POST /api/v1/pins/live-check`, and the approval card that runs it) and the dashboard's reachability probe (`GET /api/v1/hosts/{h}/ping-remote`) make the server open a connection to an address an admin names. Each is a handshake only, and none goes to link-local or cloud-metadata addresses (169.254.0.0/16, fe80::/10, 100.100.100.200). Loopback and private networks (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) are refused unless `FETCH_ALLOW_PRIVATE_TARGETS=true` — set it in a lab that pins hosts on its own LAN (`LIVE_CHECK_HOST_MAP` targets on loopback need it too). The name is resolved once and the connection goes to the address that was checked. A name must be one a pin entry may hold. `ping-remote` probes only a host pinned in the scope or registered, and only on the common TLS ports (443, 8443, 9443, 8444, 9444), its mock listeners' ports and the ports of its `host:port` pin entries; another `?port=` is `400`.

## Runbooks

### Planned signing-key rotation (key sets enabled)

1. Bring the new key up **next to** the old one: `CONFIG_SIGNERS=local,local:next`, or add `pkcs11` or `command`. Every config now carries both signatures.
2. Publish a key set that lists both keys: `signing-keys.sh keyset -v N -k server -s recovery-1`, then `upload`.
3. Make the new key primary: `CONFIG_SIGNERS=local:next,local`. The primary's signature is the only one apps older than 2.1 read, and they trust just their compiled-in key, so keep the old key primary until those app versions are retired.
4. Publish set N+1 that lists only the new key. The old key is now revoked on every device that fetches.
5. Retire the old signer.

The server refuses a set that its active signers could not satisfy. The dashboard's "regenerate" is disabled while a set is active, because a freshly generated key would be in no set.

### A signing key is stolen

- **With key sets:**
  1. Start a new key as an additional signer.
  2. Publish a set that lists **only** the new key, signed with the recovery key.
  3. Remove the stolen signer.

  Each device drops the stolen key the first time it fetches, and it never trusts that key again, not even through a later app restart or a restored backup. Then read the audit log for what was published with the stolen key, and look for `auth_failed` bursts.
- **Without key sets:** switch the server to the offline backup key (`signing-keys.sh install backup-1`). Devices accept it immediately, but the stolen key **stays trusted** until an app update removes it. Ship that update.

### The signing key is lost (server wiped, HSM gone)

- Install the offline backup key, or publish a key set for a new key.
- Without either, every installed app needs an update. This is the main reason to have at least Level 1.

### A recovery key is compromised or lost

- Recovery keys are compiled into the app, so replacing one takes an app update.
- `requiredRecoverySignatures(2)`, with the two keys held apart, means a single compromised recovery key is not enough to publish a set.

### Wrong pins were published

With `PIN_LIVE_CHECK=enforce` this is refused unless someone overrode it, and every override is audited and notified. If it happens anyway:

- Publish the corrected set. Versions only move forward, so the fix is a new version, not a rollback.
- Devices recover through pin-mismatch recovery, which refetches the config when a handshake fails. A circuit breaker (3 failures in 5 minutes, then 10 minutes of cooldown) keeps them from hammering the server.

### Planned TLS certificate rotation

Every host carries two pins. For a certificate the server generated, the second belongs to a backup key the server keeps in `certs/<id>.backup.jks`. "Switch to Backup Key" in the dashboard (`POST /api/v1/hosts/{hostname}/rotate-to-backup`) reissues the certificate with that key, prepares a new backup and publishes `{backup, new-backup}` in one step. Devices already hold the backup pin, so they keep connecting without a config refresh. A mock host served by this server switches at once; a host that serves an exported keystore must get the new one right away, because devices that fetch the new list reject the old key until then.

For the config server's own certificate it is `POST /api/v1/server-tls-pins/rotate-to-backup` and a restart. Apps carry the backup pin as a bootstrap pin, so no app update is needed. Put the new backup pin into the next release.

Certificates generated before backup keys were kept, and hosts whose pins were fetched from a URL, have no stored backup (the endpoints answer 409). An uploaded certificate gets one when it is uploaded. Regenerate once to get one; for the config server's certificate that costs one more app update.

### A pinned host's TLS key is stolen

Which backup is still safe depends on where the key leaked from.

- **Somewhere other than the server's `certs/` directory** (a load balancer it was exported to, a backup copy, a laptop): switch to the stored backup key as in the planned rotation above. The stolen key's pin leaves the list in the same step.
- **The server's `certs/` directory was read.** The stored backup was taken with the key, so regenerate the certificate instead. Devices recover through pin-mismatch recovery. For the config server's own certificate, apps need an update with the new bootstrap pins.
- **A host whose pins were fetched from a URL:** its backup pin is its CA's. Have the site reissued by the same CA with a new key; devices accept the new leaf through the CA pin. Then publish the new leaf with the CA pin to drop the stolen key's pin. With `PIN_LIVE_CHECK=enforce` a set is accepted only if devices would accept what the host serves at that moment, which this order satisfies.

### Changing the keystore password

Put the new password in `KEYSTORE_PASSWORD` and the old one in `KEYSTORE_PASSWORD_PREVIOUS`, then restart. The server re-encrypts its keystores, backup keys, truststore and stored host client certificates at startup and logs what it moved. Remove `KEYSTORE_PASSWORD_PREVIOUS` afterwards. Devices are not affected: the password never leaves the server.

### Changing the vault password

Same pattern: new password in `VAULT_AT_REST_PASSWORD`, old one in `VAULT_AT_REST_PASSWORD_PREVIOUS`, restart. At startup every at_rest and per-device file that opens only with the previous password is re-encrypted under the new one; files written while the variable was unset (the demo password) move over without `_PREVIOUS`. A file that no password opens is named in the log, and downloads of it fail until the old password is supplied or the file is uploaded again: the server never hands a device the encrypted bytes as the file. The `PinVault-Token` secrets move over the same way, except that one no password opens refuses the start (tokens would be signed with the wrong bytes): supply the old password, or delete that secret. Devices are not affected.

### The config server is down

Devices keep their stored config and pins. Only a config marked `forceUpdate` makes a device refuse to start without the backend, so use force sparingly.

### A device certificate is about to expire, or has expired

Nothing to do. The library renews with a third of the lifetime left over the mTLS connection, and an expired certificate is renewed over the recovery URL (`renewalUrl`, a TLS listener) with the CSR signature as proof of the device key. Both show up in the audit log as `client_cert_renewed` with the door used (`via: mtls | recovery`); the dashboard's mTLS tab lists expiry and renewal counts. A device that stays offline past its expiry recovers on its next start. Only a device whose Keystore key is gone (app reinstalled, factory reset) needs a new enrollment token.

### The recovery door's certificate

Nothing to do: the server reissues it (new key, same server CA) 30 days before it expires and restarts the door. Apps pin the CA, so they never notice. If the active server CA key is lost or stolen, stop the server, replace `server-ca.jks` with `server-ca.backup.jks`, delete `recovery.jks` and start it — the door comes back under the backup CA, whose pin every app already carries. Generate a new backup and ship its pin in the next app release.

### Proven device ids

A device id sent at enrollment (`deviceUid`, the ANDROID_ID) is the enrolling party's word: whoever holds a token or a code and knows another phone's ANDROID_ID could name it. Such a *claimed* id still ties the certificate to the device for reports and `X-Device-Id`, but opens nothing of that device's. Only a **proven** id lets the certificate replace the device's E2E or user-auth key without the device's token, open its `token_mtls` files, take host client certificates under a per-device host ACL, and lift the device's revocation block. An id is proven (migration V20, `client_certs.device_uid_proven`) when:

- the client id is the device id (open mode, or a token minted with the ANDROID_ID as client id);
- the administrator bound the token to it: `POST /api/v1/enrollment-tokens/generate {"clientId":"tablet-7","deviceUid":"<ANDROID_ID>"}` (dashboard: the *Device id (ANDROID_ID)* field of the enrollment-token form; the sample app shows the id on its mTLS screen) — an enrollment with that token naming another device is `403 device_uid_mismatch`, before the token is spent;
- the enrollment key's Android Key Attestation passed with the app binding (`ATTESTATION_PACKAGE_NAMES` + `ATTESTATION_SIGNER_SHA256`): its challenge is the device id.

Re-sending the device's existing public key over a certificate no longer counts as proof of anything: it is a public key. Existing identities start unproven — mint bound tokens for devices that use `token_mtls` files or replace keys over mTLS, or have them enroll with an attested key.

### Revoking a device

`DELETE /api/v1/client-certs/{id}` (or the dashboard's Revoke). From the next request on, every mTLS Config API listener and every mock mTLS host answers that device `403 reenroll_required` (audited as `client_cert_revoked_refused`, summarised per minute): the TLS handshake still succeeds — the listener trusts the client CA — but nothing is served, and renewal is refused the same way. The device hears it at that request: from 2.1.1 the library emits `ClientCertRenewal(status = REENROLL_REQUIRED)` the first time any request is refused this way (2.1.0 noticed only when renewal came due). The client id stays revoked: a new enrollment under the same id is refused, so issue a new id. In the same transaction the device is cut off the vault: every vault token it holds, in every Config API, is revoked and its E2E and user-auth keys are deleted (audited as `client_cert_revoked`, with what was taken).

**Which devices are cut off.** Only device ids the identity *proved*: its own client id (in open enrollment that is the device id) and the device ids for which it used one of the device's vault tokens over its own certificate — on a download, or with a key registration — or re-registered over it the key the device had on file before the identity was enrolled (recorded as it happens, `identity_devices`). Registering a new key, or its own key again, proves nothing: the certificate is tied to the device id only by what was claimed at enrollment. The `deviceUid` sent at enrollment is a claim — anyone with a token or code can name another phone's id — and a revocation that wiped every claimed id would let someone enroll as a victim's device, get revoked, and take the victim's tokens and keys with them. Claimed but unproven ids come back in the response as `unverifiedDeviceIds` and in the audit entry as "left alone". If you know they really are that identity's devices, cascade deliberately: `DELETE /api/v1/client-certs/{id}?cascadeUnverified=true` (again on an already revoked id is fine; `…/forget?cascadeUnverified=true` takes the same flag). A device id another active identity holds is left alone either way.

**When to press "Cut these devices off too".** The dashboard shows the ids that were left alone right after *Revoke* (and before *Forget identity*, which asks *Forget only* or *Forget and cut these devices off*), with the cascade behind a confirmation; it never cascades by default. Press it when the revoked identity was the phone itself — a stolen or lost device, an employee leaving with it, a device you know is compromised — and the listed id is that phone's id (the device id you issued its tokens for; with a token or code enrollment the client id differs from it, so a device that never used a token over its certificate has proved nothing and is always listed). A thief's phone keeps its vault tokens and keys otherwise, and can still download `token` files on a TLS Config API. Do **not** press it when you revoked an identity you do not trust to have named its own device — a leaked code or token used by someone else, an identity that showed up claiming a phone you know to be elsewhere — because the listed id may be the victim's phone, and cutting it off wipes that phone's tokens and keys.

A TLS Config API asks no certificate, so there a download with a still-valid token for a cut-off device (`token`, `token_mtls`) is refused with `403 reenroll_required` too. The check comes after the token check: a caller without a credential is handled exactly as for any device id, so nobody can probe which device ids were revoked — not from one answer and not from a sequence of them. That has a consequence to know: where nothing authenticates the caller, revocation plays no part. A key registration without a credential is kept for a revoked device id as for any other (first key kept, a different one `409`; the audit entry says the id's identity was revoked), and an `end_to_end` / `user_auth` file under the `public` policy is then served to it — as it is to anyone who makes up a device id. Revocation took the device's keys, tokens and certificate; files that must stop reaching a revoked device belong under `token` or `token_mtls`.

Revocation is **not** behind two-person approval (`PIN_CHANGE_APPROVALS`) on purpose: when a device is stolen it has to stop working now, not when a second admin wakes up. It is audited and pushed to the webhook like every admin write.

To use the same client id again — in open enrollment it is the device's own id, so a revoked device could never enroll again otherwise — press *Forget identity* on the revoked row (`POST /api/v1/client-certs/{id}/forget`, audited as `client_identity_forgotten`). Only a revoked identity can be forgotten. Every key the client id enrolled with is retired first, so its old certificates stay refused on every request and those keys never get a certificate again, under any client id; the device enrolls again over a new key, which means unenrolling (or clearing the app's data) on the device first. Keys retired this way are kept for good (`client_keys`). A key replaced by re-enrolling the same id (a new token for it, or a server-made P12 over a CSR identity) is retired the same way at that moment.

### A device is enrolled again under a new client id (409)

The server keeps one active identity per device id (the `deviceUid` a device sends at enrollment, its ANDROID_ID). token_mtls files and E2E key registration trust that id to tie a certificate to a device, and it is self-reported — so a second identity claiming a device id that is already enrolled is refused with `409 device_already_enrolled`, before its token is spent (audited as `client_cert_enroll_refused`). A reinstalled app has lost its key; either mint the new token for the device's old client id (re-enrolling the same id replaces it and retires the old key), or revoke the old id and let the device retry with the token it already has. One identity covers every mTLS Config API of a server: they all trust the same client CA.

With `ENROLLMENT_MODE=open` (demo only) the device id is the client id and nothing else authenticates the request, so an enrolled id is never replaced: another key asking for it gets `409 identity_already_enrolled` (the same key asking again is served), and open mode issues certificates only over a CSR (`403 csr_required` for a P12 request). A device that lost its key comes back after an administrator revokes and forgets its old identity.

### Enrolling a fleet with one code

Create an enrollment policy (dashboard: mTLS Config API → *Client Certificates* → *Enrollment policies*, or `POST /api/v1/enrollment-policies`): a name, the most devices it may enroll, how many days it is valid, and whether each device needs approval. Keep approval on unless the code travels only over a channel you control (an MDM profile, your own signed-in backend): with approval a leaked code lets strangers *ask*, not enroll. Set the device limit and the days to the rollout at hand, not to "enough for later" — a new code costs one click. Approve from *Devices awaiting approval* only what you expect: the row shows the device model and id, the source address, the time, a verification code and whether the device's key is *Hardware-attested*, and the webhook announces each one (`enrollment_request_pending`). The device shows the same verification code (it is made from the device's key: 16 characters, `XXXX-XXXX-XXXX-XXXX`, 80 bits since 2.2.0): compare all of it before approving. Under `ENROLLMENT_ATTESTATION=warn` a *Not attested* key (hover for the reason) is an emulator, a rooted or modified phone, an old phone, or an app that is not yours: approve it only if you know why. A device that already has an active identity (a reinstall) is flagged; revoke the old identity first, then approve.

### An enrollment code leaked

*Stop* the policy (or `POST /api/v1/enrollment-policies/{id}/stop`). From that moment the code is answered like a used token, and devices still waiting are turned away; devices approved before keep the right to pick up their certificates. Then look at what came in with it: the audit log has `enrollment_request_pending` and `client_cert_issued` entries naming the policy, with addresses — revoke any identity you do not recognise (`DELETE /api/v1/client-certs/{id}`). Hand the remaining devices a new code.

### Letting devices in without a code

For devices that cannot be handed a code (no camera, no keyboard, kiosks): turn *Applications without a code* on in *Devices awaiting approval* (or `PUT /api/v1/enrollment-open` `{"enabled": true}`, audited as `enrollment_open_changed`). Every device running the app can then ask (`autoEnroll`) and waits in the list marked *without a code*; nothing is issued without an approval. Approve by the verification code on the device's screen when it has one; otherwise by model, source address and time — approve only while you are expecting the device, and reject what you cannot place. Keep the switch on only for the rollout: off, new devices get `403 Token required`, and the waiting ones can still be decided. If the list fills with strangers, turn it off and reject them; the limits keep it bounded meanwhile — `OPEN_ENROLLMENT_RATE_LIMIT` new applications per source address per 10 minutes (default 20; devices behind one NAT share it, so raise it for a large rollout from one site), `OPEN_ENROLLMENT_MAX_PENDING` waiting at once (default 50), and every unanswered request lapses after `ENROLLMENT_REQUEST_TTL_HOURS` (default 24). A device asking twice shows every one of its requests flagged (`sameDevicePending`). Approve none of them: reject every duplicate and ask the device to apply again. A device id is only claimed — one of the requests may be someone else naming the same device — and a reinstall that applies again after the rejection costs the real device a minute.

### A device cannot register its encryption key (409, 429, 503)

A device's user-auth key (`"purpose":"user_auth"`, for `user_auth` files) is registered and counted apart from its E2E key, under stricter rules: see *User-auth keys and attestation* below. Without one, the device's `user_auth` downloads get `412 user_auth_key_required`.

Only on a TLS Config API. It keeps the first E2E key a device registered; a device whose app data was cleared comes back with a new Keystore key and is refused (`409 key_change_requires_proof`, audited as `device_key_refused`) unless it presents its token for one of that scope's `end_to_end` files — the library sends one whenever the app has it, so issuing the device a token for such a file is enough. A device with no such file has nothing to prove itself with: remove its old key (`DELETE /api/v1/config-apis/{configApiId}/vault/devices/{deviceId}/public-key`, audited as `device_key_reset`) and it registers again at its next start. On an mTLS Config API there is nothing to do: a certificate that belongs to the device may replace its key.

On a TLS Config API the endpoint asks for no credential, so it is bounded. `429 rate_limited`: the device's address wrote `DEVICE_KEY_RATE_LIMIT` keys in the last 10 minutes (default 30; a device repeating its own key is not counted). Many devices behind one address (an office NAT, a reverse proxy) starting for the first time look like this; they retry at their next start. Raise the limit for a rollout (`0` turns it off), or move the `end_to_end` files to an mTLS Config API, where it does not apply. `503 device_key_limit_reached`: the Config API holds `DEVICE_KEY_LIMIT` keys (default 100 000) and new devices are not stored; known devices keep working. That many is usually made-up device ids: the `device_key_registered` audit entries show their source addresses. Remove them (`DELETE …/vault/devices/{deviceId}/public-key`, or in the database with the server stopped) or raise the limit. Both refusals are audited as `device_key_refused`.

### A device is answered 413, 429 or `tls_required`

The endpoints devices reach without an admin key are bounded, because anyone who reaches the port can call them. The address every limit counts is the TCP peer (an IPv6 address by its /64): behind one NAT, a reverse proxy or Docker Desktop's port forwarding every device shares it, so size the limits for the site, not for one phone.

- **`429 rate_limited` on enrollment, key registration, a vault download or a host client certificate download.** The address collected `DEVICE_REFUSAL_RATE_LIMIT` refusals (400, 401, 403, 404, 409, 411, 413) on those endpoints in the last 10 minutes (default 300, `0` = off) and is cut off there until the window ends, before anything is read or parsed (audited as `device_rate_limited`, summarised per minute). Requests that are served are never counted, so a fleet working normally does not use the quota up; a fleet that keeps asking for something it is refused does — a file whose tokens were revoked, a vault switched off, an app pointing at a file that is gone. Fix what is refused, or raise the limit for that site.
- **`429` on certificate renewal.** Refused renewals count per address (10 in 10 minutes, whatever client id they name), successful ones per identity (10 in 10 minutes). A device hears `403 reenroll_required` once and stops, so only something sending renewals in a loop gets here.
- **`429` on a report**, and gaps in the dashboard's history. A source address files at most `REPORT_RATE_LIMIT` reports per 10 minutes (default 600) and a device `REPORT_DEVICE_RATE_LIMIT` (default 120); the library ignores the refusal and reports again next time. Reports ask for no credential on a TLS Config API — a device that cannot authenticate is the one whose report matters — so read them as claims: fields are checked or cut to size and the time is the server's, but a row says what a caller said. History is kept per Config API: the newest 500 successful vault downloads and, apart from them, the newest 1000 failures; the newest 200 healthy connection rows and, apart, the newest 500 failures (`pin_mismatch`, `config_update_failed`). A flood of healthy reports therefore cannot push a `pin_mismatch` out, and reports sent to one Config API cannot touch another's history; a flood of made-up *failures* can still displace real ones, and shows as exactly that. On an mTLS Config API a vault report must be about the certificate's own device (`403 device_identity_mismatch`).
- **`413 body_too_large`.** A device request body is at most 64 KB, counted while it is read — a body that declares no length (HTTP/2 allows that) is cut off at the cap, not read whole. A vault upload is at most `VAULT_MAX_FILE_BYTES` (default 50 MB): the file is held in memory and stored in one row, so raise it only with the heap to match.
- **`400 invalid_csr` for a device that used to enroll.** A CSR is accepted only over RSA 2048–4096 with public exponent 65537, or EC P-256 / P-384; Android Keystore keys are one of these. Other key types were never issued for, and are now refused before any signature is verified.
- **`403 tls_required`.** Enrollment (and any device endpoint that takes a token or returns a key) is not answered on the management server's plain-HTTP port except to the server's own machine: the token, the private key and its password would cross the network readable. Point devices at a Config API port, or set `MANAGEMENT_HTTPS_PORT`. A TLS-terminating proxy on another host does not help — the hop from it to the server is the cleartext one.
- **`403 host_not_allowed` on a host client certificate.** Where a Config API has a device host ACL (a default entry or any per-device grant), a device downloads the client certificate only of hosts the ACL allows it — the same list that decides which pins it gets. Grant the host (dashboard: *Device ACL*, or `PUT …/devices/{deviceId}/host-acl`), under the device id the certificate enrolled with. A Config API without any ACL serves every enrolled device as before.

**Listener restarts.** A server-made P12 enrollment, a generated or uploaded client certificate and a P12 revocation change the client truststore, which the mTLS listeners (Config APIs and mock hosts) read when they start. The restart runs at once for the first change and at most once per `MTLS_RESTART_MIN_INTERVAL_SECONDS` (default 5) after that, later changes folded into one restart — a device that enrolls with a P12 during a burst may wait that long before its certificate is trusted. CSR enrollment needs no restart.

### Enrollment key attestation

A client certificate is only as good as the key it was issued over. Over a CSR the device keeps its key, but the server cannot tell from the CSR whether that key sits in the phone's secure hardware or in a file that root code — or an emulator posing as the app — can copy. Since 2.2.0 the library sends the key's Android Key Attestation chain with every CSR enrollment (`attestationChain`, Base64 DER, leaf first; on the code and code-less paths with the first request and again when picking up). The server checks it (`ENROLLMENT_ATTESTATION`) with the same verifier and settings as user-auth keys, against a second profile:

- the leaf is the CSR's key; the challenge is SHA-256 of `pinvault-identity-key:v1:<deviceUid>` — the request's `deviceUid`, or its `deviceId` when it sends none (the library hashes exactly that into the key);
- a SIGN key, generated (not imported) in TEE or StrongBox; no user-auth requirement;
- locked bootloader and verified boot (`ATTESTATION_REQUIRE_VERIFIED_BOOT`), your app's package and signer (`ATTESTATION_PACKAGE_NAMES` + `ATTESTATION_SIGNER_SHA256` — without both nothing counts as attested), no revoked certificate, the patch level (`ATTESTATION_MIN_PATCH_LEVEL`) and a current revocation list (`ATTESTATION_STATUS_MAX_AGE_HOURS`).

It runs after the cheap refusals (revoked id, device enrolled elsewhere, retired key) and **before** a token or a policy slot is spent, so a refusal costs the device nothing.

- **`off`**: the chain is not read.
- **`warn`** (default): every enrollment goes ahead; the verdict is stored with the identity and shown in *Devices awaiting approval* and in the client certificate list (*Hardware-attested* / *Not attested* with the reason / *Not checked* / *Made by the server* for a P12). The audit entries (`enrollment_request_pending`, `client_cert_issued`) carry it too.
- **`enforce`**: `403 attestation_required` without a chain (or without a `deviceUid`/`deviceId` to check it against), `403 attestation_invalid` with a `reason` for one that fails; and since a key made on the server cannot be attested, an enrollment without a CSR gets `403 csr_required`. A request recorded under `warn` before the switch is issued under `enforce` only when the pickup carries a passing chain. The library maps both refusals to `EnrollmentRefusal.ATTESTATION_FAILED` (and, when its key carried no chain, makes a new key once and asks again).

Emulators attest in software and fail (`software_attestation`); so do phones with an unlocked bootloader (`device_unlocked`). Run test hosts on `warn`.

### Server-made keys (P12) and old trust anchors

`ENROLLMENT_P12=on` (default) keeps apps that cannot make a CSR working: an enrollment without one gets a server-made key in a P12. Production runs `ENROLLMENT_P12=off`: every path that would make a key here — the Config API and management copies of `POST /api/v1/client-certs/enroll`, and *Generate client certificate* (`POST /api/v1/client-certs/generate`) — answers `403 csr_required` before anything is spent (the library reports `CSR_REQUIRED`). `ENROLLMENT_ATTESTATION=enforce` implies the same.

Since 2.2.0 a P12 certificate is issued by the **client CA** — CA:false, client authentication only, one year; the bundle carries the leaf and the CA — and nothing is added to the truststore, so no listener restarts. Until then each P12 was a self-signed leaf added to the truststore as its own trust anchor, and the identity is read from the certificate's CN: an anchor that may sign (any on a JDK running with `jdk.security.allowNonCaAnchor=true`, or a v1 certificate on any JDK) let its holder sign a leaf naming **another** client id and be accepted as that device. Now:

- **Every mTLS request** (Config APIs and mock mTLS hosts) must present the certificate on record for the id its CN names — one over the identity's registered key (CSR enrollments), or exactly the stored certificate (P12s, uploaded certificates) — otherwise `403 reenroll_required`, audited as `client_cert_revoked_refused` with "certificate not on record".
- **Old anchors keep working** until they expire or the id enrolls again. Any new enrollment of the id (CSR, P12, *Generate*) removes its anchor from the truststore, retires its key (`client_keys`: refused on every request even before the listeners restart) and restarts the mTLS listeners once. Nothing else needs doing; to clear them all at once, revoke the old P12 ids and let the devices enroll over a CSR.
- **Uploaded client certificates** stay anchors, so they must be leaves that say what they are for: v3, no CA flag or `keyCertSign`, an extended key usage that includes client authentication (`400 invalid_client_certificate` otherwise; v1 certificates and certificates without the extension were accepted before 2.2.0 — re-upload those as proper leaves).

### User-auth keys and attestation

A `user_auth` file is sealed to the device's user-auth key, whose private half the phone's hardware uses only after the user unlocked. That holds only if the key really is such a key. Root code running as the app holds everything the app holds — its client certificate, its vault tokens — so it could register a software key of its own and read the next copy of the file without anyone unlocking. Android Key Attestation closes that: the library sends the key's certificate chain (`attestationChain`, from `KeyStore.getCertificateChain`), signed by the phone's secure hardware under a Google root, stating how the key was made. The server checks it (`USER_AUTH_ATTESTATION`):

- **What a passing chain proves:** the chain reaches a Google hardware attestation root (shipped in `attestation/google-hardware-attestation-roots.pem`; trust is by root key, so a root past its own end date still counts, but every certificate below it must be current); the leaf is the key being registered; the key lives in the TEE or StrongBox, cannot be used without the user (a `userAuthType`; no `noAuthRequired` and no `allowWhileOnBody` in either authorization list; no `authTimeout` over 10 seconds in either list — `auth_timeout_too_long` otherwise), decrypts, was generated on the phone (not imported); the bootloader is locked and the boot verified (`ATTESTATION_REQUIRE_VERIFIED_BOOT=false` to drop this for test phones); the challenge is SHA-256 of `pinvault-user-auth-key:v1:<deviceId>`, so the key was made for this device id; and, with `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256` (the SHA-256 of your release signing certificate), it was made by your app. With `ATTESTATION_MIN_PATCH_LEVEL=YYYYMM` the phone's security patch must be at least that (`patch_level_too_old`).
- **Root running as the app cannot pass with a key of its own making — as long as the key must ask on every use.** Root holds the app's uid, so it can delete the per-use key and generate one in the same hardware, with the right challenge, that the attestation describes truthfully — except that it works for some seconds after any unlock (`authTimeout`), letting root decrypt right after the user unlocks the phone for anything else. The library makes per-use keys on Android 11 and later, so there a key with any `authTimeout` above 0 is refused (`time_bound_key`, read from the attested osVersion). On Android 7–10 the library itself falls back to a 10-second key on phones without a strong fingerprint; `USER_AUTH_REQUIRE_PER_USE=true` refuses those too (production), at the price of those phones' `user_auth` files. Every passing key is stored with its kind — `per_use` or `time_bound` with its seconds, and whether only a biometric unlocks it — listed under `GET /api/v1/config-apis/{configApiId}/vault/devices/user-auth-keys`.
- **The revocation list.** `ATTESTATION_REVOKED_SERIALS_FILE` points at a copy of Google's attestation status list (`https://android.googleapis.com/attestation/status`). The server never fetches it; it re-reads the file when its modification time changes (looked at every 10 minutes and on verifications). Keep it current with a cron job: `demo-server/scripts/fetch-attestation-status.sh /data/attestation-status.json` (curl, checks the answer is the list, atomic rename; a failed fetch leaves the old file). With `ATTESTATION_STATUS_MAX_AGE_HOURS` set, once the file is older than that **no attestation passes** (`revocation_list_stale`): under `enforce` new keys and enrollments are refused until the job runs again, under `warn` they are recorded as not attested. Pick a value a few fetch intervals long (48 with a 6-hour job) and watch for the reason in the audit log.
- **The app binding is what makes an attestation count.** Without both `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256`, any app on any locked phone can make a key with *any* device id's challenge, so the chain says nothing about whose device it is. The server then lets no attestation count (stored with reason `app_binding_not_configured`): `enforce` refuses to start, `warn` prints a warning at start-up. With the signer bound, the genuine app on a stranger's phone attests that phone's own device id, never someone else's.
- **`off`**: nothing is checked; the first key is accepted; replacing it is an administrator's job.
- **`warn`** (default): the first key is accepted with or without a passing chain, and without any credential — trust on first use — and the outcome is stored with it.
- **`enforce`**: every first key needs a passing chain (`403 attestation_required` without one, `403 attestation_invalid` with a `reason` such as `software_attestation`, `device_unlocked`, `package_not_allowed`, `auth_timeout_too_long`). The sample host's production profile sets `enforce` with `com.example.sampleclient` and asks for the signer.

**Replacing a registered user-auth key needs both, in every mode:** the device's credential (a client certificate bound to the device, or the device's token for one of the scope's `end_to_end` / `user_auth` files) **and** a new key whose attestation passes. Root code running as the app holds the credential but cannot attest a key it controls; a stranger with a phone of their own can attest a key for the victim's device id (without the signer binding) but has no credential. Otherwise `409 user_auth_key_exists` with a `reason`: `credential_required`, `attestation_off`, or the attestation's own reason (`chain_missing`, `app_binding_not_configured`, `challenge_mismatch`, …). A chain sent without a credential is not even verified. Registrations, replacements and refusals are audited with the attestation outcome; `device_key_replaced` goes to the webhook.

An attestation is never a credential for anything else: a revoked device's `reenroll_required` answer goes only to a caller with a bound certificate or a valid token.

**Emulators and test hosts.** An emulator produces a software attestation (no TEE), and a phone with an unlocked bootloader fails the boot check: under `enforce` neither registers a user-auth key. Test hosts run `warn` (the demo profile) or `off`.

**Checking what you have.** `GET /api/v1/config-apis/{configApiId}/vault/devices/user-auth-keys` lists each key with `attestation` (`attested`, `securityLevel`, `reason`, `keyKind`, `authTimeoutSeconds`, `biometricOnly`; null = not checked). Under `enforce` a key on file that was registered without a passing attestation (before `enforce` was switched on) is **not sealed for**: the download answers `412 user_auth_key_required` with `reason: key_not_attested`, the library registers the key again with its chain, and the file follows once it passes. With `USER_AUTH_REQUIRE_PER_USE=true` the same happens to a `time_bound` key (`time_bound_key`) and to a key attested before kinds were recorded (`key_kind_unknown`, settled by the re-registration). A key that cannot pass (made without a challenge, or time-bound) stays refused — the same key sent again is answered `403 attestation_required` / `attestation_invalid` — until the device makes a new one; reset it so the new one counts as a first key.

**Resetting a device's user-auth key** (a new phone, a factory reset, a key registered under `warn` you do not trust): `DELETE /api/v1/config-apis/{configApiId}/vault/devices/{deviceId}/public-key?purpose=user_auth` (audited as `device_key_reset`). The device's next registration counts as its first. A device that still has its client certificate or token does not need this under `warn`/`enforce` with the app binding set: its new key's attestation passes and, with the credential, replaces the old one.

#### A device's `user_auth` files stop with `409 user_auth_key_exists` (by design)

The phone retires its user-auth key when the key can no longer be used — a fingerprint was added, the screen lock was removed, the app was unenrolled with its vault files wiped, or the app data was cleared — and registers a new one. The server keeps the old one unless the new one comes with the device's credential **and** a passing attestation. It does not when: the server runs `off`; it runs `warn` without `ATTESTATION_PACKAGE_NAMES` + `ATTESTATION_SIGNER_SHA256`; the phone cannot attest (an emulator, an unlocked bootloader, a phone without hardware attestation); or the device lost its certificate and has no token for an `end_to_end` / `user_auth` file. The device then gets `409 user_auth_key_exists` (audited as `device_key_refused`, with the `reason`) and its `user_auth` files stay locked until an administrator resets the key:

1. Check the refusal is the device and not someone else: the `device_key_refused` audit entries for that device id, their source address and `reason`; ask the user whether they changed the screen lock, fingerprints or reinstalled.
2. Reset it: `curl -X DELETE -H "X-API-Key: $KEY" "https://<server>:<management-port>/api/v1/config-apis/<configApiId>/vault/devices/<deviceId>/public-key?purpose=user_auth"` (`200 {"removed":"true"}`; `404` = no key; audited as `device_key_reset`).
3. The device registers its current key at its next start or fetch (first registration again: accepted under `off`/`warn`, needs a passing chain under `enforce`) and downloads its `user_auth` files sealed to that key.

Do not reset on a request you cannot tie to the device's owner: a reset is what an attacker who wants a file sealed to *their* key needs.

### Rotating the client CA

Not automated, and it means re-enrollment: a device accepts a renewed certificate only from the CA that issued its current one, so after a client CA change every CSR-enrolled device — and every P12 issued since 2.2.0, which the client CA signs too — has to enroll again with a new token. Stop the server, move `certs/client-ca.jks` away, start it: a new CA is generated and added to the truststore under the same alias. Plan it like a fleet re-enrollment.

## Known limits

- Recovery renewal proves possession of the device key and nothing else: a key extracted from a rooted device without hardware-backed Keystore keeps renewing until the client id is revoked. `ENROLLMENT_ATTESTATION=enforce` keeps such keys from enrolling in the first place; under `warn` they enroll, marked *Not attested*. Renewal does not attest again.
- **Old self-signed P12 certificates stay trust anchors** until they expire (a year) or their id enrolls again; every request is held to the certificate on record for its CN, which keeps an anchor from impersonating another id, but the anchor itself remains a way into the mTLS listeners for its holder until then.
- Client identities (`client_identities`, `client_certs`) are global, not per Config API, like the truststore.
- **The device id is self-reported unless proven** (see *Proven device ids*). One active identity per device id — decided in the statement that writes the identity, so two enrollments racing for one device cannot both win — stops a second enrollment from taking over an enrolled device, but whoever enrolls *first* with a given id holds it — a stolen enrollment token used before the real device can claim the real device's id. The real device's enrollment then fails with `409`, which shows the theft; revoke the thief's id. After enrollment, an mTLS Config API holds a device to it: `X-Device-Id` must belong to the client certificate (`403 device_identity_mismatch`). A TLS Config API cannot check it: there the per-device host ACL only shapes what an honest device receives, and a `token` file opens for whoever holds the token. Because the id is only claimed, revoking an identity cuts off only the device ids it proved (see *Revoking a device*); the rest need `cascadeUnverified=true`.
- **Device-facing request bodies are capped at 64 KB** (`413`, declared or not; a chunked HTTP/1.1 body without a declared length gets `411`). Vault uploads are capped at `VAULT_MAX_FILE_BYTES`; other admin uploads (keystores, certificates) and admin JSON bodies are capped at `ADMIN_UPLOAD_MAX_BYTES` (1 MB by default, `413` beyond).
- **Every per-address limit trusts the TCP peer address.** Many devices behind one address share a quota (see *A device is answered 413, 429 or `tls_required`*) — a carrier-grade NAT, an office NAT, and on Docker Desktop **every** client, phone or browser, arrives from the one gateway address; someone with many addresses gets a quota for each. When a limiter's table is full (10 000 live windows), a new address is counted in the bucket of its network (IPv4 /24, IPv6 /48) instead of being refused, so a flood from many addresses limits those networks and not the whole server; limits keyed by an identity that just proved itself (renewals, issuance, key replacements) let a new identity through when full. The limits bound what one source costs the server, not who may call.
- **Successful work is bounded per identity.** A device asking again with the same key gets the certificate it was given while half its lifetime is left (no new signature, audit entry or webhook); beyond that, `ISSUANCE_RATE_LIMIT` (10) certificates per client id, `KEY_REPLACEMENT_RATE_LIMIT` (10) key replacements per certificate, `PICKUP_RATE_LIMIT` (120) pickups per waiting request and `PICKUP_SOURCE_RATE_LIMIT` (600) per address, all per 10 minutes, `429` beyond. `VAULT_DOWNLOAD_CONCURRENCY` (4) downloads run at once per address. Reports on a TLS listener are counted per address only (a claimed device id would let anyone use up a victim's quota); `CLIENT_DEVICES_MAX` (20 000) reported devices are kept, the least recently seen go first. When the webhook queue is nearly full, routine events are dropped before pin changes, revocations, key replacements, approvals and refused admin keys.
- **A renewal CSR is single-use per identity.** The same signed request sent again is refused (`403 reenroll_required`). The library's identity keys are EC (each CSR carries a fresh signature); a client renewing with an RSA key must vary the CSR between renewals.
- **Open mode and code-less applications are bounded, not authenticated.** Open mode enrolls whoever names a device id first (`ENROLLMENT_MODE=open` is for demos); code-less applications wait for an administrator, and the rate limit, the pending cap and the expiry bound the list, not who appears in it.
- **Some answers still tell things apart.** A device endpoint answers a stranger exactly as it answers any made-up id where it can (revoked devices, missing vault files), but an `api_key` vault file answers with its own `401` text, an enrollment code's existence shows in `401` vs `403`, and the time an answer takes is not constant. The refusal limits bound how fast anyone can ask.
- **Attestation under `enforce` needs a fresh revocation list to mean what it says.** Run `ENROLLMENT_ATTESTATION` / `USER_AUTH_ATTESTATION=enforce` with `ATTESTATION_REVOKED_SERIALS_FILE` (fetched by `scripts/fetch-attestation-status.sh`) and `ATTESTATION_STATUS_MAX_AGE_HOURS`; without them a key from a phone whose attestation key Google revoked still passes. The server does not refuse to start without them (the sample host's production profile would not start), it says so at start-up.
- **An enrollment code is a shared secret.** Whoever holds it can enroll up to the policy's device limit before its end date — or, with approval on, ask to; approval is only as good as the administrator's check of the request. Codes are 125 random bits, stored as SHA-256 hashes, never listed again after creation; waiting requests are capped at the device limit per policy, and refusals anyone with the code can cause are summarised per minute in the audit log. A device is recognised by its key throughout: a request id picks up a certificate only with a CSR signed by the key the request was made with.
- **Applications without a code let anyone who reaches the Config API ask.** The administrator's approval is the only gate, and it is only as good as the check behind it: the verification code ties the request to the key of the device on the desk, but a device without a screen can be told apart only by model, address and time, all of which an applicant chooses or shares. The switch is off by default; the rate limit, the pending cap and the expiry bound the list, not who may appear in it.
- The management-port copy of `POST /api/v1/client-certs/enroll` issues P12s only; CSR enrollment is on the Config API listeners. It records the device id under the same one-identity rule, and answers only over TLS (`MANAGEMENT_HTTPS_PORT`) or to the server's own machine (`403 tls_required` otherwise).
- **On a TLS Config API the first E2E key wins.** Whoever registers first for a device id that never registered holds the slot until the device shows its `end_to_end` file token or an administrator removes the key, and a stolen `end_to_end` file token is enough to replace the key and read the file. On an mTLS Config API a certificate sets a first key only for its own device, and replaces one only when its device id is proven (see *Proven device ids*) — otherwise, as on TLS, with the device's token. Put files that matter there, with `token_mtls`, which also needs a proven device id. Key registration there is bounded, not authenticated: RSA 2048–4096 only, `DEVICE_KEY_RATE_LIMIT` writes per source address, `DEVICE_KEY_LIMIT` keys per Config API. The address is the TCP peer, so behind a reverse proxy every device shares the proxy's quota.

- **A rooted or jailbroken phone is a source of tokens.** Code inside the genuine app signs reports with the device's own key, so a device the policy passes gets tokens whatever it is running. The server-side flags (hardware facts, revocation, Play Integrity, App Attest) decide whether it passes; the token binding (`cnf`, `requireCertBinding`) keeps a token from being used anywhere but on that device's own mTLS connections, not from being used by that device. See ATTESTATION.md §5.
- **The attested patch level is the one at registration.** `old_patch_level` reads it when the registration's chain carried one, so a phone updated since keeps the older level until it registers a new key; raising `ATTESTATION_MIN_PATCH_LEVEL` flags such phones until then. The libraries do not yet re-attest periodically with a fresh key.
- **`config_rollback` compares within one signing-key set.** A newer set (an upload under `RECOVERY_PUBLIC_KEYS`) starts every device's comparison again; an app update that changes the compiled-in signing key or threshold resets that device's watermark without a new set, and the device reports lower until it fetched a config newer than its old watermark. It catches a restored backup reported by the genuine library, not a client that lies about the value.
- **Key sets never expire.** A device that has not fetched since a revocation still trusts the old key.
- **A fresh install (or cleared app data) trusts the compiled-in keys** until its first successful fetch. Ship an app update after a revocation.
- **Per-file vault keys (`VaultFileConfig.signaturePublicKey`) are fixed.** Key sets do not rotate them.
- **Some writes are outside two-person approval, on purpose:** revoking and forgetting a device, stopping an enrollment code, turning code-less applications off, and deciding on a device that asked to enroll. Mock-host start/stop and connection tests are not gated either. Everything in *What waits for a second admin* is, unless `APPROVAL_EXEMPT_OPERATIONS` says otherwise. All of them are audited.
- **An approval is as good as what the approver reads.** The card shows the full pins, the certificate and the content hash of a vault file; it cannot show whether that key or that file is the right one. Compare them with what the requester sent you through another channel.
- **Under `PIN_LIVE_CHECK=enforce` a certificate this server installs itself needs an override.** Generating, uploading or rotating a host's certificate publishes pins the host does not serve yet (it serves them a moment later), so the check fails by construction and the request needs `liveCheckOverride=<reason>`. Pins fetched from the live host pass. `PIN_LIVE_CHECK_ALLOW_OVERRIDE=false` takes the override away: then no failing set is published, and a certificate this server installs itself has to be served by the host before its pins can be published.
- **A vault file behind `api_key` still answers with its own `401` text**, so its name can be confirmed by asking; names of `token` and `token_mtls` files cannot.
- **The attestation challenge is fixed per device id.** It binds a user-auth key to the device id, not to a moment, so a captured chain can be sent again — for the same public key, whose private half stays in that phone's hardware, so it opens nothing. The device id in the challenge is the app's own claim: only the signer binding (`ATTESTATION_SIGNER_SHA256`) stops another app from claiming any id, which is why no attestation counts without it. Under `warn` the first key of a device is trusted without a chain or a credential (stored as not attested), so whoever registers first for a device id that never registered holds the slot until an administrator resets it; use `enforce` where that matters. Attestation proves how the key was made, not that the phone is unrooted now: a key needing the user still needs the user.
- **A user-auth key that cannot be replaced is a lockout, on purpose.** With `off`, with `warn` on phones that cannot attest, or for a device without its credential, a retired key (new fingerprint, screen lock removed, unenroll with wipe) leaves the device's `user_auth` files locked until an administrator resets the key (runbook above).
- **A generated or uploaded certificate's backup key sits next to its primary** in `certs/`. It covers planned rotation and a key leaked elsewhere, not a server whose disk was read.
- **The live check is a safety net against mistakes, not attackers.** It trusts whatever the server's network path returns.
- **Freezing is bounded, not prevented.** Someone who can stop fresh configs from reaching a device can keep it on the last valid config until that config's `expiresAt`, which is `CONFIG_TTL_SECONDS`, plus the app's `expiredConfigGrace` (zero by default). Since library 2.2.0 the device stores `expiresAt` and refuses an expired config at start-up and on every handshake; 2.1.1 and earlier checked it only when fetching.
- **A database-level attacker can rewrite the whole audit chain.** The webhook copy, pushed as events happen and carrying the entry hash, is the tamper-evident record.
- **The server cannot see your app's signing settings.** Set `RECOVERY_REQUIRED_SIGNATURES` to the app's `requiredRecoverySignatures`, and never publish a set whose `requiredSignatures` your signers cannot meet for the app's own minimum.
- **With a local key file, signing is per request for apps older than 2.1** (and for anyone who leaves the `redelivery` header out), even with `CONFIG_SIGNATURE_CACHE` on. A local signature costs little. With an HSM, KMS or command signer nobody gets a per-request signature: such apps see a repeated envelope as a replay while nothing changed.
- **The signed payload names its Config API (`configApiId`, 2.2.0), but only a block with `serverScope(id)` checks it**, and vault files carry v2 signatures naming it (`X-Vault-Signature-V2`) that only such a block requires. Apps without `serverScope` accept an envelope or a file signed for another Config API that shares the signing key. Starting and stopping listeners is therefore under two-person approval too: whoever decides which scope a port serves decides which pins devices on that port receive. Signing-key sets do not name a Config API: they are signed offline by the recovery keys and apply to every Config API that trusts those keys.
