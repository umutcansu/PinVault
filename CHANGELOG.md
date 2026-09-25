# Changelog

## Unreleased — Optional security layers

Every item below is **opt-in**. A client and a server that configure none of them behave exactly as before, and each side keeps working with an older version of the other. See [`SECURE_OPERATIONS.md`](SECURE_OPERATIONS.md) for which layers to enable and the operational runbooks.

### Library (opt-in)

- **Several trusted signing keys.** `ConfigApiBlock.Builder.signaturePublicKeys(vararg)` (also a `List` overload for Java): a config signed by any of them is accepted. Ship an offline backup key in the app and a lost or stolen primary can be replaced on the server without an app update. `signaturePublicKey(key)` still works and means a one-key list.
- **m-of-n signatures.** `requiredSignatures(n)`: every config (and every vault file of the block) needs valid signatures from `n` *distinct* trusted keys. The envelope carries them in the new optional `signatures: [{keyId, signature}]` field; vault downloads in `X-Vault-Signatures: <keyId>:<sig>,…`. Keys are parsed and compared in canonical form, so two spellings of one key never count as two signers.
- **Signing-key sets: rotation and revocation over the air.** `recoveryPublicKeys(vararg)` + `requiredRecoverySignatures(n)`: offline recovery keys sign a versioned list of signing keys (`{"type":"pinvault-signing-keys","version":N,"keys":[…],"requiredSignatures":m}`), delivered in the envelope's optional `signingKeys` field. A device applies a newer set and from then on trusts exactly the keys it lists — a key left out is revoked. Sets are persisted in their own encrypted file (`pinvault_signing_keys.xml`, excluded from backup, kept across `PinVault.reset()`), re-verified against the app's recovery keys on every load, can raise but never lower the app's signature count, and may not name a recovery key as a signing key. A forged or malformed set fails the whole response.
- **`PinVault.signingStatus(configApiId)`** → `SigningStatus`: trusted key ids, required signature count, applied key-set version, recovery key ids and the keys that signed the last accepted config. `null` for unsigned blocks and blocks served by a custom `CertificateConfigApi`.

### Library (behaviour)

- **A pin can name an issuer.** A pin matches the leaf's key, as before, or the key of an issuer certificate in the served chain, as with OkHttp's `CertificatePinner` and Android's network security config; a host pinned to its CA survives a leaf renewal with a new key. The library does no CA validation, so an issuer pin counts only when the leaf validly chains to that issuer (PKIX, with the pinned certificate as the only trust anchor): a forged leaf with the genuine intermediate appended is refused. The server used to publish an intermediate as a fetched host's "backup" pin that devices could never match.
- **The same signed config served twice is `AlreadyCurrent`, not a replay.** A backend that signs once per change (HSM/KMS signer, signature cache, CDN) serves byte-identical configs; the updater used to reject every repeat with "Config replay rejected" because it compared `issuedAt <= stored` before change detection. An equal `issuedAt` with the same hosts, versions and pin sets is now a no-op (its force flag is not re-applied); an equal `issuedAt` with different content and any older `issuedAt` are still rejected.
- Signed-config requests send `X-PinVault-Features: redelivery,multisig,keyset` so a backend can tell which clients understand the new fields.
- Config signature failures name the reason: "1 of 2 required signatures valid", "signed by a key revoked by signing-key set v3".

### Demo server (opt-in)

- **Pluggable signers** — `CONFIG_SIGNERS=local` (default: the key file, as before) `| pkcs11 | command`, comma-separated for several signatures. `pkcs11` signs with a key generated inside an HSM as sensitive, never-extractable and sign-only — no decrypt, unwrap, sign-recover or derive (SunPKCS11; `PKCS11_LIBRARY`, `PKCS11_PIN`, `PKCS11_SLOT_INDEX`, `PKCS11_KEY_LABEL`, `PKCS11_GENERATE_KEY`). `command` runs an external signer — a cloud KMS CLI, Vault transit, a remote signing service — with the bytes on stdin (`SIGNER_COMMAND`, `SIGNER_PUBLIC_KEY[_FILE]`, `SIGNER_INPUT=payload|digest`); every signature it returns is verified before use. Named signers (`local:next`, `command:kms`) take suffixed variables.
- **Signature cache** — `CONFIG_SIGNATURE_CACHE=true`: identical content is signed once and served identically until half its TTL has passed; the pin store pre-signs every publish, so the signer is called when an operator publishes, not when devices poll. Cached envelopes go only to clients that announce `redelivery`; the cache is dropped on every admin write, and `issuedAt` is monotonic.
- **Signing-key sets** — `RECOVERY_PUBLIC_KEYS` (+ `RECOVERY_REQUIRED_SIGNATURES`) enables `PUT /api/v1/signing-keyset`: the server checks an offline-signed set the way a device will (recovery signatures, type, increasing version, parseable keys, no recovery key as signing key) and refuses a set that its own active signers could not satisfy, then attaches the latest set to every signed config. `GET /api/v1/signing/status`, `GET /api/v1/signing-keyset`. Regenerating the local key is refused while a set is active.
- **Named admins** — `ADMIN_KEYS=name:sha256hex,…` (or `ADMIN_KEYS_FILE`): personal admin keys, of which the server holds only hashes. `API_KEY` keeps working as the admin `admin`. `GET /api/v1/admin/me`.
- **Audit log** — every admin write is recorded with who, when and what (pin changes as a host-by-host diff), in an append-only table (`V10__audit_log`, UPDATE/DELETE triggers) where each row carries the SHA-256 of the previous one. `GET /api/v1/audit-log`, `GET /api/v1/audit-log/verify`. Invalid API keys are recorded (one entry per source per minute); expiring certificates once a day per host.
- **Webhook notifications** — `NOTIFY_WEBHOOK_URL` (+ `NOTIFY_WEBHOOK_SECRET` for an `X-PinVault-Signature: sha256=<HMAC>` header, `NOTIFY_EVENTS` to filter): security events are pushed as they happen, Slack-compatible `text` included, with retries. `GET /api/v1/notifications`, `POST /api/v1/notifications/test`.
- **Two-person approval** — `PIN_CHANGE_APPROVALS=2` (or more): pin, force, certificate, bootstrap-pin and signing-key changes become change requests (`202 {pendingApproval, changeRequestId}`) that another *named* admin must approve; the server then replays the exact request as the requester. No self-approval, the shared `API_KEY` cannot approve, a request made against pins that have since changed is refused as stale, requests expire after `APPROVAL_TTL_HOURS`. The device-facing Config API ports refuse pin writes in this mode. `GET/POST /api/v1/change-requests…`.
- **Live certificate gate** — `PIN_LIVE_CHECK=warn|enforce`: a new or changed pin set must be one devices accept for the chain the host serves right now: its leaf's pin, or the pin of an issuer the leaf validly chains to. `enforce` answers 422 with what the host serves; `?liveCheckOverride=<reason>` stores it anyway (audited, notified) unless `PIN_LIVE_CHECK_ALLOW_OVERRIDE=false`. `LIVE_CHECK_HOST_MAP` maps names the server cannot resolve (and wildcard entries) to a probe address. `POST /api/v1/pins/live-check` is a dry run for the dashboard.

- Hardening from an independent review before release: the approval gate decides on the path as routing resolves it, the shared `API_KEY` cannot request gated changes, undescribable or non-UTF-8 requests are refused, the signature cache can no longer serve an older `issuedAt` than a device applied, invalid-key attempts are summarised, decided change requests drop their stored bodies, the command signer runs without the server's secrets and is killed with its children on timeout, and `config-apis/start|stop` are gated too (see `SECURITY_AUDIT.md` N-33…N-39).

### Demo server (behaviour)

- **A backup pin is a real second key.** A host needs two *different* pins; `[X, X]` is refused. An uploaded certificate gets a stored backup key like a generated one, so it can switch to it; it used to get its chain's issuer or, for a lone certificate, its own pin twice. A host fetched from a URL gets its issuer's pin as the backup, and a site that serves its certificate alone is refused with 422 `reason: no_second_certificate`. The live gate applies the device rule (`PinChain`).
- **Generated certificates keep their backup key.** Host certificates (`generate-cert`, `regenerate-cert`) and the config server's own certificate published a backup pin but threw the backup private key away, so no certificate could ever serve that pin. The key is now stored in `certs/<id>.backup.jks`, a separate keystore, so TLS listeners only ever load the serving key. New `POST /api/v1/hosts/{hostname}/rotate-to-backup` and `POST /api/v1/server-tls-pins/rotate-to-backup` (dashboard: "Switch to Backup Key") reissue the certificate with the stored backup key, prepare a new backup and publish `{old backup, new backup}`. Devices keep connecting without a config refresh, and apps keep connecting to the config server without an update (after a restart). Both are certificate changes for two-person approval. They answer 409 with `reason: no_backup_key` (pins fetched from a URL, certificates generated before this change) or `backup_not_published`. The backup sits next to the primary, so a server whose `certs/` directory was read needs a regenerate instead (`SECURE_OPERATIONS.md`).
- `POST /api/v1/config/{id}/update` runs the same validation, per-host versioning, history and live gate as `PUT /api/v1/certificate-config`; it used to store the body as sent, versions included.
- `GET /api/v1/signing-key` also returns `keyId`, every signer's key and the current key-set version (`publicKey` is unchanged).
- The dashboard no longer resets a host's `mtls` / `clientCertVersion` flags and the scope's force flag when pins are edited.

## Earlier — Security hardening

**Breaking** — this stream of changes flips several "optional" defenses into "required" defaults. See `MIGRATION.md` for the upgrade path.

### Library (breaking)

- **`signaturePublicKey` is now required.** `ConfigApiBlock.Builder.build()` throws unless `signaturePublicKey(...)` is set, or `allowUnsigned()` is called as an explicit opt-out. Closes the silent-disable footgun (H-03).
- **Signed configs must carry `issuedAt` + `expiresAt`** (Unix epoch ms). The library rejects responses where `expiresAt <= now`, `issuedAt <= storedIssuedAt`, or either field is missing. Closes the replay window even when the signature is still cryptographically valid (M-08).
- **Per-host pin enforcement.** Pin lookup is now keyed by hostname (with single-label wildcard support `*.example.com`). A pin entry for host A no longer validates a cert on host B; unknown hostnames fail closed. Pre-V3 the library flattened every host's hashes into one set (H-01).
- **Per-host version monotonicity.** Updater rejects fetched configs whose per-host `version` is lower than the stored value — closes a downgrade attack the prior change-detect logic permitted (M-08).
- **`getClient()` is fail-closed before the first config.** `HttpClientProvider` used to start with (and `reset()` return to) a system-trust `OkHttpClient`, so an app calling `PinVault.getClient()` while a callback-style `init()` was still fetching config sent requests with no pinning at all. The initial/reset client now installs the pinning trust manager over the live config: TLS handshakes are refused until a config is applied and succeed right after, without rebuilding the client. `getClient(settings)` follows the same rule and re-reads the config on every handshake instead of snapshotting it.
- **Enrollment requires `X-P12-SHA256` response header.** Enrollment refuses to install a P12 if the header is missing; previously the check was skipped with a warning (H-05).
- **`PinRecoveryInterceptor` no longer matches exception messages.** Recovery is driven by typed `CertificateException` causes only. Adds a per-host circuit breaker (3 failures in 5 min → 10 min cooldown) so a poisoned backend can't thrash the client (M-03).

### Library (non-breaking)

- Pin-mismatch logs no longer dump the full accepted-hashes list — only a short cert-hash prefix (M-01).
- `ANDROID_ID` auto-enrollment annotated as a soft identifier; production callers should layer Play Integrity / SafetyNet on top (M-02).
- Backup rules exclude `ssl_cert_config_*.xml` and the vault file store so an attacker can't pin-downgrade by restoring a pre-rotation device backup (M-07).
- `CertificateConfigStore` wipes the prefs on parse failure so a corrupt blob can't loop on every load (L-01).
- Dropped the leftover `"changeit"` placeholder from the static-pin init path (M-06).

### Demo server (breaking)

- **`API_KEY` env var is now required to start.** Set `ALLOW_ANONYMOUS_ADMIN=true` to opt out explicitly (dev). Previous behavior silently disabled auth on missing env var — `docker compose up` from the demo file would have shipped an open admin API (C-01).
- **Every signed `/api/v1/certificate-config` response carries `issuedAt` + `expiresAt`.** TTL via `CONFIG_TTL_SECONDS` env var (default 24h). Required by the new library freshness check.
- **`api_key` vault files now actually require `X-API-Key`.** `GET /api/v1/vault/{key}` is allowlisted for devices, and the handler's `api_key` branch was a no-op, so "admin-only" files were served to anyone. The handler now checks the key itself and answers 403 when no `API_KEY` is configured (N-2).
- **Narrower unauthenticated allowlist.** Prefix rules exposed admin reads on the Config API ports: `GET /api/v1/vault/distributions`, `/vault/stats` and `/certificate-config/history/{host}` now require `X-API-Key`. Vault keys named `distributions`, `stats`, `devices`, `report` or `tokens` are rejected on upload (N-3).
- **`ping-remote` no longer runs a shell.** The `{hostname}` path segment was interpolated into `sh -c`; it is now validated and passed to `openssl s_client` as an argument, with the pin computed in-process (N-1).
- **Revoking a client certificate takes effect immediately.** `DELETE /api/v1/client-certs/{id}` removed the certificate from the truststore file, but the running mTLS listeners kept the truststore they were started with, so a revoked device could keep connecting until the next server restart. Revocation now restarts the mTLS Config APIs and mock mTLS hosts, as enrollment already did (N-5).
- **Per-host versions survive delete + re-add.** A host that was deleted and added back restarted at v1. Clients reject per-host version downgrades, so every device that had seen the old versions ignored the re-added host's updates and kept its stale pins. New migration `V7__host_version_watermark` keeps a per-scope high-water mark; `PinConfigStore.save` places re-added hosts above it and every add path reports the stored version.

### Demo server (non-breaking)

- `SIGNING_KEY_PASSWORD` env var enables AES-256-GCM at-rest encryption (PBKDF2-SHA256, 200k iterations) of the ECDSA signing key. Existing plaintext key files are auto-migrated on first startup with the env var set (H-04).
- `DefaultHeaders` plugin installs CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy on the management server. Tightens the admin UI's XSS surface (M-05).
- Connection-report endpoint regex-validates `hostname`, `deviceManufacturer`, `deviceModel`. Vault `{key}` parameter regex-validated as defense-in-depth (M-04, L-02).
- Admin web UI escapes server-supplied strings via `esc()` helper before innerHTML interpolation in connection-history, client-device, pin-history, and global-health views (H-02).
- BouncyCastle `bcprov-jdk18on` / `bcpkix-jdk18on` 1.78.1 → 1.79 (L-03).
- Dashboard no longer reports "pins updated", "host added" or "host deleted" after the server rejected the save; only the error toast is shown.
- Dashboard "mTLS client certificates" tab renders again. Its integration snippet referenced an undefined `data.httpsPort`, so the tab always showed the generic error and enrollment tokens could not be generated or certificates revoked from the UI. The snippet now uses the selected mTLS Config API's port.
- **Regenerating the signing key now takes effect in the running server.** `POST /api/v1/signing-key/regenerate` rewrote the key file and reassigned a local variable, but every route had captured the `ConfigSigningService` instance at startup. The dashboard reported success while the server kept signing with the old key, and the rotation only landed at the next restart — silently invalidating every client that had embedded the previous public key. The service now rotates its key pair in place (`regenerate()`), and the response carries `clientUpdateRequired`. Tests: `SigningKeyAndForceUpdateTest`.
- **Per-host `forceUpdate` reaches the client's force gate.** The dashboard only ever sets per-host flags, while the library's "force update or refuse to start" check reads the config-level flag, so a device with a stale forced config still started up happily against an unreachable backend. Served configs are now stamped with `forceUpdate = hasAnyForceUpdate()`.
- The signing key can be rewritten when the key file itself is a mount point. `writeOwnerOnly` renames a temp file over the target, which fails with `EBUSY` on a single-file Docker bind mount: the server refused to start as soon as `SIGNING_KEY_PASSWORD` triggered the at-rest migration, and "regenerate signing key" in the dashboard failed the same way. It now falls back to an in-place write and re-applies 0600. (`SamplePinVaultHost` also mounts the whole `data/` directory now.)
- Removed `static/app.js.bak`, a stale April copy of the dashboard script that the server was serving unauthenticated under `/static/` (it is git-ignored, so it never left this working tree, but a deployed image built from a dirty checkout would have shipped it).
- A blank `SIGNING_KEY_PASSWORD` is treated as unset. Compose files that pass the variable through (`${SIGNING_KEY_PASSWORD:-}`) used to turn an empty value into an empty encryption password.
- `EXTRA_CERT_SANS` env var (comma-separated IPv4 / DNS names) is added to every certificate the server generates. In a container the interface scan only sees the container's own address, so without it Android clients connecting by the Docker host's LAN IP fail hostname verification.

### Library — Trust manager dynamism

- **`PinVault.applyTo(builder)` trust manager is now actually dynamic.** Previously the trust manager snapshotted `pinMap` at the time of the call, so config swaps from `updateNow()` / WorkManager never reached requests issued through an externally maintained `OkHttpClient`. The KDoc claimed dynamic behavior but the implementation was static, and the recovery interceptor couldn't compensate when a rotation kept old pins valid for the still-unrotated cert. The dynamic trust manager re-reads `clientProvider.currentConfig` on every TLS handshake; the old snapshot overload has been removed and internal callers (`buildClient`, `buildBootstrapClient`) pass constant lambdas.
- **`applyTo(builder)` is now fail-closed when no config has loaded yet.** The previous early-return left the consumer's builder untouched and warned "system defaults" — silent unpinned traffic during the brief window between `setup()` and `executeInit()` on the callback init path. The dynamic trust manager is now installed unconditionally; its first handshake refuses to connect until init completes.

### Library — Additional security hardening

- **`forceUpdate` flag now persists across restarts.** `CertificateConfigStore.save()` did not write the flag and `load()` hardcoded `false`, so a backend that pushed `forceUpdate=true` lost the guard after every process restart — an attacker blocking the backend at that moment could keep a revoked config in service.
- **Constant-time P12 hash comparison in enrollment.** `validateP12` compared the server's `X-P12-SHA256` header against the locally computed hash via `String.equals`, which short-circuits on first byte mismatch. Switched to `MessageDigest.isEqual` on decoded bytes.
- **TLD-level wildcard patterns refused.** `PinHostMatcher.match` now skips `*.com`, `*.tr`, etc. (suffixes without a dot). Keeps a misconfigured single entry from authorizing every domain under a TLD and silently re-opening the H-01 cross-host reuse path.
- **Recovery circuit-breaker no longer reset by a single success.** `PinRecoveryInterceptor.recordSuccess` used to wipe the per-host failure counter, letting a partial MITM keep the 3-in-5-minutes breaker permanently disarmed by interleaving forged handshakes with legitimate ones. Now a no-op; the counter only ages out through the existing window.
- **Connection-listener dispatch queue is bounded** (256 entries, `DiscardPolicy`). A consumer-supplied listener that blocks (e.g. a synchronous POST to an unreachable telemetry endpoint) used to let handshake events accumulate without limit.

### Library — Recovery retry

- **Pin-mismatch recovery retries on the caller's own client.** `PinRecoveryInterceptor` always re-issued the request through PinVault's internally managed client, so a consumer client built with `applyTo(builder)` lost its `Dns`, interceptors and timeouts on the retry: an app resolving private hostnames through a custom `Dns` saw the recovery attempt die with `UnknownHostException` even though the refreshed pins were correct. The retry now runs on the intercepted chain, which keeps the caller's configuration and picks up the new pins through the dynamic trust manager; the internally managed client (built against a config snapshot) still falls back to the freshly swapped client.
- **The fallback attempt no longer hides the original error.** When the retry on the caller's chain failed and the fallback on the library's internal client failed too, the interceptor threw the *fallback's* exception. Because that client does not carry the caller's `Dns`, the app was handed an `UnknownHostException` in place of the pin mismatch it actually hit — the same `Dns` gap as above, one layer down. The original exception is now rethrown with the fallback's failure attached via `addSuppressed`, so the diagnosis is right and the fallback attempt stays visible in a stack trace. Tests: `PinRecoveryInterceptorTest`.
- **An expired server certificate no longer triggers a config refresh.** `DynamicSSLManager` reported a leaf outside its validity window as a plain `CertificateException`, which `isPinMismatch` could not tell apart from a real pin mismatch: every request to a host with an expired certificate refetched the pin config, retried, failed again with the retry's error instead of the real reason, and pushed the per-host recovery circuit breaker towards its cooldown — for a condition no config can repair. The trust manager now throws the new public `CertificateValidityException` (still a `CertificateException`, so trust-manager semantics are unchanged) and the interceptor lets it pass straight through to the caller. A bare `CertificateException` cause still recovers as before.

### Library — Empty config is a rejection, not a no-op

- **An empty `pins` list is treated as a change and fails validation.** `SSLCertificateUpdater.updateNow` decided "nothing changed" from three clauses that are *all* false when the remote and the stored pin sets are both empty, so it returned `AlreadyCurrent` and never reached the "config must contain at least one pin entry" check. `init` then reported `Ready(v0)` and the app showed itself as configured while not a single host was pinned. An empty remote config now always routes into validation and comes back as `Failed` / `InvalidPinFormatException`; a stored config is left untouched, so a device that already holds good pins keeps them. `validateConfig` raises `InvalidPinFormatException` for that case instead of the `require(...)` it used to be, so a now-reachable rejection carries the library's own type (the message, and therefore `UpdateResult.Failed.reason`, is unchanged). Tests: `SSLCertificateUpdaterTest`.

### Library — Connection events

- **`PinVaultConnectionEvent.ConfigUpdate` added.** Sealed class now carries config-rotation outcomes (`UPDATED` / `UNCHANGED` / `FAILED`) on the same listener pipe as handshake events. `notifyUpdateResult` emits both on the legacy `OnUpdateListener` and on `PinVaultConnectionListener.onEvent`. `when` expressions over `PinVaultConnectionEvent` need a new branch — the sealed-class doc already advertised this kind of extension.

### Reporter — Throttling and filtering

- **`reportSuccessEvents: Boolean`** (default `true`, legacy behavior). Set to `false` to POST only anomaly events — pin mismatches and config-update failures. Healthy handshakes and successful config rotations are suppressed entirely.
- **`dedupWindowMs: Long`** (default `0`, legacy behavior). When > 0, duplicate "healthy" Connection reports for the same `(hostname, pinVersion, serverCertPin)` tuple inside the window are dropped. ConfigUpdate events are not deduped — they are already periodic.
- **`reportToPinVaultBackend(...)` DSL helper** exposes the same two parameters.

### Reporter — Config-update endpoint

- Reporter POSTs `PinVaultConnectionEvent.ConfigUpdate` events to a new endpoint, `POST /api/v1/connection-history/config-update-report`, with status (`config_updated` / `config_unchanged` / `config_update_failed`), pinVersion, device fields, and optional `failureReason`.

### Library — Runtime listener registration

- **`PinVault.setConnectionListener(listener: PinVaultConnectionListener?)`** added. Lets callers attach (or detach) a listener after `init` has returned — needed for production reporter setups where the reporter's own `OkHttpClient` must be pinned via `PinVault.applyTo(...)`, which itself requires the active config to already be loaded. Builder-time `onConnectionEvent(...)` is unchanged; this new method is purely additive. README documents both "same-host as Config API" and "separate management host" pinning patterns.

### Demo server — Config-update reports

- New route `POST /api/v1/connection-history/config-update-report` accepts reporter payloads, reuses the existing `connection_history` table with `source='config_update'`, and applies the same M-04 identifier validation as `/client-report`. Whitelisted in `ApiKeyAuth` so unauthenticated clients can report (matches `/client-report`).

### Library — Dead settings and mismatched labels (breaking)

- **`ConfigApiBlock.Builder.enrollmentToken(token)` removed.** The token was stored on the block and never read — neither `PinVault.enroll` nor `PinVault.autoEnroll` consulted it — so a builder-time token silently did nothing while looking like enrollment was configured, and a single-use secret sat in a process-lifetime config object. Pass it at the call site instead: `PinVault.enroll(context, token)` (or `PinVault.autoEnroll(context)` for deviceId-based enrollment). `ConfigApiBlock.enrollmentToken` is gone from the data class, builder, `equals` and `hashCode`.
- **`wantPinsFor(...)` now actually reaches the server.** The block stored the host list and `DefaultCertificateConfigApi.fetchScopedConfig` was implemented, but `SSLCertificateUpdater.updateNow()` always called the unscoped `fetchConfig`, so `?hosts=` and `X-Device-Id` were never sent and the server returned every pin it had — the least-privilege scoping was inert. A block that declares `wantPinsFor` now fetches through `fetchScopedConfig(currentVersion, hosts, deviceId)`; blocks that declare nothing keep the legacy call. The device id comes from the new internal `DeviceIdentity` helper (ANDROID_ID), the same source `PinVault` sends as `deviceUid` at enrollment, so the server-side ACL key matches.
- **`isEnrolled` / `unenroll` / `enrolledClientCN` read the label `enroll` writes.** All three defaulted to `ClientCertSecureStore.DEFAULT_LABEL` while `enroll`/`autoEnroll` default to the Config API block's `clientCertLabel`. With a custom `clientCertLabel(...)` the certificate was written under one key and queried under another: `isEnrolled` returned false right after a successful enrollment and `unenroll` deleted nothing. All four paths now resolve the default the same way.

### Library — Unenroll actually unenrolls

- **`PinVault.unenroll` clears the in-memory client key.** It deleted the P12 from encrypted storage but left the `KeyManager` built at enrollment time loaded in `DynamicSSLManager`, so the device kept authenticating to mTLS hosts until the process restarted. `DynamicSSLManager.clearClientKeystore()` (the inverse of `loadClientKeystore`) drops the default and per-host key managers, and `unenroll` calls it for every Config API block and re-publishes the config so the next request presents no client certificate. Pinning itself is untouched.

### Library — Documentation

- **`getClient(HttpConnectionSettings)` documents that it has no pin-recovery.** Unlike `getClient()` and `applyTo(builder)`, this overload installs pinning only: a pin mismatch surfaces as an SSL exception and PinVault does not auto-refresh the config and retry. Behaviour unchanged; the gap was simply undocumented.

### Demo server — `token_mtls` vault policy works

- **`token_mtls` files were unreachable.** `extractClientCertCn` read a `TLSPeerPrincipal` call attribute that nothing populated, so it always returned null and every `token_mtls` request answered 401 even with a valid client certificate — an advertised policy that was dead. The new `route/ClientCertIdentity.kt` reads the verified peer certificate off the Netty channel's `SslHandler`, so the policy now enforces what it promised: a valid per-device token **and** a client-authenticated connection whose certificate belongs to that device. Match rule: the CN's `PinVault Client: ` prefix is stripped and compared to `X-Device-Id` (auto-enrollment, where the client id is the ANDROID_ID), falling back to `client_certs.device_uid` recorded at enrollment (token enrollment, where the client id is admin-chosen). Revoked certificates are rejected. `CertificateConfigRoute`'s cert-based deviceId fallback for ACL scoping shares the same helper and is no longer inert.
- **`token_mtls` is selectable in the dashboard.** The vault upload form offered only `token` / `public` / `api_key`.

### Demo server — Missing endpoint and header

- **`GET /api/v1/client-devices?configApiId=` added.** The dashboard's Device-ACL manager called this endpoint, no such route existed, and the failure was swallowed — the "enrolled devices" table was always empty, so per-device host ACLs could not be assigned from the UI. The new route (X-API-Key protected) lists devices keyed by the identifier the ACL itself uses (`X-Device-Id` / ANDROID_ID), merging certificates issued at enrollment with devices seen in connection reports for hosts in that scope.
- **Management-port enrollment sends `X-P12-SHA256`.** `POST /api/v1/client-certs/enroll` on port 8090 returned the P12 without the integrity header while the Config API copy sent it. The library refuses to install a P12 with no header (H-05), so a client pointed at the management port failed enrollment outright.
- **Global force-update endpoints accept `?configApiId=`.** `POST /api/v1/certificate-config/force-update` and `/clear-force` are mounted on the management server under the fixed `default-tls` scope, so an admin UI button could only ever act on that one Config API. They now take an optional scope parameter, defaulting to the route's own scope.
- **`GET /api/v1/health` answered 500 on every call.** The response was built from nested `mapOf(...)` with mixed `String` / `Int` / `Map` values, which kotlinx.serialization refuses ("Serializing collections of different element types is not yet supported"). Nothing exercised it — the container probe uses the bare `/health` and the dashboard did not call it — so the failure went unnoticed until the new certificate-expiry card started reading it. The payload is now built from serializable `ServerHealth` / `ConfigApiHealth` / `CertHealth` types; the JSON shape is unchanged from what the endpoint was meant to return.

### Demo server — Enrollment tokens hashed at rest (breaking for API consumers)

- **`enrollment_tokens.token` now stores SHA-256(plaintext), not the plaintext.** A database dump — or `GET /api/v1/enrollment-tokens`, which listed the values verbatim — handed over usable enrollment credentials. The plaintext now exists exactly once, as the response of `POST /api/v1/enrollment-tokens/generate`; validation hashes the presented token and looks it up. The listing returns a masked prefix (`AbC12dEf…`) plus a new `masked: true` field, matching how vault access tokens already work. New migration `V8__enrollment_token_hash` adds `token_prefix` and marks pre-migration plaintext rows used, since they could never match a hash lookup again — re-mint any token still in flight during the upgrade.

### Demo server — API documentation

- **Swagger UI at `/docs` renders again.** `docs.html` loaded swagger-ui from `unpkg.com` and ran an inline `<script>`, both blocked by the server's own `script-src 'self'` CSP, so the page was blank. The dist files are vendored under `static/vendor/` (swagger-ui 5.33.0) and the init code moved to `static/docs.js`; the CSP is unchanged.
- **`static/openapi.yaml` rewritten.** It documented 15 of ~80 endpoints and declared a `currentVersion` query parameter on `/api/v1/certificate-config` that the server does not read (it reads `hosts` and `signed`).

### Demo server — mTLS trust refresh and host pin versions

- **A newly generated or uploaded client certificate is trusted immediately.** `POST /api/v1/client-certs/generate` and `/upload` wrote the certificate into the truststore file and stopped there, but a running mTLS listener holds the truststore it was handed at start — so a client connecting with the P12 the operator had just downloaded was rejected with "certificate unknown" until the server was restarted. Enrollment and revocation already restarted the listeners; all four paths now go through one helper (`refreshMtlsTrust` in `Main.kt`) that restarts the mTLS Config APIs and the mock mTLS hosts against the current truststore.
- **`toggle-mtls` and `upload-client-cert` bump the host's pin version.** Both wrote `mtls` / `clientCertVersion` into the config without moving the version. The client's change detection is per-host version based, so a device that already held the config answered `AlreadyCurrent` in `SSLCertificateUpdater.updateNow` and never ran `syncHostClientCerts` — the host-specific certificate reached only devices whose data had been wiped. Both endpoints now increment the host's `version` (watermark semantics in `PinConfigStore.save` unchanged), record the stored version in the pin history, and report it in the response. Tests: `HostMtlsVersionBumpTest`.
- **`GET /api/v1/enrollment-tokens` reports expiry.** `EnrollmentTokenStore.validate` has always honoured `expires_at`, but the listing did not expose it, so an expired token was indistinguishable from a fresh one. Rows now carry `expiresAt` and a server-computed `expired` flag (an absent or unparseable value means "no expiry", the same rule `validate` applies). Tests: `EnrollmentTokenStoreTest`.
- **`PUT /api/v1/certificate-config` and the per-host force endpoints accept `?configApiId=`.** Same reason the global force endpoints already did: the management server mounts these routes under the fixed `default-tls` scope. Deliberately *not* mirrored on the `GET`, which is in the unauthenticated client allowlist — a scope parameter there would let a device on one Config API port read another scope's pins.

### Demo server — Dashboard

- **Host add / edit / delete write the Config API that is actually selected.** `loadConfig()` always read `GET /api/v1/certificate-config?signed=false` and `saveFullConfig()` always wrote `PUT /api/v1/certificate-config`, both of which resolve to `default-tls` on the management server. With any other Config API open, "+ → Manual", "Edit pins" and "Delete host" therefore read and rewrote the default scope: hosts landed in the wrong Config API and the default scope's pin list was silently modified. Both now use the selected scope (`GET /api/v1/config/{id}`, which the host detail view already used, and `PUT …?configApiId=`), as does the per-host force-update toggle. The "+" button reloads the target scope's config before opening the form — the manual tab submits the whole pin list, so a stale scope would have copied one Config API's pins into another.
- **The "Client certificates" tab renders its enrollment-token list.** `renderConfigApiDetail` rewrites `#content` with the header and tab bar as soon as the tab function returns, but `loadEnrollmentTokens` resolved `#enrollment-token-list` *before* its fetch — that node was detached by the rewrite, so the fill went nowhere and the list appeared only right after "Generate token" / "Revoke". The container is now resolved after the fetch, which finds the rewritten node. (Awaiting the fill inside `renderMtlsSection` instead would work too, but it holds the rewrite open long enough to wipe text typed into the client-id field in the meantime.)
- **Expired enrollment tokens are labelled "Expired" instead of "Pending".** The status column read only the `used` flag, so a token the server would refuse was listed as available. Uses the new `expired` field; the cell's tooltip shows the expiry instant.
- **Vault file policy is editable from the UI.** `PUT …/vault/{key}/policy` existed with no way to reach it; changing a file's access policy or encryption meant re-uploading the file. The file detail view now has a policy/encryption control.
- **Certificate expiry surfaced in the dashboard.** `GET /api/v1/cert-expiry` and the richer `GET /api/v1/health` were never called by the UI, so approaching expiry was visible only in server logs. The health section now shows a per-host card with days remaining and colour-coded status (ok / warning / expired), plus a near-expiry count tile.
- **Dead dashboard code removed or wired up.** `regenerateCert`, `startConfigApi`, `stopConfigApi` and the per-host `forceUpdate` / `clearForce` were unreachable duplicates of `renewCertAuto`, `createConfigApi`, `toggleConfigApi` and `toggleForce` — deleted, along with the unreferenced `showEditPins`. `createHostFetch` is now an "fetch from URL" tab on the add-host screen, `fetchBootstrapFromUrl` a button in the bootstrap section (for servers behind a TLS terminator), and new global force-update / clear-force buttons sit in the Config API general tab.
- **Enrollment tokens are shown once.** Generating a token now copies it to the clipboard and shows it in a one-time dialog (same flow as vault tokens); the list shows the masked prefix.

### Library — Post-update health gate now rolls back (G08)

- **A config that fails the post-update health check is rolled back instead of being left on disk.** `SSLCertificateUpdater.verifyPinnedConnection` had three branches: healthy → `Ready`, unhealthy → `Failed` *without touching the store*, exception → `configStore.clear()` + `httpClientProvider.reset()`. The third branch was unreachable: `DefaultCertificateConfigApi.healthCheck()` catches every exception and returns `false`, so the documented "on failure clears the config store and resets the client" never happened with the default API. The observable result was worse than a missing rollback: init reported failure while the new config stayed in the encrypted store, and the *next* cold start came up "Ready" on it — the second round returns `AlreadyCurrent`, which never reaches the gate at all. Unhealthy and threw are now the same outcome: the config that was in force before the update is restored to the store **and** to the live HTTP client, or, on a first install with nothing to fall back to, the store is cleared and the client returns to its fail-closed state. Re-saving the previous config also rewinds the persisted `issuedAt`, so the replay guard accepts the server's config again on the next attempt. Offline start-up is unaffected — the gate only runs after a config was actually applied (`UpdateResult.Updated`), never on the "backend unreachable" path that keeps running on the stored config. The KDoc now also states what the check really proves: it is a liveness check of the Config API over its bootstrap client, not a re-verification of the freshly installed target-host pins. Tests: `SSLCertificateUpdaterTest`.

### Library — Turning force-update off reaches the device (D04)

- **A cleared `forceUpdate` flag is now written to the stored config.** Change detection treated a raised flag as a change but not a cleared one, so a config whose only difference was `forceUpdate: true → false` was dropped as `AlreadyCurrent` and never rewritten — the stored copy kept `forceUpdate: true`. That is not cosmetic: `initializeAndUpdate` reads the *stored* flag on every cold start and fails with `ForceUpdateFailedException` when the backend is unreachable, so a device stayed unable to start offline after the operator had switched force off, until some unrelated pin version happened to bump. Clearing the flag deliberately does **not** produce `UpdateResult.Updated` — nothing about the pins changed and callers should not be told a new config was applied — but the flags are written back to disk on the already validated stored config (never an unvalidated remote payload), and the live client is left alone. Both the global and the per-host flag are compared. The in-memory config follows the disk (`HttpClientProvider.replaceConfigInPlace`, no client rebuild), so `isForceUpdate()` reports the cleared flag right away instead of after the next process start. Tests: `SSLCertificateUpdaterTest`.
- **`CertificateConfigStore` persists the per-host `forceUpdate` flag.** The stored entry format gained a trailing field (`hostname|version|hash1,hash2|forceUpdate`); entries written by earlier versions have three fields and load with `false`, which is also the fail-safe value. Without this the per-host half of the comparison above could never see anything but `false`. Tests: `CertificateConfigStoreTest`.

### Library — Vault file diagnostics

- **A blank vault access token is no longer sent as an empty header.** When `accessToken { … }` returned `""` — the normal state of a host app whose token store is still empty — `VaultFileRouter` sent `X-Vault-Token: ` anyway and the server answered "Invalid or revoked token", pointing operators at a revoked token that was never issued. Blank and whitespace-only tokens now omit the header, so the server reports the accurate "X-Vault-Token header required". Both are still HTTP 401; only the reason recorded in the server's distribution history changes. Tests: `VaultFileTokenHeaderTest`.
- **`VaultFileAccessPolicy.API_KEY` warns at build time.** The policy is satisfied with the server's admin `X-API-Key`, which the library deliberately never sends from a device (it would ship inside the APK), so a file declared this way silently fails with 401 on every fetch and the only trace is a `failed` row in the distribution history. `PinVaultConfig.Builder.build()` now logs one warning per such file, and the enum's KDoc says plainly that it is for server-side tooling only. The dashboard's vault upload form carries the same note next to the `api_key` option. Behavior is otherwise unchanged — the library still does not send the admin key.
- **Uncovered Config API ids warn at build time (M-07 follow-up).** The bundled backup rules exclude the stored pin config per file name, and Android's `<exclude>` takes no wildcards, so they can only name ids the library knows. An app registering its own `configApiId` had its `shared_prefs/ssl_cert_config_<id>.xml` included in cloud backup and device transfer, re-opening the pin-downgrade restore the exclusions exist to close. `PinVaultConfig.Builder.build()` now logs one warning per uncovered id, naming the exact `<exclude>` line to add; `configApi(...)`'s KDoc and both rule files carry the same warning. The library's own default id (`default`) was itself missing from the rules and has been added. The rules are otherwise unchanged: collapsing every scope into one preferences file would need a store migration, and the per-scope namespacing is itself what keeps two Config APIs' pins from colliding.

### Demo server — The vault switch actually switches something (C09)

- **`GET /api/v1/vault/{key}` refuses with 403 while the scope's `vault_enabled` is off.** The flag was written and read by two admin endpoints and consulted by nothing else, so "vault enabled" was a dashboard checkbox with no effect — an operator who noticed a file had gone out by mistake had no way to stop distribution short of deleting it. The download route now reads the flag per request (so the toggle takes effect without restarting the listener) and answers 403 for every key, present or absent, so a disabled vault does not reveal which keys it holds. Vault **administration** in that scope is deliberately unaffected — upload, list, policy, delete, tokens and distribution history stay reachable, because inspecting and cleaning up is exactly what follows flipping the switch. The flag is an operator kill switch, not an authentication boundary; per-file `access_policy` remains what guards content.
- **The default Config API has a `config_apis` row.** `default-tls` is mounted directly by `Main.kt` rather than through `POST /api/v1/config-apis/start`, so it never had a registry row, and `PUT /api/v1/config-apis/default-tls/vault-enabled` answered 404 — the switch was unusable on the one scope the sample app talks to. New `ConfigApiRegistry.ensureRegistered` registers it at boot and preserves an existing row's `vault_enabled`.
- **Restarting a Config API no longer re-enables its vault.** `POST /api/v1/config-apis/start` persisted the API with `INSERT OR REPLACE`, which deletes and re-inserts the row and therefore reset `vault_enabled` to its column default (1). It now goes through `ConfigApiRegistry.ensureRegistered`, which updates only port and mode.
- **The dashboard's vault toggle reflects the server's answer.** A rejected `PUT` left the checkbox in the position the operator had clicked, showing "vault disabled" for a vault that was still serving files; the toast did not carry the status code either. The checkbox now reverts on failure and the toast names the HTTP status.
- Tests: `VaultEnabledSwitchTest`. `openapi.yaml` updated — the previous text ("dashboard state only") described the old behavior.

### Known limitations (documented, not changed)

- **A failed enrollment still consumes its token.** `POST /api/v1/client-certs/enroll` generates the certificate and marks the enrollment token used before the response reaches the device; if the device then rejects the P12 (for example a missing `X-P12-SHA256` header) the token is spent and the operator has to issue a new one. Recording consumption only after a device-confirmed install would need a second round trip (a confirm/ack endpoint) and a way to expire never-confirmed certificates — out of scope here; see `SERVER_IMPLEMENTATION_GUIDE.md`.

## 2.0.0 — 2026-04-17

**PinVault 2.0 — Multi-Config-API + Vault Scoping + Per-File Security.**

### Config / DSL

- **Multi-Config-API DSL**. `PinVaultConfig.Builder()` accepts one or more
  `.configApi(id, url) { … }` blocks. Each block has its own bootstrap pins,
  TLS/mTLS pipeline, and endpoint paths. Vault files bind to a specific
  block via `.vaultFile(key) { configApi(id); … }`.
- **Per-file access policies**: `PUBLIC`, `API_KEY`, `TOKEN`, `TOKEN_MTLS`.
  `TOKEN` is the default — admin issues per-(device, file) tokens via
  `POST /api/v1/vault/{key}/tokens`. Replaced or revoked tokens invalidate
  immediately.
- **End-to-end encryption**: `encryption(VaultFileEncryption.END_TO_END)`
  wraps content with the device's Android-Keystore-backed RSA 2048 key
  (StrongBox when available) using RSA-OAEP-SHA256 + AES-256-GCM hybrid.
- **Server-side pin scoping**: `wantPinsFor(...)` + per-device
  `device_host_acl` table. Server returns only pins for hostnames the
  device is authorized to see; unauthorized requests logged.

### Library

- **`VaultFileDecryptor`**: pure JCA decryption of E2E envelopes (no
  Android deps — runs in Robolectric and plain JVM).
- **`DeviceKeyProvider`**: Android Keystore backend + software fallback.
- **`ConfigApiClient` + `VaultFileRouter`**: internal runtime that routes
  each vault fetch to the correct per-block client. Per-Config-API
  `CertificateConfigStore` namespaces pin storage to prevent cross-API
  hostname collisions.
- **`CertificateConfigApi`** gained three new methods with default
  implementations:
  - `fetchScopedConfig(currentVersion, hosts, deviceId)` for pin scoping
  - `downloadVaultFileWithMeta(endpoint, currentVersion, deviceId, accessToken)`
    for policy + encryption support
  - `registerDevicePublicKey(deviceId, publicKeyPem)` for E2E
- **`VaultFileConfig`** gained `configApiId`, `accessPolicy`,
  `accessTokenProvider`, `encryption` fields.

### Demo server

- **Flyway V2 migration**: drops and recreates `vault_files` and
  `vault_distributions` with `config_api_id` scoping. Adds four new tables:
  `vault_file_tokens`, `device_public_keys`, `device_host_acl`,
  `default_host_acl`. Adds `config_apis.vault_enabled` column.
- **New stores**: `VaultFileTokenStore`, `DevicePublicKeyStore`,
  `DeviceHostAclStore`.
- **New services**: `VaultEncryptionService` (RSA-OAEP + AES-GCM hybrid),
  `VaultAccessTokenService` (SHA-256 hashed, constant-time validation).
- **`vaultRoutes(configApiId, …)`**: every route Config-API-scoped.
  Enforces access policy (public / api_key / token / token_mtls) and
  applies end-to-end encryption when configured.
- **`CertificateConfigRoutes`**: accepts `?hosts=` parameter, intersects
  with `device_host_acl`, logs unauthorized host requests.
- **`AdminVaultRoutes`**: `PUT /config-apis/{id}/vault-enabled`,
  per-device + default host ACL CRUD endpoints.

### Web UI

- File list shows access policy badge + encryption indicator.
- Upload dialog has policy/encryption dropdowns; default is `token` + `plain`.
- File detail page includes a **Token Management** card (list + issue token
  modal that shows plaintext once + revoke).
- Config API detail page has a **Vault (V2)** section with vault-enabled
  toggle and a "Cihaz ACL yönet" button opening the ACL manager (default
  ACL editor + per-device ACL editing).

### Demo app

- **New `VaultSecurityDemoActivity`** demonstrating multi-API + 3 files
  across public / token / E2E policies, with a token editor dialog.
- `VaultFileDemoActivity` and `BaseDemoActivity` migrated to the new DSL.

### Security

- Default vault file policy is `token` — unauthenticated fetch is no longer
  the path of least resistance. `public` must be explicitly chosen.
- Token plaintext is generated from `SecureRandom` (32 bytes → URL-safe
  base64), returned once, stored as SHA-256 only, validated with
  `MessageDigest.isEqual` (constant-time).
- `token_mtls` requires both a matching token and an mTLS cert whose CN
  equals `X-Device-Id`. Token leak alone does not grant access.
- Device RSA private key stays in Android Keystore; server never sees it.

### Compatibility

- **Kotlin 1.9 consumer support**. Library is still compiled with Kotlin
  2.1, but `apiVersion` and `languageVersion` are now pinned to `1.9` so
  the emitted metadata is readable by Kotlin 1.9.x compilers.
- **Coroutines downgraded** `kotlinx-coroutines-android` `1.9.0` → `1.8.1`
  (and `kotlinx-coroutines-test` to match). The `1.9.0` artifact ships
  Kotlin 2.0 metadata, which Kotlin 1.9.x consumers cannot read; since
  PinVault's public API exposes `suspend` functions (`init`, `updateNow`,
  `enroll`, `fetchFile`, `syncAllFiles`, …), the coroutines metadata is
  reachable transitively and must also be 1.9-compatible.
- Fixes `Unable to read Kotlin metadata due to unsupported metadata
  version` (and `unsupported metadata kind: null`) on consumer projects
  using Kotlin 1.9.x.

### Tests

- **+38 server tests**: `VaultRoutesAccessPolicyTest` (11),
  `VaultEncryptionServiceTest` (7), `VaultFileTokenStoreTest` (9),
  `DeviceHostAclStoreTest` (9), existing suites migrated to scoped stores.
- **+17 library tests**: `VaultFileDecryptorTest` (6),
  `MultiConfigApiConfigTest` (10 DSL validations), `PinVaultConfigTest`
  updated to V2 DSL.
- Total: 143 library + 109 server = **252 tests, 0 failures**.
