# PinVault — Secure Operations

Pins are public: anyone can read a server's certificate. What has to be protected is **what devices trust** (the keys that sign configs), **who can change pins**, and **availability** (a wrong pin set locks every device out of a host). PinVault ships layers for each of these. Every layer is optional and off by default, so a team enables what its infrastructure and staffing can carry. None of them changes anything for clients or servers that don't use it.

## Security levels

Pick the highest level you can operate reliably. A layer you can't run well, such as an HSM nobody knows how to restore or approvals nobody answers at night, is worse than no layer at all.

**Level 0: default.** One signing key file on the server and one shared admin key (`API_KEY`). Devices verify every config (signature, freshness, replay, per-host downgrade).

**Level 1: no extra infrastructure.**

| Layer | Enable with | Protects against |
|---|---|---|
| Signing key encrypted at rest | `SIGNING_KEY_PASSWORD` | A copied data directory yielding the key |
| Management API off the network | sample host: plain HTTP bound to `127.0.0.1`, `MANAGEMENT_HTTPS_PORT` for devices and remote admins | The admin key crossing the network in the clear; read or forged device reports |
| Keystores under a real password | `KEYSTORE_PASSWORD` (the sample host's `setup.sh` generates one) | A copied data directory yielding TLS, backup and client keys |
| Vault files under a real password | `VAULT_AT_REST_PASSWORD` (the sample host's `setup.sh` generates one; unset means a password printed in the source code) | A copied database yielding at_rest and per-device vault files |
| Offline backup signing key in the app | client `signaturePublicKeys(primary, backup)` | Lost or stolen primary → switch without an app update |
| Named admins + audit log | `ADMIN_KEYS=alice:<sha256>,…` (log is always on) | "Who changed this pin?" having no answer |
| Webhook notifications | `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET` (`NOTIFY_EVENTS=*` sends every event but the routine `device_key_registered`) | Changes nobody notices; a DB-only rewrite of the audit log going unseen |
| Live certificate check, warn | `PIN_LIVE_CHECK=warn` | Typos and wrong-host pins (flagged, still stored) |

**Level 2: an offline key and a second person.**

| Layer | Enable with | Protects against |
|---|---|---|
| Signing-key sets | client `recoveryPublicKeys(r1[, r2])`; server `RECOVERY_PUBLIC_KEYS` | A stolen signing key staying trusted until every app is updated |
| Two-person approval | `PIN_CHANGE_APPROVALS=2` (needs `ADMIN_KEYS`; the shared `API_KEY` can neither request nor approve a change) | One phished admin key or one insider publishing pins |
| Live certificate check, enforce | `PIN_LIVE_CHECK=enforce` | Publishing a set that the live host fails |

**Level 3: HSM/KMS and no single point.**

| Layer | Enable with | Protects against |
|---|---|---|
| Key inside an HSM (never extractable) | `CONFIG_SIGNERS=pkcs11` + `PKCS11_*` | The signing key ever being copied off the server |
| KMS / remote signer | `CONFIG_SIGNERS=command` + `SIGNER_COMMAND`, `SIGNER_PUBLIC_KEY` | Same, with the provider's own access policy and audit |
| Sign once per publish | `CONFIG_SIGNATURE_CACHE=true` | HSM/KMS called on every poll; unaccountable signatures |
| m-of-n signatures | server `CONFIG_SIGNERS=a,b` + client `requiredSignatures(2)` | A compromised server (or one team) publishing pins alone |

m-of-n is the only layer that holds against a fully compromised config server. An HSM keeps the key from being stolen, but whoever controls the server can still ask the HSM to sign. With two signers whose keys sit with different teams or systems, and each signer checking what it signs, neither one alone can produce a config devices accept.

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
- **The client CA** (`certs/client-ca.jks`, under `KEYSTORE_PASSWORD`, re-keyed with the other keystores) signs every device certificate issued over a device-held key. Its certificate is the only thing the mTLS listeners trust for those devices; the database (`client_identities`) says which device keys are still allowed to renew.
- **The server CA** (`certs/server-ca.jks`, with a backup key in `server-ca.backup.jks`, both under `KEYSTORE_PASSWORD`) signs the recovery door's TLS certificate and nothing else. Apps pin both keys for `<host>:RECOVERY_PORT` only. Ten years; move the backup off the server once the app ships with its pin. If it is stolen, the thief can impersonate the recovery door — which issues nothing secret and whose answers the device checks against its own client CA — so the damage is blocked renewals, not stolen identities.
- **Device identity keys** are generated in each device's Android Keystore and never leave it. The server keeps their SPKI hash; a certificate is a 90-day credential over the key, renewed by a CSR the key signs.

The sample host's `scripts/signing-keys.sh` generates keys, builds and signs key sets, uploads them and installs a key for the local signer. `scripts/add-admin.sh` creates admin keys, and `scripts/softhsm-init.sh` prepares a SoftHSM token for the PKCS#11 signer.

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

Same pattern: new password in `VAULT_AT_REST_PASSWORD`, old one in `VAULT_AT_REST_PASSWORD_PREVIOUS`, restart. At startup every at_rest and per-device file that opens only with the previous password is re-encrypted under the new one; files written while the variable was unset (the demo password) move over without `_PREVIOUS`. A file that no password opens is named in the log, and downloads of it fail until the old password is supplied or the file is uploaded again: the server never hands a device the encrypted bytes as the file. Devices are not affected.

### The config server is down

Devices keep their stored config and pins. Only a config marked `forceUpdate` makes a device refuse to start without the backend, so use force sparingly.

### A device certificate is about to expire, or has expired

Nothing to do. The library renews with a third of the lifetime left over the mTLS connection, and an expired certificate is renewed over the recovery URL (`renewalUrl`, a TLS listener) with the CSR signature as proof of the device key. Both show up in the audit log as `client_cert_renewed` with the door used (`via: mtls | recovery`); the dashboard's mTLS tab lists expiry and renewal counts. A device that stays offline past its expiry recovers on its next start. Only a device whose Keystore key is gone (app reinstalled, factory reset) needs a new enrollment token.

### The recovery door's certificate

Nothing to do: the server reissues it (new key, same server CA) 30 days before it expires and restarts the door. Apps pin the CA, so they never notice. If the active server CA key is lost or stolen, stop the server, replace `server-ca.jks` with `server-ca.backup.jks`, delete `recovery.jks` and start it — the door comes back under the backup CA, whose pin every app already carries. Generate a new backup and ship its pin in the next app release.

### Revoking a device

`DELETE /api/v1/client-certs/{id}` (or the dashboard's Revoke). From the next request on, every mTLS Config API listener answers that device `403 reenroll_required` (audited as `client_cert_revoked_refused`, summarised per minute): the TLS handshake still succeeds — the listener trusts the client CA — but nothing is served, and renewal is refused the same way. The client id stays revoked: a new enrollment under the same id is refused, so issue a new id.

### A device is enrolled again under a new client id (409)

The server keeps one active identity per device id (the `deviceUid` a device sends at enrollment, its ANDROID_ID). token_mtls files and E2E key registration trust that id to tie a certificate to a device, and it is self-reported — so a second identity claiming a device id that is already enrolled is refused with `409 device_already_enrolled`, before its token is spent (audited as `client_cert_enroll_refused`). A reinstalled app has lost its key; either mint the new token for the device's old client id (re-enrolling the same id replaces it), or revoke the old id and let the device retry with the token it already has. One identity covers every mTLS Config API of a server: they all trust the same client CA.

### A device cannot register its encryption key (409, 429, 503)

Only on a TLS Config API. It keeps the first E2E key a device registered; a device whose app data was cleared comes back with a new Keystore key and is refused (`409 key_change_requires_proof`, audited as `device_key_refused`) unless it presents its token for one of that scope's `end_to_end` files — the library sends one whenever the app has it, so issuing the device a token for such a file is enough. A device with no such file has nothing to prove itself with: remove its old key (`DELETE /api/v1/config-apis/{configApiId}/vault/devices/{deviceId}/public-key`, audited as `device_key_reset`) and it registers again at its next start. On an mTLS Config API there is nothing to do: a certificate that belongs to the device may replace its key.

On a TLS Config API the endpoint asks for no credential, so it is bounded. `429 rate_limited`: the device's address wrote `DEVICE_KEY_RATE_LIMIT` keys in the last 10 minutes (default 30; a device repeating its own key is not counted). Many devices behind one address (an office NAT, a reverse proxy) starting for the first time look like this; they retry at their next start. Raise the limit for a rollout (`0` turns it off), or move the `end_to_end` files to an mTLS Config API, where it does not apply. `503 device_key_limit_reached`: the Config API holds `DEVICE_KEY_LIMIT` keys (default 100 000) and new devices are not stored; known devices keep working. That many is usually made-up device ids: the `device_key_registered` audit entries show their source addresses. Remove them (`DELETE …/vault/devices/{deviceId}/public-key`, or in the database with the server stopped) or raise the limit. Both refusals are audited as `device_key_refused`.

### Rotating the client CA

Not automated, and it means re-enrollment: a device accepts a renewed certificate only from the CA that issued its current one, so after a client CA change every CSR-enrolled device has to enroll again with a new token. Stop the server, move `certs/client-ca.jks` away, start it: a new CA is generated and added to the truststore under the same alias. Plan it like a fleet re-enrollment.

## Known limits

- Recovery renewal proves possession of the device key and nothing else: a key extracted from a rooted device without hardware-backed Keystore keeps renewing until the client id is revoked. Attestation of the key at enrollment is not implemented.
- Client identities (`client_identities`, `client_certs`) are global, not per Config API, like the truststore.
- **The device id is self-reported.** One active identity per device id stops a second enrollment from taking over an enrolled device, but whoever enrolls *first* with a given id holds it — a stolen enrollment token used before the real device can claim the real device's id. The real device's enrollment then fails with `409`, which shows the theft; revoke the thief's id. After enrollment, an mTLS Config API holds a device to it: `X-Device-Id` must belong to the client certificate (`403 device_identity_mismatch`). A TLS Config API cannot check it: there the per-device host ACL only shapes what an honest device receives, and a `token` file opens for whoever holds the token.
- **Device-facing request bodies are capped at 64 KB** (`413`; a body without a declared length gets `411`). Admin uploads are not capped.
- The management-port copy of `POST /api/v1/client-certs/enroll` issues P12s only; CSR enrollment is on the Config API listeners. It records the device id under the same one-identity rule.
- **On a TLS Config API the first E2E key wins.** Whoever registers first for a device id that never registered holds the slot until the device shows its `end_to_end` file token or an administrator removes the key, and a stolen `end_to_end` file token is enough to replace the key and read the file. On an mTLS Config API only a certificate that belongs to the device sets its key — put files that matter there, with `token_mtls`. Key registration there is bounded, not authenticated: RSA 2048–4096 only, `DEVICE_KEY_RATE_LIMIT` writes per source address, `DEVICE_KEY_LIMIT` keys per Config API. The address is the TCP peer, so behind a reverse proxy every device shares the proxy's quota.

- **Key sets never expire.** A device that has not fetched since a revocation still trusts the old key.
- **A fresh install (or cleared app data) trusts the compiled-in keys** until its first successful fetch. Ship an app update after a revocation.
- **Per-file vault keys (`VaultFileConfig.signaturePublicKey`) are fixed.** Key sets do not rotate them.
- **Some writes are outside two-person approval:** device ACL edits (which pins a device receives), vault uploads, and token management. They are still audited.
- **A generated or uploaded certificate's backup key sits next to its primary** in `certs/`. It covers planned rotation and a key leaked elsewhere, not a server whose disk was read.
- **The live check is a safety net against mistakes, not attackers.** It trusts whatever the server's network path returns.
- **Freezing is bounded, not prevented.** Someone who can stop fresh configs from reaching a device can keep it on the last valid config until that config's `expiresAt`, which is `CONFIG_TTL_SECONDS`.
- **A database-level attacker can rewrite the whole audit chain.** The webhook copy, pushed as events happen and carrying the entry hash, is the tamper-evident record.
- **The server cannot see your app's signing settings.** Set `RECOVERY_REQUIRED_SIGNATURES` to the app's `requiredRecoverySignatures`, and never publish a set whose `requiredSignatures` your signers cannot meet for the app's own minimum.
- **Signing is per request for apps older than 2.1.** Even with `CONFIG_SIGNATURE_CACHE` on, such an app gets a fresh signature on every poll. The config endpoint is public, so put it behind your edge rate limiting when the signer is an HSM or KMS.
- **The signed payload does not name its Config API.** Starting and stopping listeners is therefore under two-person approval too: whoever decides which scope a port serves decides which pins devices on that port receive.
