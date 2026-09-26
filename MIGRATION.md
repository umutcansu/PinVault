# PinVault 2.0 — Configuration Guide

PinVault 2.0 uses a unified multi-Config-API DSL. This document is a quick
reference for how to configure it in common scenarios.

## Upgrading from 2.0.x to the security-hardened stream

The hardening changes (per-host pinning, required signatures, replay/freshness,
required P12 hash) flip several defenses from "optional" to "required". The
upgrade path depends on what your backend already does.

### 1. `signaturePublicKey` is now required on every `ConfigApiBlock`

```kotlin
// Before — accepted silently, signatures off.
.configApi("api", "https://api.example.com/") {
    bootstrapPins(...)
}

// After — `build()` throws IllegalArgumentException unless one of these is set.
.configApi("api", "https://api.example.com/") {
    bootstrapPins(...)
    signaturePublicKey("MFkwEwYHKoZIzj0CAQYIKoZI...")   // production
}

// OR, for tests / unsigned-endpoint demos:
.configApi("api", "https://api.example.com/") {
    bootstrapPins(...)
    allowUnsigned()    // disables signature, freshness, replay checks together
}
```

The exception message points at the same fix: set `signaturePublicKey(...)` or
call `allowUnsigned()` to opt out explicitly.

### 2. Signed configs must include `issuedAt` and `expiresAt`

If you run the demo server, you already get this — it stamps the fields and
honors `CONFIG_TTL_SECONDS` (default 24h).

If you run your own server, the signed payload must now look like:

```json
{
  "version": 3,
  "pins": [...],
  "issuedAt": 1715423456789,
  "expiresAt": 1715509856789
}
```

Both fields are Unix epoch **milliseconds**. Set `issuedAt = now()` and
`expiresAt = now() + ttl` right before signing. The library rejects responses
where either field is missing/zero, where `expiresAt <= now`, or where
`issuedAt <= storedIssuedAt`. See `SERVER_IMPLEMENTATION_GUIDE.md` for sample
signing code.

### 3. Enrollment must return `X-P12-SHA256` header

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
X-P12-SHA256: <base64(sha256(p12Bytes))>

<p12 bytes>
```

The library refuses to install a P12 if the header is absent. Compute the
SHA-256 over the response body and Base64-encode it (no padding stripping).

### 4. Pin scoping is per-host

Pin entries no longer cross-validate hosts. If your config registers pins for
both `bank.com` and `analytics.com`, the bank cert will only validate on
`bank.com` — analytics's pins cannot be used to MITM the bank channel even
when their private key leaks.

Wildcard support is RFC-6125-style single-label: `*.example.com` matches
`api.example.com` and `cdn.example.com`, but **not** `example.com` (apex) or
`a.b.example.com` (multi-label).

### 5. Per-host version downgrade is rejected

`updateNow()` now refuses a fetched config whose `HostPin.version` is lower
than the stored value for the same hostname. If you intentionally rolled back
a host's pin set (e.g., to revoke a bad rotation), bump the per-host
`version` past the previous value rather than resetting it.

### 6. `PinVaultConnectionEvent` is no longer one-of

The sealed class gains a `ConfigUpdate` variant alongside `Connection`.
Exhaustive `when` expressions over it need an extra branch — the compiler
will tell you exactly where. If you only care about handshake outcomes:

```kotlin
.onConnectionEvent { event ->
    when (event) {
        is PinVaultConnectionEvent.Connection   -> handle(event)
        is PinVaultConnectionEvent.ConfigUpdate -> Unit  // ignore
    }
}
```

Listeners that already use `PinVaultBackendReporter` need no code change —
the reporter handles both variants internally and POSTs to separate
endpoints.

### 7. Demo server: `API_KEY` is now required to start

```bash
# Before — silently disabled auth.
docker compose up

# After — refuses to start.
API_KEY=your-secret docker compose up

# Or opt out explicitly (dev only):
ALLOW_ANONYMOUS_ADMIN=true docker compose up
```

### 8. Custom `configApiId`? Add your own backup exclusion

The library's backup rules can only name the ids it knows (`default`,
`default-tls`, `secure-mtls`) — Android's `<exclude>` takes no wildcards. If
you register another id, your stored pins go into cloud backup and device
transfer, and restoring an old backup reinstates an old pin set:

```xml
<!-- your fullBackupContent AND both sections of your dataExtractionRules -->
<exclude domain="sharedpref" path="ssl_cert_config_my-api.xml" />
```

…or set `android:allowBackup="false"`. `PinVaultConfig.Builder.build()` logs a
warning naming the exact line when it sees an uncovered id. Nothing breaks if
you ignore it; the exposure is the M-07 downgrade-by-restore path.

### 9. No action needed: stored pin format gained a field

`CertificateConfigStore` now persists each host's `forceUpdate` flag as a
trailing field (`hostname|version|hash1,hash2|forceUpdate`). Entries written by
earlier versions have three fields and load with `false`, so upgrading in place
needs no migration and no refetch. (Downgrading the library below this version
is not supported — an older parser would fold the new field into the last pin
hash.)

### Suggested rollout order

1. Update server first so signed responses carry `issuedAt`/`expiresAt` and
   enrollment returns `X-P12-SHA256`.
2. Update client APK; the new library accepts both old (legacy-pinned) and new
   pin entries — only the signature/freshness checks are stricter.
3. Once all devices are on the new APK, you can tighten per-host version
   sequences and turn off `allowUnsigned()` in any remaining test fixtures.

## Optional: stronger signing (2.1)

Nothing here is required, and nothing changes until you opt in. Your existing `signaturePublicKey(key)` keeps working exactly as before. [`SECURE_OPERATIONS.md`](SECURE_OPERATIONS.md) explains which layer to use and when.

- **Ship a backup key:** `signaturePublicKeys(serverKey, offlineBackupKey)`. If the server key is lost, start signing with the backup and every installed app keeps updating.
- **Rotate or revoke keys without an app update:** add `recoveryPublicKeys(recoveryKey)` and give the same key to the server (`RECOVERY_PUBLIC_KEYS`). From then on, rotate through signed key sets, not the dashboard's "regenerate", which the server disables while a set is active.
- **Require two signatures:** `requiredSignatures(2)` with two `signaturePublicKeys`. Enable it only after the server signs with both keys (`CONFIG_SIGNERS=a,b`). An APK that asks for two signatures rejects every config signed by one.

Rollout order:

1. The server first. New fields and headers are ignored by older clients.
2. Then the app.
3. Turn on server features that assume new clients last. `CONFIG_SIGNATURE_CACHE` is safe at any time: it only serves cached envelopes to clients that announce `redelivery`.

Behaviour change to know about: a byte-identical signed config served twice is now reported as `AlreadyCurrent`. It used to fail as a replay. An older `issuedAt`, or an equal one with different content, is still rejected.

## Encrypted storage moves to the Android Keystore (2.1)

No action needed. PinVault no longer stores with androidx.security's EncryptedSharedPreferences, which Google deprecated in April 2025. Four fixed files replace it: `pinvault_secure_config.xml` (every Config API block, each in its own namespace), `pinvault_secure_client_cert.xml`, `pinvault_secure_signing_keys.xml` and `pinvault_secure_vault_files.xml`. Values are sealed with AES-256-GCM and names hidden with HMAC-SHA256; both keys are generated in the Android Keystore and never leave it.

- **First start after the update:** each store reads its 2.0.x file once with the old library, writes the entries in the new format and deletes the old file. Stored configs, enrolled client certificates, signing-key sets and cached vault files carry over: nothing is downloaded again and no device enrolls again. A 2.0.x file that no longer opens (its Keystore key is gone) is deleted, and the device fetches its config as on a fresh install.
- **Downgrading** to 2.0.x after that start is not supported: the old version finds none of its files and starts like a fresh install. It fetches the config again with its bootstrap pins, and mTLS devices enroll again.
- **Backups:** the bundled rules name the four files, so every Config API id is excluded. The per-id exclusion from step 8 is no longer needed (keeping it is harmless), and the build-time warning about uncovered ids is gone.
- **Dependency:** androidx.security:security-crypto stays on the classpath only to read 2.0.x files on that first start. A later major version drops it.

## Single Config API

Simplest setup — one backend, one or more vault files.

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(
            HostPin("api.example.com", listOf("sha256/AAAA…", "sha256/BBBB…"))
        ))
    }
    .vaultFile("flags") {
        configApi("api")
        endpoint("api/v1/vault/flags")
    }
    .build()

PinVault.init(context, config)
```

Block-level setters (inside `.configApi(id, url) { … }`):

| Setter | Purpose |
|---|---|
| `bootstrapPins(list)` | Pins compiled into the APK for the first connection |
| `configEndpoint(path)` | Overrides default `api/v1/certificate-config` |
| `healthEndpoint(path)` | Overrides default `health` |
| `signaturePublicKey(pem)` | Enables ECDSA signature verification on config responses |
| `clientKeystore(bytes, password)` | mTLS client P12 |
| `enrollmentEndpoint(path)` | Overrides `api/v1/client-certs/enroll` |
| `clientCertEndpoint(path)` | Overrides `api/v1/client-certs` |
| `vaultReportEndpoint(path)` | Overrides `api/v1/vault/report` |
| `clientCertLabel(label)` | Isolation namespace for multiple certs |
| `wantPinsFor(vararg hosts)` | Server-side pin scoping (least-privilege) |

Top-level setters (on the outer `Builder`):

| Setter | Purpose |
|---|---|
| `maxRetryCount(n)` | Default: 3 |
| `updateIntervalHours(n)` / `updateIntervalMinutes(n)` | Periodic refresh cadence |
| `deviceAlias(name)` | Human-readable device label |
| `vaultFile(key) { … }` | Register a vault file |
| `staticPins(config)` | Offline mode |

## Multi-Config-API

Register multiple Config APIs and bind each vault file to a specific one:

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("prod-tls", "https://host:8091") {
        bootstrapPins(prodTlsPins)
        wantPinsFor("cdn.example.com", "api.example.com")
    }
    .configApi("secure-mtls", "https://host:8092") {
        bootstrapPins(secureMtlsPins)
        clientKeystore(p12Bytes, devicePassword)
        wantPinsFor("internal.acme.com")
    }
    .vaultFile("feature-flags") {
        configApi("prod-tls")
        endpoint("api/v1/vault/feature-flags")
        accessPolicy(VaultFileAccessPolicy.PUBLIC)
    }
    .vaultFile("production-secrets") {
        configApi("secure-mtls")
        endpoint("api/v1/vault/production-secrets")
        storage(StorageStrategy.ENCRYPTED_FILE)
        accessPolicy(VaultFileAccessPolicy.TOKEN)
        accessToken { tokenForSecrets() }
        encryption(VaultFileEncryption.END_TO_END)
    }
    .build()

PinVault.init(context, config)
```

At runtime:

- `PinVault.fetchFile("feature-flags")` routes to the `prod-tls`
  pin-verified `OkHttpClient`.
- `PinVault.fetchFile("production-secrets")` routes to `secure-mtls`
  (mTLS handshake + token header + server-side RSA-OAEP + AES-GCM encryption
  + local Keystore-backed decryption).

Each Config API has its own pin-verified client, its own namespaced
`CertificateConfigStore` (no hostname collisions), and its own independent
bootstrap + init flow.

## Access policies

Register vault files with a server-enforced access policy:

| Policy | Device headers | Server check |
|---|---|---|
| `PUBLIC` | None | None (demo/test only) |
| `API_KEY` | `X-API-Key` | Global admin key (management tooling) |
| `TOKEN` | `X-Device-Id` + `X-Vault-Token` | Exact `(configApiId, key, deviceId)` triple match |
| `TOKEN_MTLS` | Same as `TOKEN` + mTLS cert | Same + cert CN must equal `X-Device-Id` |

**How tokens are issued**: Admin calls `POST /api/v1/vault/{key}/tokens` with
`{"deviceId": "…"}`. The plaintext is returned once; the server stores only
SHA-256. Admin delivers the plaintext to the device out-of-band (QR code,
enrollment response, secure channel). A new token for the same
`(configApi, key, deviceId)` triple replaces the previous one — the old
token becomes invalid automatically.

## End-to-end encryption

Server wraps the file with the device's RSA public key before sending:

```kotlin
.vaultFile("top-secret-model") {
    configApi("secure-mtls")
    endpoint("api/v1/vault/top-secret-model")
    storage(StorageStrategy.ENCRYPTED_FILE)
    accessPolicy(VaultFileAccessPolicy.TOKEN)
    accessToken { /* … */ }
    encryption(VaultFileEncryption.END_TO_END)
}
```

On first init PinVault:

1. Generates (or loads) an Android Keystore-backed RSA 2048 key pair
   (StrongBox if available).
2. Registers the public key with every Config API in the config.
3. When fetching an E2E file, the server wraps the content with that public
   key; the library decrypts via `VaultFileDecryptor` using the Keystore
   private key.

Hybrid scheme: fresh AES-256-GCM session key per response, RSA-OAEP-SHA256
wraps the session key. See `crypto/VaultFileDecryptor.kt` for the envelope
format.

## Server-side pin scoping

Declare which hosts the device actually uses:

```kotlin
.configApi("prod-tls", "https://host:8091") {
    bootstrapPins(listOf(HostPin("host:8091", listOf("…"))))
    wantPinsFor("cdn.example.com", "api.example.com")
}
```

The library sends `?hosts=cdn.example.com,api.example.com` with `X-Device-Id`
to the config endpoint. The server returns only pins for hostnames that
appear in both:

- the client's `wantPinsFor` request
- the `device_host_acl` table (+ `default_host_acl` fallback)

Hostnames the client asked for but is not authorized for are logged as
"unauthorized host request" events. Admin manages per-device ACLs and
defaults via the web UI (Config API detail → Vault → "Cihaz ACL yönet").

## Offline mode (no server)

```kotlin
val config = PinVaultConfig.static(
    HostPin("api.example.com", listOf("pin1", "pin2"))
)
PinVault.init(context, config)
```

No Config API is contacted. The library uses the embedded pins directly.
Vault files are ignored in this mode.

## Custom backend

Implement `CertificateConfigApi` and pass it to `PinVault.init`:

```kotlin
class MyBackendApi : CertificateConfigApi {
    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig { /* … */ }
    override suspend fun downloadHostClientCert(hostname: String): ByteArray { /* … */ }
    override suspend fun downloadVaultFile(endpoint: String): ByteArray { /* … */ }
    override suspend fun enroll(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?
    ): EnrollmentResult { /* … */ }
    override suspend fun healthCheck(): Boolean { /* … */ }

    // Optional V2 overrides (defaults delegate to the methods above):
    override suspend fun fetchScopedConfig(
        currentVersion: Int, hosts: List<String>?, deviceId: String?
    ): CertificateConfig { /* send hosts + deviceId to your backend */ }

    override suspend fun downloadVaultFileWithMeta(
        endpoint: String, currentVersion: Int, deviceId: String?, accessToken: String?
    ): VaultFetchResponse { /* return bytes + version + encryption header */ }

    override suspend fun registerDevicePublicKey(
        deviceId: String, publicKeyPem: String
    ) { /* register for E2E support */ }
}
```
