# PinVault — Upgrading and configuration

The upgrade notes for every release since 2.0, troubleshooting, and a quick
reference for the multi-Config-API DSL. The full list of changes is in
[CHANGELOG.md](CHANGELOG.md).

## Upgrading from 2.3.0 to 2.3.1

Everything compiles unchanged. One behaviour changes for apps that call
`requireUnlockedDevice()`:

### `requireUnlockedDevice()` no longer falls back silently

Until 2.3.0, when a device's Keystore refused to make a key with
`setUnlockedDeviceRequired(true)`, the library made the key **without** the
requirement and logged a warning; the app had no way to know its keys were
usable while the phone was locked. Now the operation that needed the key
fails with `UnlockedDeviceKeyRequiredException` (a subclass of
`SSLPinningException`): `init` returns `InitResult.Failed` for the store
keys, enrollment `ClientCertEnrollmentResult.Failed`, a vault file
`VaultFileResult.Failed`, an imported P12 the same, each with that cause.
Devices whose Keystore accepts the flag — every Android 9+ device that
passes CTS — see no difference; Android 7 and 8 never had the flag and are
unchanged.

```kotlin
// Before 2.3.0 and now — strict: a refusing Keystore fails the operation.
.requireUnlockedDevice()

// The old behaviour, as an explicit choice: make the key without the
// requirement and warn. Java: requireUnlockedDevice(true).
.requireUnlockedDevice(allowFallback = true)
```

Keys that already exist are untouched either way; the option applies to
keys generated from now on ([Production Security Checklist §9](GUIDE.md#9-optional-keys-that-work-only-while-the-phone-is-unlocked-22)).

## Upgrading from 2.2.x to 2.3

Most apps compile unchanged. The exception: `PinVaultConnectionEvent` gained
an `Attestation` variant, so an exhaustive `when` over connection events needs
one more branch (or an `else`). What to expect:

- **Attestation is off** until a block calls `attestation()`; nothing changes
  for apps that do not. Play Integrity needs the separate
  `pinvault-play-integrity` artifact and a provider registered on the
  config; without it the APK carries nothing of Play Services.
- **Reference server:** migrations V21–V23 add the attestation tables and
  the Play Integrity columns; stored policies gain `play_integrity` /
  `play_integrity_missing` as `warn` automatically. Server keystores are
  rewritten as PKCS12 at start-up (file names unchanged); a JDK 9+ server
  of an older version still opens them. `CONFIG_API_ADMIN_ROUTES=off` and
  `ATTESTATION_KEY_POLICY=enforce` are the production profile, not the
  default.
- **A host entry that lists the same pin twice** is refused, by the library
  and by the reference server: a rotation needs two different pins.
- **Pinned clients follow no redirect into the clear.** `getClient()` and
  `getClient(settings)` no longer follow an https→http redirect, and the
  Config API's own client follows no redirect at all, not even to another
  https host. Builders you pass to `applyTo` keep their own settings.
- **An issuer pin checks the host name too.** When a host's pin matches a CA
  certificate in the chain rather than the leaf, the leaf must now carry a
  `subjectAltName` for that host, or the handshake fails with
  `HostnameMismatchException` (a `CertificateException`; no config refetch is
  tried for it). Leaf pins are unchanged, so self-signed and SAN-less
  certificates pinned by their own key still work.
- **The consumer R8 rules no longer keep PinVault's class names.** In a
  minified app the library's log tags are obfuscated; add
  `-keepnames class io.github.umutcansu.pinvault.**` yourself if you need
  them in logs.
- **Response bodies are read with a ceiling:** 1 MiB for a config, 256 KiB
  for small answers (enrollment, renewal, key registration, attestation,
  host client certificates), 64 MiB for a vault file. A larger body fails as
  an `IOException`; a vault fetch reports it as `Failed` with code
  `response_too_large`.
- **`VaultFileResult.Failed` has a `code`** (one of the
  `VaultFileResult.Failed.CODE_*` constants, or `http_<status>`), and the
  distribution report sends that code to the server instead of `reason`.
  `reason` still carries the full text for the app and the local log.

## Upgrading from 2.1.x to 2.2

Most apps compile unchanged. What to expect, and what may need a line:

- **Signed blocks: each vault file needs one fetch.** A copy stored by 2.1.x
  has no signature on record, so `loadFile` returns `null` for it
  (`fileStatus` = `NEEDS_FETCH`) until `fetchFile` / `syncAllFiles` has run
  once. Nothing is deleted. (The same release already asks a signed block for
  one config fetch, see the changelog.)
- **A server that answers enrollment with a P12** now gets `Failed` unless
  the block calls `allowServerGeneratedKey()`. The reference server from 2.1
  on issues over the CSR and needs nothing.
- **A server that issues a certificate without its CA certificate** (a chain
  of one), or valid for more than 825 days, is refused: send leaf + CA, or
  raise `maxClientCertLifetimeDays`.
- **The verification code is 16 characters.** A screen that showed 8 needs
  the room; a server of your own must compute the same 80 bits.
- **A backend of your own with `serverScope` set** must send
  `X-Vault-Signature-V2` for its vault files.
- **A custom `CertificateConfigApi` on a signed block** must also implement
  `SignedConfigSource` and hand over the signed envelope; otherwise `init`
  returns `Failed`, unless the block calls `allowUnsigned()`. See
  [Custom backend](#custom-backend).
- **`when` over `EnrollmentRefusal`** needs branches for
  `ATTESTATION_FAILED` and `CSR_REQUIRED`.
- **Pointing a block id at another Config API** (a new `configUrl` or
  `serverScope`) gives it a store of its own; going back finds the old
  watermarks again. **Changing the compiled-in signing or recovery keys** (or
  their thresholds) resets the replay watermarks once, on purpose.
- **`clientCertHosts`** — if you set it, list every host that must see the
  client certificate; `mtls = true` pins then add none.
- **An `END_TO_END` file served as `plain`** is refused (`Failed`).
- **Reference server:** mint enrollment tokens with the phone's device id
  (see [Where the token comes from](GUIDE.md#where-the-token-comes-from)) wherever the certificate must stand in for
  the device — `TOKEN_MTLS` files, key replacement over mTLS, host client
  certificates. `API_KEY` needs 16 characters.
- Stored P12 identities and host client certificates are moved into the
  Android Keystore on first load. Going back to 2.1.x afterwards means
  enrolling again (2.1.x does not know the imported form).

## Upgrading from 2.0.x to 2.1

No app code changes are needed from 2.0.9. A backend of your own that serves
vault files to a signed block must start sending `X-Vault-Signature`
([Signed vault files](GUIDE.md#signed-vault-files-21)); the reference server does.
On the first start 2.1 moves the 2.0.x
EncryptedSharedPreferences files (configs, client certificates, cached vault
files) into its Keystore-backed store and deletes them. Going back to 2.0.x
afterwards starts from scratch: bootstrap pins, re-enrollment, re-download.
Details: [Encrypted storage moves to the Android Keystore](#encrypted-storage-moves-to-the-android-keystore-21).

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
`issuedAt` is lower than or equal to the stored one and the content differs
from the stored config. The same signed config served again (equal
`issuedAt`, identical content) is reported as `AlreadyCurrent`, not as a
replay. See `SERVER_IMPLEMENTATION_GUIDE.md` for sample
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
        is PinVaultConnectionEvent.ConfigUpdate      -> Unit  // ignore
        is PinVaultConnectionEvent.ClientCertRenewal -> Unit  // 2.1
        is PinVaultConnectionEvent.Attestation       -> Unit  // 2.3
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

### 8. Custom `configApiId`? Add your own backup exclusion (2.0.x only)

From 2.1 every block is covered by the bundled rules; see [Encrypted storage moves to the Android Keystore](#encrypted-storage-moves-to-the-android-keystore-21).

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

From 2.2 the pins are stored as JSON (`config_pins_json`) instead. The
`|`-separated entry above is read once on the first load and rewritten as
JSON; nothing needs to be done.

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

Behaviour change to know about: a byte-identical signed config served twice is now reported as `AlreadyCurrent`. It used to fail as a replay. An older copy of the same content (a cache serving an earlier envelope) is `AlreadyCurrent` too: nothing is applied. An older or equal `issuedAt` with different content is still rejected.

## Encrypted storage moves to the Android Keystore (2.1)

No action needed. PinVault no longer stores with androidx.security's EncryptedSharedPreferences, which Google deprecated in April 2025. Four fixed files replace it: `pinvault_secure_config.xml` (every Config API block, each in its own namespace), `pinvault_secure_client_cert.xml`, `pinvault_secure_signing_keys.xml` and `pinvault_secure_vault_files.xml`. Values are sealed with AES-256-GCM and names hidden with HMAC-SHA256; both keys are generated in the Android Keystore and never leave it.

- **First start after the update:** each store reads its 2.0.x file once with the old library, writes the entries in the new format and deletes the old file. Stored configs, enrolled client certificates, signing-key sets and cached vault files carry over: nothing is downloaded again and no device enrolls again. A 2.0.x file that no longer opens (its Keystore key is gone) is deleted, and the device fetches its config as on a fresh install.
- **Downgrading** to 2.0.x after that start is not supported: the old version finds none of its files and starts like a fresh install. It fetches the config again with its bootstrap pins, and mTLS devices enroll again.
- **Backups:** the bundled rules name the four files, so every Config API id is excluded. The per-id exclusion from step 8 is no longer needed (keeping it is harmless), and the build-time warning about uncovered ids is gone.
- **Dependency:** androidx.security:security-crypto stays on the classpath only to read 2.0.x files on that first start. A later major version drops it.

## Troubleshooting

### Kotlin 1.9.x projects

Use PinVault `2.0.3` or later. Older 2.0.x versions emit Kotlin 2.1
metadata in their POM and trigger `Unable to read Kotlin metadata due to
unsupported metadata version`.

### "Unable to read Kotlin metadata"

If you see one of these errors when adding PinVault to your project:

```
warning: Unable to read Kotlin metadata due to unsupported metadata version.
error: Unable to read Kotlin metadata due to unsupported metadata kind: null.
```

it means a Kotlin compiler in your build pipeline is older than the
metadata it's trying to read. Try in this order:

1. **Use PinVault `2.0.0` or later** — earlier versions only support
   Kotlin 2.1+ consumers.
2. **Upgrade your project to Kotlin `1.9.25+`** — Kotlin 1.8 and below
   cannot read 1.9 metadata.
3. **If you use Hilt / Dagger / kapt**: upgrade Hilt to `2.51+` or Dagger
   to `2.51+`. Older versions bundle a pre-K2 `kotlin-metadata-jvm` that
   stumbles on transitive dependencies. Migrating from `kapt` to `KSP` is
   the long-term fix.
4. **Last resort**: add `kotlin.suppressKotlinVersionCompatibilityCheck=true`
   to your `gradle.properties`. This silences the warning, but the
   underlying issue may still surface elsewhere.

### Compile errors after upgrading from 1.x to 2.x

If you upgraded from PinVault `1.x` to `2.x` and now see compile errors
like:

```
error: constructor Builder in class Builder cannot be applied to given types;
       new PinVaultConfig.Builder("https://...")
       required: no arguments

error: constructor HostPin in class HostPin cannot be applied to given types;
       new HostPin("host", Arrays.asList(...))
       required: String,List<String>,int,boolean,boolean,Integer
```

these are **API breaking changes** introduced in `2.0`, not metadata
errors. v2 replaced the single-URL constructor with a multi-Config-API
DSL, and `HostPin` gained four optional fields. Update your Java code
following the patterns in the guide's
[section 2b](GUIDE.md#2b-initialize-v2-dsl--java-consumers), or read
the DSL reference below. If migrating
to v2 isn't an option right now, pin the dependency to the latest
`1.x` release.

## Single Config API

Simplest setup — one backend, one or more vault files.

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(
            // Base64 SHA-256 of the SPKI, 44 characters, no "sha256/" prefix
            HostPin("api.example.com", listOf("AAAA…=", "BBBB…="))
        ))
        signaturePublicKey(SIGNING_KEY)   // or allowUnsigned() for tests
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
        signaturePublicKey(SIGNING_KEY)
        wantPinsFor("cdn.example.com", "api.example.com")
    }
    .configApi("secure-mtls", "https://host:8092") {
        bootstrapPins(secureMtlsPins)
        signaturePublicKey(SIGNING_KEY)
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
    bootstrapPins(listOf(HostPin("host:8091", listOf("primaryPin…", "backupPin…"))))
    signaturePublicKey(SIGNING_KEY)
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

Implement `CertificateConfigApi` and pass it to `PinVault.init`. For a block
with `signaturePublicKey(...)` (2.2 on), also implement `SignedConfigSource`
and return the signed envelope as your backend serves it; PinVault verifies it
like its own fetches. Without it, `init` returns `Failed` unless the block
calls `allowUnsigned()`.

```kotlin
class MyBackendApi : CertificateConfigApi, SignedConfigSource {
    // Signed blocks: the envelope, verified by PinVault. fetchConfig is then
    // not called. fetchScopedSignedConfig(...) is the wantPinsFor variant
    // (default: fetchSignedConfig).
    override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse {
        val body = myBackend.getSignedPins(currentVersion)   // {"payload": "...", "signature": "..."}
        return SignedConfigResponse(payload = body.payload, signature = body.signature)
    }

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

More detail, including Java: [Custom `CertificateConfigApi`](GUIDE.md#custom-certificateconfigapi-bring-your-own-backend).
