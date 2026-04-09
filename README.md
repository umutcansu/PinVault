# PinVault

Dynamic SSL certificate pinning library for Android. Update pins remotely without releasing a new APK.

## Features

- Remote pin config updates over HTTPS
- ECDSA signature verification (opt-in)
- Encrypted pin storage (AES-256-GCM via Android Keystore)
- Background periodic updates via WorkManager
- Certificate expiry validation
- Automatic pin recovery on mismatch (update + retry)
- Mutual TLS (mTLS) with host-specific client certificates
- Client certificate enrollment (token-based and automatic)
- Per-host versioning and force update support
- Configurable endpoints and retry logic

## Installation

```gradle
implementation("io.github.umutcansu:pinvault:1.0.1")
```

## Quick Start

```kotlin
// 1. Configure
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(
        HostPin("api.example.com", listOf("sha256hash1...", "sha256hash2..."))
    ))
    .build()

// 2. Initialize (in Application.onCreate or before first HTTPS call)
val result = PinVault.init(context, config)
when (result) {
    is InitResult.Ready -> Log.d("PinVault", "Ready — version ${result.version}")
    is InitResult.Failed -> Log.e("PinVault", "Init failed: ${result.reason}")
}

// 3. Use the pinned client
val client = PinVault.getClient()

// Or apply to an existing builder
val builder = OkHttpClient.Builder()
PinVault.applyTo(builder)
val client = builder.build()
```

### Callback API (Java / non-coroutine)

```kotlin
PinVault.init(context, config) { result ->
    when (result) {
        is InitResult.Ready -> { /* use PinVault.getClient() */ }
        is InitResult.Failed -> { /* handle error */ }
    }
}
```

## Configuration Options

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin(...)))
    .configEndpoint("ssl/pins")           // default: "api/v1/certificate-config"
    .healthEndpoint("ping")               // default: "health"
    .updateIntervalHours(6)               // default: 12
    .updateIntervalMinutes(30)            // takes precedence over hours
    .maxRetryCount(5)                     // default: 3
    .signaturePublicKey("MFkwEwYH...")    // ECDSA P-256 public key (optional)
    .clientKeystore(p12Bytes, "password") // mTLS client cert (optional)
    .enrollmentToken("one-time-token")    // auto-enrollment (optional)
    .clientCertLabel("my-cert")           // multi-cert label (optional)
    .build()
```

## Background Updates

Schedule periodic pin updates via WorkManager:

```kotlin
// Schedule updates (uses config interval, or 12h default)
PinVault.schedulePeriodicUpdates()

// With custom interval
PinVault.schedulePeriodicUpdates(intervalHours = 6)

// Cancel scheduled updates
PinVault.cancelPeriodicUpdates()

// Listen for update results
PinVault.setOnUpdateListener { result ->
    when (result) {
        is UpdateResult.Updated -> Log.d("PinVault", "Updated to v${result.newVersion}")
        is UpdateResult.AlreadyCurrent -> Log.d("PinVault", "Already current")
        is UpdateResult.Failed -> Log.e("PinVault", "Update failed: ${result.reason}")
    }
}
```

Updates run with a `NetworkType.CONNECTED` constraint and retry up to 3 times with exponential backoff on failure.

## Pin Recovery

When a request fails due to a pin mismatch (e.g., after a server certificate rotation), PinVault automatically:

1. Detects the SSL exception (`SSLPeerUnverifiedException` or `SSLHandshakeException`)
2. Fetches updated pins from the backend
3. Retries the original request with the new pinned client
4. Notifies the `OnUpdateListener` if registered

No manual intervention is needed. If the update itself fails, the original exception is propagated.

## Signature Verification

Sign your config responses with ECDSA P-256 to prevent tampering even if the backend is compromised.

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin(...)))
    .signaturePublicKey("MFkwEwYHKoZIzj0C...")  // ECDSA P-256 public key (Base64, X.509)
    .build()
```

When enabled, the backend must return a signed envelope:
```json
{
  "payload": "{\"version\":3,\"pins\":[...],\"forceUpdate\":false}",
  "signature": "MEUCIQD2a...base64..."
}
```

Unsigned or tampered responses are rejected and the library keeps the previous safe config.

## Mutual TLS (mTLS)

PinVault supports mTLS with host-specific client certificates.

### Direct P12 Loading

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(
        HostPin("api.example.com", listOf("hash1", "hash2"), mtls = true)
    ))
    .clientKeystore(p12Bytes, "password")
    .build()
```

### Host-Specific Certificates

When the backend sets `mtls = true` and `clientCertVersion` on a `HostPin`, PinVault automatically downloads the host-specific P12 certificate from `api/v1/client-certs/{hostname}/download` and stores it in encrypted storage. When the `clientCertVersion` changes, the new certificate is downloaded automatically.

## Client Certificate Enrollment

### Token-Based Enrollment

```kotlin
val success = PinVault.enroll(context, token = "one-time-token")
```

### Automatic Enrollment (Device ID)

```kotlin
val success = PinVault.autoEnroll(context)
```

### Check and Remove

```kotlin
// Check enrollment status
val enrolled = PinVault.isEnrolled(context)
val enrolledLabel = PinVault.isEnrolled(context, label = "custom-label")

// Remove client certificate
PinVault.unenroll(context)
PinVault.unenroll(context, label = "custom-label")
```

Certificates are stored encrypted using Android Keystore. Multiple certificates can coexist using different labels.

## Custom Backend

Implement `CertificateConfigApi` for full control over the config fetch:

```kotlin
class MyApi : CertificateConfigApi {
    override suspend fun healthCheck(): Boolean { ... }
    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig { ... }
    override suspend fun downloadHostClientCert(hostname: String): ByteArray { ... }
}

PinVault.init(
    context = appContext,
    configUrl = "https://...",
    bootstrapPins = listOf(HostPin(...)),
    configApi = MyApi()
)
```

## Vault Files (Remote File Versioning)

PinVault can manage arbitrary files (JSON configs, ML models, binary assets) with the same remote versioning and encrypted storage infrastructure used for certificate pins.

### Registration (DSL)

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin(...)))
    .vaultFile("ml-model") {
        endpoint("api/v1/vault/ml-model")
        storage(StorageStrategy.ENCRYPTED_FILE)  // large files
    }
    .vaultFile("feature-flags") {
        endpoint("api/v1/vault/flags")
        updateWithPins(true)  // sync during periodic updates
    }
    .vaultFile("secret-config") {
        endpoint("api/v1/vault/config")
        signaturePublicKey("MFkwEwYH...")  // tamper protection
        storage(myCustomStorageProvider)    // pluggable backend
    }
    .build()
```

### Fetch and Access

```kotlin
// Download and store
val result = PinVault.fetchFile("ml-model")
when (result) {
    is VaultFileResult.Updated -> Log.d("Vault", "v${result.version}, ${result.bytes.size} bytes")
    is VaultFileResult.AlreadyCurrent -> Log.d("Vault", "Already current v${result.version}")
    is VaultFileResult.Failed -> Log.e("Vault", result.reason)
}

// Read from cache
val bytes = PinVault.loadFile("ml-model")
val json = PinVault.loadFileAsString("feature-flags")

// Status
PinVault.hasFile("ml-model")      // true/false
PinVault.fileVersion("ml-model")  // current version
PinVault.clearFile("ml-model")    // remove from cache
```

### Storage Strategies

| Strategy | Use case | DSL |
|----------|----------|-----|
| `ENCRYPTED_PREFS` | Default. Small/medium files (<1MB) | `storage(StorageStrategy.ENCRYPTED_PREFS)` |
| `ENCRYPTED_FILE` | Large files (ML models, etc.) | `storage(StorageStrategy.ENCRYPTED_FILE)` |
| Custom | Your own backend | `storage(myProvider)` |

All strategies use Android Keystore for key management. Implement `VaultStorageProvider` for custom storage:

```kotlin
class MyStorage : VaultStorageProvider {
    override fun save(key: String, bytes: ByteArray, version: Int) { ... }
    override fun load(key: String): ByteArray? { ... }
    override fun getVersion(key: String): Int { ... }
    override fun exists(key: String): Boolean { ... }
    override fun clear(key: String) { ... }
}
```

### Background Sync

Files with `updateWithPins(true)` are synced automatically during periodic WorkManager updates. Listen for updates:

```kotlin
PinVault.setOnFileUpdateListener { key, result ->
    Log.d("Vault", "File $key: $result")
}
```

### Vault File Backend Contract

`GET {configUrl}/{vaultFile.endpoint}`

Response: Raw bytes (binary or JSON). Optional version header:

```
X-Vault-Version: 5
```

## Backend JSON Contract

### Config Endpoint

`GET {configUrl}/{configEndpoint}?currentVersion={version}`

Response:
```json
{
  "version": 3,
  "pins": [
    {
      "hostname": "api.example.com",
      "sha256": ["primaryPinBase64...", "backupPinBase64..."],
      "version": 3,
      "forceUpdate": false,
      "mtls": false,
      "clientCertVersion": null
    }
  ],
  "forceUpdate": false
}
```

**Pin fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | String | Yes | Hostname pattern (e.g. `"api.example.com"`) |
| `sha256` | String[] | Yes | SHA-256 hashes of SubjectPublicKeyInfo (Base64). **Minimum 2** (primary + backup). |
| `version` | Int | No | Per-host version (default: 0). Used for incremental updates. |
| `forceUpdate` | Boolean | No | Per-host force update flag (default: false). |
| `mtls` | Boolean | No | Whether this host requires a client certificate (default: false). |
| `clientCertVersion` | Int? | No | Client cert version. When changed, triggers re-download. |

### Health Endpoint

`GET {configUrl}/{healthEndpoint}`

Expected response:
```json
{"status": "ok"}
```

Returns `true` when `status` is `"ok"`, `false` otherwise.

### Client Certificate Download

`GET {configUrl}/api/v1/client-certs/{hostname}/download`

Returns PKCS12 binary bytes.

### Enrollment Endpoint

`POST {configUrl}/{enrollmentEndpoint}`

Request body (token-based):
```json
{"token": "one-time-token"}
```

Request body (auto-enrollment):
```json
{"deviceId": "android-device-id"}
```

Returns PKCS12 binary bytes.

## Validation Rules

- Each host must have **at least 2 SHA-256 pins** (primary + backup for safe rotation).
- SHA-256 pins must be Base64-encoded (44 characters).
- `configUrl` must not be blank.
- `bootstrapPins` must not be empty.
- Certificate expiry is validated during TLS handshake.

## API Reference

### Initialization

| Method | Description |
|--------|-------------|
| `PinVault.init(context, config): InitResult` | Initialize with config (suspend) |
| `PinVault.init(context, config, callback)` | Initialize with config (callback) |
| `PinVault.reset()` | Reset to system defaults (emergency fallback) |

### Client Access

| Method | Description |
|--------|-------------|
| `PinVault.getClient(): OkHttpClient` | Get pinned OkHttpClient |
| `PinVault.getClient(settings): OkHttpClient` | Get client with custom timeouts |
| `PinVault.applyTo(builder)` | Apply pinning to existing builder |

### Updates

| Method | Description |
|--------|-------------|
| `PinVault.updateNow(): UpdateResult` | Force immediate update (suspend) |
| `PinVault.schedulePeriodicUpdates(hours, callback)` | Schedule via WorkManager |
| `PinVault.cancelPeriodicUpdates()` | Cancel scheduled updates |
| `PinVault.setOnUpdateListener(listener)` | Register update callback |
| `PinVault.getScheduledWorkInfo(callback)` | Query scheduled task status |

### Enrollment

| Method | Description |
|--------|-------------|
| `PinVault.enroll(context, token, label?): Boolean` | Token-based enrollment (suspend) |
| `PinVault.autoEnroll(context): Boolean` | Device ID enrollment (suspend) |
| `PinVault.isEnrolled(context, label?): Boolean` | Check enrollment status |
| `PinVault.unenroll(context, label?)` | Remove client certificate |

### Status

| Method | Description |
|--------|-------------|
| `PinVault.currentVersion(): Int` | Current config version |
| `PinVault.isForceUpdate(): Boolean` | Whether force update is set |

### Result Types

```kotlin
sealed class InitResult {
    data class Ready(val version: Int) : InitResult()
    data class Failed(val reason: String, val exception: Exception?) : InitResult()
}

sealed class UpdateResult {
    data class Updated(val newVersion: Int) : UpdateResult()
    data object AlreadyCurrent : UpdateResult()
    data class Failed(val reason: String, val exception: Exception?) : UpdateResult()
}
```

## License

MIT
