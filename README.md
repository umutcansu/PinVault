# PinVault

Dynamic SSL certificate pinning library for Android. Manage pins remotely, support mTLS, distribute versioned files — all with encrypted storage.

## Features

- **Dynamic pin management** — fetch pins from your server, per-host versioning, force update
- **Bootstrap pinning** — hardcoded pins for initial connection security
- **mTLS support** — mutual TLS with token-based or automatic device enrollment
- **Pin mismatch recovery** — automatic config refresh and retry on pin failure
- **VaultFile** — remote versioned file distribution (ML models, configs, feature flags)
- **Encrypted storage** — AES-256-GCM with Android Keystore (hardware-backed)
- **Server-agnostic** — works with any backend, or offline with static pins
- **ECDSA signed configs** — verify config integrity with SHA256withECDSA

## Quick Start

### 1. Add dependency

```gradle
implementation("io.github.umutcansu:pinvault:1.0.0")
```

### 2. Initialize

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(
        HostPin("api.example.com", listOf("primaryPin...", "backupPin..."))
    ))
    .build()

val result = PinVault.init(context, config)
if (result is InitResult.Ready) {
    val client = PinVault.getClient() // pinned OkHttpClient
}
```

### 3. Use the pinned client

```kotlin
val response = PinVault.getClient()
    .newCall(Request.Builder().url("https://api.example.com/data").build())
    .execute()
```

## Usage Modes

### Remote pins (standard)

```kotlin
PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin("api.example.com", listOf("pin1", "pin2"))))
    .signaturePublicKey("MFkwEwYH...") // optional: ECDSA config verification
    .build()
```

### Static pins (offline, no server needed)

```kotlin
val config = PinVaultConfig.static(
    HostPin("api.example.com", listOf("pin1...", "pin2..."))
)
PinVault.init(context, config)
```

### Custom endpoints

```kotlin
PinVaultConfig.Builder("https://myserver.com/")
    .configEndpoint("ssl/pins")
    .healthEndpoint("ping")
    .enrollmentEndpoint("auth/register")
    .clientCertEndpoint("certs/client")
    .vaultReportEndpoint("analytics/vault")
    .build()
```

### Custom backend (any language)

```kotlin
class MyApi : CertificateConfigApi {
    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
        return myBackend.getPins(currentVersion)
    }
    override suspend fun healthCheck() = true
    override suspend fun enroll(token: String?, deviceId: String?,
        deviceAlias: String?, deviceUid: String?) = myBackend.enroll(token)
    override suspend fun downloadHostClientCert(hostname: String) = myBackend.getCert(hostname)
    override suspend fun downloadVaultFile(endpoint: String) = myBackend.getFile(endpoint)
}

PinVault.init(context, config, MyApi())
```

## mTLS Enrollment

```kotlin
// Token-based
PinVault.enroll(context, "one-time-token")

// Automatic (device ID)
PinVault.autoEnroll(context)
```

## VaultFile (Remote File Distribution)

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(...))
    .vaultFile("ml-model") {
        endpoint("api/v1/vault/ml-model")
        storage(StorageStrategy.ENCRYPTED_FILE)
    }
    .vaultFile("feature-flags") {
        endpoint("api/v1/vault/feature-flags")
        updateWithPins(true) // auto-sync on pin update
    }
    .deviceAlias("Warehouse Tablet #3") // human-readable device name
    .build()

// Fetch
val result = PinVault.fetchFile("ml-model")

// Load cached
val bytes = PinVault.loadFile("ml-model")
val json = PinVault.loadFileAsString("feature-flags")
```

## Device Tracking

```kotlin
PinVaultConfig.Builder("https://api.example.com/")
    .deviceAlias("Warehouse Tablet #3") // shown in server dashboard
    .build()
```

Server dashboard shows which device has which certificate and vault file version.

## Server

### Reference implementation (Docker)

```bash
cd demo-server
API_KEY=your-secret docker compose up
```

Dashboard: `http://localhost:8080`
API docs: `http://localhost:8080/docs`

### Build your own server

See [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md) for the API contract. Your server needs 3 endpoints:

1. `GET /health` — return `{"status":"ok"}`
2. `GET /api/v1/certificate-config` — return pin config JSON
3. `POST /api/v1/client-certs/enroll` — return PKCS12 bytes (if using mTLS)

Works with any language: Python, Node.js, Go, .NET, etc.

## Architecture

```
Android App                           Your Server
───────────                           ───────────
PinVault.init()              ───→     GET /certificate-config
  Pin config received        ←───     {pins: [{hostname, sha256[]}]}
  Stored encrypted (AES-GCM)

PinVault.getClient()         ───→     Your API endpoints
  Every request pinned                (TLS certificate verified)

PinVault.enroll()            ───→     POST /client-certs/enroll
  P12 certificate            ←───     PKCS12 bytes
  Stored in Keystore

PinVault.fetchFile("key")   ───→     GET /vault/{key}
  File cached encrypted      ←───     Binary bytes
```

## Requirements

- Android minSdk 24 (Android 7.0+)
- Kotlin coroutines or callback API
- OkHttp 4.x

## Production Security Checklist

PinVault is built around OWASP MASVS guidelines (NETWORK, CRYPTO, STORAGE).
Before shipping to production, verify the following:

### 1. Never ship the default keystore password
The `"changeit"` default in `PinVaultConfig.clientKeyPassword` and the
`clientKeystore(bytes, password)` builder is a development placeholder. In
production, generate a unique high-entropy password per device and negotiate
it with your backend during enrollment — never hard-code it in the APK.

```kotlin
// ❌ Don't
PinVaultConfig.Builder(url).clientKeystore(p12Bytes).build()

// ✅ Do
val devicePassword = backend.fetchKeystorePassword(deviceId) // ≥ 16 random chars
PinVaultConfig.Builder(url).clientKeystore(p12Bytes, devicePassword).build()
```

### 2. Strip Timber logs in release builds
The library logs every pin verification, enrollment, and vault file operation
through [Timber](https://github.com/JakeWharton/timber). Timber is silent
unless your application calls `Timber.plant()` — so in release builds, only
plant a `Timber.DebugTree()` when `BuildConfig.DEBUG` is true:

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) Timber.plant(Timber.DebugTree())
    }
}
```

### 3. Always use bootstrap pins for the first connection
Without bootstrap pins, the first config fetch is unpinned (vulnerable to MITM
on first install). Hardcode at least 2 SHA-256 SPKI hashes in the APK:

```kotlin
PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(
        HostPin("api.example.com", listOf("primary...", "backup..."))
    ))
    .build()
```

### 4. Enable ECDSA signature verification on configs
Without `signaturePublicKey()`, a compromised backend can serve any pins it
wants. Sign your configs server-side with ECDSA P-256 and ship the public key
in the APK:

```kotlin
PinVaultConfig.Builder(url)
    .signaturePublicKey("MFkwEwYHKoZI...") // X.509 public key, Base64
    .build()
```

See `SERVER_IMPLEMENTATION_GUIDE.md` for the signing protocol.

### 5. Backup exclusion is automatic
Client certificates are excluded from cloud backup and device-to-device transfer
via `pinvault_backup_rules.xml` and `pinvault_data_extraction_rules.xml`. The
manifest merger handles this automatically — no configuration needed.

### 6. Verify TLS configuration on your backend
- TLS 1.2 or higher (1.3 preferred)
- Server certificate matches at least one pinned SHA-256(SPKI) hash
- mTLS endpoints reject unknown client certs
- HTTP-only endpoints are off (the library refuses cleartext HTTPS hosts)

### 7. Rotate pins ahead of expiry
Configure at least 2 pins per host (primary + backup). Add the new pin to the
config 30+ days before the old certificate expires. Set `forceUpdate: true`
on the host entry to force clients to refresh immediately.

### What PinVault does NOT do
- **Root/jailbreak detection** — combine with libraries like RootBeer if needed
- **Code obfuscation** — enable R8/ProGuard in your app (`isMinifyEnabled = true`)
- **Network anomaly detection** — pair with your APM/SIEM
- **Frida/Xposed hooking detection** — out of scope; consider a dedicated
  RASP solution for high-value targets

## License

Apache 2.0
