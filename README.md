# PinVault

Dynamic SSL certificate pinning library for Android. Update pins remotely without releasing a new APK.

## Features

- Remote pin config updates over HTTPS
- ECDSA signature verification (opt-in)
- Encrypted pin storage (AES-256-GCM via Android Keystore)
- Background periodic updates via WorkManager
- Certificate expiry validation
- Configurable endpoints and retry logic

## Installation

```gradle
implementation("io.github.umutcansu:pinvault:1.0.0")
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

// 3. Apply to OkHttpClient
val builder = OkHttpClient.Builder()
PinVault.applyTo(builder)
val client = builder.build()
```

## Custom Endpoints

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin(...)))
    .configEndpoint("ssl/pins")       // default: "api/v1/certificate-config"
    .healthEndpoint("ping")           // default: "health"
    .updateIntervalHours(6)           // default: 12
    .maxRetryCount(5)                 // default: 3
    .build()
```

## Signature Verification

Sign your config responses with ECDSA P-256 to prevent tampering even if the backend is compromised.

```kotlin
val config = PinVaultConfig.Builder("https://api.example.com/")
    .bootstrapPins(listOf(HostPin(...)))
    .signaturePublicKey("MFkwEwYHKoZIzj0C...")  // ECDSA P-256 public key
    .build()
```

When enabled, the backend must return:
```json
{
  "payload": "{\"version\":3,\"pins\":[...],\"forceUpdate\":false}",
  "signature": "MEUCIQD2a...base64..."
}
```

## Custom Backend

Implement `CertificateConfigApi` for full control over the config fetch:

```kotlin
class MyApi : CertificateConfigApi {
    override suspend fun healthCheck(): Boolean { ... }
    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig { ... }
}

PinVault.init(
    context = appContext,
    configUrl = "https://...",
    bootstrapPins = listOf(HostPin(...)),
    configApi = MyApi()
)
```

## Backend JSON Contract

Standard config endpoint must return:
```json
{
  "version": 3,
  "pins": [
    {
      "hostname": "api.example.com",
      "sha256": ["primaryPinBase64...", "backupPinBase64..."]
    }
  ],
  "forceUpdate": false
}
```

## License

MIT
