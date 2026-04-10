# PinVault — Claude Context

## What Is This
Android SSL certificate pinning library. Remote pin config, mTLS, VaultFile (generic remote file versioning), encrypted storage. Server-agnostic — works with any backend or offline with static pins.

## Architecture
- `pinvault/` — core library (126 unit tests, all passing)
- `demo-app/` — 5 demo activities (TLS/mTLS scenarios + VaultFile), 61 Espresso tests
- `demo-server/` — Ktor reference backend (Docker, API key auth, Flyway, Swagger)
- `sample-mtls-host/` — 192.168.1.217:9443 mTLS host

## Stack
- Gradle 8.7.3, Kotlin 2.1.0, Android compileSdk 35, minSdk 24, JVM 17
- Test: JUnit4, MockK, Robolectric, Espresso, MockWebServer, BouncyCastle
- Test Orchestrator + clearPackageData (device isolation)
- Physical device: Xiaomi Mi 9T (serial: 4360fdf2, Android 11)
- Emulators: Pixel 6 Pro, Pixel 7a, Pixel 8 Pro, Medium Phone API 36

## Servers (192.168.1.80)
- Management HTTP: :8090 (API key auth: X-API-Key header)
- TLS Config API: :8091 (server cert pin: ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=)
- mTLS Config API: :8092
- TLS Mock Host: :8444
- mTLS Host (192.168.1.217): :9443 (server pin: 0q4X9Qjv0eAzdAmRHsAF9G2Zj5fYSTPBGPt4522yYJw=)

## Library Features
### SSL Pinning
- Dynamic pin config (remote fetch, per-host versioning, forceUpdate)
- Bootstrap pins (hardcoded in APK for initial connection)
- Pin mismatch recovery (automatic config refresh + retry)
- ECDSA config signing (SHA256withECDSA)
- Periodic updates (WorkManager)

### mTLS
- Host-specific client cert, composite KeyManager
- Token-based and auto-enrollment (deviceId)
- P12 integrity check (SHA-256 hash + PKCS12 format validation)

### VaultFile
DSL-based remote file versioning:
```kotlin
.vaultFile("ml-model") {
    endpoint("api/v1/vault/ml-model")
    storage(StorageStrategy.ENCRYPTED_FILE)
}
```
- PinVault.fetchFile(), loadFile(), syncAllFiles(), hasFile(), clearFile(), fileVersion()
- Server distribution tracking (deviceAlias + ANDROID_ID based)

### Encrypted Storage
- AES-256-GCM, Android Keystore backed (hardware)
- Legacy SharedPreferences keys auto-migrated
- Backup rules: client certs excluded from cloud backup

### Server Independence
All endpoints configurable:
```kotlin
PinVaultConfig.Builder("https://myserver.com/")
    .configEndpoint("ssl/pins")
    .healthEndpoint("ping")
    .enrollmentEndpoint("auth/register")
    .clientCertEndpoint("certs/client")
    .vaultReportEndpoint("analytics/vault")
    .build()
```

Custom backend via CertificateConfigApi interface:
```kotlin
PinVault.init(context, config, myCustomConfigApi)
```

Static/offline mode (no server required):
```kotlin
val config = PinVaultConfig.static(
    HostPin("api.example.com", listOf("pin1...", "pin2..."))
)
```

## Server (demo-server)
### Production Features
- Docker + docker-compose (single command deployment)
- API Key authentication (X-API-Key header, protects management endpoints)
- Flyway DB migration (SQLite, baseline + versioned)
- OpenAPI / Swagger UI (`/docs`)
- Certificate expiry monitoring (`/api/v1/cert-expiry`, background check)
- Web dashboard (TR/EN, certificate management, vault file distribution tracking)

### Running
```bash
# Development
gradle :demo-server:run

# Docker
cd demo-server && API_KEY=secret docker compose up
```

## Test Status
### Passing tests (187 total)
- 126 library unit tests (Robolectric) — all passing
- 61 Espresso instrumented tests (ActivityScenario + onView, Test Orchestrator)

### Test files (instrumented)
| File | Tests | Activity |
|------|-------|----------|
| VaultFileEspressoTest.kt | 17 | VaultFileDemoActivity |
| MtlsVaultFileTest.kt | 6 | VaultFileDemoActivity (mTLS) |
| TlsConfigApiTest.kt | 5 | TlsToTlsActivity |
| MtlsConfigApiTest.kt | 6 | MtlsToTlsActivity |
| ScenarioConnectionTest.kt | 4 | TlsToTls / MtlsToTls |
| ActivityTransitionTest.kt | 3 | Various |
| AutoEnrollmentTest.kt | 3 | TlsToMtlsActivity |
| UnenrollTest.kt | 4 | TlsToTls / MtlsToTls |
| CertRotationTest.kt | 2 | TlsToTlsActivity |
| OfflineReconnectTest.kt | 3 | TlsToTlsActivity |
| PinMismatchRecoveryTest.kt | 2 | TlsToTlsActivity |
| WorkManagerAndPersistenceTest.kt | 6 | TlsToTlsActivity |

### Known issues
- Medium Phone API 36 emulator cannot reach demo server (192.168.1.80) — network config needed
- Mi 9T UiAutomation crash — resolved with Test Orchestrator

## File Locations
- Library: `pinvault/src/main/kotlin/io/github/umutcansu/pinvault/`
- Demo app: `demo-app/src/main/kotlin/com/example/pinvault/demo/`
- Demo app tests: `demo-app/src/androidTest/kotlin/com/example/pinvault/demo/`
- Demo server: `demo-server/src/main/kotlin/com/example/pinvault/server/`
- Web UI: `demo-server/src/main/resources/static/` (app.js, index.html, style.css)
- API docs: `demo-server/src/main/resources/static/openapi.yaml`
- Server guide: `SERVER_IMPLEMENTATION_GUIDE.md`
