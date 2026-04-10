# PinVault — Claude Context

## Proje Nedir
Android SSL certificate pinning library. Remote pin config, mTLS, VaultFile (generic remote file versioning), encrypted storage. Server-agnostic — herhangi bir backend ile veya sunucusuz (statik pin) calısır.

## Mimari
- `pinvault/` — ana library (126 unit test, hepsi geciyor)
- `demo-app/` — 5 demo activity (TLS/mTLS senaryolar + VaultFile), 61 Espresso test
- `demo-server/` — Ktor referans backend (Docker, API key auth, Flyway, Swagger)
- `sample-mtls-host/` — 192.168.1.217:9443 mTLS host

## Altyapi
- Gradle 8.7.3, Kotlin 2.1.0, Android compileSdk 35, minSdk 24, JVM 17
- Test: JUnit4, MockK, Robolectric, Espresso, MockWebServer, BouncyCastle
- Test Orchestrator + clearPackageData (cihaz izolasyonu)
- Fiziksel cihaz: Xiaomi Mi 9T (serial: 4360fdf2, Android 11)
- Emulatorler: Pixel 6 Pro, Pixel 7a, Pixel 8 Pro, Medium Phone API 36

## Sunucular (192.168.1.80)
- Management HTTP: :8090 (API key auth: X-API-Key header)
- TLS Config API: :8091 (server cert pin: ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=)
- mTLS Config API: :8092
- TLS Mock Host: :8444
- mTLS Host (192.168.1.217): :9443 (server pin: 0q4X9Qjv0eAzdAmRHsAF9G2Zj5fYSTPBGPt4522yYJw=)

## Kutuphane Ozellikleri
### SSL Pinning
- Dinamik pin config (remote fetch, per-host versioning, forceUpdate)
- Bootstrap pin (APK'ya gomulu ilk baglanti korumasi)
- Pin mismatch recovery (otomatik config guncelleme + retry)
- ECDSA config imzalama (SHA256withECDSA)
- Periyodik guncelleme (WorkManager)

### mTLS
- Host-spesifik client cert, composite KeyManager
- Token-based ve auto-enrollment (deviceId)
- P12 integrity check (SHA-256 hash + PKCS12 format dogrulama)

### VaultFile
DSL ile remote dosya versiyonlama:
```kotlin
.vaultFile("ml-model") {
    endpoint("api/v1/vault/ml-model")
    storage(StorageStrategy.ENCRYPTED_FILE)
}
```
- PinVault.fetchFile(), loadFile(), syncAllFiles(), hasFile(), clearFile(), fileVersion()
- Server distribution tracking (deviceAlias + ANDROID_ID bazli)

### Encrypted Storage
- AES-256-GCM, Android Keystore backed (hardware)
- Legacy SharedPreferences anahtarlari otomatik migrate
- Backup rules: client cert cloud backup'tan haric

### Server Bagimsizlik
Tum endpoint'ler yapilandirilabilir:
```kotlin
PinVaultConfig.Builder("https://myserver.com/")
    .configEndpoint("ssl/pins")
    .healthEndpoint("ping")
    .enrollmentEndpoint("auth/register")
    .clientCertEndpoint("certs/client")
    .vaultReportEndpoint("analytics/vault")
    .build()
```

CertificateConfigApi interface ile tamamen ozel backend:
```kotlin
PinVault.init(context, config, myCustomConfigApi)
```

Statik/offline mod (sunucu gerektirmez):
```kotlin
val config = PinVaultConfig.static(
    HostPin("api.example.com", listOf("pin1...", "pin2..."))
)
```

## Server (demo-server)
### Production Ozellikleri
- Docker + docker-compose (tek komutla deployment)
- API Key authentication (X-API-Key header, management endpoint'leri korur)
- Flyway DB migration (SQLite, baseline + versioned)
- OpenAPI / Swagger UI (`/docs`)
- Certificate expiry monitoring (`/api/v1/cert-expiry`, background check)
- Web dashboard (TR/EN, sertifika yonetimi, vault file dagitim takibi)

### Calistirma
```bash
# Gelistirme
gradle :demo-server:run

# Docker
cd demo-server && API_KEY=secret docker compose up
```

## Test Durumu
### Gecen testler (187 toplam)
- 126 library unit test (Robolectric) — hepsi geciyor
- 61 Espresso instrumented test (ActivityScenario + onView, Test Orchestrator)

### Test dosyalari (instrumented)
| Dosya | Test | Activity |
|-------|------|----------|
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

### Bilinen sorunlar
- Medium Phone API 36 emulatoru demo server'a (192.168.1.80) ulasamiyor — ag yapilandirmasi
- Mi 9T'de UiAutomation crash → Test Orchestrator ile cozuldu

## Dosya Konumlari
- Library: `pinvault/src/main/kotlin/io/github/umutcansu/pinvault/`
- Demo app: `demo-app/src/main/kotlin/com/example/pinvault/demo/`
- Demo app tests: `demo-app/src/androidTest/kotlin/com/example/pinvault/demo/`
- Demo server: `demo-server/src/main/kotlin/com/example/pinvault/server/`
- Web UI: `demo-server/src/main/resources/static/` (app.js, index.html, style.css)
- API docs: `demo-server/src/main/resources/static/openapi.yaml`
- Server guide: `SERVER_IMPLEMENTATION_GUIDE.md`
- QA evidence: `qa-evidence/` (screenshots, server JSON)
