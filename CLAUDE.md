# PinVault — Claude Context

## Proje Nedir
Android SSL certificate pinning library. Remote pin config, mTLS, VaultFile (generic remote file versioning), encrypted storage.

## Mimari
- `pinvault/` — ana library (126 unit test, hepsi geciyor)
- `demo-app/` — 4 TLS/mTLS senaryo + VaultFile demo activity
- `demo-server/` — Ktor backend (config API, vault routes, distribution tracking, web UI)
- `sample-mtls-host/` — 192.168.1.217:9443 mTLS host

## Altyapi
- Gradle 8.7.3, Kotlin 2.1.0, Android compileSdk 35, minSdk 24, JVM 17
- Test: JUnit4, MockK, Robolectric, Espresso, MockWebServer, BouncyCastle
- Allure raporlama: manuel JSON + adb screenshot eslestirme
- Fiziksel cihaz: Xiaomi Mi 9T (serial: 4360fdf2, Android 11)
- Emulatorler: Pixel 6 Pro, Pixel 7a, Pixel 8 Pro, Medium Phone API 36

## Sunucular (192.168.1.80)
- Management HTTP: :8090
- TLS Config API: :8091 (server cert pin: ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=)
- mTLS Config API: :8092
- TLS Mock Host: :8444
- mTLS Host (192.168.1.217): :9443 (server pin: 0q4X9Qjv0eAzdAmRHsAF9G2Zj5fYSTPBGPt4522yYJw=)

## VaultFile Ozelligi (bu session'da eklendi)
DSL ile remote dosya versiyonlama:
```kotlin
.vaultFile("ml-model") {
    endpoint("api/v1/vault/ml-model")
    storage(StorageStrategy.ENCRYPTED_FILE)
}
```
- PinVault.fetchFile(), loadFile(), syncAllFiles(), hasFile(), clearFile(), fileVersion()
- Server distribution tracking: POST /api/v1/vault/report
- Web UI: sidebar "Vault Files" bolumu (upload, dagitim gecmisi, stats)
- Storage: VaultStorageProvider interface, VaultFileStore (EncryptedPrefs), EncryptedFileStorageProvider (AES-GCM file)

## Test Durumu
### Gecen testler (187 toplam)
- 126 library unit test (Robolectric) — hepsi geciyor
- 17 VaultFileEspressoTest — Espresso UI, Activity acar, screenshot kaniti var
- 44 programmatik device test — PinVault API dogrudan cagirir, Activity ACMAZ

### Bilinen sorun
- `TlsConfigApiTest.tlsConfig_hostCert_not_downloaded_on_tls_api` — 192.168.1.217 host'unu TLS API'ye mtls=true eklemem sonucu regression. Config'den mtls flag'ini kaldir veya testi guncelle.

### YAPILACAK: 44 Programmatik Testi Espresso'ya Cevir
Asagidaki test dosyalari su an Activity acmadan PinVault API cagirir. HER BIRINI Espresso'ya cevirmek lazim — Activity acilacak, butonlara basilacak, sonuclar ekranda dogrulanacak, screenshot kaniti olacak.

| Dosya | Test | Kullanilacak Activity |
|-------|------|-----------------------|
| TlsConfigApiTest.kt | 5 test | TlsToTlsActivity |
| MtlsConfigApiTest.kt | 6 test | MtlsToTlsActivity (enrollment dahil) |
| ScenarioConnectionTest.kt | 4 test | TlsToTlsActivity |
| ActivityTransitionTest.kt | 3 test | Herhangi biri (reset/reinit testi) |
| AutoEnrollmentTest.kt | 3 test | TlsToMtlsActivity |
| UnenrollTest.kt | 4 test | TlsToTlsActivity / MtlsToTlsActivity |
| CertRotationTest.kt | 2 test | TlsToTlsActivity |
| OfflineReconnectTest.kt | 3 test | TlsToTlsActivity |
| PinMismatchRecoveryTest.kt | 2 test | TlsToTlsActivity |
| WorkManagerAndPersistenceTest.kt | 6 test | TlsToTlsActivity |
| MtlsVaultFileTest.kt | 6 test | VaultFileDemoActivity (mTLS config ile) |

Her Espresso test su akisi izlemeli:
1. PinVault.reset() — onceki test state'ini temizle
2. ActivityScenario.launch(XxxActivity::class.java) — Activity ac
3. Thread.sleep(12000) — PinVault init bekle
4. onView(withId(R.id.btnTest)).perform(click()) — butona bas
5. Thread.sleep(8000) — sonuc bekle
6. onView(withId(R.id.tvResult)).check(matches(...)) — assert
7. Background adb screenshot yakalanir

VaultFileEspressoTest.kt ornegini takip et — ActivityScenario.launch() pattern.

### Allure Rapor Olusturma
```bash
# 1. Testleri calistir + paralel screenshot
(while true; do adb shell screencap ... ; sleep 2; done) &
./gradlew :demo-app:connectedDebugAndroidTest

# 2. Screenshot'lari testlere esle (timestamp bazli)
python3 map script (allure-results icinde)

# 3. Rapor olustur
allure generate allure-results -o allure-report --clean
allure open allure-report --port 9999
```

### Report Bug: Screenshot Eslestirme
adb screenshot 2 saniye aralikla alinir, test timestamp'iyla eslestirme python3 script ile yapilir. Bazi testler cok kisa surerse ayni screenshot'a duser. Ideal cozum: Android Test Orchestrator + Allure-Kotlin entegrasyonu (ama Allure-Kotlin Mi 9T'de calismiyor — scoped storage sorunu).

### Report Bug: PinVault.reportFileDownload
Pinned client ile POST yapilamiyor (self-signed cert). Trust-all OkHttpClient ile cozuldu. `PinVault.kt:reportFileDownload()` fonksiyonunda.

## Dosya Konumlari
- Library: `pinvault/src/main/kotlin/io/github/umutcansu/pinvault/`
- Demo app: `demo-app/src/main/kotlin/com/example/pinvault/demo/`
- Demo app tests: `demo-app/src/androidTest/kotlin/com/example/pinvault/demo/`
- Demo server: `demo-server/src/main/kotlin/com/example/pinvault/server/`
- Web UI: `demo-server/src/main/resources/static/` (app.js, index.html, style.css)
- QA evidence: `qa-evidence/` (screenshots, server JSON)
- Allure: `allure-results/`, `allure-report/`
