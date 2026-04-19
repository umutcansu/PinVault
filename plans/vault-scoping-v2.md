# PinVault 2.0 — Multi-Config-API + Vault Scoping + Per-File Security

## Bağlam (karar verilen seçimler)

| # | Soru | Seçim |
|---|---|---|
| 1 | Vault feature kapsamı | **B** — Config API toggle + per-file güvenlik (token + E2E şifreleme) aynı sürümde |
| 2 | Mevcut 3 vault dosyası | **B** — Sil, baştan yükle |
| 3 | Mobil SDK API değişikliği | **B** — Mobilde de explicit Config API seçimi |
| 4 | E2E şifreleme key yönetimi | **B** — Server her cihazın public key'iyle ayrı ayrı şifreler |
| 5 | Access token modeli | **C** — Per-cihaz token (enrollment sırasında üretilir) |
| 6 | Multi-Config-API mobil API | **A** — DSL ile tanım, tek PinVault singleton |
| Pin scoping | — | **D** — Client `wantPinsFor(...)` + server per-device ACL (hybrid) |
| Mimari disiplin | — | Library ↔ interface ↔ backend ayrımı. Web UI sunum katmanı. |

## Mimari hedef

```
Library (pinvault/)
    │ CertificateConfigApi interface (soyut)
    ▼
PinVaultBackendApi (demo impl) ───── CustomImpl (kullanıcı kendi)
    │ HTTP
    ▼
demo-server (Ktor + SQLite)
    ▲
    │ HTTP
Web UI (static/) — sadece sunum
```

- **Library hiçbir URL/endpoint bilmez** — sadece interface metodlarını çağırır
- **Demo-server referans implementasyon** — kullanıcı kendi backend'ini yazabilir
- **Web UI backend'in management katmanı** — library'i hiç import etmez

---

## Faz 1 — DB Schema Migration (~3 saat)

### Yeni Flyway migration: `V2__vault_scoping_and_security.sql`

```sql
-- Config API'ye vault toggle
ALTER TABLE config_apis ADD COLUMN vault_enabled INTEGER NOT NULL DEFAULT 1;

-- vault_files scoping + policy (kullanıcı 2B: mevcut veriyi sil)
DROP TABLE IF EXISTS vault_files;
CREATE TABLE vault_files (
    config_api_id      TEXT    NOT NULL,
    key                TEXT    NOT NULL,
    content            BLOB    NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1,
    access_policy      TEXT    NOT NULL DEFAULT 'public',
                        -- public | api_key | token | enrolled_device
    encryption         TEXT    NOT NULL DEFAULT 'plain',
                        -- plain | at_rest | end_to_end
    updated_at         TEXT    NOT NULL,
    PRIMARY KEY (config_api_id, key),
    FOREIGN KEY (config_api_id) REFERENCES config_apis(id)
);

-- vault_distributions scoping
DROP TABLE IF EXISTS vault_distributions;
CREATE TABLE vault_distributions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id        TEXT    NOT NULL,
    vault_key            TEXT    NOT NULL,
    version              INTEGER NOT NULL,
    device_id            TEXT    NOT NULL,
    device_manufacturer  TEXT,
    device_model         TEXT,
    enrollment_label     TEXT,
    status               TEXT    NOT NULL,
    timestamp            TEXT    NOT NULL,
    device_alias         TEXT
);

-- Per-cihaz access token (her dosya için ayrı token)
CREATE TABLE vault_file_tokens (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id      TEXT    NOT NULL,
    vault_key          TEXT    NOT NULL,
    device_id          TEXT    NOT NULL,
    token_hash         TEXT    NOT NULL,       -- SHA-256 of plaintext token
    created_at         TEXT    NOT NULL,
    revoked            INTEGER NOT NULL DEFAULT 0,
    UNIQUE(config_api_id, vault_key, device_id)
);

-- Cihaz public key'leri (E2E encryption için)
CREATE TABLE device_public_keys (
    device_id          TEXT    NOT NULL,
    config_api_id      TEXT    NOT NULL,
    public_key_pem     TEXT    NOT NULL,       -- RSA public key
    algorithm          TEXT    NOT NULL DEFAULT 'RSA-OAEP-SHA256',
    registered_at      TEXT    NOT NULL,
    PRIMARY KEY (device_id, config_api_id)
);

-- Per-device host ACL (pin scoping)
CREATE TABLE device_host_acl (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    config_api_id      TEXT    NOT NULL,
    device_id          TEXT    NOT NULL,
    hostname           TEXT    NOT NULL,
    granted_at         TEXT    NOT NULL,
    UNIQUE(config_api_id, device_id, hostname)
);

-- Default ACL (enroll edilen cihaz için varsayılan izin seti)
CREATE TABLE default_host_acl (
    config_api_id      TEXT    NOT NULL,
    hostname           TEXT    NOT NULL,
    PRIMARY KEY (config_api_id, hostname)
);
```

---

## Faz 2 — Backend (demo-server) (~15 saat)

### 2.1 Store katmanı
- `VaultFileStore` — tüm metodlara `configApiId: String` parametresi
- **Yeni:** `VaultFileTokenStore` — token üret/doğrula/iptal
- **Yeni:** `DevicePublicKeyStore` — cihaz public key kayıt + getir
- **Yeni:** `DeviceHostAclStore` — per-cihaz ACL + default ACL
- `VaultDistributionStore` — `configApiId` parametresi

### 2.2 Servis katmanı (yeni)
- `VaultEncryptionService`:
  - `encryptForDevice(content: ByteArray, devicePublicKey: RSAPublicKey): ByteArray`
  - RSA-OAEP-SHA256 ile hybrid (AES session key RSA ile sarılı)
- `VaultAccessTokenService`:
  - `generate(configApiId, vaultKey, deviceId): String` — 32 byte random base64
  - `validate(token, configApiId, vaultKey, deviceId): Boolean` — constant-time

### 2.3 Route genişleme

**VaultRoutes.kt** — her endpoint `configApiId` scoped:

```
POST /api/v1/vault/devices/{deviceId}/public-key
  [cihaz enrollment sonrası public key kaydeder]

GET /api/v1/vault/{key}?version=N
  Headers: X-Device-Id, X-Vault-Token (opsiyonel)
  Flow:
    1. configApiId context'ten (URL scope'tan)
    2. Dosyayı DB'den çek + access_policy kontrol et
       - public: direkt ver
       - api_key: X-API-Key header iste
       - token: X-Vault-Token header iste + tokenStore.validate
       - enrolled_device: mTLS cert + device_id kontrol
    3. encryption == "end_to_end" ise:
       - devicePublicKeyStore.get(deviceId, configApiId) bul
       - VaultEncryptionService.encryptForDevice(content, publicKey)
       - response body = şifreli blob
    4. Response: encrypted/plain bytes + X-Vault-Version + X-Vault-Encryption headers

POST /api/v1/vault/tokens
  Body: { configApiId, vaultKey, deviceId }
  → Admin tarafından çağrılır, token üretir, cihaza verilmek üzere döner
  Admin yetkisi: X-API-Key

DELETE /api/v1/vault/tokens/{tokenId}
  → Token iptal
```

**CertificateConfigRoutes.kt** — pin scoping:

```
GET /api/v1/certificate-config?hosts=host1,host2
  Flow:
    1. configApiId URL scope'tan
    2. deviceId mTLS cert'ten veya X-Device-Id header'dan
    3. requested = hosts parametresi (null ise "hepsi")
    4. allowed = DeviceHostAclStore.getAllowed(configApiId, deviceId)
                  ∪ DefaultHostAclStore.get(configApiId)
    5. response = pins WHERE hostname IN (requested ∩ allowed)
    6. requested - allowed boşsa 403 (log: "unauthorized host access attempt")
```

### 2.4 Admin endpoints (Web UI için)

```
PUT    /api/v1/config-apis/{id}/vault-enabled    → toggle
PUT    /api/v1/vault/{id}/{key}/policy           → access_policy + encryption güncelle
GET    /api/v1/vault/{id}/{key}/tokens           → token listesi
POST   /api/v1/vault/{id}/{key}/tokens           → yeni token üret
DELETE /api/v1/vault/tokens/{tokenId}            → iptal
GET    /api/v1/devices/{deviceId}/host-acl       → cihazın ACL'si
PUT    /api/v1/devices/{deviceId}/host-acl       → ACL güncelle
GET    /api/v1/config-apis/{id}/default-host-acl → default set
PUT    /api/v1/config-apis/{id}/default-host-acl → default set güncelle
```

---

## Faz 3 — Library (pinvault/) (~20 saat)

### 3.1 Interface genişleme

```kotlin
interface CertificateConfigApi {
    suspend fun fetchConfig(
        configApiId: String,
        hosts: List<String>? = null,      // YENİ: pin scoping
        deviceId: String? = null          // YENİ
    ): ConfigResponse

    suspend fun fetchVaultFile(
        configApiId: String,              // YENİ: multi-API
        key: String,
        currentVersion: Int,
        deviceId: String,                 // YENİ
        accessToken: String? = null       // YENİ: per-file token
    ): VaultResponse

    suspend fun registerDevicePublicKey(
        configApiId: String,              // YENİ
        deviceId: String,
        publicKeyPem: String
    )

    suspend fun reportVaultDownload(configApiId: String, report: VaultReport)
    suspend fun enrollDevice(configApiId: String, req: EnrollmentRequest): EnrollmentResponse
}
```

Response genişler:
```kotlin
data class VaultResponse(
    val content: ByteArray,
    val version: Int,
    val encryption: String,               // YENİ: "plain"|"at_rest"|"end_to_end"
    val notModified: Boolean = false
)
```

### 3.2 DSL — PinVaultConfig.Builder

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("prod-tls", "https://host:8091") {
        bootstrapPins(listOf(HostPin("host:8091", listOf("ziA0...="))))
        configEndpoint("api/v1/certificate-config")
        wantPinsFor("cdn.example.com", "api.example.com")  // YENİ
    }
    .configApi("secure-mtls", "https://host:8092") {
        bootstrapPins(listOf(HostPin("host:8092", listOf("XyZ9...="))))
        configEndpoint("api/v1/certificate-config")
        clientCert(keystorePath, password)
        wantPinsFor("internal.acme.com")
    }
    .vaultFile("feature-flags") {
        configApi("prod-tls")              // YENİ: hangi API
        endpoint("api/v1/vault/feature-flags")
        accessPolicy(PUBLIC)                // YENİ
    }
    .vaultFile("ml-model") {
        configApi("secure-mtls")
        storage(ENCRYPTED_FILE)
        accessPolicy(TOKEN)                 // YENİ
        accessToken(provideTokenFromEnrollment())
        encryption(END_TO_END)              // YENİ
    }
    .build()

PinVault.init(context, config)
```

### 3.3 Internal mimari

```kotlin
// PinVault singleton içinde
private val apiClients: Map<String, ConfigApiClient>
    // her Config API için ayrı OkHttp + pin store
private val keyToApi: Map<String, String>
    // "feature-flags" → "prod-tls"
private val pinStores: Map<String, CertificateConfigStore>
    // her Config API için ayrı namespace
private val devicePrivateKey: PrivateKey
    // Android Keystore'da üretilen RSA key
    // public key'i enrollment sırasında her Config API'ye register edilir
```

### 3.4 Yeni sınıflar

- **`DeviceKeyProvider`** — Android Keystore-backed RSA 2048 key üretimi
- **`VaultFileDecryptor`** — `encryption=end_to_end` response'u device private key ile decrypt
- **`PerConfigApiPinStore`** — pin store'u configApiId ile namespace'le (EncryptedSharedPreferences key: `"pins:$configApiId:$hostname"`)
- **`ConfigApiClient`** — her Config API için bir OkHttpClient + pin store sarmalı
- **`VaultFileRouter`** — `fetchFile(key)` çağrısını doğru `ConfigApiClient`'a yönlendir

### 3.5 Init akışı (multi-API)

```kotlin
PinVault.init(context, config, callback):
  1. DeviceKeyProvider.ensureKey()  // RSA key hazırla (bir kez)
  2. For each configApi in config.configApis:
       a. Bootstrap pin ile ConfigApiClient oluştur
       b. publicKey'i registerDevicePublicKey(configApiId, deviceId, pub) ile gönder
       c. fetchConfig(configApiId, hosts=wantPinsFor) çağır
       d. Response'taki pin'leri PerConfigApiPinStore'a yaz
       e. ConfigApiClient'ı güncel pin'lerle yeniden yapılandır
  3. keyToApi map'i DSL'den doldur
  4. callback(Ready)
```

---

## Faz 4 — Demo-app (~3 saat)

### 4.1 VaultFileDemoActivity güncelle
- İki Config API (TLS + mTLS) örneği
- 3 vault dosyası: biri public, biri token-protected, biri E2E-encrypted

### 4.2 Yeni activity: VaultSecurityDemoActivity
- Access policy değişimlerini live göster
- E2E decrypt'ın başarılı / başarısız (kasıtlı yanlış key) senaryoları

---

## Faz 5 — Web UI (~10 saat)

### 5.1 Config API editor
- Vault enabled toggle

### 5.2 Vault Dosyaları sekmesi (mevcut sekmeyi refactor)
- Üstte Config API seçici (aktif API'yi scope)
- Upload dialog'u genişle:
  - Access policy dropdown (public / api_key / token / enrolled_device)
  - Encryption dropdown (plain / at_rest / end_to_end)
- Dosya detayında "Token Yönetimi" butonu:
  - Tokens tablosu (deviceId + created_at + revoked)
  - "Yeni token üret" + "İptal et"

### 5.3 YENİ: Cihaz yönetim ekranı
- Enrolled cihaz listesi
- Her cihaz için:
  - Host ACL toggle'ları (config_api × hostname matrix)
  - "Default ACL uygula" butonu
- Default ACL editor (per Config API)

### 5.4 YENİ: Pin ACL audit log
- "Yasaklı host isteği" event'leri (`requested - allowed` boşsa log'lanır)

---

## Faz 6 — Testler (~15 saat)

### 6.1 Library unit (Robolectric) — ~15 yeni

- `PerConfigApiPinStoreTest` — namespace isolation, aynı hostname farklı API'de çakışmaz
- `VaultFileRouterTest` — key → configApi lookup, bilinmeyen key error
- `VaultFileDecryptorTest` — E2E blob decrypt (happy + wrong-key + corrupted)
- `DeviceKeyProviderTest` — RSA key üretimi, persistent across runs
- `MultiConfigApiInitTest` — iki API bootstrap, biri fail olursa diğeri etkilenmez
- `ConfigApiClientTest` — wantPinsFor request serialization

### 6.2 Server integration — ~20 yeni

- `VaultFileStoreScopingTest` — configApiId crud, scope leakage yok
- `VaultRoutesAccessPolicyTest` — 5 policy × 4 scenario = 20 case
- `VaultEncryptionServiceTest` — E2E encrypt → cihaz private key ile decrypt edilebilir
- `VaultAccessTokenServiceTest` — üret/doğrula/iptal/TTL
- `DeviceHostAclStoreTest` — intersection, default fallback
- `CertificateConfigRoutesScopingTest` — requested ∩ allowed, 403 response
- `DevicePublicKeyStoreTest` — idempotent register, per-API izolasyonu

### 6.3 Cross-layer — ~10 yeni

- `VaultScopingCrossTest` — cihaz yanlış configApi'den key isterse 404
- `VaultE2EEncryptionCrossTest` — upload (admin) → encrypted delivery → decrypt (cihaz)
- `PinAclCrossTest` — wantPinsFor whitelist + server ACL enforcement
- `MultiConfigApiVaultCrossTest` — bir cihaz iki API'den ayrı dosya çeker
- `VaultTokenLifecycleCrossTest` — token üret → fetch OK → iptal → fetch 401

### 6.4 Espresso — ~8 yeni

- `T_multiConfigApi_init_both_apis_ready`
- `T_fetch_public_file_no_token_succeeds`
- `T_fetch_token_protected_without_token_fails`
- `T_fetch_token_protected_with_token_succeeds`
- `T_fetch_e2e_encrypted_decrypts_locally`
- `T_fetch_from_wrong_config_api_returns_not_found`
- `T_unauthorized_host_pin_request_blocked`
- `T_token_revocation_invalidates_cached_access`

---

## Faz 7 — Migration guide + breaking changes (~4 saat)

### 7.1 Yeni dosyalar
- `MIGRATION.md` — 1.0 → 2.0 adım adım
- `CHANGELOG.md` — breaking changes listesi
- `README.md` güncelle — yeni DSL örnekleri

### 7.2 Breaking changes (library major bump 1.x → 2.0)

| Eski | Yeni |
|---|---|
| `Builder(url)` | `Builder().configApi(id, url){...}` |
| `Builder(url).bootstrapPins(...)` | `.configApi(id, url){ bootstrapPins(...) }` |
| `.vaultFile(key){ endpoint(...) }` | `.vaultFile(key){ configApi(id); endpoint(...) }` |
| `CertificateConfigApi.fetchConfig()` | `fetchConfig(configApiId, hosts, deviceId)` |
| `CertificateConfigApi.fetchVaultFile(key, ver)` | `fetchVaultFile(configApiId, key, ver, deviceId, token)` |

Legacy `Builder(url)` constructor, **deprecated ama çalışır** — tek Config API olarak `"default"` ID'siyle kaydolur, mevcut kullanıcılar için zero-diff migration.

---

## Zamanlama (toplam ~70 saat solo)

| Faz | Süre | Bağımlılık |
|---|---|---|
| 1 Schema | 3h | — |
| 2 Backend | 15h | Faz 1 |
| 3 Library | 20h | Faz 2 (interface stabilite için) |
| 4 Demo-app | 3h | Faz 3 |
| 5 Web UI | 10h | Faz 2 |
| 6 Testler | 15h | her faz'a paralel |
| 7 Docs | 4h | Faz 1-3 sonu |

Kritik path: 1 → 2 → 3 (sırayla ~38 saat).
Paralel edilebilir: 4 + 5 + 6 (Faz 3 bitince veya sırayla).

---

## Doğrulama kriterleri

Bittiğinde aşağıdakiler çalışmalı:

1. **Schema**: `sqlite3 pinvault.db ".schema"` → yeni tablolar ve kolonlar görünür, foreign key'ler tutarlı.
2. **Backend**: `curl /api/v1/vault/nonexistent-key` → 404 + log'da "unauthorized config api scope" yoksa geçer.
3. **Pin ACL**: Cihaz `wantPinsFor("evil.com")` dese bile server ACL'de yoksa response boş, log'da 403.
4. **E2E**: Admin upload → DB'de plain tutulur → cihaza E2E policy'li endpoint'ten geldiğinde şifreli gelir → cihaz private key ile decrypt edebilir.
5. **Multi-API**: İki Config API farklı pin setleri döner, cihaz birinden diğerine geçiş yapabilir (key → api lookup doğru).
6. **Web UI**: Config API değişimi vault listesini filtreler. Policy dropdown'ları DB'deki kolonları güncellar. Token lifecycle panel'i çalışır.
7. **Testler**: `gradle test` server'da 12 → ~85 test, library'de 126 → ~141 test, Espresso 61 → ~69 test. Hepsi yeşil.

---

## Risk & belirsizlikler

1. **Android Keystore RSA key persistence** — bazı cihazlarda factory reset sonrası kaybolur. Mitigation: key yoksa yeniden üret + public key'i tüm Config API'lere yeniden register et (init akışında zaten oluyor).
2. **mTLS + E2E combo** — mTLS cert ile zaten wire encrypted. E2E ekstra katman, performance overhead 100-200ms/dosya (2048-bit RSA decrypt). Büyük dosyalar için hybrid (AES session key + RSA sarma) kullanıyoruz → kabul edilebilir.
3. **DB migration riskli** — mevcut 3 dosya silinecek (kullanıcı 2B onayladı). Production'da bu downtime olur, demo'da sorun yok.
4. **Web UI compleksity** — cihaz yönetim ekranı + host ACL matrix epey kod. Testlenmesi manuel + Playwright (yoksa en azından smoke test).
5. **Breaking change** — 1.x kullanıcıları adapte etmek zorunda. `@Deprecated` + migration rehberi yeterli olmalı.

---

## Onay sonrası çalışma sırası

1. Faz 1 (schema) → migration dosyası + testler yeşil
2. Faz 2.1 (store katmanı) → 10-15 yeni test
3. Faz 2.2-3 (servis + route) → ~20 yeni test
4. Faz 3.1 (interface) → library compile eder, demo-server impl güncelle
5. Faz 3.2-5 (DSL + multi-API client) → library testleri yeşil
6. Faz 4 (demo-app) → Espresso 8 yeni test
7. Faz 5 (web UI) → manuel smoke test
8. Faz 6 (cross tests) → paralel
9. Faz 7 (docs) → son

Her faz sonrası commit + test run.
