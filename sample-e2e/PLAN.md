# Tam kapsam planı: sıfırdan kurulum + her özellik için kanıt

Durum: onaylandı (2026-09-20). Kararlar: kanıt = metin panelleri + Depolama ekranı; kurcalama vekili G0–G8 dahil; ajanlar tamamen sıralı (her ajan kendi grubunu yazar ve koşturur); envanter bulguları düzeltilir ve UI eksikleri tamamlanır. Envanter koddan çıkarıldı (kütüphane ~120 özellik, sunucu ~70 uç, dashboard'daki bütün işlemler, host betikleri).

## 1. Amaç ve ilkeler

- Sistemi sıfırdan kuracak birinin izleyeceği her adım, o adımın ekran görüntüsüyle belgelenir.
- Kütüphanenin ve sunucunun her özelliği en az bir uçtan uca senaryoda, web ve telefon ekran görüntüsüyle kanıtlanır. Şifreleme, imzalama ve depolama gibi ekranda görünmeyen işlemler için kablodaki bayt, cihazdaki dosya ve sunucudaki kayıt kanıt olarak eklenir.
- Bir özellik "unit testi var" diye atlanmaz. Kara kutu olarak gösterilemeyen bir özellik varsa nedeni bölüm 3.4'te yazılır.
- Uygulamaya test kodu gömülmez. Kanıt için gereken ekranlar (Depolama görüntüleyici, mod seçici) örnek uygulamanın gerçek demo özellikleri olarak eklenir.
- Senaryolar alt ajanlarla yazılır ve koşturulur; tek emülatör, tek host ve tek derleme dizini olduğu için koşular seri, yazım paraleldir.
- Test yazılırken ortaya çıkan kütüphane/sunucu/dashboard hataları "bulgu" olarak listelenir (bölüm 3.5), düzeltilir ve CHANGELOG'a girer; senaryo düzeltmeden sonra yeniden koşar.

## 2. Kurulum yolculuğu (sıfırdan kuran kişi)

Kanıt sayfasında ayrı "Kurulum" bölümü. `tests/00-setup-*.spec.js` altında gerçek arayüzden yürütülür; betiklerin yaptığı işler arayüzden de bir kez gösterilir. Sonunda `SETUP.md` (adım adım rehber, kanıt görüntülerine atıfla) üretilir.

| # | Adım | Kanıt |
|---|---|---|
| K0 | Gereksinimler: Docker Desktop, JDK 17, Android SDK + AVD, Node 18+, openssl/curl/jq | sürüm çıktıları (metin paneli) |
| K1 | Dört depoyu alma: PinVault, SamplePinVaultHost, SamplePinVaultClient, SamplePinVaultE2E | dizin ağacı |
| K2 | `scripts/setup.sh`: `.env` (API anahtarı, LAN IP), `data/signing-key.pem` (0600); API anahtarı boşken compose'un başlamayı reddetmesi | terminal, `.env` (anahtar maskeli), `ls -l`, hata mesajı |
| K3 | `docker compose up -d --build`; healthy; Flyway migration logları; `smoke-test.sh` bütün kontroller PASS | `docker compose ps`, log, smoke çıktısı |
| K4 | Dashboard ilk açılış: API anahtarı istemi; yanlış anahtar 403 (anahtarsız 401) ve yeniden istem; doğru anahtarla giriş | web + istem metinleri paneli |
| K5 | `default-tls` Config API: Genel (port, mod, vault açık/kapalı), Bootstrap (sertifika pin'leri, SAN'da LAN IP, istemci kodu), İmzalama (public key) | web |
| K6 | Host ekleme üç yolla: elle pin (ping-remote ile hesaplanan pin), sunucuda sertifika üretme, JKS/P12 yükleme; hatalı biçim reddi | web |
| K7 | mTLS Config API oluşturma: önce istemci sertifikası üretilmeden denenince 400 (truststore yok), sertifika üretilince başarı; enrollment modu rozeti | web |
| K8 | Mock hedef host'lar: host detayında TLS ve mTLS mock başlatma, "Bağlantıyı test et", Bağlı/Offline rozeti | web |
| K9 | Vault dosyası yükleme: metin ve dosya; her politika ve şifreleme seçeneği; dosya listesi ve detay | web |
| K10 | İstemci değerleri: `client-config.sh` çıktısı → `sample-host.properties` (bkz. bölüm 6), `network_security_config.xml` | terminal + dosya |
| K11 | Derleme ve kurulum: `./gradlew installDebug`, composite build satırı | terminal |
| K12 | İlk açılış: "Hazır — config vN", host ve sürüm listesi; dashboard'da Bağlı Cihazlar ve Bağlantı Geçmişi | telefon + web |
| K13 | Swagger UI (`/docs`) ve OpenAPI; dashboard TR/EN; sayfalama | web |

## 3. Özellik envanteri ve kapsam matrisi

Durum: **var** = mevcut senaryo kanıtlıyor, **yeni** = yazılacak, **bulgu** = düzeltme gerektiren (bölüm 3.5), **unit** = kara kutuda gösterilemiyor (bölüm 3.4).

### 3.1 Kütüphane (pinvault)

| Özellik | Giriş noktası | Senaryo | Kanıt | Durum |
|---|---|---|---|---|
| Suspend / callback init, `InitResult` | `PinVault.init` | K12, F6 | telefon "Hazır — config vN" / "başlatılamadı" | var |
| Init yeniden deneme ve gecikme (3 deneme, 2s·n) | `SSLCertificateUpdater` | F6 | logcat paneli: deneme satırları | yeni (ek) |
| Çift init koruması | `PinVault.init` | A26 | logcat "already initialized", ağ isteği yok | yeni |
| Bootstrap pin'lerle ilk bağlantı; yanlış bootstrap → init başarısız | `bootstrapPins` | E3 | telefon "başlatılamadı"; Bootstrap sekmesi yeni pin'ler | yeni |
| `getClient()` config gelmeden TLS'i reddeder (fail-closed) | `PinVault.getClient` | A26 | telefon "No pins configured" | yeni |
| `getClient(HttpConnectionSettings)`: özel zaman aşımı, kurtarma yok | `PinVault.getClient(settings)` | A25 | uyuşmazlık kendiliğinden düzelmez | yeni |
| `applyTo(builder)` dinamik trust manager | `PinVault.applyTo` | A2 | client yeniden kurulmadan yeni config | var |
| `updateNow()`, `UpdateResult` | `PinVault.updateNow` | A2, A4 | telefon | var |
| `currentVersion`, `hostPinVersions`, `pinsForHost`, `currentPins`, `isForceUpdate` | `PinVault.*` | K12, A5, D8 | durum kutusu, production-style client | var + yeni (isForceUpdate) |
| Per-host sürüm, host kümesi değişimi, force update (global / host) | `SSLCertificateUpdater` | A2, A4, A8 | web + telefon sürümleri | var |
| Pin biçim doğrulama: ≥1 host, host başına ≥2 pin, 44 karakter / 32 bayt | `SSLCertificateUpdater` | A9, A10, A16 | web red, telefon eski config | var + yeni |
| Bilinmeyen host reddi, wildcard tek etiket, TLD wildcard reddi | `PinHostMatcher` | A8, A17 | `*.example.com` bağlanır, `*.com` reddedilir | var + yeni |
| Sunucu sertifikası geçerlilik kontrolü | trust manager | E4 | süresi dolmuş sertifikalı mock host reddedilir | yeni |
| Pin uyuşmazlığı → kurtarma, tür tabanlı tespit | `PinRecoveryInterceptor` | A3, A5 | kendiliğinden toparlanır | var |
| Devre kesici: 5 dk'da 3 hata → 10 dk soğuma | `PinRecoveryInterceptor` | F2 | hızlı hata, ek config isteği yok, saat ileri alınınca döner | yeni |
| ECDSA imza doğrulama, `signaturePublicKey` zorunlu | `ConfigSignatureVerifier` | A19, G02 | "imza doğrulanamadı", eski config kalır | yeni |
| `allowUnsigned()` opt-out | `ConfigApiBlock` | — | kod örneği + unit | unit |
| `issuedAt/expiresAt` tazelik | `enforceFreshness` | A18 | TTL kısa + cihaz saati ileri → "expired" | yeni |
| Replay reddi | `SSLCertificateUpdater` | G03 | vekil | yeni |
| Per-host sürüm düşürme reddi | `SSLCertificateUpdater` | G04 | vekil | yeni |
| Güncelleme sonrası sağlık doğrulaması | `SSLCertificateUpdater` | G08 | vekil `/health` 500 → init başarısız; config geri ALINMIYOR (bulgu) | yeni |
| forceUpdate + sunucu erişilemez → init başarısız | `SSLCertificateUpdater` | F1 | telefon | yeni |
| Periyodik güncelleme (WorkManager), iş bilgisi, iptal | `schedulePeriodicUpdates`, `getScheduledWorkInfo`, `cancelPeriodicUpdates` | A11, C5 | olay listesi, iş listesi, `dumpsys` paneli | var + yeni |
| `reset()` | `PinVault.reset` | A26 | telefon | yeni |
| Statik (sunucusuz) mod; vault bu modda kapalı | `PinVaultConfig.static` | H03 | bağlanır, host'ta istek yok | yeni |
| Multi-Config-API: ikinci blok başarısız olsa da varsayılan hazır | `PinVault.init` | B11 | telefon | yeni |
| Multi-Config-API: vault dosyasının bloğa bağlanması | `vaultFile.configApi` | B1, C3 | mTLS bloğuna bağlı dosya | yeni |
| Özel uç yolları (5 yol) | `ConfigApiBlock` | H01 | harness backend'i, kablo paneli | yeni |
| Özel `CertificateConfigApi` | `PinVault.init(ctx, cfg, api)` | H02 | kütüphaneden HTTP çıkmaz | yeni |
| Bağlantı olayları ve listener; runtime tak/çıkar | `PinVaultConnectionListener`, `setConnectionListener` | A1, A3, A31 | olay listesi | var + yeni |
| Backend reporter: bağlantı ve config güncelleme raporları; seçenekler | `PinVaultBackendReporter`, `reportToPinVaultBackend` | A1, A3, A31 | Bağlantı Geçmişi: healthy / pin_mismatch / config_* | var + yeni |
| Listener kuyruğu sınırlı; telemetri ucu kapalıyken uygulama akıcı | `DynamicSSLManager` | F3 | emülatörde 6650'ye DROP | yeni |
| Cihaz kimliği (`deviceAlias`, ANDROID_ID) | `resolveDeviceIdentity` | A1, C13 | web cihaz adı | var |
| Token ile kayıt, `X-P12-SHA256`, PKCS12 kontrolü, şifreli saklama | `PinVault.enroll` | B12 | telefon + web | var |
| `X-P12-SHA256` yok/yanlış → kayıt reddi | `validateP12` | G05 | vekil | yeni |
| Otomatik kayıt (deviceId) | `PinVault.autoEnroll` | B4 | `ENROLLMENT_MODE=open` | yeni |
| `isEnrolled`, `enrolledClientCN`, `unenroll` | `PinVault.*` | B12, B8, B9 | telefon | var + bulgu |
| Elle P12 (`clientKeystore`) | `ConfigApiBlock` | B5 | dashboard'da üretilen P12 | yeni |
| mTLS Config API üzerinden config çekme | mTLS blok varsayılan | B1 | web mTLS API host listesi; kablo: sertifikasız red | yeni |
| Host'a özel istemci sertifikası (`mtls`, `clientCertVersion`), composite KeyManager | `SSLCertificateUpdater`, `DynamicSSLManager` | B2, B3 | mock mTLS host; kayıtsızken 403 | yeni |
| Vault: `fetchFile`, 304 → `AlreadyCurrent`, `Updated`, `Failed` | `PinVault.fetchFile` | C13 | telefon | var |
| Vault: `loadFile`, `hasFile`, `fileVersion`, `clearFile` | `PinVault.*` | C6 | telefon; run-as | yeni |
| Vault: `syncAllFiles`, `updateWithPins`, `OnFileUpdateListener`, worker eşitlemesi | `PinVault.syncAllFiles` | C5 | telefon | yeni |
| Vault politikaları: public, token, token_mtls; api_key cihazdan geçmez | `VaultFileAccessPolicy` | C13, C14, C3, C2 | telefon 401 / indirildi | var + yeni + bulgu (C3) |
| Vault şifreleme: plain, at_rest, end_to_end | `VaultFileEncryption`, `VaultFileDecryptor` | C13, C1, C15 | kablo hex, sunucu blob, telefon | var + yeni |
| Sunucu `X-Vault-Encryption` başlığı yapılandırmayı ezer | `VaultFileRouter` | C10 | telefon | yeni |
| Vault içerik imzası; başlık yoksa red | `ConfigSignatureVerifier` | C13, G06 | telefon | var + yeni |
| Vault sürüm düşürme reddi | `VaultFileRouter` | G07 | vekil | yeni |
| Vault depolama: ENCRYPTED_PREFS, ENCRYPTED_FILE | `StorageStrategy` | C4, D3 | run-as, Depolama ekranı | yeni |
| Özel `VaultStorageProvider` | arayüz | — | kod + unit | unit |
| Vault dağıtım raporu (downloaded / failed, authMethod, neden), 5 s zaman aşımı | `reportFileDownload` | C13, C8 | web dağıtım geçmişi | var + yeni |
| Cihaz RSA anahtarı (Keystore 2048, StrongBox denemesi), public key kaydı | `DeviceKeyProvider` | C15, D4 | Depolama ekranı; sunucudaki PEM ile eşleşme | var + yeni |
| Şifreli config deposu, forceUpdate kalıcı | `CertificateConfigStore` | D1, D8 | run-as | yeni |
| Şifreli istemci sertifikası deposu | `ClientCertSecureStore` | D2 | run-as | yeni |
| Yedekleme dışı tutma | `res/xml` | D5 | yerel yedek dökümü | yeni (fizibilite) |
| Legacy göç, bozuk depo temizliği | store sınıfları | — | unit | unit |
| Debug log yardımcı | `enableDebugLogging` | K12 | logcat paneli | var |
| `wantPinsFor` (sunucu tarafı pin kapsamı) | `ConfigApiBlock` | E12 | kütüphane çağırmıyor | bulgu |
| `enrollmentToken(token)` blok ayarı | `ConfigApiBlock` | — | hiçbir yol okumuyor | bulgu |

### 3.2 Sunucu, dashboard ve host paketi

| Özellik | Uç / işlem | Senaryo | Kanıt | Durum |
|---|---|---|---|---|
| API anahtarı zorunlu; anahtarsız 401; `ALLOW_ANONYMOUS_ADMIN` uyarıyla açık | `ApiKeyAuth` | K2, K4, E2 | compose hatası, dashboard istemi, curl 401, log WARN | yeni |
| Cihaz uçları anahtarsız (config, enroll, vault indirme, rapor, public-key) | allowlist | A1, C13, B12 | kablo | var |
| İmzalı config: `issuedAt/expiresAt`, `CONFIG_TTL_SECONDS`, `?signed=false`, public key ucu | `CertificateConfigRoute`, `/signing-key` | K5, A18, A19 | web İmzalama, smoke imza doğrulama paneli | var + yeni |
| Config doğrulama: ≥2 pin, 44 karakter, 409 çift host; pin geçmişi | `PUT certificate-config`, `/history` | A10, A16, E7 | web | var + yeni |
| Force update host / global | `/force-update`, `/clear-force` | A4, E7 | web | var + yeni (global düğmeler ölü: bulgu) |
| Host ekleme yolları: elle, üret, yükle; `fetch-from-url`, `fetch-cert-url` | `HostRoutes` | K6, E5 | web; UI'da olmayan uçlar curl paneli | yeni |
| Sertifika bilgisi ve yenileme (otomatik / yükleme); bütün kapsamlara yayılma; mock yeniden başlatma | `/cert-info`, `/regenerate-cert`, `/upload-cert` | A20 | gerçek sertifika rotasyonu: telefon yeni pin'le bağlanır | yeni |
| Host mTLS bayrağı, host'a özel istemci sertifikası (yükleme, bilgi, indirme) | `/toggle-mtls`, `/upload-client-cert`, `/client-cert/*`, `client-certs/{host}/download` | B2, B3 | web + telefon | yeni |
| Mock host'lar (TLS ve mTLS), durum, `test-connection`, `ping-remote` (geçersiz hostname 400) | `/start-mock`, `/status`, `/test-connection`, `/ping-remote` | K8, E6 | web + smoke paneli | yeni |
| Config API yönetimi: oluştur (mTLS için truststore şartı), durdur, başlat, sil (kapsam temizliği), port çakışması | `/config-apis/*` | K7, E5, B11 | web | yeni |
| Sunucu bootstrap pin'leri: göster, yenile, yükle | `/server-tls-pins/*` | K5, E3 | web | yeni |
| İmzalama anahtarı: göster, yenile; `SIGNING_KEY_PASSWORD` ile diskte şifreli, otomatik göç | `/signing-key/*`, `ConfigSigningService` | A19, E1 | web; `signing-key.pem` başı `ENCv1:` paneli | yeni |
| İstemci sertifikaları: üret (P12 indirme), yükle, listele, iptal (dinleyicileri yeniden başlatır) | `/client-certs/*` | B12, B5, B10 | web | var + yeni |
| Kayıt token'ı: üret, listele, tek kullanım, `ENROLLMENT_TOKEN_TTL_SECONDS`; `ENROLLMENT_MODE` open/token | `/enrollment-tokens/*`, `/enroll`, `/enrollment-mode` | B12, B6, B4 | web + telefon | var + yeni |
| Vault yönetimi: yükle (politika × şifreleme), listele, sil, politika değiştir, token üret/iptal, dağıtım ve istatistik, `vault-enabled` | `ScopedVaultAdminRoutes`, `AdminVaultRoutes` | K9, C13, C14, C9, C11 | web | var + yeni (politika değiştirme UI'ı yok: bulgu) |
| Vault at_rest (`VAULT_AT_REST_PASSWORD`), end_to_end sarma, 412 anahtar yoksa, imza başlığı | `VaultRoutes` | C1, C15, C12 | sqlite blob, kablo | var + yeni |
| `token_mtls` politikası | `VaultRoutes` | C3 | sunucu CN çıkaramıyor → hep 401 | bulgu |
| Cihaz host ACL'i, varsayılan ACL, `?hosts=` + `X-Device-Id` filtreleme | `AdminVaultRoutes`, `CertificateConfigRoute` | E12 | curl paneli; UI cihaz listesi bozuk | bulgu |
| Telemetri: web/android/config_update kayıtları, Bağlı Cihazlar, giriş doğrulama (regex 400) | `/connection-history/*` | A1, A3, A31, E8 | web | var + yeni |
| Sağlık ve sertifika süre izleme (`/api/v1/health`, `/cert-expiry`, 6 saatlik döngü, `CERT_EXPIRY_WARN_DAYS`) | `CertExpiryMonitor` | E4 | curl paneli + docker log; dashboard kartı yok | yeni (+ öneri: kart) |
| Swagger UI / OpenAPI | `/docs`, `openapi.yaml` | K13 | web | bulgu (CSP engelliyor, spec eksik) |
| Dashboard: TR/EN, sayfalama, toast, `confirm`/`alert`/`prompt` akışları, host durum önbelleği | `app.js` | K13, E8 | web | yeni |
| Güvenlik başlıkları (CSP, X-Frame-Options…) | `DefaultHeaders` | E2 | curl -I paneli | yeni |
| Flyway migration, kalıcı veri, sıfırlama, `EXTRA_CERT_SANS`, `KEYSTORE_PASSWORD` | compose, `CertificateService` | K3, E11 | log, SAN paneli | yeni |
| Host betikleri: setup, generate-signing-key, provision, smoke-test, client-config | `scripts/` | K2, K3, K10 | terminal | yeni |
| Docker imajı: kaynak seçimi (yerel / upstream), healthcheck, `WORKDIR /data` | Dockerfile | K3 | log | yeni |

### 3.3 Senaryo grupları

Mevcut 15 senaryo korunur. Numaralar dosya adı önekidir.

**A. Pin yönetimi ve imzalı config** — var: 1, 2, 3, 4, 5, 8, 9, 10, 11. Yeni:
- A16 Tek pin'li host: dashboard 400 ile reddeder; telefon etkilenmez.
- A17 Wildcard: `*.example.com` ile hedefe bağlanır; `*.com` reddedilir.
- A18 Config süresi: host TTL 60 s, cihaz saati 2 saat ileri → yeni config "expired", eski config çalışır.
- A19 İmzalama anahtarı rotasyonu (İmzalama sekmesi "yenile"): telefon imzayı reddeder; yeni anahtarla derlenen uygulama kabul eder.
- A20 Gerçek sertifika rotasyonu: mock host'un sertifikası dashboard'dan yenilenir → sürüm artar → telefon yeni pin'le bağlanır.
- A25 Özel bağlantı ayarlı istemci: pinleme aynı, kurtarma yok.
- A26 Sıfırla → istek reddedilir → tekrar başlat → Hazır; ikinci init ağ isteği yapmaz.
- A27 WorkManager iş yönetimi: planlı iş listesi → iptal (JobScheduler kaydı düşer) → yeniden planlama.
- A31 Telemetri: config güncelleme kayıtları dashboard'da; dedup penceresi; yalnızca hata raporlama.

**B. mTLS matrisi** (demo-app'in 4 senaryosu + kayıt akışları) — var: 12. Yeni:
- B01 mTLS Config API → TLS hedef: uygulama mTLS config moduna geçer (kayıtlı sertifikayla), mTLS API kapsamındaki pin'ler gelir, hedefe bağlanır; sertifikasız el sıkışma kabloda reddedilir.
- B02 TLS Config API → mTLS hedef: config TLS'ten, kayıt token'la, mock mTLS host'a kayıtlı sertifikayla bağlanır; kayıtsızken reddedilir.
- B03 mTLS Config API → mTLS hedef: host mTLS işaretli + host'a özel istemci sertifikası (`clientCertVersion`) mTLS dinleyiciden indirilir; composite KeyManager host'a göre sertifika seçer.
- B04 Otomatik kayıt (`open` mod) ve token moduna dönünce red.
- B05 Elle P12: dashboard'da üretilen P12 dosyadan yüklenir.
- B06 Token: ikinci kullanım reddi, süre dolumu (`ENROLLMENT_TOKEN_TTL_SECONDS=10`), listede "kullanıldı".
- B07 Kayıt silme: aynı süreçte bağlantı hâlâ geçiyorsa bulgu; yeniden açılışta red.
- B08 Dışarıdan sertifika yükleme (PEM/DER) → truststore → o sertifikayla bağlantı kabul.
- B09 mTLS API durdur/başlat: telefon yine Hazır; mTLS testi red/geçer.
- (Özel `clientCertLabel` tutarlılığı, eski B9: uçtan uca yazılmadı — bkz. 3.4.)

**C. Vault** — var: 13, 14, 15. Yeni:
- C01 at_rest: sunucuda blob şifreli (sqlite paneli, `VLT-ENC1`), kabloda düz, `VAULT_AT_REST_PASSWORD` ayarlı.
- C02 api_key: cihazdan 401, curl ile 200; dağıtım geçmişinde failed.
- C03 token_mtls: sunucu düzeltmesi sonrası sertifika + token ile iner; sertifikasız / CN uyuşmazsa red.
- C04 Depolama stratejileri (ENCRYPTED_FILE düzeni, ENCRYPTED_PREFS).
- C05 Tümünü eşitle ve arka plan eşitleme (`updateWithPins`).
- C06 Çevrimdışı okuma ve silme (host kapalıyken `loadFile`; `clearFile` sonrası alias yok).
- C07 Politika değişimi (public → token → public) — dashboard'a küçük UI eklenir.
- C08 Dağıtım geçmişinde başarısız indirmeler ve nedenleri; durum filtresi; cihaz detayı; sürüm zaman çizgisi.
- C09 `vault-enabled` kapalıyken indirme reddi.
- C10 end_to_end + anahtar kayıtlı değilken 412 (harness'tan yeni cihaz kimliğiyle).
- C11 Sunucu şifreleme başlığı yapılandırmayı ezer.

**D. Cihaz üstü şifreleme ve depolama** (Depolama ekranı + run-as panelleri): D01 config deposu şifreli (host adı ve pin düz metin geçmez); D02 istemci sertifikası şifreli (blob PKCS12 olarak açılmaz); vault depoları C04 içinde; D03 cihaz RSA anahtarı (alias, 2048, donanım destekli mi, sunucudaki PEM ile eşleşme); D05 yedekleme dışı (yerel yedek dökümü; olmazsa kurallar + manifest paneli); D04 forceUpdate yeniden açılışta korunur.

**E. Sunucu operasyonları**: E01 `SIGNING_KEY_PASSWORD` (dosya `ENCv1:`, otomatik göç, imza çalışmaya devam eder); E02 API anahtarı ve anonim mod, güvenlik başlıkları; E03 sunucu bootstrap sertifikası yenileme → eski uygulama başlatılamaz → yeni değerlerle derleme → çalışır ("IP değişirse" akışı) + Bootstrap sekmesinden JKS yükleme; E04 sertifika süre izleme: süresi dolmuş sertifika yüklenir → `cert-expiry` expired, log CRITICAL, telefon reddeder (ana host'un mock TLS host'unda); E05 Config API ve host yönetimi uçları (oluştur/durdur/başlat/sil, port çakışması, UI'da olmayan `fetch-cert-url` curl ile) ve ping-remote / test-connection; E06 pin geçmişi ve watermark; E07 Bağlı Cihazlar / Bağlantı Geçmişi / sayfalama / regex reddi; E08 Docker yaşam döngüsü (down/up veri kalıcı, `KEYSTORE_PASSWORD` ile yazılan keystore'lar); E09 cihaz host ACL'i ve varsayılan ACL (API + düzeltilmiş UI); kütüphane düzeltmesinden sonra telefon yalnızca izinli host'ları alır.

**F. Dayanıklılık** — var: 6, 7. Yeni: F01 force update + host kapalı → başlatılamaz; F02 devre kesici; F03 telemetri ucu erişilemezken uygulama akıcı.

**G. Kablo üstü kurcalama** (karar 2; host'un kendi anahtarıyla vekil, emülatörde `su` + iptables DNAT, doğrulandı): G01 gerçek araya girme (başka anahtar → pin uyuşmazlığı, hiçbir istek geçmez); G02 config imzası bozuk; G03 replay; G04 sürüm düşürme (yeniden imzalanmış); G05 `X-P12-SHA256` silinmiş; G06 vault imzası bozuk/silinmiş; G07 vault sürüm düşürme; G08 `/health` 500 → init başarısız ama config geri ALINMIYOR (bulgu).

**H. Sunucu bağımsızlığı**: H01 özel uç yolları (harness'ın kendi küçük backend'i, kendi EC anahtarı); H02 özel `CertificateConfigApi` (uygulama içi, HTTP çıkmaz); H03 statik mod.

Toplam: 14 kurulum adımı + mevcut 15 + yaklaşık 60 yeni senaryo.

### 3.4 Kara kutu gösterilemeyenler ve nedeni

- `allowUnsigned()`: derleme zamanı opt-out, üretimde kullanılmamalı. Kod örneği + unit; istenirse ayrı build flavor ile senaryo.
- Özel `VaultStorageProvider`: arayüz; yalnızca kod gösterir. Kod örneği + unit; istenirse eklenir.
- Legacy göç ve bozuk depo temizliği: eski biçimi cihazda üretmek için kütüphanenin eski sürümü gerekir. Unit.
- Özel `clientCertLabel` tutarlılığı (`isEnrolled`/`unenroll`'un özel etiketle aynı anahtarı okuması; eski B9): unit — bilinçli atlandı. Bulgu L3 kütüphanede düzeltildi ve unit testle doğrulanıyor; örnek uygulama varsayılan etiketi kullandığı için kara kutuda ek bir gözlem üretmiyor.
- `internal` sınıfların kural tabloları (wildcard, imza algoritması ayrıntıları): davranış A17 ve A19/G1 ile gösterilir; tablo unit'te.

### 3.5 Envanterden çıkan bulgular (testten önce düzeltilecek ya da testte doğrulanacak)

Kütüphane: `wantPinsFor` sunucuya iletilmiyor (mevcut görev); `enrollmentToken(token)` ölü ayar; `isEnrolled`/`unenroll` özel etiketle yanlış anahtarı okuyor (B9); `unenroll` bellekteki KeyManager'ı boşaltmıyor (B8); `getClient(settings)` kurtarma içermiyor (A25'te belgelenir); API_KEY politikası cihaz tarafında etkisiz (C2'de belgelenir).

Sunucu / dashboard: Swagger UI CSP yüzünden yüklenmiyor; OpenAPI ~70 ucun 15'ini belgeliyor ve `currentVersion` parametresi kodda yok; `token_mtls` için sertifika CN'i hiç okunmuyor (hep 401) ve UI'da seçenek yok; ACL cihaz listesi var olmayan `client-devices` ucunu çağırıyor; vault politika değiştirme ucunun UI'ı yok; yönetim portundaki enroll kopyası `X-P12-SHA256` vermiyor; kayıt token'ları veritabanında düz metin; ölü dashboard işlemleri (`createHostFetch`, `fetchBootstrapFromUrl`, global force düğmeleri, `regenerateCert`, `startConfigApi/stopConfigApi`); `cert-expiry` için dashboard kartı yok; host'a özel sertifika indirme yalnızca mTLS dinleyicide (tasarım, belgelenir).

## 4. Kanıt standardı

- Web: Playwright tam sayfa ya da kart görüntüsü, her adımda. Tarayıcı diyalogları (`confirm`/`alert`/`prompt`) metin paneli olarak.
- Telefon: `adb screencap`, her adımda; `#sıra · saat` damgası yeni sonucu eskisinden ayırır.
- Kablo: ham HTTP başlıkları ve gövde hex dökümü (harness'ın TLS istemcisi ya da vekil), metin paneli.
- Cihaz depolaması: `adb shell run-as <paket>` dosya listesi ve içerik; ayrıca Depolama ekranının telefon görüntüsü.
- Sunucu: `docker compose logs`, SQLite sorgusu, dosya sistemi; metin paneli.
- Terminal adımları: komut ve çıktı metin paneli.
- Kanıt sayfası: başta kapsam matrisi (özellik → senaryo → Geçti/Kaldı), Kurulum bölümü, gruplar; kalan senaryoda telefonun hata anı görüntüsü.
- Gizli değerler sayfaya girmez; token'lar kısaltılır.

## 5. Gerekli altyapı değişiklikleri

SamplePinVaultClient
- Host sabitleri `sample-host.properties` → `BuildConfig` (IP, portlar, bootstrap pin'ler, imza public key). Kurulum adımı K10 bu dosyayı yazar; A19/E3 testte yeni değerlerle yeniden derleyebilir.
- Mod seçici: TLS config (varsayılan), mTLS config (B1/B3), özel backend (H1), statik (H3). Her mod `reset()` + yeniden `init`.
- İkinci Config API bloğu `sample-mtls`; ana ekranda blok bazlı sürümler.
- Mock host adları için özel `Dns` (Mac IP'sine çözümleme, `applyTo` yolu).
- Vault ekranı: Tümünü eşitle, dosya bilgisi, sil; at_rest / api_key / token_mtls / ENCRYPTED_FILE dosya tanımları.
- Depolama ekranı: şifreli tercih dosyaları, Keystore anahtar bilgisi, P12 ve vault blob önizlemeleri.
- mTLS ekranı: otomatik kayıt, P12 dosyadan yükleme.
- Ana ekran: özel ayarlı istemci (A25), sıfırla (A26), telemetri seçenekleri (A31), planlı iş bilgisi (A11).

SamplePinVaultHost
- Mock TLS ve mTLS host portları compose'da dışarı açılır.
- `scripts/env-override.sh`: `SIGNING_KEY_PASSWORD`, `CONFIG_TTL_SECONDS`, `ENROLLMENT_MODE`, `ENROLLMENT_TOKEN_TTL_SECONDS`, `VAULT_AT_REST_PASSWORD`, `CERT_EXPIRY_WARN_DAYS` için geçici değişiklik ve geri alma.
- `scripts/export-server-key.sh`: vekil için sunucu anahtar/sertifikası PEM (`data/` altı, git dışı).

PinVault demo-server / dashboard (bulgu düzeltmeleri, karar 4): Swagger CSP; `token_mtls` CN çıkarımı ve UI seçeneği; ACL cihaz listesi ucu; vault politika değiştirme UI'ı; `cert-expiry` kartı; ölü işlemlerin temizliği; OpenAPI tamamlama; enroll kopyasında `X-P12-SHA256`; kayıt token'larının hash'lenmesi.

SamplePinVaultE2E
- `00-setup-*` senaryoları, terminal panelleri, `SETUP.md` üretimi.
- Kurcalama vekili (`lib/proxy.js`), özel backend (`lib/custom-backend.js`), DNAT/DROP yardımcıları.
- Kanıt sayfası: matris, bölümler, metin panelleri.
- Yeni sayfa nesneleri: Depolama, mod seçici, vault ek düğmeleri; dashboard: Config API yönetimi, üç host ekleme yolu, mock yönetimi, sertifika yenileme, ping-remote, İmzalama/Bootstrap sekmeleri, Swagger, dil, sayfalama.

## 6. Yürütme: alt ajanlarla

Seçilen model: tamamen sıralı. Her ajan kendi grubunu yazar, tek stack'te koşturur, kalanları düzeltir ve raporlar; sonra sıradaki başlar. Çakışma yok; ortak dosyalara da sırası gelen ajan dokunabilir (tek yazar).

- Aşama 0 (bitti): envanter ve plan. Kararlar.
- Aşama 1 (bitti): ortak altyapı.
  - İstemci: host değerleri `sample-host.properties` → `BuildConfig` (`-PsampleHostProps` ile değiştirilebilir); `AppSettings` modları (TLS, mTLS config, özel backend, gömülü API, statik); ikinci Config API bloğu `sample-mtls`; yedi vault dosyası (public, token, e2e, at_rest, api_key, ENCRYPTED_FILE + updateWithPins, token_mtls); `MockDns` ile mock host adları; Ayarlar ekranı (mod, telemetri seçenekleri, özel ayarlı istemci, reset/reinit/restart, WorkManager işleri); Depolama ekranı (şifreli tercihler, vault blob'ları, Keystore anahtarları, P12 kaydı); mTLS ekranına otomatik kayıt, P12 içe aktarma ve mock host düğmeleri; Vault ekranına eşitleme, bilgi, silme ve anahtar alanı.
  - Host: mock TLS/mTLS portları dışarı açıldı (6653/6654), `provision.sh` mock host'ları kurup başlatıyor; `env-override.sh` (geçici ortam değişkeni), `export-server-key.sh` (vekil için anahtar), `client-config.sh --properties`; compose'a isteğe bağlı ortam değişkenleri.
  - E2E: `lib/evidence.js` (metin panelleri: terminal, kablo hex, cihaz dökümü), `lib/coverage.js` (kapsam matrisi), gruplu ve matrisli kanıt sayfası, `lib/proxy.js` (kurcalama vekili: sahte anahtar / host anahtarı + hazır kurcalamalar), `lib/custom-backend.js` (özel uç yollu imzalı backend), `android.js`'e iptables/run-as/push yardımcıları, `sampleApp.js`'e yeni ekranlar, global setup uygulamayı host değerleriyle derliyor.
  - Kütüphane/sunucu: boş `SIGNING_KEY_PASSWORD` artık "ayarlanmamış" sayılıyor (compose'un boş değeri anahtarı boş parolayla şifrelemesin).
  - Doğrulandı: mevcut 15 senaryo yeni uygulama, yeni raporlayıcı ve yeni host ile 15/15 geçiyor. Yol boyunca çıkan iki harness hatası düzeltildi: dokuzuncu senaryo artık bütün host'ları siliyor (mock host'lar eklendi), ve yazılım klavyesi açıkken alttaki görünümler UI dökümüne girmediği için klavye GERİ tuşuyla kapatılıyor (enjekte edilen ENTER IME'ye ulaşmıyor); görünüm bulunamazsa ekran kaydırılarak yeniden aranıyor.
- Aşama 2, Ajan S (bulgular, çalışıyor): sunucu/dashboard ve kütüphane bulguları (bölüm 3.5) düzeltilir; sunucu ve kütüphane unit testleri; host imajı yeniden derlenir; CHANGELOG. Kapsam: kütüphane L1 `wantPinsFor` bağlanması, L2 ölü `enrollmentToken`, L3 etiket tutarlılığı, L4 `unenroll` KeyManager, L5 belgeleme; sunucu S1 Swagger (yerel dosyalar), S2 OpenAPI tamamlama, S3 `token_mtls` CN okuma + UI, S4 cihaz listesi ucu, S5 politika değiştirme UI'ı, S6 sertifika süre kartı, S7 ölü işlemler, S8 eksik `X-P12-SHA256`, S9 kayıt token'larının hash'lenmesi.
- Aşama 3, sırayla beş grup ajanı: K+E (kurulum yolculuğu ve sunucu operasyonları), A+F, B, C+D, G+H. Her ajan: senaryoları ve gerektirdiği uygulama ekranlarını / dashboard ekle­rini yazar, grubunu koşturur, kalanları düzeltir, kanıt adlarıyla rapor verir.
  - K+E bitti: K01–K07 ve E01–E09 (16 senaryo, 91 adım), `lib/freshHost.js` (ayrı portlarda tek kullanımlık host) ve `lib/clientBuild.js`, `SETUP.md`. Tam paket 31/31.
  - A+F bitti: A16–A31 ve F01–F03 (12 senaryo), kapsam matrisi 50 satır. Tam paket 43/43.
  - G+H bitti: G01–G08 ve H01–H03 (11 senaryo, 79 adım), kapsam matrisi 86 satır. `lib/proxy.js` ve `lib/custom-backend.js` iskeletleri ilk kez çalıştırıldı ve düzeltildi (gzip/hop-by-hop başlık yönetimi, TLS el sıkışma hatalarının kaydı, vault imzalayıcı, yeniden imzalayan vault sürüm düşürme, özel backend'in eksik `X-Vault-Signature` başlığı ve dosya bazlı sürümleme); `hostApi.signedConfig()` eklendi. İki bulgu: (1) güncelleme sonrası sağlık doğrulaması geri alma yapmıyor — `DefaultCertificateConfigApi.healthCheck()` bütün istisnaları yutup `false` döndürdüğü için `verifyPinnedConnection`'ın "config'i temizle ve sıfırla" dalı varsayılan API ile hiç çalışmıyor; uygulanan config diskte kalıyor ve sonraki açılışta (AlreadyCurrent yolundan) sessizce "Hazır" oluyor (G08). (2) örnek uygulamada intent ekiyle mod değiştirme yarışı: önceki init sürerken mod değişince eski init'in sonucu yeni durumu eziyor — senaryolar Ayarlar ekranından (init'in oturmasını bekleyen yol) mod değiştiriyor (H02/H03).
  - Ara bulgu turu (ben): A+F'in bulduğu üç ürün hatası düzeltildi — imzalama anahtarı yenileme çalışan sunucuya yansımıyordu (routes servisi değer olarak tutuyordu; artık yerinde rotasyon), host bazlı force bayrağı kütüphanenin force kapısına ulaşmıyordu (servis edilen config artık `hasAnyForceUpdate()` ile damgalanıyor), pin uyuşmazlığı kurtarması çağıranın istemcisi yerine kütüphanenin iç istemcisiyle tekrar deniyordu (artık çağıranın zinciri; özel `Dns` ve interceptor'lar korunuyor). Yeni test: `SigningKeyAndForceUpdateTest`.
  - B bitti: B01–B09 (9 senaryo). İkinci düzeltme turu: boş config artık init'i düşürüyor; `toggle-mtls`/`upload-client-cert` sürüm artırıyor; üretilen/yüklenen sertifikalar mTLS dinleyicilerine anında yansıyor; dashboard seçili kapsama yazıyor; token listesi ve süresi dolmuş token düzeltildi; kurtarma yedeği orijinal hatayı fırlatıyor, geçerlilik penceresi hatası kurtarma tetiklemiyor. Tam paket 52/52.
  - C+D bitti: C01–C11, D01–D05 (16 senaryo). Tam paket 68/68.
  - G+H bitti: G01–G08, H01–H03 (11 senaryo). Bütün kurcalamalar kabloda reddedildi. Tam paket 79/79, matris 86/86.
  - Son düzeltme turu: güncelleme sonrası sağlık kapısı artık gerçekten geri alıyor (önceki config'e döner, yoksa depoyu temizler); force bayrağının kapanması diske ve bellekteki config'e yazılıyor; "Vault aktif" anahtarı hem varsayılan kapsam için kayıtlı hem indirme yolunda kapı; yedekleme kuralları kapsam dışı kimlikler için derlemede uyarıyor; `API_KEY` politikası için uyarı; boş vault token'ı başlık olarak gönderilmiyor; örnek uygulamada init kuşak sayacı (mod değiştirme yarışı). Kütüphane 217, sunucu 233 test.
- Aşama 4 (tam koşu): emülatör açılışı ve derleme dahil tek koşu; kanıt sayfası ve matris; kalan sıfır olana kadar döngü.
- Aşama 5 (bağımsız denetim): işi yazmamış bir ajan kanıt sayfasını matrise karşı denetler (görüntü var mı, metin iddiayı destekliyor mu, gizli değer sızmış mı). Raporu teslimata eklenir.
- Kaba süre: altyapı yarım gün, bulgular ~1 gün, beş grup ajanı toplam ~1,5 gün (koşular dahil), tam koşu ~1,5 saat, denetim 1 saat. Toplam 3–4 iş günü.
- Cihaz: bütün kanıtlar emülatörde (saat, iptables, run-as için root/debug gerekir). Mi 9T'de root gerektirmeyen alt küme için ikinci koşu istenirse sona eklenir.

## 7. Kararlar

1. Ekranda görünmeyen kanıtlar: metin panelleri + uygulamaya Depolama demo ekranı (öneri: ikisi birden).
2. Kurcalama vekili (G grubu): eklensin mi? (öneri: evet; G0 en güçlü kanıt).
3. Yürütme modeli: paralel yazım + seri koşu (öneri) mi, tamamen sıralı ajanlar mı?
4. Bulgular: sunucu/dashboard bulguları düzeltilip UI eksikleri tamamlansın mı (öneri), yoksa yalnızca raporlansın mı?
