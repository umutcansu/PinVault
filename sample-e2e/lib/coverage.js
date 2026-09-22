// Kapsam matrisi: hangi özellik hangi senaryoyla kanıtlanıyor. Kanıt sayfası
// bunu koşu sonuçlarıyla birleştirip en üste koyar (Geçti / Kaldı / Koşmadı).
//
// Her satır: { id, group, feature, scenarios } — scenarios, tests/ altındaki
// dosya adı önekleri ("13" → tests/13-*.spec.js). Bir özellik birden fazla
// senaryoyla kanıtlanabilir; hepsi geçerse satır "Geçti"dir.
//
// Gruplar: K kurulum, A pin yönetimi ve imzalı config, B mTLS, C vault,
// D cihaz üstü şifreleme ve depolama, E sunucu operasyonları, F dayanıklılık,
// G kablo üstü kurcalama, H sunucu bağımsızlığı. Grup ajanları kendi
// satırlarını ekler; PLAN.md bölüm 3 ile aynı adlandırma.

const GROUPS = {
  K: 'Kurulum yolculuğu',
  A: 'Pin yönetimi ve imzalı config',
  B: 'mTLS',
  C: 'Vault',
  D: 'Cihaz üstü şifreleme ve depolama',
  E: 'Sunucu operasyonları',
  F: 'Dayanıklılık',
  G: 'Kablo üstü kurcalama',
  H: 'Sunucu bağımsızlığı',
};

const FEATURES = [
  // ── K (kurulum yolculuğu) ─────────────────────────────────────────────
  { id: 'K-gereksinim', group: 'K', feature: 'Gereksinimler ve depo düzeni: docker, node, java, adb, openssl sürümleri; dört depo', scenarios: ['K01'] },
  { id: 'K-setup', group: 'K', feature: 'scripts/setup.sh: .env üretimi (API anahtarı, LAN IP), signing-key.pem 0600; API_KEY boşken compose reddi', scenarios: ['K01'] },
  { id: 'K-compose', group: 'K', feature: 'docker compose up -d --build, healthcheck, Flyway migration\'ları, provision.sh, smoke-test.sh (0 FAIL)', scenarios: ['K01'] },
  { id: 'K-dashboard-giris', group: 'K', feature: 'Dashboard ilk açılış: API anahtarı istemi, yanlış anahtar reddi (401/403), doğru anahtarla giriş', scenarios: ['K02'] },
  { id: 'K-config-api-sekme', group: 'K', feature: 'Config API sekmeleri: Genel, Bootstrap (pin\'ler + istemci kod parçası), İmzalama (public key); SAN\'da LAN IP', scenarios: ['K02'] },
  { id: 'K-host-ekleme', group: 'K', feature: 'Host ekleme üç yolla: elle pin, sunucuda sertifika üretme, URL\'den pin çekme; hatalı biçim reddi', scenarios: ['K03'] },
  { id: 'K-host-yukleme', group: 'K', feature: 'Host ekleme dördüncü yol: "Yükle" sekmesi ile JKS/P12 (upload-cert) — pin\'ler yüklenen sertifikadan hesaplanır', scenarios: ['K03'] },
  { id: 'K-mtls-api', group: 'K', feature: 'mTLS Config API: truststore yokken 400, istemci sertifikası üretilince başarı', scenarios: ['K04'] },
  { id: 'K-mock-host', group: 'K', feature: 'Mock hedef host\'lar: başlatma, durum rozeti, "Bağlantıyı test et"', scenarios: ['K04'] },
  { id: 'K-vault-yukleme', group: 'K', feature: 'Vault yükleme: metin ve dosya, politika × şifreleme, dosya listesi ve detayı, at_rest blob\'u diskte şifreli', scenarios: ['K05'] },
  { id: 'K-istemci-degerleri', group: 'K', feature: 'client-config.sh --properties → BuildConfig; network_security_config; gradle derleme ve adb install', scenarios: ['K06'] },
  { id: 'K-ilk-baglanti', group: 'K', feature: 'İlk açılış "Hazır — config vN"; dashboard\'da Bağlı Cihazlar ve Bağlantı Geçmişi', scenarios: ['K06'] },
  { id: 'K-docs', group: 'K', feature: 'Swagger UI (/docs) ve openapi.yaml; dashboard TR/EN; tablo sayfalaması', scenarios: ['K07'] },
  // ── E (sunucu operasyonları) ──────────────────────────────────────────
  { id: 'E-imzalama-sifreli', group: 'E', feature: 'SIGNING_KEY_PASSWORD: anahtar diskte AES-256-GCM (ENCv1:), otomatik göç, imza doğrulanmaya devam eder', scenarios: ['E01'] },
  { id: 'E-yetki', group: 'E', feature: 'Yönetim uçları anahtarsız 401 / yanlış anahtar 403; cihaz uçları anahtarsız; güvenlik başlıkları', scenarios: ['E02'] },
  { id: 'E-anonim', group: 'E', feature: 'API_KEY yokken sunucu açılmayı reddeder; ALLOW_ANONYMOUS_ADMIN=true uyarı loglar', scenarios: ['E02'] },
  { id: 'E-cert-rotasyon', group: 'E', feature: 'Sunucu bootstrap sertifikası yenileme: eski APK başlatılamaz, yeni değerlerle derlenince bağlanır', scenarios: ['E03'] },
  { id: 'E-bootstrap-yukleme', group: 'E', feature: 'Bootstrap sekmesi → JKS yükleme (server-tls-pins/upload): pin dosyası ve yeniden başlatma sonrası sunulan sertifika yüklenen anahtar çiftine geçer', scenarios: ['E03'] },
  { id: 'E-cert-sure', group: 'E', feature: 'Sertifika süre izleme: cert-expiry expired/warning, dashboard kartı, açılışta CRITICAL/WARNING logu', scenarios: ['E04'] },
  { id: 'E-config-api-yonetim', group: 'E', feature: 'Config API oluştur/durdur/başlat/sil (kapsam temizliği), aynı portta son gelen kazanır', scenarios: ['E05'] },
  { id: 'E-host-dogrulama', group: 'E', feature: 'ping-remote (pin eşleşmesi, komut enjeksiyonu reddi) ve test-connection', scenarios: ['E05'] },
  { id: 'E-fetch-cert-url', group: 'E', feature: 'fetch-cert-url: var olan host\'un pin\'leri canlı sertifika zincirinden yenilenir (sürüm +1, geçmişte cert_fetched); arayüzde düğmesi olmayan uç', scenarios: ['E05'] },
  { id: 'E-pin-gecmisi', group: 'E', feature: 'Pin değişiklik geçmişi ve sürüm watermark\'ı: host silinip geri eklenince sürüm devam eder', scenarios: ['E06'] },
  { id: 'E-telemetri', group: 'E', feature: 'Bağlantı Geçmişi / Bağlı Cihazlar, sayfalama, client-report giriş doğrulaması (400), client-devices ucu', scenarios: ['E07'] },
  { id: 'E-docker', group: 'E', feature: 'docker compose down/up: pin, vault, sertifika ve anahtar kalıcı; Config API ve mock host\'lar auto-start', scenarios: ['E08'] },
  { id: 'E-keystore-parolasi', group: 'E', feature: 'KEYSTORE_PASSWORD: sunucu keystore\'ları (JKS) bu parolayla yazılır, varsayılan "changeit" ile açılmaz (keytool paneli)', scenarios: ['E08'] },
  { id: 'E-pin-kapsami', group: 'E', feature: 'wantPinsFor + cihaz host ACL\'i: ACL boşken sıfır pin (fail-closed), izin verilince yalnızca o host', scenarios: ['E09'] },
  // ── A ─────────────────────────────────────────────────────────────────
  { id: 'A-telemetri', group: 'A', feature: 'Bağlantı olayları ve backend telemetrisi (Bağlı Cihazlar, Bağlantı Geçmişi)', scenarios: ['01'] },
  { id: 'A-rotasyon', group: 'A', feature: 'Dinamik pin config: yedek pin ekleme/çıkarma, per-host sürüm, applyTo dinamik trust manager, updateNow', scenarios: ['02'] },
  { id: 'A-kurtarma', group: 'A', feature: 'Pin uyuşmazlığı → PinRecoveryInterceptor ile otomatik config yenileme ve tekrar', scenarios: ['03'] },
  { id: 'A-force', group: 'A', feature: 'forceUpdate: aynı sürümü yeniden uygulama ve kapatınca normale dönüş', scenarios: ['04'] },
  { id: 'A-prodstyle', group: 'A', feature: 'pinsForHost/currentPins ile PinVault import etmeyen istemcinin pinlenmesi ve kurtarması', scenarios: ['05'] },
  { id: 'A-host-sil', group: 'A', feature: 'Bilinmeyen host reddi; host silme ve geri eklemede sürüm sürekliliği (watermark)', scenarios: ['08'] },
  { id: 'A-bos-config', group: 'A', feature: 'Boş config reddi (≥1 host kuralı), eski config ile devam', scenarios: ['09'] },
  { id: 'A-pin-bicim', group: 'A', feature: 'Hatalı biçimli pin reddi (44 karakter / 32 bayt), dashboard doğrulaması', scenarios: ['10'] },
  { id: 'A-workmanager', group: 'A', feature: 'WorkManager periyodik güncelleme (düğmeye basmadan yeni config)', scenarios: ['11'] },
  { id: 'A-workmanager-yonetim', group: 'A', feature: 'WorkManager iş yönetimi: getScheduledWorkInfo listeliyor, cancelPeriodicUpdates işi JobScheduler\'dan düşürüyor, schedulePeriodicUpdates geri getiriyor (dumpsys jobscheduler)', scenarios: ['A27'] },
  { id: 'A-sertifika-gecerlilik', group: 'A', feature: 'Sunucu sertifikası geçerlilik kontrolü: süresi dolmuş sertifikalı host "expired or not yet valid" ile reddediliyor, kurtarma (config yenileme) tetiklenmiyor; sertifika yenilenince bağlantı dönüyor', scenarios: ['E04'] },
  { id: 'A-tek-pin', group: 'A', feature: 'Host başına ≥2 pin kuralı: dashboard formu reddeder, sunucu 400 verir, telefon etkilenmez', scenarios: ['A16'] },
  { id: 'A-wildcard', group: 'A', feature: 'Wildcard pin eşleşmesi: *.example.com tek alt etiketi eşler, TLD wildcard\'ı (*.com) yok sayılır (fail-safe)', scenarios: ['A17'] },
  { id: 'A-tazelik', group: 'A', feature: 'İmzalı config tazeliği (issuedAt/expiresAt, CONFIG_TTL_SECONDS): süresi geçmiş config reddedilir, eski config çalışır', scenarios: ['A18'] },
  { id: 'A-imza-dogrulama', group: 'A', feature: 'ECDSA imza doğrulaması ve anahtar rotasyonu: eski public key\'li APK config\'i reddeder ve sıfırdan açılamaz, yeni anahtarla derlenince kabul eder', scenarios: ['A19'] },
  { id: 'A-sertifika-rotasyon', group: 'A', feature: 'Gerçek sertifika rotasyonu (mock host): pin\'ler ve sürüm artar, eski pin\'le el sıkışma reddedilir, config yenilenince bağlantı döner', scenarios: ['A20'] },
  { id: 'A-ozel-istemci', group: 'A', feature: 'getClient(HttpConnectionSettings): pinleme var, kurtarma yok — uyuşmazlık kendiliğinden düzelmez', scenarios: ['A25'] },
  { id: 'A-reset', group: 'A', feature: 'reset() ve fail-closed: config silinince pinli istemci kurulamaz, TLS denenmez; "Sıfırla ve başlat" ile geri gelir', scenarios: ['A26'] },
  { id: 'A-cift-init', group: 'A', feature: 'Çift init koruması: ikinci init ağa çıkmadan Ready döner (yeni TLS el sıkışması yok)', scenarios: ['A26'] },
  { id: 'A-telemetri-secenek', group: 'A', feature: 'Telemetri seçenekleri: başarı raporlamayı kapatma, tekrar bastırma penceresi, anomalilerin bastırılmaması, config_updated / config_update_failed kayıtları', scenarios: ['A31'] },
  // ── B ─────────────────────────────────────────────────────────────────
  { id: 'B-kayit', group: 'B', feature: 'Token ile kayıt, X-P12-SHA256 doğrulama, mTLS bağlantı, iptal sonrası red, kayıt silme', scenarios: ['12'] },
  { id: 'B-mtls-config', group: 'B', feature: 'Config\'in mTLS Config API üzerinden çekilmesi: birincil blok istemci sertifikası sunuyor, sertifikasız el sıkışma kabloda reddediliyor; kapsam boşken pin uygulanmıyor (fail-closed)', scenarios: ['B01'] },
  { id: 'B-host-sertifikasi', group: 'B', feature: 'Host\'a özel istemci sertifikası (HostPin.mtls + clientCertVersion): dashboard\'dan yükleme, sürüm artışı, TLS dinleyicide 403 / mTLS dinleyicide indirme', scenarios: ['B02'] },
  { id: 'B-composite-keymanager', group: 'B', feature: 'Composite KeyManager host\'a göre seçiyor: Config API\'ye kayıt sertifikası, mock mTLS hedefine host\'a özel sertifika (kayıt sertifikası iptal edilince ikisi ayrışıyor)', scenarios: ['B03'] },
  { id: 'B-otomatik-kayit', group: 'B', feature: 'Otomatik kayıt (autoEnroll): ENROLLMENT_MODE=open iken ANDROID_ID ile sertifika, token modunda red', scenarios: ['B04'] },
  { id: 'B-elle-p12', group: 'B', feature: 'Elle yüklenen P12 (ConfigApiBlock.clientKeystore): kayıt olmadan mTLS Config API ve mock mTLS hedefine bağlantı, sonra bırakma', scenarios: ['B05'] },
  { id: 'B-token-yasam', group: 'B', feature: 'Kayıt token\'ı yaşam döngüsü: tek kullanım, ENROLLMENT_TOKEN_TTL_SECONDS ile süre dolumu, listede yalnızca maskeli önek ve "Kullanıldı"', scenarios: ['B06'] },
  { id: 'B-unenroll', group: 'B', feature: 'unenroll: aynı süreçte bellekteki istemci anahtarı boşalıyor, cihazda kayıt kalmıyor, yeniden açılışta da reddediliyor (sunucudaki sertifika etkinken)', scenarios: ['B07'] },
  { id: 'B-truststore', group: 'B', feature: 'Truststore yönetimi: dışarıdan üretilmiş PEM sertifikanın yüklenmesi, o anahtar çiftiyle mTLS bağlantısı, iptal sonrası red', scenarios: ['B08'] },
  { id: 'B-api-durdur', group: 'B', feature: 'mTLS Config API durdur/başlat: TLS modundaki cihaz "Hazır" kalıyor, mTLS config modundaki cihaz saklı config ile devam ediyor ama yenileyemiyor', scenarios: ['B09'] },
  // ── C ─────────────────────────────────────────────────────────────────
  { id: 'C-public', group: 'C', feature: 'Vault: public dosya indirme, içerik imzası, 304/AlreadyCurrent, sürüm güncelleme, dağıtım geçmişi', scenarios: ['13'] },
  { id: 'C-token', group: 'C', feature: 'Vault: token politikası (token yok → 401, cihaz token\'ı ile iner, iptal → 401)', scenarios: ['14'] },
  { id: 'C-e2e', group: 'C', feature: 'Vault: uçtan uca şifreleme (RSA-OAEP + AES-GCM zarf), kabloda şifreli, cihazda çözülür', scenarios: ['15'] },
  { id: 'C-at-rest', group: 'C', feature: 'Vault at_rest: blob SQLite\'ta AES-256-GCM ("VLT-ENC1" + salt + IV), düz metin bütün DB dosyasında yok, kabloda düz gövde + X-Vault-Encryption: at_rest', scenarios: ['C01'] },
  { id: 'C-api-key', group: 'C', feature: 'Vault api_key: kütüphane yönetim anahtarı göndermiyor → telefon 401, X-API-Key ile 200; dağıtım geçmişinde failed + neden + authMethod', scenarios: ['C02'] },
  { id: 'C-token-mtls', group: 'C', feature: 'Vault token_mtls: token + istemci sertifikası birlikte; CN↔X-Device-Id eşleşmesi (device_uid ile de), sertifikasız el sıkışma reddi, TLS dinleyicide geçerli token\'la bile 401, yanlış cihazın sertifikasıyla "Device identity mismatch"', scenarios: ['C03'] },
  { id: 'C-depolama', group: 'C', feature: 'Vault depolama stratejileri: ENCRYPTED_FILE (files/vault_files/<key>.enc, [iv_len][iv] + AES-256-GCM, Keystore anahtarı) ve ENCRYPTED_PREFS (pinvault_vault_files.xml, ad+değer şifreli)', scenarios: ['C04'] },
  { id: 'C-esitleme', group: 'C', feature: 'syncAllFiles ve WorkManager eşitlemesi: yalnızca updateWithPins dosyaları, 304 → AlreadyCurrent, düğmeye basmadan arka planda yeni sürüm', scenarios: ['C05'] },
  { id: 'C-cevrimdisi', group: 'C', feature: 'loadFile/hasFile/fileVersion host kapalıyken çalışıyor, aynı anda fetch düşüyor; clearFile .enc dosyasını, sürüm kaydını, şifreli tercih kaydını ve Keystore anahtarını siliyor', scenarios: ['C06'] },
  { id: 'C-politika-degisimi', group: 'C', feature: 'Dashboard\'dan politika değiştirme (PUT …/vault/{key}/policy): public → token → public, içerik ve sürüm değişmiyor, telefon her adımda uyuyor', scenarios: ['C07'] },
  { id: 'C-dagitim', group: 'C', feature: 'Dağıtım geçmişi ve istatistikler: downloaded / cached / failed + neden + authMethod, stats ucu, durum süzgeci, cihaz detayı, dosya detayı (sürüm zaman çizgisi)', scenarios: ['C08'] },
  { id: 'C-vault-enabled', group: 'C', feature: 'vault_enabled anahtarı: her kapsamda yazılabiliyor (varsayılan dahil) ve indirme yolunu gerçekten kapatıyor — kapalıyken her anahtar 403 (var olan da olmayan da), yönetim uçları açık kalıyor', scenarios: ['C09'] },
  { id: 'C-e2e-anahtar-yok', group: 'C', feature: 'end_to_end: anahtarı kayıtlı olmayan cihaz 412 + "public key" mesajı, kimliksiz istek 401; kayıtlı cihaz 256 baytlık sarılı anahtarla zarf alıyor', scenarios: ['C10'] },
  { id: 'C-sifreleme-basligi', group: 'C', feature: 'Sunucunun X-Vault-Encryption başlığı uygulamadaki VaultFileEncryption ayarını eziyor: plain tanımlı dosya end_to_end gelince çözülüyor, imza düz metin üzerinden doğrulanıyor', scenarios: ['C11'] },
  // ── D ─────────────────────────────────────────────────────────────────
  { id: 'D-config-deposu', group: 'D', feature: 'Saklı pin config\'i şifreli: ssl_cert_config_<id>.xml içinde host adı, IP ve pin\'ler düz geçmiyor, anahtar adları da şifreli, Tink keyset\'leri Keystore master key\'iyle sarılı', scenarios: ['D01'] },
  { id: 'D-istemci-sertifikasi', group: 'D', feature: 'İstemci P12\'si şifreli: pinvault_client_cert.xml\'deki ham kayıt PKCS12 olarak açılmıyor ve CN düz geçmiyor, ama kütüphane CN\'i okuyup mTLS el sıkışmasında kullanıyor', scenarios: ['D02'] },
  { id: 'D-cihaz-anahtari', group: 'D', feature: 'Cihaz RSA anahtarı: Keystore alias\'ı pinvault_vault_e2e_rsa, 2048 bit, donanım desteği bilgisi; SPKI SHA-256 sunucudaki kayıtlı PEM ile birebir eşleşiyor, private materyal uygulama dosyalarında yok', scenarios: ['D03'] },
  { id: 'D-force-kalicilik', group: 'D', feature: 'forceUpdate saklı config\'te kalıcı (açılışta ağdan önce depodan okunuyor); kapatılınca sürüm değişmese de saklı kopyadan siliniyor (sonuç "Config güncel" kalır, yalnızca bayrak diske yazılır)', scenarios: ['D04'] },
  { id: 'D-yedekleme', group: 'D', feature: 'Yedeklemeye girmiyor: yerel transport ile bmgr backupnow "Backup is not allowed", birleştirilmiş manifest allowBackup=false + kütüphanenin backup/extraction kuralları APK\'da; kuralların Config API kimliklerini elle sayması bulgu olarak belgelendi', scenarios: ['D05'] },
  // ── F ─────────────────────────────────────────────────────────────────
  { id: 'F-ilk-acilis', group: 'F', feature: 'Host kapalıyken ilk açılış: fail-closed, sistem güvenine düşmez; host dönünce toparlanır', scenarios: ['06'] },
  { id: 'F-init-retry', group: 'F', feature: 'Init yeniden deneme: 3 deneme, gecikme 2 s × deneme (logcat: "Update attempt n/3", "retrying in 2000/4000ms"), üçü de düşünce init başarısız', scenarios: ['06'] },
  { id: 'F-onbellek', group: 'F', feature: 'Host kapalıyken sonraki açılış: saklı (şifreli) config ile çalışır', scenarios: ['07'] },
  { id: 'F-force-offline', group: 'F', feature: 'forceUpdate + sunucu erişilemez → init başarısız (ForceUpdateFailedException); host dönünce "Tekrar dene" toparlar. Dashboard\'ın host bazlı bayrağı da (servis edilen config hasAnyForceUpdate ile damgalandığı için) aynı kapıyı açar', scenarios: ['F01'] },
  { id: 'F-devre-kesici', group: 'F', feature: 'Kurtarma devre kesicisi: 5 dk\'da 3 başarısız kurtarma → 10 dk soğuma; dördüncü istekte config yenileme isteği yapılmaz, elle yenileme çalışmaya devam eder', scenarios: ['F02'] },
  { id: 'F-telemetri-kesik', group: 'F', feature: 'Telemetri ucu erişilemezken uygulama akıcı: listener ayrı thread ve sınırlı kuyrukta, pinli istekler ve config yenileme gecikmez', scenarios: ['F03'] },
  // ── G (kablo üstü kurcalama; emülatörde iptables DNAT + kurcalama vekili) ─
  { id: 'G-araya-girme', group: 'G', feature: 'Gerçek araya girme: sahte anahtarlı sunucuya tek HTTP isteği bile geçmiyor (fatal TLS alert), saklı config\'li uygulama yenileyemiyor ama çalışmaya devam ediyor, boş kurulum hiç açılmıyor (fail-closed); kablodaki pin dashboard\'a pin_mismatch olarak düşüyor', scenarios: ['G01'] },
  { id: 'G-config-imza', group: 'G', feature: 'ECDSA config imza doğrulaması (signaturePublicKey zorunlu): imzanın tek baytı bozulunca config uygulanmıyor, saklı config ve pinli bağlantı bozulmuyor, kurcalama kalkınca bekleyen sürüm iniyor', scenarios: ['G02'] },
  { id: 'G-replay', group: 'G', feature: 'Replay reddi (issuedAt tekdüzeliği): imzası kriptografik olarak geçerli ESKİ yanıt tekrar oynatılınca reddediliyor; saklı config korunuyor', scenarios: ['G03'] },
  { id: 'G-surum-dusurme', group: 'G', feature: 'Per-host sürüm düşürme reddi: yeniden imzalanmış (imzası geçerli, issuedAt taze) düşük sürümlü config reddediliyor', scenarios: ['G04'] },
  { id: 'G-p12-butunluk', group: 'G', feature: 'X-P12-SHA256 başlığı silinince kayıt reddi: P12 diske yazılmadan doğrulanıyor, cihazda sertifika kalmıyor; sunucu tarafında sertifikanın üretilip token\'ın harcanması operasyon notu olarak belgelendi', scenarios: ['G05'] },
  { id: 'G-vault-imza', group: 'G', feature: 'Vault içerik imzası: bozuk imza "signature verification FAILED", eksik başlık "no X-Vault-Signature … fail-closed"; her iki durumda saklı sürüm ve içerik korunuyor', scenarios: ['G06'] },
  { id: 'G-vault-surum', group: 'G', feature: 'Vault sürüm düşürme reddi: sürüm imzanın kanonik metninde olduğu için başlık tek başına değiştirilince imza düşüyor; yeniden imzalansa bile açık sürüm kapısı ("downgrade rejected") devrede', scenarios: ['G07'] },
  { id: 'G-guncelleme-sagligi', group: 'G', feature: 'Güncelleme sonrası sağlık doğrulaması ve geri alma: /health 500 dönünce init "başlatılamadı" diyor VE uygulanan config geri alınıyor (önceki kopya geri yazılır, yoksa depo temizlenir); sağlık bozukken ikinci açılış da başlatılamıyor', scenarios: ['G08'] },
  // ── H (sunucu bağımsızlığı) ───────────────────────────────────────────
  { id: 'H-ozel-uclar', group: 'H', feature: 'Özel uç yolları (configEndpoint=ssl/pins, healthEndpoint=ping, vaultFile endpoint=files/<key>, vaultReportEndpoint=analytics/vault): uygulama harness\'ın kendi imzalı backend\'inden config ve vault alıyor, ana host bu süre boyunca tek config/vault isteği görmüyor', scenarios: ['H01'] },
  { id: 'H-ozel-api', group: 'H', feature: 'Özel CertificateConfigApi (uygulama içi): Config API portu iptables ile tamamen kesikken TLS modu açılamazken gömülü mod sıfırdan Hazır oluyor — kütüphaneden hiç HTTP çıkmıyor', scenarios: ['H02'] },
  { id: 'H-statik', group: 'H', feature: 'Statik (sunucusuz) mod: pin\'ler APK\'da, host container\'ı kapalıyken bile pinli bağlantı kuruluyor; vault dosyası ve kayıt bu modda kullanılamıyor', scenarios: ['H03'] },
];

module.exports = { GROUPS, FEATURES };
