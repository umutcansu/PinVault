// PinVault dashboard — Setup wizard, the "how to" part: every checklist row
// that is not READY opens numbered, concrete steps (which terminal command,
// which .env line, which card and button in the dashboard, how to verify),
// the server step starts with the order of work, and the code step ends with
// what to do once the code is in the app.
//
// The steps are this file's own text (TR and EN, `setuph_<check id>`); the
// only server data they carry is a check's `.env` fix, which reaches the page
// through esc(). Back-ticks in a step mark a command, file or value and render
// as <code>. Classic script sharing one global scope, loaded after app-setup.js.

Object.assign(i18n.tr, {
  setupHowto: 'Nasıl yapılır', setupHowtoClose: 'Kapat', setupHowtoVerify: 'Doğrula',
  setupHowtoGoSetting: 'Ayarlar kartında aç: {0}',
  setupHowtoEnvLines: '.env satırları',
  setupHowtoRestart: 'Yeniden başlat: Ayarlar kartındaki "Şimdi yeniden başlat" düğmesi ya da sunucu makinesinde `docker compose up -d`. Ayar ancak yeniden başlayınca geçerli olur.',
  setupHowtoNoScripts: 'Betikler sample-host dizinindedir (`sample-host/scripts/`). Sunucu başka türlü kuruluysa aynı işi .env satırı ve komutlar yapar.',
  setupOrderTitle: 'Kurulum sırası',
  setupOrderHint: 'Sihirbaz dört adımda ölçer ve yol gösterir; hiçbir ayarı kendisi değiştirmez. Her satırın yanındaki "Nasıl yapılır" o satırı HAZIR yapan adımları açar.',
  setupOrder: [
    'Sunucuyu kur ve aç. sample-host ile: `./scripts/setup.sh` (parolalar, API anahtarı, imza anahtarı), `docker compose up -d --build`, `./scripts/provision.sh` (mTLS Config API). Üretim için `./scripts/setup.sh --production`: bu listedeki çoğu satırı baştan HAZIR yapar.',
    'Bu adımdaki her satırı HAZIR yap. "Ayarlardan ↓" işaretli olanlar aşağıdaki Ayarlar kartından, diğerleri .env dosyasından değişir; ikisi de yeniden başlatma ister.',
    '2 · Sertifikalar: Config API sertifikasının yedek anahtarı, client CA ve sunucu CA süreleri, her host\'un yedek pin\'inin kime ait olduğu, vault dosyalarının süreleri.',
    '3 · Uygulama: uygulamanın bağlanacağı Config API ve açılacak korumalar. Gri kutu, sunucunun henüz sunmadığı korumadır: önce 1. adımdaki satır.',
    '4 · Kod: üretilen kodu uygulamanın Application sınıfına koy; altındaki "Sonraki adımlar" ilk telefona kadar götürür.'
  ],
  setupNextTitle: 'Sonraki adımlar',
  setupNextHint: 'Kod uygulamaya girdikten sonra, ilk telefon bağlanana kadar.',
  setupNext_dependency: 'Bağımlılığı ekle: `implementation("io.github.umutcansu:pinvault:<sürüm>")` (Maven Central\'daki son sürüm; README). React Native ve Flutter için kendi paketleri: `react-native-pinvault`, `pinvault_flutter`.',
  setupNext_paste: 'Yukarıdaki kodu "Kopyala" ile al ve uygulamanın `Application.onCreate` içine koy; `context` uygulama context\'i.',
  setupNext_token: 'mTLS: her telefon bir kayıt token\'ı ile kaydolur. Panel → {0} → Client Sertifikaları → "Token Üret"; token bir kez gösterilir. Token\'ı APK\'ya gömme: uygulamana kendi giriş sunucun üzerinden ver ya da bir kayıt kodu kullan (Kayıt Kodları).',
  setupNext_guard: '`environmentGuard` içine kendi root / kanca tespitini bağla (RootBeer, bir RASP ürünü). PinVault kendisi tespit yapmaz; asıl karar sunucudaki bütünlük doğrulamasıdır.',
  setupNext_integrity: 'Play Integrity: `com.google.android.play:integrity` bağımlılığını ekle ve `StandardIntegrityTokenProvider`\'ı açılışta bir kez hazırla. Sunucuda 1. adımdaki "Cihaz bütünlüğü" satırı HAZIR olmalı, yoksa token kimse okumadan gider.',
  setupNext_run: 'Uygulamayı gerçek bir telefonda çalıştır: `PinVault.init` → `InitResult.Ready`. Panel → Bağlantı Geçmişi\'nde telefon ve config sürümü görünür; mTLS\'te Client Sertifikaları\'nda sertifikası.',
  setupNext_release: 'Release derlemesi: paket adı ve imza sertifikasının SHA-256\'sı 1. adımdaki "Kayıtta donanım belgesi" ayarlarıyla aynı olmalı; emülatör ve debug derlemesi "Engelle" modunda kayıt olamaz.',
  setupNext_rerun: 'Sertifika ya da imza anahtarı değişince sihirbazı yeniden çalıştır: 4. adımdaki kod yeni değerlerle üretilir, uygulama güncellemesi gerekir.',

  // ── Step 1: server checks ───────────────────────────────────────────
  setuph_admin_auth: [
    'Terminal (sunucu makinesi): `./scripts/add-admin.sh ayse --apply` → kişisel anahtar bir kez ekranda, SHA-256\'sı .env\'deki `ADMIN_KEYS`\'e eklenir. İkinci yönetici için tekrar: `./scripts/add-admin.sh mehmet --apply` (iki kişi onayı iki ad ister).',
    'Betik yoksa: anahtar `openssl rand -hex 32`, özeti `printf %s <anahtar> | shasum -a 256`; .env: `ADMIN_KEYS=ayse:<sha256>,mehmet:<sha256>`. Sunucuya anahtarın kendisi değil, yalnızca özeti yazılır.',
    'Anahtarı sahibine güvenli bir kanaldan ilet; ortak `API_KEY`\'i artık kimseye verme.',
    'Doğrula: paneli kişisel anahtarla aç; sol üstte yönetici adı görünür, Denetim Kaydı değişiklikleri o adla yazar; bu satır "2 named admins" ile HAZIR.'
  ],
  setuph_approvals: [
    'Önce iki kişisel yönetici (üstteki satır): bir yönetici kendi değişikliğini onaylayamaz, ortak `API_KEY` onay veremez.',
    'Aşağıdaki Ayarlar kartında "Pin değişikliği için gereken yönetici sayısı" → 2 → Kaydet.',
    'Doğrula: bir host\'un pin\'ini değiştir; değişiklik Onaylar bölümüne düşer, ikinci yönetici onaylayınca uygulanır.'
  ],
  setuph_webhook: [
    'Bildirimin düşeceği kanaldan Slack uyumlu bir webhook adresi al (Slack: Incoming Webhooks; Teams, Mattermost ve benzerleri aynı biçimi kabul eder).',
    '.env: `NOTIFY_WEBHOOK_URL=https://…` ve `NOTIFY_WEBHOOK_SECRET=` için `openssl rand -hex 32`. Alıcı `X-PinVault-Signature` imzasını zaman damgasıyla doğrulamalı.',
    'Doğrula: bir host\'un pin\'ini değiştir ya da bir cihazı iptal et; kanala bildirim düşer.'
  ],
  setuph_management_tls: [
    '.env: `MANAGEMENT_HTTPS_PORT=8082` ve compose dosyasında port eşlemesi (sample-host: `6655:8082`, varsayılan olarak yalnızca bu makineye açık). Sertifika Config API\'ninki: tarayıcı self-signed uyarısı verir, uygulama onu zaten pinler.',
    'Paneli bundan sonra `https://<sunucu>:6655` üzerinden aç; düz HTTP portunu yalnızca `127.0.0.1`\'e bağlı bırak. Uzaktan: VPN ya da `ssh -L 6655:127.0.0.1:6655 <kullanıcı>@<sunucu>`.',
    'Doğrula: bu satır "port 8082" ile HAZIR; yönetici anahtarı ağda düz metin gitmez.'
  ],
  setuph_test_hooks: [
    '.env\'den `ALLOW_TEST_HOOKS` satırını sil ya da boş bırak. Bu uçlar yalnızca uçtan uca testler içindir (kısa ömürlü sertifika kancası).',
    'Doğrula: `/api/v1/test-hooks/…` 404 döner; bu satır listeden kalkar.'
  ],
  setuph_demo_secrets: [
    'sample-host ile: `./scripts/setup.sh` eksik parolaları üretir ve .env\'e 600 izinle yazar. Elle: `openssl rand -base64 32` ile `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD`, `SIGNING_KEY_PASSWORD`.',
    '`ALLOW_DEMO_SECRETS` satırını kaldır. Var olan bir kurulumda keystore parolası değişiyorsa eskisini bir açılışlığına `KEYSTORE_PASSWORD_PREVIOUS` olarak ver; sunucu depoları yeni parolaya geçirir.',
    'Doğrula: sunucu açılır (parolasız açılmaz) ve bu satır listeden kalkar.'
  ],
  setuph_signers: [
    'Karar: en az iki imzalayıcı, en az biri bu sunucunun diski dışında. Seçenekler: `pkcs11` (HSM; `PKCS11_LIBRARY` container içindeki kitaplık yolu, `PKCS11_PIN`) ve `command` (KMS ya da ayrı imza servisi; `SIGNER_COMMAND` stdin\'i imzalayıp stdout\'a yazar, `SIGNER_PUBLIC_KEY`, özet imzalayan KMS için `SIGNER_INPUT=digest`). Ayrıntı: SECURE_OPERATIONS.md.',
    '.env: `CONFIG_SIGNERS=pkcs11,command` (ya da `local,command`: biri diskte kalır). Her config iki imza taşır; 4. adımdaki kod `requiredSignatures(2)` ile üretilir, uygulamayı o kodla güncelle.',
    'Donanım yokken yolu denemek için `./scripts/softhsm-init.sh`: SoftHSM gerçek bir HSM değildir, anahtar yine diskte durur ve bu satırı HAZIR yapmaz.',
    'Doğrula: {0} → İmzalama sekmesinde iki imzalayıcı; bu satır "2 signers" ile HAZIR.'
  ],
  setuph_recovery_keys: [
    'İnternete bağlı olmayan bir makinede: `scripts/offline-keygen.sh` (yalnızca bu dosya ve openssl gerekir). Kurtarma anahtarının özel yarısı parolayla şifreli orada kalır; ekrana yazılan yalnızca public yarıdır.',
    '.env\'e yalnızca public yarıyı yaz: `RECOVERY_PUBLIC_KEYS=<Base64>`. Özel yarı sunucuya hiç gelmez: sunucuyu ele geçiren imza anahtarını döndüremez.',
    'Doğrula: bu satır HAZIR; 3. adımda "İmza anahtarı döndürme (recoveryPublicKeys)" kutusu açılır ve 4. adımdaki koda girer.'
  ],
  setuph_config_ttl: [
    'Aşağıdaki Ayarlar kartında "Config ömrü (saniye)" → en çok 86400 (1 gün) → Kaydet.',
    'Doğrula: telefon imzalı config\'i en fazla bu kadar geçerli sayar; Config API\'yi engelleyen biri cihazı bundan uzun süre eski pin\'lerde tutamaz.'
  ],
  setuph_live_check: [
    'Aşağıdaki Ayarlar kartında "Canlı sertifika kontrolü" → Engelle → Kaydet. Host\'lar bu sunucunun kendi IP\'sinde sunuluyorsa (mock) `LIVE_CHECK_HOST_MAP` ile eşle.',
    'Doğrula: bir host\'a şu an sunmadığı bir pin kaydetmeyi dene; sunucu reddeder. Telefonlara ulaşmayan pin yayımlanamaz.'
  ],
  setuph_enrollment_mode: [
    'Aşağıdaki Ayarlar kartında "Cihaz kaydı" → Yalnızca token ile → Kaydet. "Açık" mod yalnızca deneme içindir: cihaz kimliğini söyleyen her telefon kayıt olur.',
    'Telefonlara token: Panel → mTLS Config API → Client Sertifikaları → "Token Üret" (bir cihaz) ya da Kayıt Kodları (bir kod, çok cihaz, istenirse yönetici onayı).',
    'Doğrula: token\'sız kayıt isteği 403 döner; bu satır "token" ile HAZIR.'
  ],
  setuph_attestation: [
    'Release imza sertifikasının SHA-256\'sını al: `apksigner verify --print-certs app-release.apk` → "Signer #1 certificate SHA-256 digest" satırı (ya da `keytool -printcert -jarfile app-release.apk`). Paket adı: `applicationId`.',
    'Aşağıdaki Ayarlar kartında "Uygulamanın paket adı" ve "Uygulama imza sertifikasının SHA-256 parmak izi" alanlarını doldur; "Kayıtta donanım belgesi" önce Uyarı ver → Kaydet.',
    'Gerçek bir telefonla release derlemesini kaydet (emülatör yazılım köküyle belge üretir, geçmez); Denetim Kaydı\'nda kaydın belge sonucuna bak. Sonra "Kayıtta donanım belgesi" → Engelle → Kaydet.',
    'Doğrula: belgesiz ya da başka uygulamadan gelen kayıt isteği 403 `attestation_required` / `attestation_invalid`; bu satır "enforce" ile HAZIR.'
  ],
  setuph_attestation_revocation: [
    'Google\'ın iptal listesinin ilk kopyasını indir: `./scripts/fetch-attestation-status.sh` → `data/attestation-status.json`. Sunucu internete çıkmaz; listeyi bu dosyadan okur.',
    'Güncel tutmak için cron (6 saatte bir): `0 */6 * * * cd /yol/sample-host && ./scripts/fetch-attestation-status.sh`.',
    '.env: `ATTESTATION_REVOKED_SERIALS_FILE=/data/attestation-status.json` ve `ATTESTATION_STATUS_MAX_AGE_HOURS=48` (liste bundan eskiyse hiçbir belge geçmez; dosya yoksa sunucu açılmaz).',
    'Doğrula: `./scripts/smoke-test.sh` listenin yaşını gösterir; bu satır HAZIR.'
  ],
  setuph_p12: [
    'Önce bütün uygulama sürümlerinin CSR ile kayıt olabildiğinden emin ol (kütüphane 2.1 ve üstü; anahtar telefonda üretilir, sunucuya yalnızca imza isteği gider).',
    '.env: `ENROLLMENT_P12=off`. Sunucu artık özel anahtar üretip telefona taşımaz.',
    'Doğrula: P12 isteyen eski bir istemci 403 `csr_required` alır; bu satır "off" ile HAZIR.'
  ],
  setuph_integrity: [
    'Google Cloud\'da Play Integrity API\'yi aç ve bir servis hesabı anahtarı (JSON) indir → sunucuda `data/play-integrity-sa.json` (izin 600). Uygulama Play Console\'da aynı projeye bağlı olmalı.',
    '.env: `INTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh`, `INTEGRITY_PLAY_PACKAGE=<paket>`, `INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE=/data/play-integrity-sa.json`.',
    'Aşağıdaki Ayarlar kartında "Kayıtta Play Integrity kontrolü" → Uyarı ver → Kaydet. 3. adımda "Kayıtta Play Integrity token\'ı gönder" kutusunu aç; uygulamaya `com.google.android.play:integrity` bağımlılığı girer.',
    'Gerçek bir telefonda kayıt ol, Denetim Kaydı\'nda bütünlük sonucuna bak; sonra "Engelle" → Kaydet.',
    'Doğrula: root\'lu ya da Play dışından kurulmuş uygulama kayıt olamaz; bu satır "enforce" ile HAZIR.'
  ],

  // ── Step 2: certificates ────────────────────────────────────────────
  setuph_config_api_cert: [
    'Süre dolmadan önce yeni sertifika: {0} → Bootstrap sekmesi → "Sertifikayı Yenile" (ya da kendi sertifikanı "JKS Yükle"). Yeni pin\'ler 4. adımdaki koda girer.',
    'Sıra önemli: önce yeni pin\'leri taşıyan uygulama sürümünü dağıt, telefonlar güncellenince sunucuyu yeni sertifikayla yeniden başlat. Eski pin\'li bir uygulama yeni sertifikaya bağlanamaz.',
    'Doğrula: bu satır yeni tarihle HAZIR; Bağlantı Geçmişi\'nde telefonlar bağlanmaya devam eder.'
  ],
  setuph_config_api_cert_source: [
    'Self-signed sertifika pinli olduğu için üretimde geçerlidir; değiştirmek şart değil.',
    'Kendi sertifikanı kullanmak istersen: {0} → Bootstrap sekmesi → "JKS Yükle" (PKCS12 ya da JKS, anahtar + zincir). Pin\'ler değişir: 4. adımdaki kodu yeniden al ve uygulamayı güncelle.',
    'Doğrula: bu satır yeni kaynakla HAZIR.'
  ],
  setuph_config_api_backup_key: [
    'Yedek anahtar, imza anahtarı değil sertifika anahtarıdır: çalınırsa uygulama güncellemesi olmadan yedeğe geçmeyi sağlar. {0} → Bootstrap sekmesi → "Sertifikayı Yenile": yeni sertifika ile birlikte yedek anahtar üretilir, iki pin (birincil + yedek) 4. adımdaki koda girer.',
    'Sıra: önce iki pin\'i taşıyan uygulama sürümünü dağıt, sonra yeni sertifikayı sun (yeniden başlat). Anahtar çalındığında "Yedek Anahtara Geç" tek tıkla yedeğe geçer ve yeni bir yedek hazırlar.',
    'Doğrula: bu satır HAZIR; kod adımındaki `bootstrapPins` iki pin taşır.'
  ],
  setuph_config_api_cert_name: [
    'Telefonların bağlandığı ad (IP ya da alan adı) sertifikanın adlarında (SAN) olmalı: PinVault pin\'i doğrular ama OkHttp adı da arar.',
    '.env: `EXTRA_CERT_SANS=<adres>` (virgülle birden çok), yeniden başlat, sonra {0} → Bootstrap sekmesi → "Sertifikayı Yenile"; ya da adı taşıyan kendi sertifikanı "JKS Yükle". Pin\'ler değişir: 4. adımdaki kodu yeniden al.',
    'Doğrula: bu satırda adres görünür ve HAZIR.'
  ],
  setuph_client_ca: [
    'Client CA\'nın süresi dolunca hiçbir cihaz yenilenemez; CA değişimi bütün cihazların yeniden kaydı demektir. Süre yaklaşıyorsa planla: SECURE_OPERATIONS.md "client CA" bölümü.',
    'Yeni CA: `certs/client-ca.jks` dosyasını yenisiyle değiştir ve yeniden başlat; 4. adımdaki `clientCaPins` değişir, uygulama güncellemesi ve bütün telefonların yeniden kaydı gerekir (token ya da kayıt kodu dağıt).',
    'Doğrula: bu satır yeni tarihle HAZIR; Client Sertifikaları\'nda yeni kayıtlar görünür.'
  ],
  setuph_client_cert_ttl: [
    'Aşağıdaki Ayarlar kartında (1. adım) "Cihaz sertifikasının ömrü (gün)" → 90 gibi kısa bir süre → Kaydet. Cihaz süresinin üçte biri kalınca kendiliğinden yeniler.',
    'Doğrula: bu satır yeni süreyle HAZIR; yeni kayıtlar o süreyle kesilir.'
  ],
  setuph_p12_enrollment: [
    'Önce bütün uygulama sürümlerinin CSR ile kayıt olabildiğinden emin ol (kütüphane 2.1 ve üstü).',
    '.env: `ENROLLMENT_P12=off`, yeniden başlat. Özel anahtar artık telefonda üretilir, sunucudan taşınmaz.',
    'Doğrula: bu satır "off" ile HAZIR.'
  ],
  setuph_recovery_door: [
    'Kurtarma kapısı, süresi dolmuş sertifikalı telefonların yeni sertifikayı token\'sız aldığı TLS dinleyicisidir (istemci sertifikası istemez, kimliği eski anahtarla atılan imza kanıtlar).',
    '.env: `RECOVERY_PORT=8083` ve compose\'da port eşlemesi (sample-host: `6656:8083`); yeniden başlat. 3. adımda "Süresi dolan sertifikayı kurtarma kapısından yenile" kutusunu aç: 4. adımdaki kod `renewalUrl` ve sunucu CA pin\'lerini taşır.',
    'Doğrula: bu satır "port 8083" ile HAZIR.'
  ],
  setuph_server_ca: [
    'Sunucu CA\'sı kurtarma kapısının sertifikasını imzalar ve uygulama bu CA\'yı pinler (`bootstrapPins` içindeki ikinci `HostPin`). Süresi dolmadan yenisini planla: yeni CA 4. adımdaki pin\'leri değiştirir, uygulama güncellemesi gerekir.',
    'Yeni CA: `certs/server-ca.jks` ve yedeğini yenisiyle değiştir, yeniden başlat; önce yeni pin\'li uygulamayı dağıt.',
    'Doğrula: bu satır yeni tarihle HAZIR.'
  ],
  setuph_host_cert: [
    'Host\'un sertifikasını yenilemek host\'un sahibinin işidir (API sunucun, bir CDN). Yeni sertifika yayına girince: Host sayfası → "URL\'den Al" ile yeni pin\'i çek; eski pin yedek olarak kalsın (geçiş sırasında ikisi de geçerli).',
    'Bu sunucunun sunduğu test host\'uysa (mock): Host sayfası → "Sertifikayı Yenile".',
    'Doğrula: host satırı yeni tarihle HAZIR; config sürümü artar ve telefonlar yeni listeyi alır.'
  ],
  setuph_host_backup_pin: [
    'Yedek pin kimin anahtarı? URL\'den alınan host\'ta çoğu zaman sertifikayı veren CA\'nın pin\'idir: o CA\'nın anahtarı çalınırsa sahte sertifika da geçer.',
    'Kendi ikinci anahtarının pin\'ini hesapla (host\'un sahibinden ikinci sertifika ya da anahtar): `openssl x509 -in yedek.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.',
    'Host sayfası → "URL\'den Al" → "Yedek pin" alanına bu değeri yaz → Kaydet (iki kişi onayı açıksa ikinci yönetici onaylar).',
    'Doğrula: host satırında yedek pin "stored backup key" ya da kendi anahtarın olarak görünür ve HAZIR.'
  ],
  setuph_host_served_here: [
    'Bu host, test için bu sunucunun sunduğu bir hedeftir (mock); üretimde telefonlar gerçek API sunucuna bağlanır.',
    'Gerçek host\'u ekle: {0} → "+ Yeni Host" → "URL\'den Al" (`https://api.sirketiniz.com`) ve yedek pin\'ini gir; sonra mock host\'u sil ya da mock dinleyiciyi durdur.',
    'Doğrula: host listesinde yalnızca gerçek adresler; bu satır listeden kalkar.'
  ],
  setuph_host_client_cert: [
    'Bu host için cihazlara verilen ortak istemci sertifikasının süresi doluyor: yenisini host\'un CA\'sından al (P12).',
    'Host sayfası → istemci sertifikası kartı → yeni P12\'yi yükle; telefonlar bir sonraki config yenilemesinde yenisini alır.',
    'Doğrula: host satırı yeni tarihle HAZIR.'
  ],
  setuph_vault_file: [
    'Süre bir hatırlatmadır; dosya cihazlara yine verilir. Yenisini yükle: {0} → Vault sekmesi → aynı anahtarla yeni sürüm, "Süre (expiresAt)" alanına yeni tarih.',
    'Doğrula: satır yeni tarihle HAZIR; telefonlar bir sonraki eşitlemede yeni sürümü alır.'
  ]
});

Object.assign(i18n.en, {
  setupHowto: 'How to', setupHowtoClose: 'Close', setupHowtoVerify: 'Verify',
  setupHowtoGoSetting: 'Open in the Settings card: {0}',
  setupHowtoEnvLines: '.env lines',
  setupHowtoRestart: 'Restart: the "Restart now" button in the Settings card, or `docker compose up -d` on the server. A setting applies only after a restart.',
  setupHowtoNoScripts: 'The scripts live in the sample-host folder (`sample-host/scripts/`). On a server set up another way the .env line and the commands do the same job.',
  setupOrderTitle: 'Order of work',
  setupOrderHint: 'The wizard measures and points the way in four steps; it changes no setting itself. "How to" next to a row opens the steps that make it READY.',
  setupOrder: [
    'Install and start the server. With sample-host: `./scripts/setup.sh` (passwords, API key, signing key), `docker compose up -d --build`, `./scripts/provision.sh` (mTLS Config API). For production `./scripts/setup.sh --production`: most rows of this list start out READY.',
    'Make every row in this step READY. Rows marked "In Settings ↓" change in the Settings card below, the others in the .env file; both need a restart.',
    '2 · Certificates: the Config API certificate\'s backup key, client and server CA validity, whose key each host\'s backup pin trusts, vault file expiry.',
    '3 · App: the Config API the app connects to and the protections to turn on. A grey box is a protection the server does not offer yet: first the line in step 1.',
    '4 · Code: put the generated code into the app\'s Application class; the "Next steps" below it take you to the first phone.'
  ],
  setupNextTitle: 'Next steps',
  setupNextHint: 'Once the code is in the app, until the first phone connects.',
  setupNext_dependency: 'Add the dependency: `implementation("io.github.umutcansu:pinvault:<version>")` (latest release on Maven Central; README). React Native and Flutter have their own packages: `react-native-pinvault`, `pinvault_flutter`.',
  setupNext_paste: 'Take the code above with "Copy" and put it into the app\'s `Application.onCreate`; `context` is the application context.',
  setupNext_token: 'mTLS: every phone enrolls with an enrollment token. Dashboard → {0} → Client Certificates → "Generate Token"; the token is shown once. Do not embed it in the APK: hand it to the app through your own login server, or use an enrollment code (Enrollment Codes).',
  setupNext_guard: 'Wire your own root / hooking detection into `environmentGuard` (RootBeer, a RASP product). PinVault detects nothing itself; the server\'s integrity verification is what decides.',
  setupNext_integrity: 'Play Integrity: add the `com.google.android.play:integrity` dependency and prepare a `StandardIntegrityTokenProvider` once at start-up. The "Device integrity" row in step 1 must be READY on the server, or the token goes unread.',
  setupNext_run: 'Run the app on a real phone: `PinVault.init` → `InitResult.Ready`. Dashboard → Connection History shows the phone and its config version; with mTLS, Client Certificates shows its certificate.',
  setupNext_release: 'Release build: the package name and the signing certificate\'s SHA-256 must match the "Key attestation at enrollment" settings from step 1; an emulator or a debug build cannot enroll in "Block" mode.',
  setupNext_rerun: 'Run the wizard again after the certificate or a signing key changes: the code in step 4 is generated with the new values and the app needs an update.',

  // ── Step 1: server checks ───────────────────────────────────────────
  setuph_admin_auth: [
    'Terminal (server machine): `./scripts/add-admin.sh ayse --apply` → the personal key is shown once, its SHA-256 is added to `ADMIN_KEYS` in .env. Again for the second admin: `./scripts/add-admin.sh mehmet --apply` (two-person approval needs two names).',
    'Without the script: key `openssl rand -hex 32`, digest `printf %s <key> | shasum -a 256`; .env: `ADMIN_KEYS=ayse:<sha256>,mehmet:<sha256>`. The server stores only the digest, never the key.',
    'Hand the key to its owner over a safe channel; stop sharing the common `API_KEY`.',
    'Verify: open the dashboard with the personal key; the admin name shows at the top left and the Audit Log writes changes under it; this row is READY with "2 named admins".'
  ],
  setuph_approvals: [
    'First two personal admins (the row above): an admin cannot approve their own change and the shared `API_KEY` cannot approve.',
    'In the Settings card below, "Admins needed for a pin change" → 2 → Save.',
    'Verify: change a host\'s pins; the change lands in Approvals and applies once a second admin approves.'
  ],
  setuph_webhook: [
    'Get a Slack-compatible webhook URL from the channel the notifications should reach (Slack: Incoming Webhooks; Teams, Mattermost and others accept the same format).',
    '.env: `NOTIFY_WEBHOOK_URL=https://…` and `NOTIFY_WEBHOOK_SECRET=` from `openssl rand -hex 32`. The receiver should verify `X-PinVault-Signature` together with the timestamp.',
    'Verify: change a host\'s pins or revoke a device; the notification arrives in the channel.'
  ],
  setuph_management_tls: [
    '.env: `MANAGEMENT_HTTPS_PORT=8082` plus a port mapping in the compose file (sample-host: `6655:8082`, bound to this machine only by default). The certificate is the Config API\'s: the browser warns about self-signed, the app already pins it.',
    'Open the dashboard at `https://<server>:6655` from now on; keep the plain HTTP port bound to `127.0.0.1`. Remote: VPN or `ssh -L 6655:127.0.0.1:6655 <user>@<server>`.',
    'Verify: this row is READY with "port 8082"; the admin key never crosses the network in the clear.'
  ],
  setuph_test_hooks: [
    'Remove `ALLOW_TEST_HOOKS` from .env or leave it empty. These endpoints exist for the end-to-end tests only (short-lived certificate hook).',
    'Verify: `/api/v1/test-hooks/…` answers 404; this row leaves the list.'
  ],
  setuph_demo_secrets: [
    'With sample-host: `./scripts/setup.sh` generates the missing passwords and writes them to .env with mode 600. By hand: `openssl rand -base64 32` for `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD`, `SIGNING_KEY_PASSWORD`.',
    'Remove the `ALLOW_DEMO_SECRETS` line. If the keystore password changes on an existing installation, pass the old one for one start as `KEYSTORE_PASSWORD_PREVIOUS`; the server moves its stores to the new password.',
    'Verify: the server starts (it refuses to without the passwords) and this row leaves the list.'
  ],
  setuph_signers: [
    'Decide: at least two signers, at least one off this server\'s disk. Options: `pkcs11` (HSM; `PKCS11_LIBRARY` is the library path inside the container, `PKCS11_PIN`) and `command` (KMS or a separate signing service; `SIGNER_COMMAND` signs stdin to stdout, `SIGNER_PUBLIC_KEY`, `SIGNER_INPUT=digest` for a KMS that signs digests). Details: SECURE_OPERATIONS.md.',
    '.env: `CONFIG_SIGNERS=pkcs11,command` (or `local,command`: one stays on disk). Every config carries two signatures; the code in step 4 is generated with `requiredSignatures(2)`, update the app with it.',
    'To try the path without hardware: `./scripts/softhsm-init.sh`. SoftHSM is not an HSM, the key still sits on disk, and it does not make this row READY.',
    'Verify: {0} → Signing tab lists two signers; this row is READY with "2 signers".'
  ],
  setuph_recovery_keys: [
    'On a machine that is not connected to the internet: `scripts/offline-keygen.sh` (only that file and openssl are needed). The recovery key\'s private half stays there, encrypted with a passphrase; only the public half is printed.',
    'Put only the public half into .env: `RECOVERY_PUBLIC_KEYS=<Base64>`. The private half never reaches the server: whoever takes over the server cannot rotate the signing key.',
    'Verify: this row is READY; in step 3 the "Signing-key rotation (recoveryPublicKeys)" box becomes available and goes into the code in step 4.'
  ],
  setuph_config_ttl: [
    'In the Settings card below, "Config lifetime (seconds)" → at most 86400 (1 day) → Save.',
    'Verify: a phone treats the signed config as valid for at most this long; someone blocking the Config API cannot hold a device on old pins longer.'
  ],
  setuph_live_check: [
    'In the Settings card below, "Live certificate check" → Block → Save. If hosts are served on this server\'s own IP (mock), map them with `LIVE_CHECK_HOST_MAP`.',
    'Verify: try to save a pin a host does not serve right now; the server refuses. A pin that would not reach the phones cannot be published.'
  ],
  setuph_enrollment_mode: [
    'In the Settings card below, "Device enrollment" → Token only → Save. "Open" mode is for trials only: any phone that names its device id enrolls.',
    'Tokens for the phones: Dashboard → mTLS Config API → Client Certificates → "Generate Token" (one device) or Enrollment Codes (one code, many devices, with admin approval if wanted).',
    'Verify: an enrollment without a token answers 403; this row is READY with "token".'
  ],
  setuph_attestation: [
    'Get the SHA-256 of the release signing certificate: `apksigner verify --print-certs app-release.apk` → the "Signer #1 certificate SHA-256 digest" line (or `keytool -printcert -jarfile app-release.apk`). Package name: `applicationId`.',
    'In the Settings card below, fill "App package name" and "SHA-256 fingerprint of the app signing certificate"; set "Key attestation at enrollment" to Warn first → Save.',
    'Enroll the release build on a real phone (an emulator attests with a software root and does not pass); check the attestation result of the enrollment in the Audit Log. Then "Key attestation at enrollment" → Block → Save.',
    'Verify: an enrollment without attestation or from another app answers 403 `attestation_required` / `attestation_invalid`; this row is READY with "enforce".'
  ],
  setuph_attestation_revocation: [
    'Download the first copy of Google\'s revocation list: `./scripts/fetch-attestation-status.sh` → `data/attestation-status.json`. The server does not go online; it reads the list from this file.',
    'Keep it fresh with cron (every 6 hours): `0 */6 * * * cd /path/sample-host && ./scripts/fetch-attestation-status.sh`.',
    '.env: `ATTESTATION_REVOKED_SERIALS_FILE=/data/attestation-status.json` and `ATTESTATION_STATUS_MAX_AGE_HOURS=48` (an older list lets no attestation pass; without the file the server does not start).',
    'Verify: `./scripts/smoke-test.sh` shows the list\'s age; this row is READY.'
  ],
  setuph_p12: [
    'First make sure every app version can enroll with a CSR (library 2.1 or later; the key is made on the phone, only a signing request goes to the server).',
    '.env: `ENROLLMENT_P12=off`. The server no longer makes a private key and ships it to the phone.',
    'Verify: an old client asking for a P12 gets 403 `csr_required`; this row is READY with "off".'
  ],
  setuph_integrity: [
    'Enable the Play Integrity API in Google Cloud and download a service account key (JSON) → `data/play-integrity-sa.json` on the server (mode 600). The app must be linked to the same project in the Play Console.',
    '.env: `INTEGRITY_VERIFIER_COMMAND=/opt/pinvault/scripts/play-integrity-verify.sh`, `INTEGRITY_PLAY_PACKAGE=<package>`, `INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE=/data/play-integrity-sa.json`.',
    'In the Settings card below, "Play Integrity check at enrollment" → Warn → Save. In step 3 tick "Send a Play Integrity token at enrollment"; the app gets the `com.google.android.play:integrity` dependency.',
    'Enroll on a real phone and read the integrity result in the Audit Log; then "Block" → Save.',
    'Verify: a rooted device or an app not installed from Play cannot enroll; this row is READY with "enforce".'
  ],

  // ── Step 2: certificates ────────────────────────────────────────────
  setuph_config_api_cert: [
    'A new certificate before it expires: {0} → Bootstrap tab → "Renew Certificate" (or "Upload JKS" with your own). The new pins go into the code in step 4.',
    'The order matters: ship the app version with the new pins first; once the phones have updated, restart the server with the new certificate. An app with the old pins cannot connect to the new certificate.',
    'Verify: this row is READY with the new date; Connection History shows phones still connecting.'
  ],
  setuph_config_api_cert_source: [
    'The self-signed certificate is fine in production because it is pinned; changing it is not required.',
    'To use your own: {0} → Bootstrap tab → "Upload JKS" (PKCS12 or JKS, key + chain). The pins change: take the code in step 4 again and update the app.',
    'Verify: this row is READY with the new source.'
  ],
  setuph_config_api_backup_key: [
    'The backup key is the certificate\'s, not the signing key\'s: if the key is stolen it lets you switch without an app update. {0} → Bootstrap tab → "Renew Certificate": a backup key is made with the new certificate, and two pins (primary + backup) go into the code in step 4.',
    'Order: ship the app version carrying both pins first, then serve the new certificate (restart). When the key is stolen, "Switch to Backup Key" moves over in one click and prepares a new backup.',
    'Verify: this row is READY; `bootstrapPins` in the code step carries two pins.'
  ],
  setuph_config_api_cert_name: [
    'The name phones connect to (IP or domain) must be among the certificate\'s names (SAN): PinVault checks the pin, but OkHttp looks for the name too.',
    '.env: `EXTRA_CERT_SANS=<address>` (several with commas), restart, then {0} → Bootstrap tab → "Renew Certificate"; or "Upload JKS" with your own certificate that carries the name. The pins change: take the code in step 4 again.',
    'Verify: the address shows in this row and it is READY.'
  ],
  setuph_client_ca: [
    'When the client CA expires no device can renew; a CA change means every device enrolls again. Plan ahead when the date comes close: SECURE_OPERATIONS.md, the client CA section.',
    'New CA: replace `certs/client-ca.jks` with the new one and restart; `clientCaPins` in step 4 changes, so the app needs an update and every phone enrolls again (hand out tokens or an enrollment code).',
    'Verify: this row is READY with the new date; Client Certificates shows the new enrollments.'
  ],
  setuph_client_cert_ttl: [
    'In the Settings card (step 1), "Device certificate lifetime (days)" → something short like 90 → Save. A device renews on its own with a third of the lifetime left.',
    'Verify: this row is READY with the new lifetime; new enrollments are issued with it.'
  ],
  setuph_p12_enrollment: [
    'First make sure every app version can enroll with a CSR (library 2.1 or later).',
    '.env: `ENROLLMENT_P12=off`, restart. The private key is now made on the phone, never shipped from the server.',
    'Verify: this row is READY with "off".'
  ],
  setuph_recovery_door: [
    'The recovery door is the TLS listener where phones with an expired certificate get a new one without a token (no client certificate required; the signature made with the old key proves the identity).',
    '.env: `RECOVERY_PORT=8083` plus a port mapping in compose (sample-host: `6656:8083`); restart. In step 3 tick "Renew an expired certificate through the recovery door": the code in step 4 carries `renewalUrl` and the server CA pins.',
    'Verify: this row is READY with "port 8083".'
  ],
  setuph_server_ca: [
    'The server CA signs the recovery door\'s certificate and the app pins it (the second `HostPin` in `bootstrapPins`). Plan the next one before it expires: a new CA changes the pins in step 4 and needs an app update.',
    'New CA: replace `certs/server-ca.jks` and its backup with the new ones, restart; ship the app with the new pins first.',
    'Verify: this row is READY with the new date.'
  ],
  setuph_host_cert: [
    'Renewing a host\'s certificate is its owner\'s job (your API server, a CDN). Once the new certificate is live: Host page → "Fetch from URL" to take the new pin; keep the old pin as the backup during the switch (both are valid).',
    'If it is a test host this server serves (mock): Host page → "Renew Certificate".',
    'Verify: the host row is READY with the new date; the config version grows and phones take the new list.'
  ],
  setuph_host_backup_pin: [
    'Whose key is the backup pin? For a host taken from a URL it is usually the issuing CA\'s: if that CA\'s key is stolen, a forged certificate passes too.',
    'Compute the pin of your own second key (a second certificate or key from the host\'s owner): `openssl x509 -in backup.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.',
    'Host page → "Fetch from URL" → put the value into "Backup pin" → Save (with two-person approval on, a second admin approves).',
    'Verify: the host row shows the backup pin as "stored backup key" or your own key and is READY.'
  ],
  setuph_host_served_here: [
    'This host is a target this server serves for tests (mock); in production the phones connect to your real API server.',
    'Add the real host: {0} → "+ New Host" → "Fetch from URL" (`https://api.yourcompany.com`) and enter its backup pin; then delete the mock host or stop the mock listener.',
    'Verify: the host list holds only real addresses; this row leaves the list.'
  ],
  setuph_host_client_cert: [
    'The shared client certificate handed to devices for this host is running out: get a new one from the host\'s CA (P12).',
    'Host page → the client certificate card → upload the new P12; phones take it at their next config refresh.',
    'Verify: the host row is READY with the new date.'
  ],
  setuph_vault_file: [
    'The expiry is a reminder; devices are still served the file. Upload the new one: {0} → Vault tab → a new version under the same key, with the new date in "Expiry (expiresAt)".',
    'Verify: the row is READY with the new date; phones take the new version at their next sync.'
  ]
});

/** Open how-to rows, by row key ("server:<id>", "cert:<id>", "host:<hostname>", "vault:<key>"). */
let setupHowtoOpen = {};

function toggleSetupHowto(key) {
  setupHowtoOpen[key] = !setupHowtoOpen[key];
  drawSetup();
}

/** The translated step list of a check, or [] when the check has none. */
function setupHowtoSteps(id) {
  const v = (i18n[lang] || {})['setuph_' + id] || i18n.tr['setuph_' + id];
  return Array.isArray(v) ? v : [];
}

/** A translated list (setupOrder, …). */
function setupHowtoList(key) {
  const v = (i18n[lang] || {})[key] || i18n.tr[key];
  return Array.isArray(v) ? v : [];
}

/** A step as markup: escaped, with `code` spans. The text is this file's own; {0} is the Config API id. */
function setupHowtoFormat(step, apiId) {
  const text = String(step).replace(/\{0\}/g, apiId || 'Config API');
  return esc(text).replace(/`([^`]+)`/g, '<code>$1</code>');
}

/** The "How to" / "Close" button of a row; nothing when the row is READY or has no steps. */
function setupHowtoButton(key, c) {
  if (!c || c.level === 'ok' || !setupHowtoSteps(c.id).length) return '';
  const open = !!setupHowtoOpen[key];
  return `<div style="margin-top:6px"><button class="btn btn-secondary btn-sm" data-action="toggleSetupHowto" data-arg0="${esc(key)}" aria-expanded="${open}">${open ? t('setupHowtoClose') : t('setupHowto')}</button></div>`;
}

/** The steps of one check as an ordered list; the last "Verify" step is set apart. */
function setupHowtoSection(c, apiId, title) {
  const steps = setupHowtoSteps(c.id);
  if (!steps.length) return '';
  const verifyWord = t('setupHowtoVerify');
  const items = steps.map(s => {
    const isVerify = /^(Doğrula|Verify):/.test(s);
    const body = setupHowtoFormat(isVerify ? s.replace(/^(Doğrula|Verify):\s*/, '') : s, apiId);
    return isVerify ? `<li class="howto-verify"><b>${esc(verifyWord)}:</b> ${body}</li>` : `<li>${body}</li>`;
  }).join('');
  return `${title ? `<div class="howto-title">${esc(title)}</div>` : ''}<ol class="howto-steps">${items}</ol>`;
}

/** Buttons that scroll to the Settings card for every `KEY=` in the fix the form can change. */
function setupHowtoSettingButtons(fix) {
  if (!settingsData || !fix) return '';
  const keys = (String(fix).match(/^\s*([A-Z][A-Z0-9_]*)=/gm) || []).map(l => l.trim().replace(/=.*/, ''));
  const inPanel = keys.filter(k => { const s = settingsByKey(k); return s && !s.locked; });
  if (!inPanel.length) return '';
  return `<div class="howto-actions">${inPanel.map(k =>
    `<button class="btn btn-secondary btn-sm" data-action="setupGoSetting" data-arg0="${esc(k)}">${esc(t('setupHowtoGoSetting', t('sets_' + k)))}</button>`).join('')}</div>`;
}

/** The expanded how-to row under a checklist row (server step: the check's .env fix and Settings buttons too). */
function setupHowtoRow(key, c, apiId, colspan) {
  if (!setupHowtoOpen[key]) return '';
  const envOnly = c.fix && !setupFixInPanel(c.fix);
  return `<tr class="setup-howto" data-setup-howto="${esc(key)}"><td colspan="${colspan || 4}">
      ${setupHowtoSection(c, apiId)}
      ${envOnly ? `<div class="howto-title">${esc(t('setupHowtoEnvLines'))}</div><pre class="json-box">${esc(c.fix)}</pre>` : ''}
      ${setupHowtoSettingButtons(c.fix)}
      <div class="howto-restart">${setupHowtoFormat(t('setupHowtoRestart'))}</div>
    </td></tr>`;
}

/** The how-to row of a host in the certificates step: one section per check of that host that is not READY. */
function setupHowtoHostRow(key, rows, apiId) {
  if (!setupHowtoOpen[key]) return '';
  const sections = rows.filter(c => c.level !== 'ok').map(c => setupHowtoSection(c, apiId, t('setupc_' + c.id))).join('');
  return `<tr class="setup-howto" data-setup-howto="${esc(key)}"><td colspan="4">${sections}</td></tr>`;
}

function setupHowtoHostButton(key, rows) {
  const needs = rows.some(c => c.level !== 'ok' && setupHowtoSteps(c.id).length);
  if (!needs) return '';
  const open = !!setupHowtoOpen[key];
  return `<div style="margin-top:6px"><button class="btn btn-secondary btn-sm" data-action="toggleSetupHowto" data-arg0="${esc(key)}" aria-expanded="${open}">${open ? t('setupHowtoClose') : t('setupHowto')}</button></div>`;
}

/** Scrolls to a setting in the Settings card and flashes it. */
function setupGoSetting(key) {
  const el = document.getElementById('setting-' + key);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('setting-flash');
  setTimeout(() => el.classList.remove('setting-flash'), 2400);
}

/** The "Order of work" card at the top of the server step. */
function setupOrderCard() {
  const items = setupHowtoList('setupOrder').map(s => `<li>${setupHowtoFormat(s)}</li>`).join('');
  return `<div class="card" id="setup-order">
      <div class="card-head"><div class="card-title">${esc(t('setupOrderTitle'))}</div></div>
      <div class="card-hint">${esc(t('setupOrderHint'))}</div>
      <ol class="howto-steps">${items}</ol>
    </div>`;
}

/** The "Next steps" card under the generated code: what to do until the first phone connects. */
function setupNextStepsCard() {
  const api = setupSelectedApi();
  const mtls = api && api.mode === 'mtls';
  const o = setupOpts || {};
  const ids = ['dependency', 'paste'];
  if (mtls) ids.push('token');
  if (o.guard) ids.push('guard');
  if (o.integrity) ids.push('integrity');
  ids.push('run', 'release', 'rerun');
  const items = ids.map(id => `<li data-setup-next="${esc(id)}">${setupHowtoFormat(t('setupNext_' + id), api ? api.id : '')}</li>`).join('');
  return `<div class="card" id="setup-next-steps">
      <div class="card-head"><div class="card-title">${esc(t('setupNextTitle'))}</div></div>
      <div class="card-hint">${esc(t('setupNextHint'))}</div>
      <ol class="howto-steps">${items}</ol>
    </div>`;
}
