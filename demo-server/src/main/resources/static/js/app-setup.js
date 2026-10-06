// PinVault dashboard — Setup wizard: the server's production checklist and the
// app's PinVault configuration, generated from this server's public values.
// Classic scripts sharing one global scope, loaded in order by index.html.
//
// Server settings: the non-secret ones are changed in the Settings card and
// saved for the next start (`/api/v1/server-settings`; a restart applies them);
// secrets, ports and test switches stay `.env` lines. The app code it
// generates holds only public values (pins, public keys, ports).

Object.assign(i18n.tr, {
  navSetup: 'Kurulum Sihirbazı',
  setupTitle: 'Kurulum Sihirbazı',
  setupSub: 'Sunucunun üretime hazır olup olmadığını gösterir ve uygulamanın PinVault ayarlarını bu sunucunun değerleriyle üretir.',
  setupStepServer: '1 · Sunucu', setupStepApp: '2 · Uygulama', setupStepCode: '3 · Kod',
  setupReady: '{0} / {1} madde hazır',
  setupReadOnly: 'Sunucu ayarları açılışta ortam değişkenlerinden okunur. Sihirbaz onları değiştirmez: aşağıdaki satırları .env dosyasına yazıp sunucuyu yeniden başlat.',
  setupColCheck: 'Kontrol', setupColNow: 'Şu an', setupColFix: '.env',
  setupAllEnv: 'Önerilen .env satırları', setupNoFix: 'Değişiklik gerekmiyor.',
  setupCopy: 'Kopyala', setupNext: 'İleri →', setupBack: '← Geri',
  setupLevel_ok: 'HAZIR', setupLevel_warn: 'UYARI', setupLevel_fail: 'EKSİK',
  setup_admin_auth: 'Yönetici kimliği', setup_admin_auth_why: 'Her yöneticinin kendi anahtarı olmalı; ortak API_KEY kimin ne yaptığını göstermez.',
  setup_approvals: 'İki kişi onayı', setup_approvals_why: 'Pin değişikliği ikinci bir yöneticinin onayını beklesin.',
  setup_webhook: 'Güvenlik bildirimleri', setup_webhook_why: 'Pin değişikliği, iptal ve reddedilen anahtar anında bir kanala düşsün.',
  setup_management_tls: 'Yönetim paneli TLS', setup_management_tls_why: 'Yönetici anahtarı ağda düz metin gitmesin.',
  setup_test_hooks: 'Test uçları', setup_test_hooks_why: 'Yalnızca testler içindir; üretimde kapalı olmalı.',
  setup_demo_secrets: 'Demo parolaları', setup_demo_secrets_why: 'Keystore, vault ve imza anahtarı parolaları kaynak koddaki demo değerlerle çalışıyor.',
  setup_signers: 'Config imzalayıcıları', setup_signers_why: 'Pin\'leri imzalayan anahtar çalınırsa saldırgan istediği pin\'i yayınlar. En az iki imzalayıcı, biri bu diskte olmayan.',
  setup_recovery_keys: 'Kurtarma anahtarları', setup_recovery_keys_why: 'İmza anahtarını uygulama güncellemesi olmadan döndürmek ve iptal etmek için.',
  setup_config_ttl: 'Config ömrü', setup_config_ttl_why: 'Config API\'yi engelleyen biri cihazı en fazla bu süre eski pin\'lerde tutabilir.',
  setup_live_check: 'Canlı sertifika kontrolü', setup_live_check_why: 'Host\'un sunmadığı pin\'leri yayınlamayı engeller.',
  setup_enrollment_mode: 'Kayıt modu', setup_enrollment_mode_why: 'open modunda cihaz kimliği söyleyen herkes kayıt olur.',
  setup_attestation: 'Kayıtta donanım belgesi', setup_attestation_why: 'Token\'ı ele geçiren bir script ya da emülatör kayıt olamasın; anahtar gerçek telefonda, senin uygulamanda üretilmiş olsun.',
  setup_attestation_revocation: 'Belge iptal listesi', setup_attestation_revocation_why: 'Google\'ın iptal ettiği belge anahtarları geçmesin.',
  setup_p12: 'Sunucuda üretilen anahtar', setup_p12_why: 'Özel anahtar hiç ağdan geçmesin; cihaz kendi anahtarıyla CSR göndersin.',
  setup_integrity: 'Cihaz bütünlüğü (Play Integrity)', setup_integrity_why: 'Root\'lu ya da kancalanmış cihaz, Play dışından kurulmuş uygulama kayıt olamasın. Karar sunucuda verilir, cihazda atlatılamaz.',
  // Settings changed from the panel (server-settings.json, applied at the next start)
  setsTitle: 'Ayarlar',
  setsHint: 'Değiştir ve kaydet. Sunucu ayarları açılırken okur: kaydettiklerin sunucu yeniden başlayınca geçerli olur. Parolalar, gizli anahtarlar ve portlar burada yok; onlar .env dosyasında kalır.',
  setsSave: 'Kaydet', setsSaved: 'Kaydedildi. Sunucu yeniden başlayınca geçerli olacak.', setsNoChange: 'Değişiklik yok.',
  setsNotSaved: 'Kaydedilmedi: {0}', setsDefault: 'Varsayılan ({0})', setsDefaultEmpty: 'Varsayılan (boş)', setsOn: 'Açık',
  setsNow: 'Şu an: {0}', setsNext: 'Yeniden başlayınca: {0}', setsUnset: 'varsayılan',
  setsLocked: '.env dosyasında (ortam değişkeni) sabit; buradan değiştirilemez.',
  setsPending: 'Kaydedilen değişiklikler sunucu yeniden başlayınca geçerli olacak.',
  setsRestart: 'Şimdi yeniden başlat', setsRestartConfirm: 'Sunucu birkaç saniye kapanıp açılacak; o sırada telefonlar bağlanamaz. Devam edilsin mi?',
  setsNoSupervisor: 'Bu sunucu kendini yeniden başlatamıyor: sunucuyu durdurup tekrar çalıştır.',
  setsRestarting: 'Sunucu yeniden başlatılıyor…', setsRestarted: 'Sunucu yeniden başladı; ayarlar geçerli.',
  setsRestartSlow: 'Sunucu henüz cevap vermiyor; birazdan sayfayı yenile.',
  setsRejected: 'Panelden kaydedilen ayarlar sunucuyu başlatmadı, bu yüzden uygulanmadı. Neden: {0}', setsDismiss: 'Tamam',
  setsFromPanel: 'Ayarlardan ↓',
  setupFromPanelHint: '"Ayarlardan" işaretli maddeleri aşağıdaki Ayarlar kartından değiştirebilirsin. Parola ve gizli anahtar gibi diğerleri yalnızca .env dosyasından değişir.',
  setsGroup_governance: 'Değişiklik denetimi ve onay', setsGroup_config: 'Config', setsGroup_devices: 'Cihazlar ve kayıt',
  setsGroup_attestation: 'Atestasyon (uygulamanın ve telefonun düzenli kontrolü)', setsGroup_setup: 'Uygulama koduna yazılan adres',
  setsChoice_off: 'Kapalı', setsChoice_warn: 'Uyarı ver', setsChoice_enforce: 'Engelle', setsChoice_on: 'Açık',
  setsChoice_token: 'Yalnızca token ile', setsChoice_open: 'Açık (token gerekmez)', setsChoice_strict: 'Sıkı', setsChoice_lenient: 'Hoşgörülü',
  sets_PIN_CHANGE_APPROVALS: 'Pin değişikliği için gereken yönetici sayısı', sets_PIN_CHANGE_APPROVALS_why: '2 ve üstünde pin, host ve sertifika değişiklikleri (bu ayarlar dahil) başka bir yöneticinin onayını bekler. Her yöneticinin kendi anahtarı gerekir (ADMIN_KEYS).',
  sets_PIN_LIVE_CHECK: 'Canlı sertifika kontrolü', sets_PIN_LIVE_CHECK_why: 'Pin kaydedilmeden önce host\'un şu an sunduğu sertifika yeni listede mi diye bakılır. Uyarı ver: kaydeder ama uyarır. Engelle: kaydetmez.',
  sets_CONFIG_TTL_SECONDS: 'Config ömrü (saniye)', sets_CONFIG_TTL_SECONDS_why: 'Telefon imzalı config\'i en fazla bu kadar geçerli sayar. Kısa olursa sunucuya ulaşamayan telefon daha erken durur; uzun olursa eski pin\'ler daha uzun kullanılabilir. 86400 = 1 gün.',
  sets_CONFIG_API_ADMIN_ROUTES: 'Telefonların bağlandığı portlarda yönetim işlemleri', sets_CONFIG_API_ADMIN_ROUTES_why: 'Kapalı: yönetim yalnızca yönetim portundan yapılır, telefonların ulaştığı portlar yalnızca cihaz isteklerine cevap verir. Üretimde kapalı önerilir.',
  sets_ENROLLMENT_MODE: 'Cihaz kaydı', sets_ENROLLMENT_MODE_why: 'Yalnızca token ile: panelden üretilen token olmadan kimse kayıt olamaz. Açık: cihaz kimliğini söyleyen her telefon kayıt olur; yalnızca deneme içindir.',
  sets_CLIENT_CERT_TTL_DAYS: 'Cihaz sertifikasının ömrü (gün)', sets_CLIENT_CERT_TTL_DAYS_why: 'Telefonun mTLS sertifikası bu süre dolmadan yenilenir. En fazla 825.',
  sets_HOST_CLIENT_CERT_REQUIRE_GRANT: 'Host istemci sertifikası yalnızca izin verilen cihazlara', sets_HOST_CLIENT_CERT_REQUIRE_GRANT_why: 'Bir host\'un istemci sertifikası (bütün telefonların paylaştığı tek özel anahtar) yalnızca o host için izin verilmiş cihazlara verilir.',
  sets_ENROLLMENT_ATTESTATION: 'Kayıtta donanım belgesi', sets_ENROLLMENT_ATTESTATION_why: 'Telefonun anahtarının gerçek bir telefonda, senin uygulamanda üretildiğini gösteren Android belgesi istenir. Engelle için paket adı ve imza parmak izi gerekir.',
  sets_USER_AUTH_ATTESTATION: 'Ekran kilidi anahtarında donanım belgesi', sets_USER_AUTH_ATTESTATION_why: 'Ekran kilidiyle açılan dosyaların anahtarı için aynı kontrol. Engelle için paket adı ve imza parmak izi gerekir.',
  sets_INTEGRITY_VERIFICATION: 'Kayıtta Play Integrity kontrolü', sets_INTEGRITY_VERIFICATION_why: 'Kayıt isteğindeki Play Integrity token\'ı sunucuda doğrulanır. Doğrulayan komut (INTEGRITY_VERIFIER_COMMAND) .env dosyasında tanımlı olmalı.',
  sets_ATTESTATION_PACKAGE_NAMES: 'Uygulamanın paket adı', sets_ATTESTATION_PACKAGE_NAMES_why: 'Donanım belgesinde aranacak paket adı, örneğin com.sirket.uygulama. Birden fazlaysa virgülle ayır.',
  sets_ATTESTATION_SIGNER_SHA256: 'Uygulama imza sertifikasının SHA-256 parmak izi', sets_ATTESTATION_SIGNER_SHA256_why: 'Release imza sertifikasının SHA-256 değeri (keytool ya da apksigner gösterir). Birden fazlaysa virgülle ayır.',
  sets_ATTESTATION_ENABLED: 'Atestasyon', sets_ATTESTATION_ENABLED_why: 'Uygulama birkaç dakikada bir kendini ve telefonu ölçüp imzalı bir rapor gönderir; sunucu politikaya göre karar verir, geçen telefona PinVault-Token verir.',
  sets_ATTESTATION_KEY_POLICY: 'Atestasyon anahtarının ilk kaydında donanım belgesi', sets_ATTESTATION_KEY_POLICY_why: 'Kapalı: ilk gelen anahtar kabul edilir. Uyarı ver: belge varsa kontrol edilir. Engelle: belgesiz anahtar kaydedilmez (paket adı ve parmak izi gerekir).',
  sets_ATTESTATION_POLICY_DEFAULT: 'Varsayılan politika', sets_ATTESTATION_POLICY_DEFAULT_why: 'Kendi politikası olmayan Config API\'ler için. Sıkı: root, emülatör, debugger ve kanca reddedilir. Hoşgörülü: hepsi yalnızca uyarı (önce telefonları ölçmek için).',
  sets_ATTESTATION_TOKEN_TTL_SECONDS: 'PinVault-Token ömrü (saniye)', sets_ATTESTATION_TOKEN_TTL_SECONDS_why: 'Kontrolden geçen telefona verilen token\'ın geçerlilik süresi.',
  sets_ATTESTATION_INTERVAL_SECONDS: 'Atestasyon aralığı (saniye)', sets_ATTESTATION_INTERVAL_SECONDS_why: 'Uygulamanın raporu ne sıklıkla yeniden göndereceği.',
  sets_ATTESTATION_REVEAL_REASONS: 'Reddedilen telefona nedeni söyle', sets_ATTESTATION_REVEAL_REASONS_why: 'Kapalıyken telefon yalnızca bir kod (ARC) görür; nedeni panelde görünür.',
  sets_MOCK_HOST_REQUIRE_TOKEN: 'Mock host\'lar token istesin', sets_MOCK_HOST_REQUIRE_TOKEN_why: 'Test için kurulan mock host\'lar geçerli PinVault-Token taşımayan isteği reddeder, senin API\'n gibi.',
  sets_SETUP_PUBLIC_HOST: 'Telefonların sunucuya ulaştığı adres', sets_SETUP_PUBLIC_HOST_why: 'Sihirbazın uygulama koduna yazdığı adres. Boşsa panelin açıldığı adres kullanılır.',
  sets_SETUP_PUBLIC_PORTS: 'Port eşlemesi', sets_SETUP_PUBLIC_PORTS_why: 'Sunucu Docker ya da bir proxy arkasındaysa: sunucunun dinlediği port ile telefonun bağlandığı port, örneğin 8081:6651,8092:6652.',
  setupAppIntro: 'Uygulamanın bağlanacağı Config API\'yi ve açılacak korumaları seç. Kod bir sonraki adımda.',
  setupApi: 'Config API', setupHost: 'Uygulamanın bağlanacağı adres (host ya da IP)',
  setupHostHint: 'Telefonun sunucuya ulaştığı adres. Pin\'ler bu ada yazılır.',
  setupEnrollApi: 'Kayıt için TLS Config API', setupEnrollApiHint: 'mTLS bloğunda sertifikası olmayan cihaz kaydı bu adrese yapar.',
  setupLang: 'Dil', setupStopped: 'durdurulmuş',
  setupOptSigned: 'İmzalı config (sunucunun imza anahtarları)',
  setupOptScope: 'Config\'i bu Config API\'ye bağla (serverScope)',
  setupOptRecovery: 'İmza anahtarı döndürme (recoveryPublicKeys)',
  setupOptClientCa: 'İstemci CA\'sını pin\'le (clientCaPins)',
  setupOptRecoveryDoor: 'Süresi dolan sertifikayı kurtarma kapısından yenile',
  setupOptGuard: 'Ortam kontrolü (environmentGuard: root / kanca tespitinin kararı)',
  setupOptIntegrity: 'Kayıtta Play Integrity token\'ı gönder (integrityTokenProvider)',
  setupOptUnlocked: 'Anahtarlar yalnızca telefon kilidi açıkken çalışsın (requireUnlockedDevice)',
  setupOptWipe: 'Cihaz iptal edilince dosyaları sil (wipeVaultFilesOnRevocation)',
  setupOptOffline: 'Vault dosyalarının çevrimdışı ömrü (gün, 0 = sınırsız)',
  setupOptUpdate: 'Pin güncelleme aralığı (saat)',
  setupOptCaTrust: 'Pin + sistem CA onayı istenecek host\'lar (virgülle; requireCaTrust)',
  setupCodeIntro: 'Bu kodu uygulamanın Application sınıfına koy. Değerler bu sunucudan geldi; sertifika ya da imza anahtarı değişirse sihirbazı yeniden çalıştır.',
  setupNotes: 'Notlar',
  setupNoteIntegrityOff: 'Sunucuda INTEGRITY_VERIFICATION kapalı: uygulama token gönderir ama sunucu bakmaz. 1. adımdaki satırları ekle.',
  setupNoteIntegrityDeps: 'integrityTokenProvider için uygulamaya com.google.android.play:integrity bağımlılığını ekle ve StandardIntegrityTokenProvider\'ı açılışta bir kez hazırla.',
  setupNoteIntegrityDepsSwift: 'App Attest için uygulamaya App Attest yeteneğini (com.apple.developer.devicecheck.appattest-environment) ekle; sunucuda APP_ATTEST_APP_IDS ve APP_ATTEST_ROOT_CA_FILE ayarlı olmalı. Simülatörde App Attest yok: kayıt jetonsuz yapılır.',
  setupNoteGuard: 'environmentGuard içine kendi tespitini bağla (RASP ürünü, RootBeer). PinVault kendisi tespit yapmaz; uygulama içindeki kontrol atlatılabilir, asıl karar sunucudaki bütünlük doğrulamasıdır.',
  setupNoteNoSigning: 'Sunucuda imza anahtarı bulunamadı: config imzasız kalır. Bu üretim için uygun değil.',
  setupNoteMtls: 'mTLS Config API: cihaz ilk açılışta init\'ten önce kayıt olmalı (kod sonunda).',
  setupNoteAttestation: 'Sunucu kayıtta donanım belgesi istiyor ({0}). Emülatörler yazılım köküyle belge üretir; test cihazlarını warn modundaki bir sunucuya kaydet.',
  setupNoteHostIp: 'Adres olarak IP verdin: telefon sunucuya bu IP ile ulaşmalı. Sertifika "{0}" adına kesilmiş; PinVault host adını değil pin\'i doğrular.',
  setupLoadError: 'Kurulum bilgisi alınamadı'
});

Object.assign(i18n.en, {
  // Settings changed from the panel (server-settings.json, applied at the next start)
  setsTitle: 'Settings',
  setsHint: 'Change and save. The server reads its settings when it starts: what you save applies after a restart. Passwords, secret keys and ports are not here; they stay in the .env file.',
  setsSave: 'Save', setsSaved: 'Saved. Applies when the server restarts.', setsNoChange: 'Nothing changed.',
  setsNotSaved: 'Not saved: {0}', setsDefault: 'Default ({0})', setsDefaultEmpty: 'Default (empty)', setsOn: 'On',
  setsNow: 'Now: {0}', setsNext: 'After restart: {0}', setsUnset: 'default',
  setsLocked: 'Fixed in the .env file (environment variable); cannot be changed here.',
  setsPending: 'Saved changes apply when the server restarts.',
  setsRestart: 'Restart now', setsRestartConfirm: 'The server goes down for a few seconds; phones cannot connect meanwhile. Continue?',
  setsNoSupervisor: 'This server cannot restart itself: stop it and start it again.',
  setsRestarting: 'Restarting the server…', setsRestarted: 'The server restarted; the settings apply.',
  setsRestartSlow: 'The server does not answer yet; reload the page in a moment.',
  setsRejected: 'Settings saved from the panel stopped the server from starting, so they were not applied. Reason: {0}', setsDismiss: 'OK',
  setsFromPanel: 'In Settings ↓',
  setupFromPanelHint: 'Items marked "In Settings" can be changed in the Settings card below. The others, such as passwords and secret keys, change only in the .env file.',
  setsGroup_governance: 'Change control and approval', setsGroup_config: 'Config', setsGroup_devices: 'Devices and enrollment',
  setsGroup_attestation: 'Attestation (regular check of the app and the phone)', setsGroup_setup: 'Address written into the app code',
  setsChoice_off: 'Off', setsChoice_warn: 'Warn', setsChoice_enforce: 'Block', setsChoice_on: 'On',
  setsChoice_token: 'Token only', setsChoice_open: 'Open (no token)', setsChoice_strict: 'Strict', setsChoice_lenient: 'Lenient',
  sets_PIN_CHANGE_APPROVALS: 'Admins needed for a pin change', sets_PIN_CHANGE_APPROVALS_why: 'At 2 or more, pin, host and certificate changes (these settings included) wait for another admin. Every admin needs a personal key (ADMIN_KEYS).',
  sets_PIN_LIVE_CHECK: 'Live certificate check', sets_PIN_LIVE_CHECK_why: 'Before pins are saved, the certificate the host serves now must be in the new list. Warn: saves and warns. Block: does not save.',
  sets_CONFIG_TTL_SECONDS: 'Config lifetime (seconds)', sets_CONFIG_TTL_SECONDS_why: 'A phone treats a signed config as valid for at most this long. Shorter: a phone that cannot reach the server stops sooner; longer: old pins stay usable longer. 86400 = 1 day.',
  sets_CONFIG_API_ADMIN_ROUTES: 'Admin actions on the ports phones use', sets_CONFIG_API_ADMIN_ROUTES_why: 'Off: administration happens on the management port only; the ports phones reach answer device requests only. Recommended off in production.',
  sets_ENROLLMENT_MODE: 'Device enrollment', sets_ENROLLMENT_MODE_why: 'Token only: nobody enrolls without a token made in the panel. Open: any phone that names its device id enrolls; for trials only.',
  sets_CLIENT_CERT_TTL_DAYS: 'Device certificate lifetime (days)', sets_CLIENT_CERT_TTL_DAYS_why: 'The phone\'s mTLS certificate is renewed before this runs out. At most 825.',
  sets_HOST_CLIENT_CERT_REQUIRE_GRANT: 'Host client certificate only to allowed devices', sets_HOST_CLIENT_CERT_REQUIRE_GRANT_why: 'A host\'s client certificate (one private key every phone shares) goes only to devices allowed for that host.',
  sets_ENROLLMENT_ATTESTATION: 'Hardware attestation at enrollment', sets_ENROLLMENT_ATTESTATION_why: 'The Android proof that the phone\'s key was made on a real phone, in your app. Block needs the package name and the signing fingerprint.',
  sets_USER_AUTH_ATTESTATION: 'Hardware attestation for the screen-lock key', sets_USER_AUTH_ATTESTATION_why: 'The same check for the key of files opened with the screen lock. Block needs the package name and the signing fingerprint.',
  sets_INTEGRITY_VERIFICATION: 'Play Integrity check at enrollment', sets_INTEGRITY_VERIFICATION_why: 'The enrollment\'s Play Integrity token is verified on the server. The verifying command (INTEGRITY_VERIFIER_COMMAND) must be set in the .env file.',
  sets_ATTESTATION_PACKAGE_NAMES: 'App package name', sets_ATTESTATION_PACKAGE_NAMES_why: 'The package name attestation must show, e.g. com.company.app. Separate several with commas.',
  sets_ATTESTATION_SIGNER_SHA256: 'SHA-256 fingerprint of the app signing certificate', sets_ATTESTATION_SIGNER_SHA256_why: 'The SHA-256 of the release signing certificate (keytool or apksigner prints it). Separate several with commas.',
  sets_ATTESTATION_ENABLED: 'Attestation', sets_ATTESTATION_ENABLED_why: 'Every few minutes the app measures itself and the phone and sends a signed report; the server decides by policy and gives a passing phone a PinVault-Token.',
  sets_ATTESTATION_KEY_POLICY: 'Hardware attestation at the attestation key\'s first registration', sets_ATTESTATION_KEY_POLICY_why: 'Off: the first key is trusted. Warn: checked when there is a proof. Block: no key without a proof (needs the package name and fingerprint).',
  sets_ATTESTATION_POLICY_DEFAULT: 'Default policy', sets_ATTESTATION_POLICY_DEFAULT_why: 'For Config APIs without a policy of their own. Strict: root, emulators, debuggers and hooks are rejected. Lenient: all of them only warn (to measure phones first).',
  sets_ATTESTATION_TOKEN_TTL_SECONDS: 'PinVault-Token lifetime (seconds)', sets_ATTESTATION_TOKEN_TTL_SECONDS_why: 'How long the token a passing phone gets stays valid.',
  sets_ATTESTATION_INTERVAL_SECONDS: 'Attestation interval (seconds)', sets_ATTESTATION_INTERVAL_SECONDS_why: 'How often the app sends its report again.',
  sets_ATTESTATION_REVEAL_REASONS: 'Tell a rejected phone why', sets_ATTESTATION_REVEAL_REASONS_why: 'Off: the phone sees only a code (ARC); the reason shows in the panel.',
  sets_MOCK_HOST_REQUIRE_TOKEN: 'Mock hosts require a token', sets_MOCK_HOST_REQUIRE_TOKEN_why: 'The mock hosts set up for tests refuse requests without a valid PinVault-Token, as your API would.',
  sets_SETUP_PUBLIC_HOST: 'Address phones reach the server at', sets_SETUP_PUBLIC_HOST_why: 'The address the wizard writes into the app code. Empty: the address the panel was opened at.',
  sets_SETUP_PUBLIC_PORTS: 'Port mapping', sets_SETUP_PUBLIC_PORTS_why: 'When the server is behind Docker or a proxy: the port it listens on and the port phones connect to, e.g. 8081:6651,8092:6652.',
  navSetup: 'Setup Wizard',
  setupTitle: 'Setup Wizard',
  setupSub: 'Shows whether the server is ready for production and generates the app\'s PinVault configuration from this server\'s values.',
  setupStepServer: '1 · Server', setupStepApp: '2 · App', setupStepCode: '3 · Code',
  setupReady: '{0} of {1} items ready',
  setupReadOnly: 'Server settings are environment values read at start-up. The wizard does not change them: add the lines below to .env and restart the server.',
  setupColCheck: 'Check', setupColNow: 'Now', setupColFix: '.env',
  setupAllEnv: 'Suggested .env lines', setupNoFix: 'Nothing to change.',
  setupCopy: 'Copy', setupNext: 'Next →', setupBack: '← Back',
  setupLevel_ok: 'READY', setupLevel_warn: 'WARNING', setupLevel_fail: 'MISSING',
  setup_admin_auth: 'Admin identity', setup_admin_auth_why: 'Each admin should have their own key; a shared API_KEY does not show who did what.',
  setup_approvals: 'Two-person approval', setup_approvals_why: 'A pin change should wait for a second admin.',
  setup_webhook: 'Security notifications', setup_webhook_why: 'Pin changes, revocations and refused keys reach a channel as they happen.',
  setup_management_tls: 'Admin panel over TLS', setup_management_tls_why: 'The admin key should not cross the network in plain text.',
  setup_test_hooks: 'Test endpoints', setup_test_hooks_why: 'For tests only; off in production.',
  setup_demo_secrets: 'Demo passwords', setup_demo_secrets_why: 'Keystore, vault and signing key passwords are the demo values from the source code.',
  setup_signers: 'Config signers', setup_signers_why: 'Whoever steals the key that signs pins can publish any pin. At least two signers, one not on this disk.',
  setup_recovery_keys: 'Recovery keys', setup_recovery_keys_why: 'Rotate and revoke the signing key without an app update.',
  setup_config_ttl: 'Config lifetime', setup_config_ttl_why: 'Someone blocking the Config API can hold a device on old pins for at most this long.',
  setup_live_check: 'Live certificate check', setup_live_check_why: 'Refuses to publish pins the host does not serve.',
  setup_enrollment_mode: 'Enrollment mode', setup_enrollment_mode_why: 'In open mode anyone naming a device id enrolls.',
  setup_attestation: 'Key attestation at enrollment', setup_attestation_why: 'A script or emulator holding a token cannot enroll: the key must be made on a real phone, by your app.',
  setup_attestation_revocation: 'Attestation revocation list', setup_attestation_revocation_why: 'Attestation keys Google revoked do not pass.',
  setup_p12: 'Server-made keys', setup_p12_why: 'No private key crosses the network; the device sends a CSR over its own key.',
  setup_integrity: 'Device integrity (Play Integrity)', setup_integrity_why: 'A rooted or hooked device, or an app not installed from Play, cannot enroll. The server decides; the device cannot bypass it.',
  setupAppIntro: 'Pick the Config API the app connects to and the protections to turn on. The code is in the next step.',
  setupApi: 'Config API', setupHost: 'Address the app connects to (host or IP)',
  setupHostHint: 'The address the phone reaches the server at. Pins are filed under it.',
  setupEnrollApi: 'TLS Config API for enrollment', setupEnrollApiHint: 'A device without a certificate enrolls here for the mTLS block.',
  setupLang: 'Language', setupStopped: 'stopped',
  setupOptSigned: 'Signed configs (the server\'s signing keys)',
  setupOptScope: 'Bind configs to this Config API (serverScope)',
  setupOptRecovery: 'Signing-key rotation (recoveryPublicKeys)',
  setupOptClientCa: 'Pin the client CA (clientCaPins)',
  setupOptRecoveryDoor: 'Renew an expired certificate through the recovery door',
  setupOptGuard: 'Environment check (environmentGuard: your root / hooking detection\'s verdict)',
  setupOptIntegrity: 'Send a Play Integrity token at enrollment (integrityTokenProvider)',
  setupOptUnlocked: 'Keys work only while the phone is unlocked (requireUnlockedDevice)',
  setupOptWipe: 'Delete files when the device is revoked (wipeVaultFilesOnRevocation)',
  setupOptOffline: 'Offline lifetime of vault files (days, 0 = unlimited)',
  setupOptUpdate: 'Pin update interval (hours)',
  setupOptCaTrust: 'Hosts that need pins and the platform CAs (comma separated; requireCaTrust)',
  setupCodeIntro: 'Put this in the app\'s Application class. The values came from this server; run the wizard again after the certificate or a signing key changes.',
  setupNotes: 'Notes',
  setupNoteIntegrityOff: 'INTEGRITY_VERIFICATION is off on the server: the app sends a token nobody reads. Add the lines from step 1.',
  setupNoteIntegrityDeps: 'For integrityTokenProvider add the com.google.android.play:integrity dependency and prepare a StandardIntegrityTokenProvider once at app start.',
  setupNoteIntegrityDepsSwift: 'For App Attest add the App Attest capability (com.apple.developer.devicecheck.appattest-environment) to the app; the server needs APP_ATTEST_APP_IDS and APP_ATTEST_ROOT_CA_FILE. The simulator has no App Attest: it enrolls without a token.',
  setupNoteGuard: 'Wire your own detection into environmentGuard (a RASP product, RootBeer). PinVault detects nothing itself; a check inside the app can be bypassed, the server\'s integrity verification is what decides.',
  setupNoteNoSigning: 'The server has no signing key: configs stay unsigned. Not fit for production.',
  setupNoteMtls: 'mTLS Config API: on first start the device enrolls before init (end of the code).',
  setupNoteAttestation: 'The server asks for key attestation at enrollment ({0}). Emulators attest with a software root; enroll test devices against a server in warn mode.',
  setupNoteHostIp: 'You gave an IP address: the phone must reach the server at it. The certificate is issued for "{0}"; PinVault checks the pin, not the host name.',
  setupLoadError: 'Could not load the setup data'
});

let setupData = null;
let setupStep = 'server';
let setupOpts = null;
/** `GET /api/v1/server-settings`; null until loaded (or when the server is older). */
let settingsData = null;
/** Unsaved changes in the settings form: key → value (`""` = back to the default). */
let settingsDraft = {};

function defaultSetupOpts(d) {
  const apis = d.configApis || [];
  const first = apis.find(a => a.running && a.mode === 'tls') || apis.find(a => a.running) || apis[0] || null;
  const tls = apis.find(a => a.mode === 'tls') || null;
  return {
    apiId: first ? first.id : '',
    enrollApiId: tls ? tls.id : '',
    // SETUP_PUBLIC_HOST (the sample host sets it from HOST_LAN_IP); else the dashboard's own address.
    host: d.publicHost || location.hostname || 'localhost',
    lang: 'kotlin',
    signed: (d.signingKeys || []).length > 0,
    scope: true,
    recovery: (d.recoveryKeys || []).length > 0,
    clientCa: !!d.clientCaPin,
    recoveryDoor: d.recoveryPort != null && (d.recoveryPins || []).length > 0,
    guard: true,
    integrity: d.integrityMode !== 'off',
    unlocked: false,
    wipe: true,
    offlineDays: '7',
    updateHours: '12',
    caTrust: ''
  };
}

async function renderSetupSection() {
  const content = document.getElementById('content');
  if (!setupData) content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await apiFetch('/api/v1/setup');
    if (currentSection !== 'setup') return;
    if (!res.ok) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('setupLoadError')} (HTTP ${res.status})</div></div>`;
      return;
    }
    setupData = await res.json();
    await loadServerSettings();
    if (!setupOpts) setupOpts = defaultSetupOpts(setupData);
    drawSetup();
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('setupLoadError')}: ${esc(e.message)}</div></div>`;
  }
}

function setSetupStep(step) {
  setupStep = ['server', 'app', 'code'].includes(step) ? step : 'server';
  drawSetup();
}

function setSetupOpt(name, ev) {
  if (!setupOpts || !(name in setupOpts)) return;
  const el = ev.target;
  setupOpts[name] = el.type === 'checkbox' ? el.checked : String(el.value);
  if (name === 'apiId' || name === 'lang') drawSetup();
}

function copySetupText(which) {
  const text = which === 'env' ? setupEnvText() : setupCode();
  navigator.clipboard.writeText(text).then(() => toast(t('copied'), 'success'));
}

function setupEnvText() {
  // Plain text (copied, or shown through esc()), never markup.
  // Only what the Settings card cannot change.
  return (setupData.checks || []).filter(c => c.fix && !setupFixInPanel(c.fix)).map(c => '# ' + t('setup_' + c.id) + '\n' + c.fix).join('\n\n');
}

function drawSetup() {
  if (currentSection !== 'setup' || !setupData) return;
  const tabs = ['server', 'app', 'code'].map(s => {
    const label = t(s === 'server' ? 'setupStepServer' : s === 'app' ? 'setupStepApp' : 'setupStepCode');
    return `<button class="tab-btn ${setupStep === s ? 'tab-active' : ''}" data-action="setSetupStep" data-arg0="${s}">${esc(label)}</button>`;
  }).join('');
  const body = setupStep === 'server' ? setupServerStep() : setupStep === 'app' ? setupAppStep() : setupCodeStep();
  document.getElementById('content').innerHTML = `
    <div id="setup-view">
      <div class="section-header">
        <div><div class="section-title-main">${t('setupTitle')}</div><div class="section-sub">${t('setupSub')}</div></div>
        <span class="refresh-icon" data-action="renderSetupSection" title="${t('refresh')}">&#x21bb;</span>
      </div>
      <div class="tab-bar">${tabs}</div>
      ${body}
    </div>`;
}

function setupSelected(yes) { return yes ? 'selected' : ''; }

/** A check's `.env` fix, escaped; a dash when there is none. */
function setupFixBox(fix) {
  return fix ? `<pre class="json-box">${esc(fix)}</pre>` : '<span class="muted">—</span>';
}

function setupEnvCopyButton(text) {
  return text ? `<button class="btn btn-secondary btn-sm" data-action="copySetupText" data-arg0="env">${t('setupCopy')}</button>` : '';
}

function setupEnvBox(text) {
  return text ? `<pre class="json-box">${esc(text)}</pre>` : `<div class="muted">${t('setupNoFix')}</div>`;
}

function setupLevelBadge(level) {
  const cls = level === 'ok' ? 'act-ok' : level === 'fail' ? 'act-bad' : 'act-warn';
  return `<span class="act-badge ${cls}">${esc(t('setupLevel_' + level))}</span>`;
}

function setupServerStep() {
  const checks = setupData.checks || [];
  const ready = checks.filter(c => c.level === 'ok').length;
  const order = { fail: 0, warn: 1, ok: 2 };
  const rows = checks.slice().sort((a, b) => order[a.level] - order[b.level]).map(c => `
      <tr>
        <td>${setupLevelBadge(c.level)}</td>
        <td><b>${esc(t('setup_' + c.id))}</b><div class="muted small">${esc(t('setup_' + c.id + '_why'))}</div></td>
        <td class="mono small">${esc(c.current)}</td>
        <td>${setupFixInPanel(c.fix) ? `<span class="act-badge act-ok">${esc(t('setsFromPanel'))}</span>` : setupFixBox(c.fix)}</td>
      </tr>`).join('');
  const env = setupEnvText();
  return `
    ${settingsBanners()}
    <div class="card">
      <div class="card-head"><div class="card-title">${esc(t('setupReady', ready, checks.length))}</div></div>
      <div class="card-hint">${esc(t(settingsData ? 'setupFromPanelHint' : 'setupReadOnly'))}</div>
      <table class="data-table">
        <thead><tr><th></th><th>${t('setupColCheck')}</th><th>${t('setupColNow')}</th><th>${t('setupColFix')}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${settingsCard()}
    <div class="card">
      <div class="card-head">
        <div class="card-title">${t('setupAllEnv')}</div>
        ${setupEnvCopyButton(env)}
      </div>
      ${setupEnvBox(env)}
    </div>
    <div class="form-actions"><button class="btn btn-primary" data-action="setSetupStep" data-arg0="app">${t('setupNext')}</button></div>`;
}

// ── Settings changed from the panel ─────────────────────────────────────────

async function loadServerSettings() {
  try {
    const res = await apiFetch('/api/v1/server-settings', { quiet: true });
    settingsData = res.ok ? await res.json() : null;
  } catch (_) {
    settingsData = null;
  }
}

function settingsByKey(key) {
  return settingsData ? (settingsData.settings || []).find(s => s.key === key) || null : null;
}

/** The `KEY=` names in a check's fix, when every one of them can be set in the form below. */
function setupFixInPanel(fix) {
  if (!settingsData || !fix) return false;
  const keys = (String(fix).match(/^\s*([A-Z][A-Z0-9_]*)=/gm) || []).map(l => l.trim().replace(/=.*/, ''));
  return keys.length > 0 && keys.every(k => { const s = settingsByKey(k); return s && !s.locked; });
}

/** A value as the form shows it: a choice's label, "On"/"Off", or the value itself. */
function settingLabel(s, value) {
  if (value == null || value === '') return t('setsUnset');
  if (s.kind === 'bool') return value === 'true' ? t('setsChoice_on') : t('setsChoice_off');
  if (s.kind === 'choice') return t('setsChoice_' + value);
  return String(value);
}

function settingsBanners() {
  if (!settingsData) return '';
  const out = [];
  const r = settingsData.rejected;
  if (r) {
    out.push(`<div class="card" style="border-left:4px solid #ef4444">
      <div>${esc(t('setsRejected', r.reason || '?'))}</div>
      <div class="form-actions"><button class="btn btn-secondary btn-sm" data-action="dismissSettingsRejected">${t('setsDismiss')}</button></div>
    </div>`);
  }
  if (settingsData.pendingRestart) {
    const action = settingsData.restartSupervised
      ? `<button class="btn btn-primary btn-sm" data-action="restartServer">${t('setsRestart')}</button>`
      : `<span class="muted">${esc(t('setsNoSupervisor'))}</span>`;
    out.push(`<div class="card" id="settings-pending" style="border-left:4px solid #f59e0b">
      <div>${esc(t('setsPending'))}</div>
      <div class="form-actions">${action}</div>
    </div>`);
  }
  return out.join('');
}

/** The control for one setting: its draft, else what is saved, else what runs. */
function settingControl(s) {
  const current = s.key in settingsDraft ? settingsDraft[s.key] : (s.saved != null ? s.saved : (s.locked ? s.running : ''));
  const value = current == null ? '' : String(current);
  const disabled = s.locked ? 'disabled' : '';
  const attrs = `data-action-change="setServerSetting" data-arg0="${esc(s.key)}" data-event="1" ${disabled}`;
  const defaultLabel = s.default === '' ? t('setsDefaultEmpty') : t('setsDefault', settingLabel(s, s.default));
  if (s.kind === 'choice' || s.kind === 'bool') {
    const choices = s.kind === 'bool' ? ['true', 'false'] : (s.choices || []);
    const options = [`<option value="" ${value === '' ? 'selected' : ''}>${esc(defaultLabel)}</option>`]
      .concat(choices.map(c => `<option value="${esc(c)}" ${value === c ? 'selected' : ''}>${esc(settingLabel(s, c))}</option>`));
    return `<select class="form-input" ${attrs}>${options.join('')}</select>`;
  }
  const type = s.kind === 'number' ? 'number' : 'text';
  const range = s.kind === 'number' ? `min="${esc(s.min)}" max="${esc(s.max)}"` : '';
  return `<input class="form-input" type="${type}" ${range} value="${esc(value)}" placeholder="${esc(defaultLabel)}" ${attrs}/>`;
}

function settingState(s) {
  if (s.locked) return `${esc(t('setsNow', settingLabel(s, s.running)))} · ${esc(t('setsLocked'))}`;
  const now = esc(t('setsNow', settingLabel(s, s.running)));
  return s.pending ? `${now} · <b>${esc(t('setsNext', settingLabel(s, s.saved)))}</b>` : now;
}

function settingsCard() {
  if (!settingsData) return '';
  const groups = [];
  (settingsData.settings || []).forEach(s => {
    let g = groups.find(x => x.id === s.group);
    if (!g) { g = { id: s.group, items: [] }; groups.push(g); }
    g.items.push(s);
  });
  const body = groups.map(g => `
      <div class="card-title" style="margin:18px 0 6px">${esc(t('setsGroup_' + g.id))}</div>
      ${g.items.map(s => `
        <div class="form-group" id="setting-${esc(s.key)}">
          <label class="form-label">${esc(t('sets_' + s.key))}</label>
          ${settingControl(s)}
          <div class="form-hint">${esc(t('sets_' + s.key + '_why'))}</div>
          <div class="form-hint small">${settingState(s)}</div>
        </div>`).join('')}`).join('');
  return `
    <div class="card" id="settings-card">
      <div class="card-head"><div class="card-title">${t('setsTitle')}</div></div>
      <div class="card-hint">${esc(t('setsHint'))}</div>
      ${body}
      <div class="form-actions"><button class="btn btn-primary" data-action="saveServerSettings">${t('setsSave')}</button></div>
    </div>`;
}

function setServerSetting(key, ev) {
  settingsDraft[key] = String(ev.target.value).trim();
}

async function saveServerSettings() {
  const values = {};
  Object.entries(settingsDraft).forEach(([key, value]) => {
    const s = settingsByKey(key);
    if (!s || s.locked) return;
    const before = s.saved != null ? String(s.saved) : '';
    if (value !== before) values[key] = value;
  });
  if (!Object.keys(values).length) { toast(t('setsNoChange'), 'info'); return; }
  const res = await apiFetch('/api/v1/server-settings', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ values })
  });
  if (res.status === 202) { settingsDraft = {}; return; }   // waits for a second admin (shown by apiFetch)
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    toast(t('setsNotSaved', ((body && body.details) || [res.status]).join(' · ')), 'error', 10000);
    return;
  }
  settingsData = body;
  settingsDraft = {};
  toast(t('setsSaved'), 'success');
  drawSetup();
}

async function restartServer() {
  if (!confirm(t('setsRestartConfirm'))) return;
  const res = await apiFetch('/api/v1/server-settings/restart', { method: 'POST' });
  if (res.status !== 202) {
    const body = await res.json().catch(() => null);
    toast(t('setsNotSaved', ((body && body.details) || [res.status]).join(' · ')), 'error', 8000);
    return;
  }
  toast(t('setsRestarting'), 'info', 6000);
  // Wait for the old process to go, then for the new one to answer.
  await new Promise(r => setTimeout(r, 2500));
  for (let i = 0; i < 60; i++) {
    try {
      const probe = await fetch('/api/v1/server-settings', { headers: { 'X-API-Key': getApiKey(), 'X-PinVault-Admin': '1' } });
      if (probe.ok) {
        settingsData = await probe.json();
        toast(t('setsRestarted'), 'success');
        renderSetupSection();
        return;
      }
    } catch (_) { /* still down */ }
    await new Promise(r => setTimeout(r, 1500));
  }
  toast(t('setsRestartSlow'), 'warning', 10000);
}

async function dismissSettingsRejected() {
  const res = await apiFetch('/api/v1/server-settings/rejected', { method: 'DELETE' });
  if (res.ok) { settingsData = await res.json(); drawSetup(); }
}

function setupCheckbox(name, label, disabled) {
  return `<label class="form-hint" style="display:flex;gap:8px;align-items:flex-start;margin:6px 0;font-size:13px;color:#cbd5e1">
      <input type="checkbox" ${setupOpts[name] ? 'checked' : ''} ${disabled ? 'disabled' : ''}
             data-action-change="setSetupOpt" data-arg0="${name}" data-event="1"/> <span>${esc(label)}</span></label>`;
}

function setupInput(name, label, hint, type) {
  return `<div class="form-group">
      <label class="form-label">${esc(label)}</label>
      <input class="form-input" type="${type || 'text'}" value="${esc(setupOpts[name])}"
             data-action-change="setSetupOpt" data-arg0="${name}" data-event="1"/>
      ${hint ? `<div class="form-hint">${esc(hint)}</div>` : ''}
    </div>`;
}

/** The port phones reach a listener at: SETUP_PUBLIC_PORTS (a Docker mapping, a proxy), else its own. */
function setupPort(a) {
  return (a && (a.publicPort || a.port)) || 443;
}

function setupRecoveryPort(d) {
  return d.recoveryPublicPort || d.recoveryPort;
}

function setupSelectedApi() {
  return (setupData.configApis || []).find(a => a.id === setupOpts.apiId) || null;
}

function setupAppStep() {
  const apis = setupData.configApis || [];
  const apiOptions = apis.map(a => `<option value="${esc(a.id)}" ${setupSelected(a.id === setupOpts.apiId)}>${esc(a.id)} · ${esc(a.mode.toUpperCase())} · :${esc(setupPort(a))}${a.running ? '' : ' · ' + esc(t('setupStopped'))}</option>`).join('');
  const api = setupSelectedApi();
  const mtls = api && api.mode === 'mtls';
  const tlsApis = apis.filter(a => a.mode === 'tls');
  const enrollOptions = tlsApis.map(a => `<option value="${esc(a.id)}" ${setupSelected(a.id === setupOpts.enrollApiId)}>${esc(a.id)} · :${esc(setupPort(a))}</option>`).join('');
  const d = setupData;
  return `
    <div class="card">
      <div class="card-hint">${esc(t('setupAppIntro'))}</div>
      <div class="form-group">
        <label class="form-label">${t('setupApi')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="apiId" data-event="1">${apiOptions}</select>
      </div>
      ${setupInput('host', t('setupHost'), t('setupHostHint'))}
      ${mtls ? `<div class="form-group">
        <label class="form-label">${t('setupEnrollApi')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="enrollApiId" data-event="1">${enrollOptions}</select>
        <div class="form-hint">${esc(t('setupEnrollApiHint'))}</div>
      </div>` : ''}
      <div class="form-group">
        <label class="form-label">${t('setupLang')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="lang" data-event="1">
          <option value="kotlin" ${setupOpts.lang === 'kotlin' ? 'selected' : ''}>Kotlin</option>
          <option value="java" ${setupOpts.lang === 'java' ? 'selected' : ''}>Java</option>
          <option value="swift" ${setupOpts.lang === 'swift' ? 'selected' : ''}>Swift (iOS)</option>
        </select>
      </div>
    </div>
    <div class="card">
      ${setupCheckbox('signed', t('setupOptSigned'), !(d.signingKeys || []).length)}
      ${setupCheckbox('scope', t('setupOptScope'))}
      ${setupCheckbox('recovery', t('setupOptRecovery'), !(d.recoveryKeys || []).length)}
      ${setupCheckbox('clientCa', t('setupOptClientCa'), !d.clientCaPin)}
      ${mtls ? setupCheckbox('recoveryDoor', t('setupOptRecoveryDoor'), d.recoveryPort == null) : ''}
      ${setupCheckbox('guard', t('setupOptGuard'))}
      ${setupCheckbox('integrity', t('setupOptIntegrity'))}
      ${setupCheckbox('unlocked', t('setupOptUnlocked'))}
      ${setupCheckbox('wipe', t('setupOptWipe'))}
      ${setupInput('offlineDays', t('setupOptOffline'), '', 'number')}
      ${setupInput('updateHours', t('setupOptUpdate'), '', 'number')}
      ${setupInput('caTrust', t('setupOptCaTrust'), '')}
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" data-action="setSetupStep" data-arg0="server">${t('setupBack')}</button>
      <button class="btn btn-primary" data-action="setSetupStep" data-arg0="code">${t('setupNext')}</button>
    </div>`;
}

function setupCodeStep() {
  const code = setupCode();
  const notes = setupNotes().map(n => `<li>${esc(n)}</li>`).join('');
  return `
    <div class="card">
      <div class="card-head">
        <div class="card-title" lang="en">${({ java: 'Java', swift: 'Swift (iOS)' })[setupOpts.lang] || 'Kotlin'}</div>
        <button class="btn btn-primary btn-sm" data-action="copySetupText" data-arg0="code">${t('setupCopy')}</button>
      </div>
      <div class="card-hint">${esc(t('setupCodeIntro'))}</div>
      <pre class="json-box" style="max-height:none;white-space:pre;overflow-x:auto">${esc(code)}</pre>
    </div>
    ${notes ? `<div class="notice notice-info"><b>${t('setupNotes')}</b><ul class="notice-list">${notes}</ul></div>` : ''}
    <div class="form-actions"><button class="btn btn-secondary" data-action="setSetupStep" data-arg0="app">${t('setupBack')}</button></div>`;
}

function setupNotes() {
  const d = setupData, o = setupOpts, api = setupSelectedApi();
  const notes = [];
  if (!(d.signingKeys || []).length) notes.push(t('setupNoteNoSigning'));
  if (api && api.mode === 'mtls') notes.push(t('setupNoteMtls'));
  if (o.guard) notes.push(t('setupNoteGuard'));
  if (o.integrity) {
    notes.push(t(o.lang === 'swift' ? 'setupNoteIntegrityDepsSwift' : 'setupNoteIntegrityDeps'));
    if (d.integrityMode === 'off') notes.push(t('setupNoteIntegrityOff'));
  }
  if (d.attestationMode && d.attestationMode !== 'off') notes.push(t('setupNoteAttestation', d.attestationMode));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(o.host || '')) notes.push(t('setupNoteHostIp', d.bootstrapHost || 'localhost'));
  return notes;
}

/** Characters that may go into a generated string literal as they are. */
function setupLiteral(s) {
  return '"' + String(s == null ? '' : s).replace(/[^A-Za-z0-9+/=._:\-*]/g, '') + '"';
}

function setupHostOnly(raw) {
  return String(raw || '').trim().replace(/^https?:\/\//, '').replace(/[/:].*$/, '').replace(/[^A-Za-z0-9.\-]/g, '') || 'localhost';
}

/**
 * The app's configuration, Kotlin, Java or Swift. Every value comes from this
 * server's public data or the wizard's own choices; literals are reduced to
 * the characters a host, a port, an id or a Base64 key can have.
 */
function setupCode() {
  if (setupOpts.lang === 'swift') return setupCodeSwift();
  const d = setupData, o = setupOpts;
  const api = setupSelectedApi() || { id: 'default-tls', port: 443, mode: 'tls' };
  const host = setupHostOnly(o.host);
  const url = `https://${host}:${setupPort(api)}/`;
  const mtls = api.mode === 'mtls';
  const enrollApi = mtls ? (d.configApis || []).find(a => a.id === o.enrollApiId) : null;
  const door = mtls && o.recoveryDoor && d.recoveryPort != null && (d.recoveryPins || []).length > 0;
  const keys = o.signed ? (d.signingKeys || []) : [];
  const recovery = o.recovery ? (d.recoveryKeys || []) : [];
  const caTrust = String(o.caTrust || '').split(',').map(s => s.trim()).filter(Boolean);
  const offline = parseInt(o.offlineDays, 10);
  const hours = parseInt(o.updateHours, 10);
  const java = o.lang === 'java';
  const L = setupLiteral;
  const pins = (list) => list.map(L).join(', ');

  const blockLines = [];
  const bootstrap = [{ host, pins: d.bootstrapPins || [], note: 'Config API certificate' }];
  if (door) bootstrap.push({ host: `${host}:${setupRecoveryPort(d)}`, pins: d.recoveryPins, note: 'recovery door (server CA)' });
  if (java) {
    const hp = bootstrap.map((b, i) => `                new HostPin(${L(b.host)}, Arrays.asList(${pins(b.pins)}), 0, false, false, null)${i < bootstrap.length - 1 ? ',' : ''}   // ${b.note}`);
    blockLines.push(`            block.bootstrapPins(Arrays.asList(\n${hp.join('\n')}\n            ));`);
    if (keys.length) blockLines.push(`            block.signaturePublicKeys(${pins(keys)});`);
    else blockLines.push(`            block.allowUnsigned();   // the server has no signing key: not for production`);
    if (keys.length && d.requiredSignatures > 1) blockLines.push(`            block.requiredSignatures(${d.requiredSignatures});`);
    if (recovery.length) blockLines.push(`            block.recoveryPublicKeys(${pins(recovery)});`);
    if (o.scope) blockLines.push(`            block.serverScope(${L(api.id)});`);
    if (o.clientCa && d.clientCaPin) blockLines.push(`            block.clientCaPins(${L(d.clientCaPin)});`);
    if (enrollApi) blockLines.push(`            block.enrollmentUrl(${L(`https://${host}:${setupPort(enrollApi)}/`)});`);
    if (door) blockLines.push(`            block.renewalUrl(${L(`https://${host}:${setupRecoveryPort(d)}/`)});`);
    blockLines.push('            return Unit.INSTANCE;');
  } else {
    const hp = bootstrap.map((b, i) => `            HostPin(${L(b.host)}, listOf(${pins(b.pins)}))${i < bootstrap.length - 1 ? ',' : ''}   // ${b.note}`);
    blockLines.push(`        bootstrapPins(listOf(\n${hp.join('\n')}\n        ))`);
    if (keys.length) blockLines.push(`        signaturePublicKeys(${pins(keys)})`);
    else blockLines.push(`        allowUnsigned()   // the server has no signing key: not for production`);
    if (keys.length && d.requiredSignatures > 1) blockLines.push(`        requiredSignatures(${d.requiredSignatures})`);
    if (recovery.length) blockLines.push(`        recoveryPublicKeys(${pins(recovery)})`);
    if (o.scope) blockLines.push(`        serverScope(${L(api.id)})`);
    if (o.clientCa && d.clientCaPin) blockLines.push(`        clientCaPins(${L(d.clientCaPin)})`);
    if (enrollApi) blockLines.push(`        enrollmentUrl(${L(`https://${host}:${setupPort(enrollApi)}/`)})`);
    if (door) blockLines.push(`        renewalUrl(${L(`https://${host}:${setupRecoveryPort(d)}/`)})`);
  }

  const chain = [];
  const dot = java ? '        ' : '    ';
  if (caTrust.length) chain.push(`${dot}.requireCaTrust(${caTrust.map(L).join(', ')})`);
  if (offline > 0) chain.push(`${dot}.vaultFileMaxOfflineAge(${offline}${java ? 'L' : ''}, TimeUnit.DAYS)`);
  if (o.wipe) chain.push(`${dot}.wipeVaultFilesOnRevocation()`);
  if (o.unlocked) chain.push(`${dot}.requireUnlockedDevice()`);
  if (hours > 0) chain.push(`${dot}.updateIntervalHours(${hours}${java ? 'L' : ''})`);
  if (o.guard) {
    chain.push(java
      ? `${dot}// Your root / hooking detection (RASP, RootBeer). INIT stays allowed so pinned traffic keeps working.\n` +
        `${dot}.environmentGuard(operation -> operation == GuardedOperation.INIT || !DeviceShield.isCompromised())`
      : `${dot}// Your root / hooking detection (RASP, RootBeer). INIT stays allowed so pinned traffic keeps working.\n` +
        `${dot}.environmentGuard { operation -> operation == GuardedOperation.INIT || !DeviceShield.isCompromised() }`);
  }
  if (o.integrity) {
    chain.push(java
      ? `${dot}// Play Integrity, bound to the request; the server verifies it (INTEGRITY_VERIFICATION).\n` +
        `${dot}.integrityTokenProvider(requestHash -> {\n` +
        `${dot}    try {\n` +
        `${dot}        return Tasks.await(integrityProvider.request(StandardIntegrityTokenRequest.builder()\n` +
        `${dot}                .setRequestHash(requestHash).build()), 10, TimeUnit.SECONDS).token();\n` +
        `${dot}    } catch (Exception e) {\n` +
        `${dot}        return null;   // enrolls without; a server that enforces refuses\n` +
        `${dot}    }\n` +
        `${dot}})`
      : `${dot}// Play Integrity, bound to the request; the server verifies it (INTEGRITY_VERIFICATION).\n` +
        `${dot}.integrityTokenProvider { requestHash ->\n` +
        `${dot}    Tasks.await(\n` +
        `${dot}        integrityProvider.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()),\n` +
        `${dot}        10, TimeUnit.SECONDS\n` +
        `${dot}    ).token()\n` +
        `${dot}}`);
  }

  const date = new Date().toISOString().slice(0, 10);
  const header = `// PinVault configuration — setup wizard, ${date}, Config API "${api.id}" (${api.mode}).`;
  const importsKt = ['io.github.umutcansu.pinvault.PinVault', 'io.github.umutcansu.pinvault.model.*', 'java.util.concurrent.TimeUnit']
    .concat(o.integrity ? ['com.google.android.gms.tasks.Tasks', 'com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest'] : []);

  if (java) {
    const imports = importsKt.map(i => `import ${i};`).concat(['import java.util.Arrays;', 'import kotlin.Unit;']).join('\n');
    const enroll = mtls ? `\n\n// First start: enroll before init (an mTLS Config API needs the certificate).\n` +
      `// PinVault.enrollForResult(context, config, token) is a suspend function: call it from a small\n` +
      `// Kotlin helper (a coroutine) when PinVault.INSTANCE.isEnrolledWithConfig(context, config) is false,\n` +
      `// then init. README → "mTLS Enrollment".\n` : '\n';
    return `${header}\n${imports}\n\n` +
      `PinVaultConfig config = new PinVaultConfig.Builder()\n` +
      `        .configApi(${L(api.id)}, ${L(url)}, block -> {\n${blockLines.join('\n')}\n        })\n` +
      (chain.length ? chain.join('\n') + '\n' : '') +
      `        .build();\n` + enroll +
      `\nPinVault.INSTANCE.init(context, config, result -> {\n` +
      `    if (result instanceof InitResult.Ready) { /* pinned client: PinVault.INSTANCE.getClient() */ }\n` +
      `    return Unit.INSTANCE;\n` +
      `});\n`;
  }
  const imports = importsKt.map(i => `import ${i}`).join('\n');
  const enroll = mtls ? `\n// First start: enroll before init (an mTLS Config API needs the certificate).\n` +
    `if (!PinVault.isEnrolled(context, config)) {\n` +
    `    PinVault.enrollForResult(context, config, enrollmentToken)   // or autoEnrollForResult(context, config)\n` +
    `}\n` : '';
  return `${header}\n${imports}\n\n` +
    `val config = PinVaultConfig.Builder()\n` +
    `    .configApi(${L(api.id)}, ${L(url)}) {\n${blockLines.join('\n')}\n    }\n` +
    (chain.length ? chain.join('\n') + '\n' : '') +
    `    .build()\n` + enroll +
    `\nval result = PinVault.init(context, config)   // InitResult.Ready → PinVault.getClient()\n`;
}

/** [setupCode] for the iOS library (pinvault-ios, Swift package `PinVault`). */
function setupCodeSwift() {
  const d = setupData, o = setupOpts;
  const api = setupSelectedApi() || { id: 'default-tls', port: 443, mode: 'tls' };
  const host = setupHostOnly(o.host);
  const url = `https://${host}:${setupPort(api)}/`;
  const mtls = api.mode === 'mtls';
  const enrollApi = mtls ? (d.configApis || []).find(a => a.id === o.enrollApiId) : null;
  const door = mtls && o.recoveryDoor && d.recoveryPort != null && (d.recoveryPins || []).length > 0;
  const keys = o.signed ? (d.signingKeys || []) : [];
  const recovery = o.recovery ? (d.recoveryKeys || []) : [];
  const caTrust = String(o.caTrust || '').split(',').map(s => s.trim()).filter(Boolean);
  const offline = parseInt(o.offlineDays, 10);
  const hours = parseInt(o.updateHours, 10);
  const L = setupLiteral;
  const pins = (list) => list.map(L).join(', ');

  const bootstrap = [{ host, pins: d.bootstrapPins || [], note: 'Config API certificate' }];
  if (door) bootstrap.push({ host: `${host}:${setupRecoveryPort(d)}`, pins: d.recoveryPins, note: 'recovery door (server CA)' });
  const hp = bootstrap.map((b, i) => `            HostPin(hostname: ${L(b.host)}, sha256: [${pins(b.pins)}])${i < bootstrap.length - 1 ? ',' : ''}   // ${b.note}`);
  const blockLines = [`        block.bootstrapPins([\n${hp.join('\n')}\n        ])`];
  if (keys.length) blockLines.push(`        block.signaturePublicKeys(${pins(keys)})`);
  else blockLines.push(`        block.allowUnsigned()   // the server has no signing key: not for production`);
  if (keys.length && d.requiredSignatures > 1) blockLines.push(`        block.requiredSignatures(${d.requiredSignatures})`);
  if (recovery.length) blockLines.push(`        block.recoveryPublicKeys(${pins(recovery)})`);
  if (o.scope) blockLines.push(`        block.serverScope(${L(api.id)})`);
  if (o.clientCa && d.clientCaPin) blockLines.push(`        block.clientCaPins(${L(d.clientCaPin)})`);
  if (enrollApi) blockLines.push(`        block.enrollmentUrl(${L(`https://${host}:${setupPort(enrollApi)}/`)})`);
  if (door) blockLines.push(`        block.renewalUrl(${L(`https://${host}:${setupRecoveryPort(d)}/`)})`);

  const chain = [];
  const dot = '    ';
  if (caTrust.length) chain.push(`${dot}.requireCaTrust(${caTrust.map(L).join(', ')})`);
  if (offline > 0) chain.push(`${dot}.vaultFileMaxOfflineAge(${offline}, .days)`);
  if (o.wipe) chain.push(`${dot}.wipeVaultFilesOnRevocation()`);
  if (o.unlocked) chain.push(`${dot}.requireUnlockedDevice()`);
  if (hours > 0) chain.push(`${dot}.updateIntervalHours(${hours})`);
  if (o.guard) {
    chain.push(`${dot}// Your jailbreak / hooking detection (RASP). .start stays allowed so pinned traffic keeps working.\n` +
      `${dot}.environmentGuard { operation in operation == .start || !DeviceShield.isCompromised() }`);
  }
  if (o.integrity) {
    chain.push(`${dot}// App Attest, bound to the request; the server verifies it (INTEGRITY_VERIFICATION, APP_ATTEST_APP_IDS).\n` +
      `${dot}.integrityTokenProvider(AppAttestIntegrityTokenProvider())`);
  }

  const date = new Date().toISOString().slice(0, 10);
  const header = `// PinVault configuration — setup wizard, ${date}, Config API "${api.id}" (${api.mode}).\n` +
    `// Swift package: the PinVault repository (Package.swift at its root), product "PinVault".`;
  const enroll = mtls ? `\n// First start: enroll before start (an mTLS Config API needs the certificate).\n` +
    `if !PinVault.shared.isEnrolled(config: config) {\n` +
    `    _ = await PinVault.shared.enrollForResult(config: config, token: enrollmentToken)   // or autoEnrollForResult(config:)\n` +
    `}\n` : '';
  return `${header}\nimport PinVault\n\n` +
    `let config = try PinVaultConfig.Builder()\n` +
    `    .configApi(${L(api.id)}, url: ${L(url)}) { block in\n${blockLines.join('\n')}\n    }\n` +
    (chain.length ? chain.join('\n') + '\n' : '') +
    `    .build()\n` + enroll +
    `\n// At launch (application(_:didFinishLaunchingWithOptions:) or App.init): PinVault.shared.registerBackgroundTask()\n` +
    `let result = await PinVault.shared.start(config: config)   // .ready → PinVault.shared.session()\n`;
}
