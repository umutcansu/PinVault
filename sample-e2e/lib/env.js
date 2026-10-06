// Ortak yollar ve ayarlar. Host değerleri sample-host/.env'den okunur;
// E2E_* ortam değişkenleri ile ezilebilir.
//
// Platform: E2E_PLATFORM=android (varsayılan, adb + UI Automator) ya da ios
// (simülatör + lib/ios.js). iOS koşusunda sample-e2e/.env.ios varsa (git dışı;
// örneği .env.ios.example) içindeki değerler, ortamda verilmemiş olanlar için
// process.env'e yazılır: portlar ve host dizini başka bir oturumun Android
// koşusuyla çakışmasın diye orada tutulur.
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PLATFORM = process.env.E2E_PLATFORM === 'ios' ? 'ios' : 'android';

function readDotEnv(file) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

if (PLATFORM === 'ios') {
  for (const [key, value] of Object.entries(readDotEnv(path.join(ROOT, '.env.ios')))) {
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

const HOST_DIR = path.resolve(process.env.E2E_HOST_DIR || path.join(ROOT, '..', 'sample-host'));
/** Android örnek uygulaması (Gradle) ve iOS örnek uygulaması (XcodeGen + xcodebuild). */
const ANDROID_CLIENT_DIR = path.resolve(
  (PLATFORM === 'android' && process.env.E2E_CLIENT_DIR) || path.join(ROOT, '..', 'sample-client'),
);
const IOS_CLIENT_DIR = path.resolve(
  process.env.E2E_IOS_CLIENT_DIR || (PLATFORM === 'ios' && process.env.E2E_CLIENT_DIR) || path.join(ROOT, '..', 'sample-client-ios'),
);
const CLIENT_DIR = PLATFORM === 'ios' ? IOS_CLIENT_DIR : ANDROID_CLIENT_DIR;
/** Koşuya özel üretilen dosyalar (host değerleri, özel backend anahtarları); git dışı. */
const LOCAL_DIR = path.join(ROOT, '.local');
/**
 * Test edilen derleme türü (sample-client/app/build.gradle.kts):
 *   debug (varsayılan) : geliştirme derlemesi.
 *   e2e                : release'in aynısı (R8 ile küçültülmüş, aynı keep
 *                        kuralları, aynı paket adı) + test kontrolleri, debug
 *                        anahtarıyla imzalı. E2E_VARIANT=e2e ile seçilir;
 *                        teşhis log'ları -Psample.diagnosticLogs=true ile açılır.
 * Gerçek `release` türü burada KULLANILMAZ: test kontrolleri (Ayarlar, Depolama,
 * mode eki, otomatik kayıt, elle P12) onda yoktur, test bayraklarıyla
 * derlenmez ve gerçek imza anahtarı ister. E2E_VARIANT=release eski adıdır;
 * e2e sayılır.
 */
const VARIANT = ['e2e', 'release'].includes(process.env.E2E_VARIANT) ? 'e2e' : 'debug';
/**
 * -Psample.e2eScreenshots=true: uygulamanın bütün ekranları normalde
 * FLAG_SECURE ile ekran görüntüsüne kapalı (siyah çıkar). Kanıt sayfası her
 * adımın görüntüsünü istediği için yalnızca test derlemeleri bunu kapatır
 * (release türü bu bayrakla derlenmez).
 */
const GRADLE_BUILD = VARIANT === 'e2e'
  ? ['assembleE2e', '-Psample.diagnosticLogs=true', '-Psample.e2eScreenshots=true']
  : ['assembleDebug', '-Psample.e2eScreenshots=true'];

// ── iOS ────────────────────────────────────────────────────────────────────
/** iOS koşusunun simülatörü (yalnızca bu koşuya ayrılmış olmalı: veri ve Keychain silinir). */
const IOS_UDID = process.env.E2E_IOS_UDID || '1D7D6D18-E5B5-4997-A5BD-459A4A2DFB62';
/**
 * sample-client-ios derleme yapılandırması: Debug (test kontrolleri) ya da
 * E2E (Release optimizasyonu + test kontrolleri + teşhis log'ları); Android'in
 * debug / e2e türlerinin karşılığı (E2E_VARIANT).
 */
const IOS_CONFIGURATION = VARIANT === 'e2e' ? 'E2E' : 'Debug';
const IOS_PROJECT = path.join(IOS_CLIENT_DIR, 'SampleClient.xcodeproj');
const IOS_SCHEME = process.env.E2E_IOS_SCHEME || 'SampleClient';
const IOS_DERIVED_DIR = path.join(LOCAL_DIR, 'ios-derived');
const IOS_APP = path.join(
  IOS_DERIVED_DIR,
  `Build/Products/${IOS_CONFIGURATION}-iphonesimulator/${process.env.E2E_IOS_APP_NAME || 'SampleClient'}.app`,
);
/** xcodebuild argümanları (cwd: sample-client-ios); host değerleri SAMPLE_HOST_PROPS ortam değişkeniyle. */
const IOS_BUILD = [
  '-project', path.basename(IOS_PROJECT),
  '-scheme', IOS_SCHEME,
  '-configuration', IOS_CONFIGURATION,
  '-sdk', 'iphonesimulator',
  '-destination', `platform=iOS Simulator,id=${IOS_UDID}`,
  '-derivedDataPath', IOS_DERIVED_DIR,
  'build',
];
const IOS_BUILD_DISPLAY = [
  'xcodebuild',
  ...IOS_BUILD.map((a) => (a === IOS_DERIVED_DIR ? path.relative(IOS_CLIENT_DIR, a) : /\s|=/.test(a) ? `'${a}'` : a)),
].join(' ');

/** Derleme komutu: kanıt panellerinde gösterilir. */
const BUILD_COMMAND = PLATFORM === 'ios' ? IOS_BUILD_DISPLAY : `./gradlew ${GRADLE_BUILD.join(' ')}`;

/**
 * Derleme komutu + host değerleri dosyası, panelde görüneceği gibi.
 * Android: `./gradlew … -PsampleHostProps=<dosya>`; iOS: `SAMPLE_HOST_PROPS=<dosya> xcodebuild …`.
 */
function buildCommandFor(propsFile) {
  return PLATFORM === 'ios' ? `SAMPLE_HOST_PROPS=${propsFile} ${BUILD_COMMAND}` : `${BUILD_COMMAND} -PsampleHostProps=${propsFile}`;
}

/**
 * Yalnızca Android'de koşan senaryolar (dosya adı öneki → neden). fixtures.js
 * iOS koşusunda bunları atlar; senaryo dosyalarına dokunulmaz.
 */
const ANDROID_ONLY_TESTS = {
  D05: 'Yedekleme kanıtı Android\'in bmgr yerel yedekleme aktarıcısıyla alınıyor; iOS karşılığı (isExcludedFromBackup, ThisDeviceOnly) I grubunda',
  U01: 'Sürüm yükseltme Maven Central\'daki PinVault 2.0.9 ile derlenen eski APK\'dan yapılıyor; iOS kütüphanesinin önceki sürümü yok',
};

function androidSdk() {
  const candidates = [
    process.env.ANDROID_HOME,
    process.env.ANDROID_SDK_ROOT,
    path.join(os.homedir(), 'Library/Android/sdk'),
    path.join(os.homedir(), 'Android/Sdk'),
  ].filter(Boolean);
  return candidates.find((p) => fs.existsSync(p)) || null;
}

const hostEnv = readDotEnv(path.join(HOST_DIR, '.env'));
const SDK = androidSdk();

module.exports = {
  ROOT,
  /** 'android' (varsayılan) ya da 'ios' (E2E_PLATFORM). */
  PLATFORM,
  HOST_DIR,
  /** Test edilen platformun örnek uygulaması: sample-client ya da sample-client-ios. */
  CLIENT_DIR,
  ANDROID_CLIENT_DIR,
  IOS_CLIENT_DIR,
  LOCAL_DIR,
  API_KEY: process.env.E2E_API_KEY || hostEnv.API_KEY || '',
  /** Ana host'un anahtar depolarının parolası (dışa aktarılan JKS'leri geri yüklemek için). Gizli: panellere girmez. */
  KEYSTORE_PASSWORD: hostEnv.KEYSTORE_PASSWORD || 'changeit',
  WEB_URL: process.env.E2E_WEB_URL || `http://localhost:${hostEnv.HOST_HTTP_PORT || '6650'}`,
  HTTP_PORT: Number(hostEnv.HOST_HTTP_PORT || 6650),
  /** Yönetim API'sinin şifreli portu (başka makineden dashboard). Telefonlar bu porta bağlanmaz. */
  MANAGEMENT_TLS_PORT: Number(hostEnv.HOST_MANAGEMENT_TLS_PORT || 6655),
  CONFIG_API_PORT: Number(hostEnv.HOST_HTTPS_PORT || 6651),
  /**
   * Telefonların raporlarının (telemetri) gittiği port: Config API portu.
   * Uygulama raporları config'le aynı dinleyiciye, aynı pin'lerle gönderir.
   */
  REPORT_PORT: Number(hostEnv.HOST_HTTPS_PORT || 6651),
  MTLS_API_PORT: Number(hostEnv.HOST_MTLS_PORT || 6652),
  MOCK_TLS_PORT: Number(hostEnv.HOST_MOCK_TLS_PORT || 6653),
  MOCK_MTLS_PORT: Number(hostEnv.HOST_MOCK_MTLS_PORT || 6654),
  RECOVERY_PORT: Number(hostEnv.HOST_RECOVERY_PORT || 6656),
  /** Host'taki mock hedef host'ların adları; uygulama bunları host IP'sine çözümler. */
  MOCK_TLS_HOST: 'mock-tls.sample',
  MOCK_MTLS_HOST: 'mock-mtls.sample',
  /** Harness'ın Mac'te açtığı servisler: kurcalama vekili ve özel backend. */
  PROXY_PORT: Number(process.env.E2E_PROXY_PORT || 6661),
  /** Güvenlik bildirimlerini yakalayan webhook alıcısı (lib/webhookSink.js). */
  WEBHOOK_PORT: Number(process.env.E2E_WEBHOOK_PORT || 6662),
  CUSTOM_BACKEND_PORT: Number(process.env.E2E_CUSTOM_BACKEND_PORT || 6660),
  /**
   * iOS: iptables DROP'un karşılığı. Bağlantıyı kabul edip hiç yanıt vermeyen
   * TCP sunucusu (lib/blackhole.js); "drop" kuralı trafiği buraya yönlendirir.
   */
  BLACKHOLE_PORT: Number(process.env.E2E_BLACKHOLE_PORT || 6663),
  /** iOS: iptables REJECT'in karşılığı. 127.0.0.1'de kimsenin dinlemediği port (bağlantı hemen reddedilir). */
  CLOSED_PORT: Number(process.env.E2E_CLOSED_PORT || 9),
  /** iOS UI sürücüsünün (ios-driver, XCUITest) 127.0.0.1'de dinlediği port. */
  IOS_DRIVER_PORT: Number(process.env.E2E_IOS_DRIVER_PORT || 6870),
  /**
   * Geçici test sunucusunun (lib/freshHost.js) port tabanı (taban … taban+6),
   * compose projesi ve container adı. Aynı makinede ikinci bir koşu (ör. iOS)
   * bunları değiştirir.
   */
  FRESH_PORT_BASE: Number(process.env.E2E_FRESH_PORT_BASE || 6750),
  FRESH_PROJECT: process.env.E2E_FRESH_PROJECT || 'pinvault-fresh',
  FRESH_CONTAINER: process.env.E2E_FRESH_CONTAINER || 'pinvault-host-fresh',
  /** Telefonların host'a ulaştığı IP; host'un kendi pin kaydı bu adla tutulur. */
  LAN_IP: hostEnv.HOST_LAN_IP || '',
  /** Host TLS sertifikasının pin'leri (birincil + yedek). */
  HOST_PINS_FILE: path.join(HOST_DIR, 'data/certs/demo-server.pins'),
  SIGNING_KEY_FILE: path.join(HOST_DIR, 'data/signing-key.pem'),
  /**
   * Ana host'un imzalama anahtarı dosyasının parolası (.env → SIGNING_KEY_PASSWORD;
   * setup.sh demo profilinde de üretir). Dosya diskte "ENCv1:" ile şifrelidir;
   * lib/signingKeyFile.js bununla açar. Gizli: panellere girmez.
   */
  SIGNING_KEY_PASSWORD: hostEnv.SIGNING_KEY_PASSWORD || '',
  /**
   * Harness'ın çevrimdışı anahtarları (yedek, kurtarma, ek imzalayıcılar);
   * lib/offlineKeys.js. Host'un signing-keys.sh betiği OFFLINE_KEYS_DIR ile
   * buraya yönlendirilir.
   */
  OFFLINE_KEYS_DIR: path.join(LOCAL_DIR, 'offline-keys'),
  /**
   * Sunucunun SQLite veritabanı. Container'ın /data dizini Mac'e bind-mount
   * edildiği için dosya doğrudan okunabilir (container'da sqlite3 yok).
   * Vault blob'unun diskte şifreli durduğunu göstermek için kullanılır.
   */
  DB_FILE: path.join(HOST_DIR, 'data/db/pinvault.db'),
  /** scripts/export-server-key.sh çıktısı (kurcalama vekili için). */
  PROXY_KEY_FILE: path.join(HOST_DIR, 'data/proxy/server-key.pem'),
  PROXY_CERT_FILE: path.join(HOST_DIR, 'data/proxy/server-cert.pem'),
  /** Host container'ı: E2E_CONTAINER, yoksa host .env'indeki HOST_CONTAINER_NAME, yoksa pinvault-host. */
  CONTAINER: process.env.E2E_CONTAINER || hostEnv.HOST_CONTAINER_NAME || 'pinvault-host',
  /**
   * Hedefin sertifikası herkesin güvendiği bir CA'dan değilse
   * (E2E_TARGET_REQUIRE_CA_TRUST=false) host'un client-config.sh betiğine
   * verilecek ek argüman; betik onsuz doğrulanmayan bir zincirden pin almaz.
   */
  CLIENT_CONFIG_ARGS: process.env.E2E_TARGET_REQUIRE_CA_TRUST === 'false'
    ? ['--properties', '--target-private-ca']
    : ['--properties'],
  /** Uygulamanın pin'lediği gerçek site: sample-host/.env'deki TARGET_HOST. */
  TARGET_HOST: process.env.E2E_TARGET_HOST || hostEnv.TARGET_HOST || 'www.example.com',
  /**
   * Uygulamanın vault dosyalarının ve telemetrisinin bağlı olduğu Config API.
   * Uygulamanın TLS bloğu bu kimliğe bağlıdır (host.tlsScope → serverScope).
   */
  VAULT_API: 'default-tls',
  /** scripts/provision.sh'ın açtığı mTLS Config API. */
  MTLS_API: 'sample-mtls',
  /**
   * Gizli vault dosyalarının (secret, e2e, mtlsSecret) bulunduğu Config API.
   * Uygulama onları mTLS bloğunda, token_mtls ve ekran kilidiyle tanımlar;
   * yalnızca cihaz mTLS'e kayıtlıyken (lib/secureVault.js).
   */
  SECURE_VAULT_API: 'sample-mtls',
  /** Gizli dosya senaryolarının emülatöre geçici koyduğu ekran kilidi PIN'i. */
  SCREEN_LOCK_PIN: process.env.E2E_SCREEN_LOCK_PIN || '1357',
  /** Uygulamanın "Aç" düğmesindeki kilit sorusunun başlığı (strings.xml: vault_unlock_prompt_title). */
  UNLOCK_PROMPT_TITLE: 'Gizli dosyayı aç',
  /** Uygulamanın tanıdığı vault anahtarları (App.java). */
  VAULT_KEYS: {
    flags: 'sample-flags',
    secret: 'sample-secret',
    e2e: 'sample-e2e',
    atrest: 'sample-atrest',
    admin: 'sample-admin',
    model: 'sample-model',
    mtlsSecret: 'sample-mtls-secret',
  },
  /** Uygulamanın çalışma modları (AppSettings.Mode). */
  MODES: ['TLS', 'MTLS_CONFIG', 'CUSTOM_BACKEND', 'EMBEDDED_API', 'STATIC'],
  APP_ID: 'com.example.sampleclient',
  VARIANT,
  /** Uygulamayı derleyen Gradle görevi ve argümanları; kanıtta `BUILD_COMMAND` gösterilir. */
  GRADLE_BUILD,
  BUILD_COMMAND,
  buildCommandFor,
  /** Derleme çıktısında başarıyı gösteren satır (Gradle / xcodebuild). */
  BUILD_OK_REGEX: PLATFORM === 'ios' ? /\*\* BUILD SUCCEEDED \*\*/ : /BUILD SUCCESSFUL/,
  /** Kurulum çıktısında başarıyı gösteren satır (adb install / lib/ios.js installApp). */
  INSTALL_OK_REGEX: PLATFORM === 'ios' ? /Kuruldu: / : /Success/,
  APK: path.join(ANDROID_CLIENT_DIR, `app/build/outputs/apk/${VARIANT}/app-${VARIANT}.apk`),
  /** Test edilen platformun derleme çıktısı: APK dosyası ya da .app dizini. */
  APP_ARTIFACT: PLATFORM === 'ios' ? IOS_APP : path.join(ANDROID_CLIENT_DIR, `app/build/outputs/apk/${VARIANT}/app-${VARIANT}.apk`),
  APP_ARTIFACT_EXT: PLATFORM === 'ios' ? '.app' : '.apk',
  IOS_UDID,
  IOS_CONFIGURATION,
  IOS_PROJECT,
  IOS_SCHEME,
  IOS_DERIVED_DIR,
  IOS_APP,
  IOS_BUILD,
  ANDROID_ONLY_TESTS,
  /** Derlemeye verilen host değerleri; global setup üretir. */
  PROPS_FILE: path.join(LOCAL_DIR, 'sample-host.properties'),
  ADB: process.env.ADB || (SDK ? path.join(SDK, 'platform-tools/adb') : 'adb'),
  EMULATOR: SDK ? path.join(SDK, 'emulator/emulator') : 'emulator',
  /** En yeni build-tools'taki aapt2 (APK'nın kaynak tablosunu okumak için). */
  AAPT2: (() => {
    const dir = SDK && path.join(SDK, 'build-tools');
    if (!dir || !fs.existsSync(dir)) return 'aapt2';
    const versions = fs.readdirSync(dir).filter((v) => fs.existsSync(path.join(dir, v, 'aapt2'))).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    return versions.length ? path.join(dir, versions[versions.length - 1], 'aapt2') : 'aapt2';
  })(),
  STATE_FILE: path.join(ROOT, '.e2e-state.json'),
};
