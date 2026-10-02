// Ortak yollar ve ayarlar. Host değerleri sample-host/.env'den okunur;
// E2E_* ortam değişkenleri ile ezilebilir.
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const HOST_DIR = path.resolve(process.env.E2E_HOST_DIR || path.join(ROOT, '..', 'sample-host'));
const CLIENT_DIR = path.resolve(process.env.E2E_CLIENT_DIR || path.join(ROOT, '..', 'sample-client'));
/** Koşuya özel üretilen dosyalar (host değerleri, özel backend anahtarları); git dışı. */
const LOCAL_DIR = path.join(ROOT, '.local');
/**
 * Test edilen derleme. E2E_VARIANT=release: R8 ile küçültülmüş release
 * derlemesi (gerçek uygulamaların yayınladığı hâl); teşhis log'ları
 * -Psample.diagnosticLogs=true ile açılır, senaryolar log'lardan izler.
 */
const VARIANT = process.env.E2E_VARIANT === 'release' ? 'release' : 'debug';
const GRADLE_BUILD = VARIANT === 'release' ? ['assembleRelease', '-Psample.diagnosticLogs=true'] : ['assembleDebug'];

function readDotEnv(file) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

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
  HOST_DIR,
  CLIENT_DIR,
  LOCAL_DIR,
  API_KEY: process.env.E2E_API_KEY || hostEnv.API_KEY || '',
  /** Ana host'un anahtar depolarının parolası (dışa aktarılan JKS'leri geri yüklemek için). Gizli: panellere girmez. */
  KEYSTORE_PASSWORD: hostEnv.KEYSTORE_PASSWORD || 'changeit',
  WEB_URL: process.env.E2E_WEB_URL || `http://localhost:${hostEnv.HOST_HTTP_PORT || '6650'}`,
  HTTP_PORT: Number(hostEnv.HOST_HTTP_PORT || 6650),
  /** Yönetim API'sinin şifreli portu: telefonların raporları buraya gider. */
  MANAGEMENT_TLS_PORT: Number(hostEnv.HOST_MANAGEMENT_TLS_PORT || 6655),
  CONFIG_API_PORT: Number(hostEnv.HOST_HTTPS_PORT || 6651),
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
  /** Telefonların host'a ulaştığı IP; host'un kendi pin kaydı bu adla tutulur. */
  LAN_IP: hostEnv.HOST_LAN_IP || '',
  /** Host TLS sertifikasının pin'leri (birincil + yedek). */
  HOST_PINS_FILE: path.join(HOST_DIR, 'data/certs/demo-server.pins'),
  SIGNING_KEY_FILE: path.join(HOST_DIR, 'data/signing-key.pem'),
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
  CONTAINER: process.env.E2E_CONTAINER || 'pinvault-host',
  TARGET_HOST: process.env.E2E_TARGET_HOST || 'www.example.com',
  /** Uygulamanın vault dosyalarının ve telemetrisinin bağlı olduğu Config API. */
  VAULT_API: 'default-tls',
  /** scripts/provision.sh'ın açtığı mTLS Config API. */
  MTLS_API: 'sample-mtls',
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
  BUILD_COMMAND: `./gradlew ${GRADLE_BUILD.join(' ')}`,
  APK: path.join(CLIENT_DIR, `app/build/outputs/apk/${VARIANT}/app-${VARIANT}.apk`),
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
