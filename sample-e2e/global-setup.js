// Testlerden önce bir kez: host ayakta ve hazırlanmış mı, cihaz var mı,
// uygulama host değerleriyle derlenip kurulmuş mu, sunucu bilinen iyi durumda mı.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./lib/env');
const hostApi = require('./lib/hostApi');
const hostControl = require('./lib/hostControl');
const state = require('./lib/state');
const { Device } = require('./lib/android');
const customBackend = require('./lib/custom-backend');
const offlineKeys = require('./lib/offlineKeys');

function findJavaHome() {
  if (process.env.JAVA_HOME) return process.env.JAVA_HOME;
  const studio = '/Applications/Android Studio.app/Contents/jbr/Contents/Home';
  if (fs.existsSync(studio)) return studio;
  const jvms = path.join(os.homedir(), 'Library/Java/JavaVirtualMachines');
  if (!fs.existsSync(jvms)) return undefined;
  return fs
    .readdirSync(jvms)
    .filter((name) => name.includes('17'))
    .map((name) => path.join(jvms, name, 'Contents/Home'))
    .find((home) => fs.existsSync(home));
}

/**
 * Uygulamanın derlemeye gömeceği host değerleri (sample-host.properties).
 * Host'un kendi dosyalarından ve canlı hedef pin'lerinden üretilir; özel
 * backend değerleri harness'ın ürettiği anahtarlardan gelir.
 */
function writeProperties({ goodPins, hostPins, custom, signing, backup, recovery, door }) {
  const lines = [
    '# SamplePinVaultE2E global setup tarafından üretildi; elle düzenleme.',
    `host.ip=${env.LAN_IP}`,
    `host.httpPort=${env.HTTP_PORT}`,
    `host.managementTlsPort=${env.MANAGEMENT_TLS_PORT}`,
    `host.httpsPort=${env.CONFIG_API_PORT}`,
    `host.mtlsPort=${env.MTLS_API_PORT}`,
    `host.bootstrapPinPrimary=${hostPins[0]}`,
    `host.bootstrapPinBackup=${hostPins[1]}`,
    `host.signingPublicKey=${signing.publicKey}`,
    // İsteğe bağlı imza katmanları: sunucunun imzalayıcıları + çevrimdışı yedek
    // anahtar, ve anahtar setlerini (döndürme/iptal) doğrulayan kurtarma anahtarı.
    // Sunucu bir anahtar seti taşımadıkça davranışı değiştirmezler.
    `host.signingPublicKeys=${[...signing.signers.map((s) => s.publicKey), backup.pub].join(',')}`,
    'host.requiredSignatures=1',
    `host.recoveryPublicKeys=${recovery.pub}`,
    // Kurtarma kapısı: süresi dolmuş istemci sertifikası mTLS portuna giremez,
    // uygulama onu buradan (TLS, sunucu CA'sına pinli) yeniler.
    `host.recoveryPort=${door.caPins.length ? env.RECOVERY_PORT : ''}`,
    `host.recoveryPins=${door.caPins.join(',')}`,
    `target.host=${env.TARGET_HOST}`,
    `target.pins=${goodPins.join(',')}`,
    `mock.tlsHost=${env.MOCK_TLS_HOST}`,
    `mock.tlsPort=${env.MOCK_TLS_PORT}`,
    `mock.mtlsHost=${env.MOCK_MTLS_HOST}`,
    `mock.mtlsPort=${env.MOCK_MTLS_PORT}`,
    `custom.baseUrl=${custom.baseUrl}`,
    `custom.bootstrapPins=${custom.pins.join(',')}`,
    `custom.signingPublicKey=${custom.signingPublicKey}`,
    '',
  ];
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  const next = lines.join('\n');
  const changed = !fs.existsSync(env.PROPS_FILE) || fs.readFileSync(env.PROPS_FILE, 'utf8') !== next;
  if (changed) fs.writeFileSync(env.PROPS_FILE, next);
  return changed;
}

module.exports = async () => {
  // 1. Host: ayakta, anahtar geçerli, mTLS API, kendi pin kaydı ve mock host'lar hazır.
  if (!env.API_KEY) throw new Error(`API_KEY bulunamadı: ${env.HOST_DIR}/.env`);
  if (!env.LAN_IP) throw new Error(`HOST_LAN_IP bulunamadı: ${env.HOST_DIR}/.env`);
  if (!(await hostApi.isHealthy())) {
    // Önceki bir koşu container'ı durdurmuş olabilir; hiç kurulmamışsa docker hata verir.
    try {
      await hostControl.start({ requireMtls: false });
    } catch (e) {
      throw new Error(`Host'a ulaşılamıyor (${env.WEB_URL}). Önce: cd ${env.HOST_DIR} && docker compose up -d\n${e.message}`);
    }
  }
  const probe = await hostApi.api('/api/v1/connection-history');
  if (probe.status !== 200) throw new Error(`Host API anahtarını reddetti (HTTP ${probe.status}).`);
  hostApi.provision();

  // 2. Cihaz
  let serial = process.env.ANDROID_SERIAL || Device.connected()[0] || null;
  let booted = false;
  if (!serial && process.env.E2E_AVD) {
    console.log(`[e2e] Emülatör açılıyor: ${process.env.E2E_AVD}`);
    serial = (await Device.bootEmulator(process.env.E2E_AVD)).serial;
    booted = true;
  }
  if (!serial) {
    throw new Error('Bağlı Android cihaz yok. Telefonu USB ile bağla ya da E2E_AVD=<avd adı> ile çalıştır.');
  }
  const device = new Device(serial);
  device.disableAnimationsIfEmulator();

  // 3. Sunucunun temel durumu: hedefin canlı pin'leri, host'un ve mock host'ların pin'leri.
  const goodPins = await hostApi.livePins(env.TARGET_HOST);
  const hostPins = hostApi.hostPins();
  const cfg = await hostApi.getConfig();
  const pinsOf = (hostname) => (cfg.pins.find((p) => p.hostname === hostname) || {}).sha256;
  const baseline = { [env.TARGET_HOST]: goodPins, [env.LAN_IP]: hostPins };
  for (const mock of [env.MOCK_TLS_HOST, env.MOCK_MTLS_HOST]) {
    const pins = pinsOf(mock);
    if (!pins) throw new Error(`Mock host pin kaydı yok: ${mock} (scripts/provision.sh)`);
    baseline[mock] = pins;
  }

  // 4. Uygulama: host değerleri + özel backend anahtarlarıyla derle ve kur.
  const custom = customBackend.material();
  // İmza anahtarları dosyadan değil sunucudan: imzalayıcı bir HSM/KMS olabilir,
  // anahtar dosyası SIGNING_KEY_PASSWORD ile şifreli olabilir.
  const signingInfo = await hostApi.api('/api/v1/signing-key', { withKey: false });
  if (signingInfo.status !== 200 || !signingInfo.json || !signingInfo.json.publicKey) {
    throw new Error(`İmzalama anahtarları okunamadı: GET /api/v1/signing-key → HTTP ${signingInfo.status}`);
  }
  const signing = signingInfo.json;
  const backup = offlineKeys.ensure('backup-1');
  const recovery = offlineKeys.ensure('recovery-1');
  // Kapı kapalıysa ya da sunucu eskiyse (uç yok) uygulama kapısız derlenir.
  const doorInfo = await hostApi.api('/api/v1/recovery-door');
  const door = doorInfo.status === 200 && doorInfo.json && doorInfo.json.enabled ? doorInfo.json : { caPins: [] };
  const propsChanged = writeProperties({ goodPins, hostPins, custom, signing, backup, recovery, door });
  if (process.env.E2E_SKIP_BUILD !== '1' || propsChanged || !fs.existsSync(env.APK)) {
    console.log('[e2e] SamplePinVaultClient derleniyor…');
    const javaHome = findJavaHome();
    execFileSync('./gradlew', [...env.GRADLE_BUILD, '-q', `-PsampleHostProps=${env.PROPS_FILE}`], {
      cwd: env.CLIENT_DIR,
      stdio: 'inherit',
      timeout: 15 * 60 * 1000,
      env: { ...process.env, ...(javaHome ? { JAVA_HOME: javaHome } : {}) },
    });
  }
  if (!fs.existsSync(env.APK)) throw new Error(`APK bulunamadı: ${env.APK}`);
  device.adb(['install', '-r', '-t', env.APK]);

  await hostApi.restoreBaseline(baseline);

  state.write({
    serial,
    booted,
    goodPins,
    hostPins,
    lanIp: env.LAN_IP,
    baseline,
    custom: { baseUrl: custom.baseUrl, pins: custom.pins, signingPublicKey: custom.signingPublicKey },
    // APK'nın güvendiği imza anahtarlarının kimlikleri (telefon ekranındakilerle karşılaştırılır).
    signing: { primaryKeyId: signing.keyId, backupKeyId: backup.keyId, recoveryKeyId: recovery.keyId },
    model: device.prop('ro.product.model'),
    manufacturer: device.prop('ro.product.manufacturer'),
  });
  console.log(`[e2e] Hazır: cihaz ${serial}, hedef ${env.TARGET_HOST}`);
};
