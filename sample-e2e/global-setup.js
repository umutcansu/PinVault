// Testlerden önce bir kez: host ayakta ve hazırlanmış mı, cihaz var mı,
// uygulama host değerleriyle derlenip kurulmuş mu, sunucu bilinen iyi durumda mı.
// iOS koşusunda (E2E_PLATFORM=ios) cihaz simülatördür: açılır, UI sürücüsü
// (ios-driver) derlenip başlatılır, sample-client-ios derlenip kurulur.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./lib/env');
const hostApi = require('./lib/hostApi');
const hostControl = require('./lib/hostControl');
const state = require('./lib/state');
const { Device } = require('./lib/device');
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
 * Debug/e2e derlemelerini imzalayan anahtarın (`~/.android/debug.keystore`)
 * sertifika SHA-256'sı, 64 hane küçük harf hex. Android'de
 * host.expectedSignerSha256'ya yazılır: uygulama başka anahtarla imzalanmış
 * (yeniden paketlenmiş) bir kopyayı atestasyonda `app_integrity` ile bildirir
 * (R06). iOS'ta ve hesaplanamazsa '' (değer verilmez, istemci yargılamaz).
 */
function debugSignerSha256() {
  if (env.PLATFORM === 'ios') return '';
  try {
    const keystore = path.join(os.homedir(), '.android', 'debug.keystore');
    if (!fs.existsSync(keystore)) return '';
    const javaHome = findJavaHome();
    const keytool = javaHome ? path.join(javaHome, 'bin', 'keytool') : 'keytool';
    const out = execFileSync(
      keytool,
      ['-list', '-v', '-keystore', keystore, '-storepass', 'android', '-alias', 'androiddebugkey'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
    const m = out.match(/SHA256:\s*([0-9A-Fa-f:]+)/);
    return m ? m[1].replace(/:/g, '').toLowerCase() : '';
  } catch {
    return '';
  }
}

/**
 * Uygulamanın derlemeye gömeceği host değerleri (sample-host.properties).
 * Host'un kendi dosyalarından ve canlı hedef pin'lerinden üretilir; özel
 * backend değerleri harness'ın ürettiği anahtarlardan gelir.
 */
function writeProperties({ goodPins, hostPins, custom, signing, backup, recovery, door, clientCaPin, scoped, expectedSigner }) {
  const lines = [
    '# sample-e2e global setup tarafından üretildi; elle düzenleme.',
    `host.ip=${env.LAN_IP}`,
    // Telefon yönetim portlarını bilmez: raporları da Config API portuna gider.
    `host.httpsPort=${env.CONFIG_API_PORT}`,
    `host.mtlsPort=${env.MTLS_API_PORT}`,
    // Sunucudaki Config API kimlikleri: uygulama her bloğu kendi kimliğine bağlar
    // (serverScope); başka bir Config API için imzalanmış config kabul edilmez.
    // Sunucu imzalı config'e configApiId yazmıyorsa (scoped=false) bağlama yapılmaz:
    // yoksa uygulama hiçbir config'i kabul etmezdi.
    `host.tlsScope=${scoped ? env.VAULT_API : ''}`,
    `host.mtlsScope=${scoped ? env.MTLS_API : ''}`,
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
    // Cihaz sertifikalarını imzalayan istemci CA'sı: kayıtta ve yenilemede gelen zincir
    // bu CA'nın imzasını taşımalı (clientCaPins). Okunamadıysa boş (ilk zincire güvenilir).
    `host.clientCaPin=${clientCaPin || ''}`,
    `target.host=${env.TARGET_HOST}`,
    `target.pins=${goodPins.join(',')}`,
    // Hedefin sertifikası herkesin güvendiği bir CA'dan: uygulama pin'e ek olarak
    // sistemin CA onayını da ister (requireCaTrust). Kurum içi CA'lı bir hedef için
    // E2E_TARGET_REQUIRE_CA_TRUST=false.
    `target.requireCaTrust=${process.env.E2E_TARGET_REQUIRE_CA_TRUST === 'false' ? 'false' : 'true'}`,
    `mock.tlsHost=${env.MOCK_TLS_HOST}`,
    `mock.tlsPort=${env.MOCK_TLS_PORT}`,
    `mock.mtlsHost=${env.MOCK_MTLS_HOST}`,
    `mock.mtlsPort=${env.MOCK_MTLS_PORT}`,
    `custom.baseUrl=${custom.baseUrl}`,
    `custom.bootstrapPins=${custom.pins.join(',')}`,
    `custom.signingPublicKey=${custom.signingPublicKey}`,
    // Yeniden paketleme tespiti (R06): APK'yı imzalayan debug anahtarının SHA-256'sı.
    // Boşsa istemci app_integrity'yi yargılamaz.
    `host.expectedSignerSha256=${expectedSigner || ''}`,
    '',
  ];
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  const next = lines.join('\n');
  const changed = !fs.existsSync(env.PROPS_FILE) || fs.readFileSync(env.PROPS_FILE, 'utf8') !== next;
  if (changed) fs.writeFileSync(env.PROPS_FILE, next);
  return changed;
}

/**
 * Hedef host üretim profilinde mi (.env → SAMPLE_PROFILE ya da setup.sh
 * --production'ın bıraktığı data/.sample-profile)? Testler sunucunun
 * sertifikasını, imza anahtarını ve verisini değiştirir, test anahtarları açar:
 * üretim kurulumuna karşı hiç çalışmamalı.
 */
function hostProfile() {
  let profile = '';
  try {
    for (const line of fs.readFileSync(path.join(env.HOST_DIR, '.env'), 'utf8').split('\n')) {
      const m = line.match(/^\s*SAMPLE_PROFILE\s*=\s*(.*?)\s*$/);
      if (m) profile = m[1].replace(/^["']|["']$/g, '');
    }
  } catch {
    // .env yoksa aşağıdaki API_KEY denetimi durdurur.
  }
  try {
    const marker = fs.readFileSync(path.join(env.HOST_DIR, 'data/.sample-profile'), 'utf8').trim();
    if (marker === 'production') profile = 'production';
  } catch {
    // işaret dosyası yalnızca üretim kurulumunda var
  }
  return profile || 'demo';
}

module.exports = async () => {
  // 0. Üretim kurulumuna karşı asla.
  if (hostProfile() === 'production') {
    throw new Error(
      `Hedef host üretim profilinde (${env.HOST_DIR}: SAMPLE_PROFILE=production). Uçtan uca testler ` +
        'sunucunun sertifikasını, imza anahtarını ve verisini değiştirir ve test anahtarları açar; üretim ' +
        'kurulumuna karşı çalıştırılmaz. Demo profilli ayrı bir host kur ya da E2E_HOST_DIR ile onu göster.',
    );
  }

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
  let serial;
  let booted = false;
  let device;
  if (env.PLATFORM === 'ios') {
    // Yalnızca bu koşuya ayrılmış simülatör (E2E_IOS_UDID): verisi ve Keychain'i silinir.
    console.log(`[e2e] iOS simülatörü: ${env.IOS_UDID}`);
    ({ device, booted } = Device.boot(env.IOS_UDID));
    serial = env.IOS_UDID;
    const iosDriver = require('./lib/iosDriver');
    console.log('[e2e] iOS UI sürücüsü (ios-driver) derleniyor…');
    console.log(iosDriver.build({ udid: serial }));
    iosDriver.start({ udid: serial });
  } else {
    serial = process.env.ANDROID_SERIAL || Device.connected()[0] || null;
    if (!serial && process.env.E2E_AVD) {
      console.log(`[e2e] Emülatör açılıyor: ${process.env.E2E_AVD}`);
      serial = (await Device.bootEmulator(process.env.E2E_AVD)).serial;
      booted = true;
    }
    if (!serial) {
      throw new Error('Bağlı Android cihaz yok. Telefonu USB ile bağla ya da E2E_AVD=<avd adı> ile çalıştır.');
    }
    device = new Device(serial);
  }
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
  const clientCaPin = hostApi.clientCaPin();
  if (!clientCaPin) console.warn('[e2e] UYARI: istemci CA\'sının pin\'i okunamadı; uygulama clientCaPins olmadan derleniyor.');
  // serverScope yalnızca sunucu imzalı config'e configApiId (ve vault'a X-Vault-Signature-V2)
  // yazıyorsa: yazmayan bir sunucuyla bağlı uygulama hiçbir config'i kabul etmez.
  const signedNow = await hostApi.signedConfig();
  const scoped = signedNow.config.configApiId === env.VAULT_API;
  if (!scoped) {
    console.warn(
      `[e2e] UYARI: sunucunun imzalı config'inde configApiId ${signedNow.config.configApiId ? `"${signedNow.config.configApiId}"` : 'yok'}; ` +
        'uygulama serverScope olmadan derleniyor (host.tlsScope/host.mtlsScope boş).',
    );
  }
  const propsChanged = writeProperties({ goodPins, hostPins, custom, signing, backup, recovery, door, clientCaPin, scoped, expectedSigner: debugSignerSha256() });
  if (env.PLATFORM === 'ios') {
    if (process.env.E2E_SKIP_BUILD !== '1' || propsChanged || !fs.existsSync(env.APP_ARTIFACT)) {
      console.log(`[e2e] sample-client-ios derleniyor (${env.IOS_CONFIGURATION})…`);
      console.log(require('./lib/iosBuild').build(env.PROPS_FILE));
    }
    if (!fs.existsSync(env.APP_ARTIFACT)) throw new Error(`Uygulama bulunamadı: ${env.APP_ARTIFACT}`);
    // Yüklemenin üstüne kurar: uygulama silinmez (identifierForVendor değişmesin).
    console.log(device.installApp(env.APP_ARTIFACT));
  } else if (process.env.E2E_SKIP_BUILD !== '1' || propsChanged || !fs.existsSync(env.APK)) {
    console.log('[e2e] sample-client derleniyor…');
    const javaHome = findJavaHome();
    execFileSync('./gradlew', [...env.GRADLE_BUILD, '-q', `-PsampleHostProps=${env.PROPS_FILE}`], {
      cwd: env.CLIENT_DIR,
      stdio: 'inherit',
      timeout: 15 * 60 * 1000,
      env: { ...process.env, ...(javaHome ? { JAVA_HOME: javaHome } : {}) },
    });
  }
  if (env.PLATFORM === 'android') {
    if (!fs.existsSync(env.APK)) throw new Error(`APK bulunamadı: ${env.APK}`);
    device.adb(['install', '-r', '-t', env.APK]);
  }

  await hostApi.restoreBaseline(baseline);

  state.write({
    platform: env.PLATFORM,
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
    ...(env.PLATFORM === 'ios' ? { deviceName: device.name(), osVersion: device.osVersion() } : {}),
  });
  console.log(`[e2e] Hazır: ${env.PLATFORM === 'ios' ? 'simülatör' : 'cihaz'} ${serial}, hedef ${env.TARGET_HOST}`);
};
