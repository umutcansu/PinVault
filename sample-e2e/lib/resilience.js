// Dayanıklılık (R grubu) senaryoları için ortak yardımcılar: atestasyon
// politikasını okuma/yazma, cihaz kaydını okuma ve cihaza bir güvenlik
// aracı (debugger, Frida) iliştirme.
//
// Bu testler kütüphanenin KENDİ tespit kodunun (integrity/Probes.kt) çalışıp
// çalışmadığını doğrular: root'lu / hooking yapılmış / hata ayıklanan bir
// cihazda ilgili sinyalin yükseldiğini, host politikası onu reddedince
// telefonun token alamadığını ve token isteyen mock host'un isteği 401 ile
// geri çevirdiğini gösterir. Hepsi tek kullanımlık emülatörde yapılır; gerçek
// telefon root'lanmaz.
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { execFileSync } = require('child_process');
const hostApi = require('./hostApi');
const env = require('./env');

/**
 * Atestasyon politikasının bütün bayraklarını "uyarı"ya çeken temel durum:
 * emülatörde zaten yükselen sinyaller (emulator, debuggable, software_key,
 * key_unattested, unknown_installer) tek başına reddetmesin diye. Bir senaryo
 * yalnızca ölçtüğü sinyali (ör. rooted, debugger) "reject" yapıp onu izole eder.
 */
const LENIENT = {
  rooted: 'warn',
  emulator: 'warn',
  debugger: 'warn',
  debuggable: 'warn',
  hooking_framework: 'warn',
  app_integrity: 'warn',
  cloner: 'warn',
  unknown_installer: 'warn',
  adb_enabled: 'ignore',
  software_key: 'warn',
  key_unattested: 'warn',
  old_patch_level: 'warn',
  play_integrity: 'warn',
  play_integrity_missing: 'warn',
};

const policyPath = (scope) => `/api/v1/config-apis/${scope}/attestation/policy`;
const devicePath = (scope, deviceId) =>
  `/api/v1/config-apis/${scope}/attestation/devices/${encodeURIComponent(deviceId)}`;

/** Kapsamın atestasyon politikasını okur. */
async function getPolicy(scope) {
  const res = await hostApi.api(policyPath(scope));
  if (res.status !== 200) throw new Error(`politika okunamadı: HTTP ${res.status} ${res.text}`);
  return res.json;
}

/**
 * Politikayı okur, `flags` içindeki değerleri (ve `extra` alanlarını) üstüne
 * yazıp geri gönderir. Önceki değeri döndürür ki test sonunda geri yüklenebilsin.
 */
async function setPolicy(scope, flags, extra = {}) {
  const current = await getPolicy(scope);
  const next = { ...current, ...extra, flags: { ...current.flags, ...flags } };
  const res = await hostApi.api(policyPath(scope), { method: 'PUT', body: next });
  if (res.status !== 200) throw new Error(`politika yazılamadı: HTTP ${res.status} ${res.text}`);
  return res.json;
}

/** Bu telefonun son atestasyon kaydı (cihaz kimliğine göre), yoksa null. */
async function deviceRecord(scope, deviceId) {
  const res = await hostApi.api(devicePath(scope, deviceId));
  return res.status === 200 ? res.json : null;
}

/** Cihazın yönetici ek açıklamalarını (forcePass/forceFail/annotations) sıfırlar. */
async function clearDeviceOverrides(scope, deviceId) {
  await hostApi
    .api(devicePath(scope, deviceId), {
      method: 'PUT',
      body: { forcePass: false, forceFail: false, annotations: [] },
    })
    .catch(() => {});
}

/** Bir cihaz kaydının reddi gerekçelerini (lastReasons/rejectionReasons) tek listede verir. */
function reasonsOf(record) {
  if (!record) return [];
  return record.rejectionReasons || record.lastReasons || [];
}

/** Bir cihaz kaydının uyarılarını tek listede verir. */
function warningsOf(record) {
  return (record && (record.warnings || record.lastWarnings)) || [];
}

// ── Hata ayıklayıcı (debugger) iliştirme ───────────────────────────────────

/**
 * Debuggable uygulamanın sürecine ham bir JDWP hata ayıklayıcısı bağlar:
 * JDWP soketi yerele yönlendirilir, "JDWP-Handshake" yapılır ve soket açık
 * tutulur. Bu, `Debug.isDebuggerConnected()`'ı true yapar (DebuggerProbe
 * `debugger` sinyalini yükseltir) ama HİÇBİR thread'i askıya almaz — jdb'nin
 * aksine (jdb'nin varsayılan exception catchpoint'leri uygulamayı ağ çağrısı
 * sırasında dondurup bağlantıyı kırıyordu). Dönen fonksiyon soketi kapatıp
 * yönlendirmeyi kaldırır.
 */
async function attachDebugger(device, pkg, { port = 8700 } = {}) {
  const pid = device.shell(`su 0 pidof ${pkg}`).trim().split(/\s+/)[0];
  if (!pid) throw new Error(`${pkg} çalışmıyor: debugger bağlanamaz`);
  device.adb(['forward', `tcp:${port}`, `jdwp:${pid}`]);

  const socket = await new Promise((resolve, reject) => {
    const s = net.connect({ host: 'localhost', port }, () => s.write('JDWP-Handshake'));
    let got = Buffer.alloc(0);
    s.on('data', (chunk) => {
      got = Buffer.concat([got, chunk]);
      if (got.length < 14) return;
      if (got.slice(0, 14).toString('ascii') !== 'JDWP-Handshake') {
        reject(new Error(`beklenmeyen JDWP el sıkışma yanıtı: ${got.slice(0, 14).toString('ascii')}`));
        return;
      }
      // Oturumu tam kurmak için bir VirtualMachine.Version komutu gönder (askıya
      // almaz), sonra boşta bekle; yanıt umursanmaz.
      s.removeAllListeners('data');
      s.on('data', () => {});
      s.write(Buffer.from([0, 0, 0, 11, 0, 0, 0, 1, 0, 1, 1]));
      resolve(s);
    });
    s.on('error', reject);
    setTimeout(() => reject(new Error('JDWP el sıkışması zaman aşımı')), 8000);
  });
  socket.on('error', () => {});

  return async function detach() {
    try {
      socket.destroy();
    } catch {
      /* no-op */
    }
    try {
      device.adb(['forward', '--remove', `tcp:${port}`]);
    } catch {
      /* no-op */
    }
  };
}

// ── Kök (root) yönetici paketi iliştirme ───────────────────────────────────

/**
 * Bir kök yöneticisinin paket adı (RootProbe.ROOT_PACKAGES'ten; kütüphane
 * manifestindeki <queries> ile Android 11+'da görünür). Root'lu bir
 * kullanıcıda tipik olarak kuruludur.
 */
const ROOT_MANAGER_PACKAGE = 'com.topjohnwu.magisk';

/**
 * RootProbe'un `package:` kanıtını deterministik biçimde tetiklemek için
 * paket adı bir kök yöneticisininkiyle aynı olan boş bir stub APK üretir
 * (yoksa SDK ile derler) ve yolunu döndürür. SELinux enforcing altında
 * su ikililerini stat edemeyen bir uygulamanın da gördüğü sinyal budur.
 */
function ensureRootManagerStub() {
  const dir = path.join(env.LOCAL_DIR, 'stubs');
  const apk = path.join(dir, 'magisk-stub.apk');
  if (fs.existsSync(apk)) return apk;
  fs.mkdirSync(dir, { recursive: true });

  const sdk = androidSdk();
  if (!sdk) throw new Error('Android SDK bulunamadı: kök yöneticisi stub\'ı derlenemiyor');
  const bt = latestDir(path.join(sdk, 'build-tools'));
  const platform = latestDir(path.join(sdk, 'platforms'));
  const androidJar = path.join(platform, 'android.jar');
  const aapt2 = path.join(bt, 'aapt2');
  const zipalign = path.join(bt, 'zipalign');
  const apksigner = path.join(bt, 'apksigner');
  const keystore = path.join(os.homedir(), '.android', 'debug.keystore');

  const manifest = path.join(dir, 'AndroidManifest.xml');
  fs.writeFileSync(
    manifest,
    `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${ROOT_MANAGER_PACKAGE}" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
    <application android:label="Magisk" android:hasCode="false" />
</manifest>
`,
  );
  const unsigned = path.join(dir, 'stub-unsigned.apk');
  execFileSync(aapt2, ['link', '--manifest', manifest, '-I', androidJar, '-o', unsigned], { stdio: 'ignore' });
  execFileSync(zipalign, ['-f', '4', unsigned, apk], { stdio: 'ignore' });
  execFileSync(
    apksigner,
    ['sign', '--ks', keystore, '--ks-pass', 'pass:android', '--key-pass', 'pass:android', '--ks-key-alias', 'androiddebugkey', apk],
    { stdio: 'ignore' },
  );
  return apk;
}

/** Stub kök yöneticisi paketini kurar (RootProbe `rooted` yükseltir). */
function plantRootManager(device) {
  const apk = ensureRootManagerStub();
  device.adb(['install', '-r', apk]);
  return ROOT_MANAGER_PACKAGE;
}

/** Stub kök yöneticisi paketini kaldırır (varsa). */
function removeRootManager(device) {
  try {
    device.adb(['uninstall', ROOT_MANAGER_PACKAGE]);
  } catch {
    /* kurulu değilse */
  }
}

// ── Frida (hooking çerçevesi) enjeksiyonu — gadget + LD_PRELOAD ────────────
//
// frida-SERVER (ptrace enjeksiyonu) bu arm64 emülatörlerinde de çalışır (17.19.0
// hariç: ajanı her süreçte çöküyor; sunucu `adb shell '… &'` ile bırakılırsa
// oturumla ölür ve istemci "jailed Android" der). Burada frida-GADGET'i debuggable
// uygulamaya LD_PRELOAD ile yüklüyoruz (wrap.<pkg>): sunucu ve ptrace gerektirmez,
// testi tek komutla tekrarlanabilir kılar. Gadget uygulamanın
// adres uzayında `frida-gadget` / `gum-js-loop` / `gmain` / `gdbus` /
// `pool-frida` thread'lerini ve maps'te kendi .so'sunu bırakır — HookingProbe
// tam da bunları arar.

/** İndirilmiş frida-gadget .so'sunun yolu (sample-e2e/.local/frida). */
function fridaGadgetPath() {
  const dir = path.join(env.LOCAL_DIR, 'frida');
  if (fs.existsSync(dir)) {
    const so = fs.readdirSync(dir).find((f) => /frida-gadget-.*android-arm64\.so$/.test(f));
    if (so) return path.join(dir, so);
  }
  return null;
}

/** Gadget araçları (indirilmiş .so) hazır mı — R02 testleri bununla skip kararı verir. */
function fridaGadgetAvailable() {
  return fridaGadgetPath() != null;
}

/**
 * frida-gadget'i debuggable [pkg]'ya LD_PRELOAD ile bağlar: .so + "on_load:resume"
 * yapılandırması uygulamanın veri dizinine kopyalanır (run-as) ve
 * `wrap.<pkg>` özelliği ayarlanır (root; API 31+ shell'den reddediyor).
 * Çağırandan sonra uygulama YENİDEN BAŞLATILMALI (launchFresh DEĞİL — o veriyi
 * siler); gadget açılışta linker tarafından yüklenir.
 */
function plantFridaGadget(device, pkg, { soName = 'libgadget.so' } = {}) {
  const gadget = fridaGadgetPath();
  if (!gadget) throw new Error('frida-gadget .so yok (sample-e2e/.local/frida); indirip tekrar deneyin');
  // Gadget, .so'nun yanındaki "<temel ad>.config" dosyasını okur.
  const confName = soName.replace(/\.so$/, '.config');
  const config = path.join(env.LOCAL_DIR, 'frida', 'gadget-resume.config');
  fs.writeFileSync(config, '{ "interaction": { "type": "listen", "address": "127.0.0.1", "port": 27042, "on_load": "resume" } }');
  device.adb(['push', gadget, '/data/local/tmp/pv-gadget.so']);
  device.adb(['push', config, '/data/local/tmp/pv-gadget.config']);
  device.shell('chmod 644 /data/local/tmp/pv-gadget.so /data/local/tmp/pv-gadget.config');
  device.shell(`run-as ${pkg} sh -c 'cp /data/local/tmp/pv-gadget.so ./${soName}; cp /data/local/tmp/pv-gadget.config ./${confName}'`);
  // Değer TIRNAKSIZ olmalı; literal tırnak zygote'ta "exit 127" yapar.
  device.shell(`su 0 setprop wrap.${pkg} LD_PRELOAD=/data/data/${pkg}/${soName}`);
}

/** wrap özelliğini temizler ve gadget dosyalarını siler (varsa). */
function removeFridaGadget(device, pkg) {
  try {
    device.shell(`su 0 setprop wrap.${pkg} ""`);
  } catch {
    /* no-op */
  }
  try {
    // Hangi adla konmuş olursa olsun tüm gadget kalıntılarını temizle.
    device.shell(`run-as ${pkg} sh -c 'rm -f ./libgadget.so ./libgadget.config ./libhelper.so ./libhelper.config'`);
  } catch {
    /* no-op */
  }
}

// ── Yeniden paketleme (farklı anahtarla imzalama) ─────────────────────────

/**
 * Atılabilir bir "saldırgan" anahtar deposu üretir (yoksa). Yeniden paketlemeyi
 * taklit etmek için APK bununla yeniden imzalanır; debug anahtarından farklı
 * olduğu için istemcinin expectedSignerSha256'sıyla uyuşmaz → app_integrity.
 */
function ensureTamperKeystore() {
  const dir = path.join(env.LOCAL_DIR, 'stubs');
  const ks = path.join(dir, 'tamper.jks');
  if (fs.existsSync(ks)) return ks;
  fs.mkdirSync(dir, { recursive: true });
  const javaHome = process.env.JAVA_HOME
    || ['/Applications/Android Studio.app/Contents/jbr/Contents/Home'].find((p) => fs.existsSync(p));
  const keytool = javaHome ? path.join(javaHome, 'bin', 'keytool') : 'keytool';
  execFileSync(
    keytool,
    ['-genkeypair', '-keystore', ks, '-storepass', 'tamper', '-keypass', 'tamper', '-alias', 'tamper',
      '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650', '-dname', 'CN=PinVault Tamper,O=E2E'],
    { stdio: 'ignore' },
  );
  return ks;
}

/**
 * [srcApk]'yı atılabilir bir anahtarla yeniden imzalar (zipalign + apksigner,
 * eski imzaların yerine) ve yeni dosyanın yolunu döndürür. Üretilen APK farklı
 * bir imzalama sertifikası taşır → yeniden paketlenmiş bir kopyayı temsil eder.
 */
function repackageApk(srcApk) {
  const sdk = androidSdk();
  if (!sdk) throw new Error('Android SDK bulunamadı: APK yeniden imzalanamıyor');
  const bt = latestDir(path.join(sdk, 'build-tools'));
  const dir = path.join(env.LOCAL_DIR, 'stubs');
  fs.mkdirSync(dir, { recursive: true });
  const aligned = path.join(dir, 'tampered-aligned.apk');
  const out = path.join(dir, 'tampered.apk');
  execFileSync(path.join(bt, 'zipalign'), ['-f', '4', srcApk, aligned], { stdio: 'ignore' });
  const ks = ensureTamperKeystore();
  execFileSync(
    path.join(bt, 'apksigner'),
    ['sign', '--ks', ks, '--ks-pass', 'pass:tamper', '--key-pass', 'pass:tamper', '--ks-key-alias', 'tamper', '--out', out, aligned],
    { stdio: 'ignore' },
  );
  return out;
}

function androidSdk() {
  const candidates = [
    process.env.ANDROID_HOME,
    process.env.ANDROID_SDK_ROOT,
    path.join(os.homedir(), 'Library/Android/sdk'),
    path.join(os.homedir(), 'Android/Sdk'),
  ].filter(Boolean);
  return candidates.find((p) => p && fs.existsSync(p)) || null;
}

function latestDir(parent) {
  const names = fs.readdirSync(parent).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  if (!names.length) throw new Error(`boş dizin: ${parent}`);
  return path.join(parent, names[names.length - 1]);
}

module.exports = {
  LENIENT,
  getPolicy,
  setPolicy,
  deviceRecord,
  clearDeviceOverrides,
  reasonsOf,
  warningsOf,
  attachDebugger,
  plantRootManager,
  removeRootManager,
  ensureRootManagerStub,
  ROOT_MANAGER_PACKAGE,
  repackageApk,
  ensureTamperKeystore,
  plantFridaGadget,
  removeFridaGadget,
  fridaGadgetAvailable,
  fridaGadgetPath,
  policyPath,
  devicePath,
};
