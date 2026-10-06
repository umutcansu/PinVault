// iOS simülatörü sürücüsü: lib/android.js ile aynı yöntem adları ve dönüş
// biçimleri. Uygulamaya dışarıdan, bir kullanıcı gibi dokunur ve ekrandaki
// metni erişilebilirlik ağacından okur (ios-driver: XCUITest, lib/iosDriver.js).
//
// Android'de adb/su ile yapılanların karşılıkları (pinvault-ios/PORTING.md §8):
//   am start --es mode, date -s, iptables → E2E denetim dosyası
//       <veri kabı>/Library/Caches/pinvault-e2e/control.json + Darwin bildirimi
//       com.example.sampleclient.e2e.control (uygulama dosyayı yeniden okur)
//   cmd jobscheduler run -f → bildirim com.example.sampleclient.e2e.runScheduledWork,
//       planlı işler report.json'dan (BGTaskScheduler simülatörde yok)
//   run-as → veri kabı Mac'ten doğrudan okunur (simctl get_app_container)
//   pm clear → uygulama kapatılır, Documents/Library/tmp boşaltılır, simülatörün
//       Keychain'i sıfırlanır (uygulama hiç silinmez: identifierForVendor değişmesin)
//   logcat → `log show` (subsystem io.github.umutcansu.pinvault ve uygulama)
//   ekran kilidi PIN'i → Face ID kaydı + eşleşme/eşleşmeme bildirimleri
//
// Simülatörde cihaz şifresi her zaman var: "ekran kilidi yok" durumu kurulamaz.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const env = require('./env');
const driver = require('./iosDriver');
const blackhole = require('./blackhole');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

/** Uygulamanın E2E denetim kanalı (PORTING.md §8). */
const E2E_DIR = 'Library/Caches/pinvault-e2e';
const CONTROL_NOTIFICATION = `${env.APP_ID}.e2e.control`;
const RUN_WORK_NOTIFICATION = `${env.APP_ID}.e2e.runScheduledWork`;
const LOG_SUBSYSTEMS = ['io.github.umutcansu.pinvault', env.APP_ID];

/** Face ID (simülatör): kayıt durumu ve tarama sonucu bildirimleri. */
const FACE_ID_ENROLLED = 'com.apple.BiometricKit.enrollmentChanged';
const FACE_ID_MATCH = 'com.apple.BiometricKit_Sim.pearl.match';
const FACE_ID_NOMATCH = 'com.apple.BiometricKit_Sim.pearl.nomatch';
const AUTH_CANCEL_BUTTON = 'com.apple.localauthentication.ax.authentication.button.cancel';

/** Değeri metin olan erişilebilirlik türleri (Android'de EditText). */
const FIELD_TYPES = new Set(['textField', 'secureTextField', 'textView', 'searchField']);

function androidOnly(what) {
  const e = new Error(`${what} yalnızca Android'de var; iOS simülatöründe karşılığı yok (lib/ios.js)`);
  e.code = 'ANDROID_ONLY';
  return e;
}

function simctl(args, opts = {}) {
  return execFileSync('xcrun', ['simctl', ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 128 * 1024 * 1024,
    ...opts,
  });
}

/**
 * Android'in uygulama veri dizinine göre yolu (shared_prefs/…, files/…) iOS veri
 * kabındaki karşılığına çevirir (kaba göre):
 *   shared_prefs/<ad>.xml   → Library/Application Support/pinvault/<ad>.plist
 *   shared_prefs            → Library/Application Support/pinvault
 *   files/vault_files/…     → Library/Application Support/pinvault/vault_files/…
 *   files/<x>               → Library/Application Support/<x>
 *   .                       → kabın kökü
 */
function mapAppPath(rel) {
  const p = String(rel || '.').replace(/^\.\/+/, '').replace(/\/+$/, '');
  if (p === '' || p === '.') return '.';
  if (p === 'shared_prefs') return 'Library/Application Support/pinvault';
  let m = p.match(/^shared_prefs\/(.+)\.xml$/);
  if (m) return `Library/Application Support/pinvault/${m[1]}.plist`;
  if (p.startsWith('shared_prefs/')) return `Library/Application Support/pinvault/${p.slice('shared_prefs/'.length)}`;
  if (p === 'files/vault_files' || p.startsWith('files/vault_files/')) return `Library/Application Support/pinvault/${p.slice('files/'.length)}`;
  if (p === 'files') return 'Library/Application Support';
  m = p.match(/^files\/(.+)$/);
  if (m) return `Library/Application Support/${m[1]}`;
  return p;
}

function unescapeXml(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * XML plist'teki üst düzey sözlüğün kayıtları: [{ name, value, type, selfClosing, plistType, raw }]
 * (android.js parsePrefsXml ile aynı biçim). PinVault'un şifreli tercih
 * dosyası düz bir sözlük: HMAC ad → Base64 değer. <string> ve <data> ikisi de
 * type "string" sayılır (value Base64 metin); asıl tür plistType'ta.
 */
function parsePlistEntries(xml) {
  const out = [];
  const dict = (xml || '').match(/<dict>([\s\S]*)<\/dict>/);
  if (!dict) return out;
  const re = /<key>([^<]*)<\/key>\s*(?:<(string|data|integer|real|date)>([^<]*)<\/\2>|<(true|false)\s*\/>|<(string|data)\s*\/>|<(array|dict)>)/g;
  let m;
  while ((m = re.exec(dict[1]))) {
    const name = unescapeXml(m[1]);
    let type;
    let value;
    if (m[2]) {
      type = m[2];
      value = type === 'data' ? m[3].replace(/\s+/g, '') : unescapeXml(m[3]);
    } else if (m[4]) {
      type = 'boolean';
      value = m[4];
    } else if (m[5]) {
      type = m[5];
      value = '';
    } else {
      type = m[6];
      value = '';
    }
    out.push({ name, value, type: type === 'data' ? 'string' : type, selfClosing: false, plistType: type, raw: m[0] });
  }
  return out;
}

/** Yerel saat "YYYY-MM-DD HH:MM:SS" (log show --start). */
function localStamp(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// "2026-10-07 00:59:51.544 Df Spike[59085:4062e] [io.github.umutcansu.pinvault:Spike] mesaj"
const LOG_LINE = /^(\d{4})-(\d\d)-(\d\d) (\d\d:\d\d:\d\d\.\d+)\s+(\w+)\s+\S+\[\d+:[0-9a-fA-F]+\]\s+\[([^:\]]+):([^\]]*)\]\s?(.*)$/;

class Device {
  constructor(udid) {
    this.udid = udid;
    /** android.js ile aynı ad: kanıt sayfası ve durum dosyası bunu yazar. */
    this.serial = udid;
    this.platform = 'ios';
    /** Uygulamanın saatine eklenen saniye (control.json clockOffsetSeconds). */
    this.clockOffset = 0;
    /** Bu nesnenin kurduğu ağ kuralları: { kind: redirect|reject|drop, from, to }. */
    this.netRules = [];
    this._containers = {};
    this._deviceIds = {};
  }

  // ── Simülatör ────────────────────────────────────────────────────────

  /** Açık (Booted) simülatörlerin UDID'leri. */
  static connected() {
    return Device.list().filter((d) => d.state === 'Booted').map((d) => d.udid);
  }

  /** Bütün simülatörler: [{ udid, name, state, runtime, deviceTypeIdentifier }]. */
  static list() {
    const json = JSON.parse(simctl(['list', 'devices', '-j']));
    const out = [];
    for (const [runtime, devices] of Object.entries(json.devices || {})) {
      for (const d of devices) out.push({ ...d, runtime });
    }
    return out;
  }

  static info(udid) {
    return Device.list().find((d) => d.udid === udid) || null;
  }

  /**
   * Simülatörü açar (kapalıysa) ve açılış bitene kadar bekler. Yalnızca bu
   * UDID'ye dokunur. { device, booted: bu çağrı mı açtı }.
   */
  static boot(udid, { timeoutMs = 300_000 } = {}) {
    const info = Device.info(udid);
    if (!info) throw new Error(`Simülatör yok: ${udid} (xcrun simctl list devices)`);
    let booted = false;
    if (info.state !== 'Booted') {
      simctl(['boot', udid]);
      booted = true;
    }
    simctl(['bootstatus', udid, '-b'], { timeout: timeoutMs });
    return { device: new Device(udid), booted };
  }

  isEmulator() {
    return true;
  }

  adb() {
    throw androidOnly('adb');
  }

  /** Simülatörün içinde /bin/sh ile komut (simctl spawn). */
  shell(command, opts) {
    return simctl(['spawn', this.udid, '/bin/sh', '-c', `PATH=/usr/bin:/bin:/usr/sbin:/sbin; ${command}`], opts);
  }

  notify(name) {
    simctl(['spawn', this.udid, 'notifyutil', '-p', name], { timeout: 30_000 });
  }

  /** Android getprop adlarının iOS karşılıkları (yalnızca kullanılanlar). */
  prop(name) {
    switch (name) {
      case 'ro.product.model':
        return this.model();
      case 'ro.product.manufacturer':
      case 'ro.product.brand':
        return 'Apple';
      case 'ro.build.version.sdk':
        return String(parseInt(this.osVersion(), 10) || 0);
      case 'ro.build.version.release':
        return this.osVersion();
      case 'sys.boot_completed':
        return (Device.info(this.udid) || {}).state === 'Booted' ? '1' : '0';
      default:
        throw androidOnly(`getprop ${name}`);
    }
  }

  /** Model kimliği (ör. iPhone17,1): uygulamanın raporlarındaki deviceModel. */
  model() {
    if (!this._model) {
      try {
        this._model = simctl(['getenv', this.udid, 'SIMULATOR_MODEL_IDENTIFIER'], { timeout: 30_000 }).trim();
      } catch {
        this._model = '';
      }
      if (!this._model) this._model = (Device.info(this.udid) || {}).name || 'iPhone Simulator';
    }
    return this._model;
  }

  /** Simülatörün adı ve iOS sürümü ("PinVault-iOS-E2E", "26.5"). */
  name() {
    return (Device.info(this.udid) || {}).name || this.udid;
  }

  osVersion() {
    const runtime = (Device.info(this.udid) || {}).runtime || '';
    const m = runtime.match(/iOS-(\d+)-(\d+)(?:-(\d+))?/);
    return m ? [m[1], m[2], m[3]].filter(Boolean).join('.') : '';
  }

  /** Uygulamanın gördüğü duvar saati (ms): simülatör Mac'in saatini kullanır, üstüne kaydırma. */
  epochMs() {
    return Date.now() + this.clockOffset * 1000;
  }

  /** A18 gibi senaryoların "cihaz saati" paneli. */
  clockText() {
    const offset = this.clockOffset;
    const sign = offset >= 0 ? '+' : '';
    return `${new Date(this.epochMs()).toString()}  (uygulamanın saati: Mac saati ${sign}${offset} sn, control.json clockOffsetSeconds)`;
  }

  disableAnimationsIfEmulator() {
    // Simülatörde dokunulmaz: sürücü XCTest'in boşta beklemesini zaten atlıyor.
  }

  screenshot() {
    const file = path.join(os.tmpdir(), `pv-e2e-ios-${process.pid}-${Date.now()}.png`);
    try {
      simctl(['io', this.udid, 'screenshot', '--type=png', file], { stdio: ['ignore', 'ignore', 'pipe'] });
      return fs.readFileSync(file);
    } finally {
      fs.rmSync(file, { force: true });
    }
  }

  // ── Ekran ────────────────────────────────────────────────────────────

  /** android.js'teki resource-id: iOS'ta düz erişilebilirlik kimliği. */
  viewId(name) {
    return name;
  }

  /**
   * Ekrandaki öğeler, android.js ile aynı biçimde: { id, text, enabled,
   * checked, password, bounds:[x1,y1,x2,y2] } + iOS'a özgü label, value, type,
   * placeholder, selected, focused. text: metin alanlarında değer (yer tutucu
   * hariç), diğerlerinde etiket. checked: değer "1" (anahtar, radyo düğmesi).
   * Ekran dışındaki SwiftUI öğeleri de listede (Android dökümünden farkı):
   * dokunmak için [tapNode] kaydırır.
   */
  uiNodes(bundle = env.APP_ID) {
    const tree = driver.request('GET', `/tree?bundle=${encodeURIComponent(bundle)}`);
    if (tree.screen) this._screen = { width: tree.screen.width, height: tree.screen.height };
    return (tree.nodes || []).map((n) => {
      const value = n.value || '';
      const field = FIELD_TYPES.has(n.type);
      const fieldText = n.placeholder && value === n.placeholder ? '' : value;
      return {
        id: n.id || '',
        text: field ? fieldText : n.label || '',
        label: n.label || '',
        value,
        type: n.type,
        placeholder: n.placeholder || '',
        enabled: !!n.enabled,
        checked: value === '1',
        selected: !!n.selected,
        focused: !!n.focused,
        password: n.type === 'secureTextField',
        bounds: Array.isArray(n.frame) ? n.frame.map((v) => Math.round(v)) : null,
      };
    });
  }

  imeShown() {
    return !!driver.request('GET', `/keyboard?bundle=${encodeURIComponent(env.APP_ID)}`).shown;
  }

  /** Klavyeyi kapatır; kapalıysa hiçbir şey yapmaz. Klavye kapandıysa true. */
  hideIme() {
    if (!this.imeShown()) return true;
    return !driver.request('POST', '/dismissKeyboard', { bundle: env.APP_ID }).shown;
  }

  /** Ekran boyutu (nokta). */
  screenSize() {
    if (!this._screen) this.uiNodes();
    return this._screen;
  }

  /** Ekranın ortasında yukarı/aşağı kaydırır ("down": içerik yukarı kayar); android.js ile aynı oranlar. */
  swipeVertical(direction = 'down', fraction = 0.4, durationMs = 300) {
    const { width, height } = this.screenSize();
    const x = Math.round(width / 2);
    const delta = Math.round(height * fraction);
    const [from, to] = direction === 'down'
      ? [Math.round(height * 0.45), Math.round(height * 0.45) - delta]
      : [Math.round(height * 0.25), Math.round(height * 0.25) + delta];
    driver.request('POST', '/swipe', { bundle: env.APP_ID, x1: x, y1: from, x2: x, y2: to, duration: durationMs });
  }

  tapCenter([x1, y1, x2, y2], bundle = env.APP_ID) {
    driver.request('POST', '/tap', { bundle, x: (x1 + x2) / 2, y: (y1 + y2) / 2 });
  }

  /**
   * Öğeye dokunur. Kimliği varsa sürücü onu bulur ve gerekirse görünür olana
   * kadar kaydırır (ekran dışındaki öğe ağaçta durur ama dokunulamaz).
   */
  tapNode(node) {
    if (node.id) driver.request('POST', '/tapElement', { bundle: env.APP_ID, id: node.id });
    else this.tapCenter(node.bounds);
  }

  /** Odaktaki alana yazar (her karakter; Türkçe dahil). */
  typeText(text) {
    driver.request('POST', '/type', { bundle: env.APP_ID, text: String(text) });
  }

  /** Alanı boşaltır (dokun, hepsini seç, sil). */
  async clearField(node) {
    driver.request('POST', '/clearAndType', { bundle: env.APP_ID, id: node.id, text: '' });
  }

  /** Alanın metnini [value] yapar (boşalt + yaz). */
  async setFieldText(node, value) {
    driver.request('POST', '/clearAndType', { bundle: env.APP_ID, id: node.id, text: String(value) });
  }

  /**
   * GERİ: iOS'ta sistem geri tuşu yok; her ekranın "backButton"u var. Ekranda
   * yoksa (ana ekran) klavyeyi kapatır.
   */
  pressBack() {
    try {
      driver.request('POST', '/tapElement', { bundle: env.APP_ID, id: 'backButton', timeout: 1500 });
    } catch (e) {
      if (e.status !== 404) throw e;
      this.hideIme();
    }
  }

  // ── Ekran kilidi (Face ID) ───────────────────────────────────────────
  //
  // Simülatörün cihaz şifresi her zaman var (canEvaluatePolicy(.deviceOwnerAuthentication)
  // Face ID kayıtlı olmasa da true). Kilidin sorulup cevaplanabilmesi için Face
  // ID kaydedilir; "PIN girmek" eşleşme bildirimi, "vazgeçmek" eşleşmeme +
  // SpringBoard'daki Vazgeç düğmesidir.

  hasScreenLock() {
    return true;
  }

  faceIdEnrolled() {
    try {
      const out = simctl(['spawn', this.udid, 'notifyutil', '-g', FACE_ID_ENROLLED], { timeout: 30_000 });
      return /\s1$/.test(out.trim());
    } catch {
      return false;
    }
  }

  setFaceIdEnrolled(enrolled) {
    simctl(['spawn', this.udid, 'notifyutil', '-s', FACE_ID_ENROLLED, enrolled ? '1' : '0'], { timeout: 30_000 });
    this.notify(FACE_ID_ENROLLED);
  }

  /** "Geçici ekran kilidi": Face ID kaydı (yoksa). [clearScreenLock]'a verilecek durumu döndürür. */
  setScreenLockPin(pin) {
    const had = this.faceIdEnrolled();
    if (!had) this.setFaceIdEnrolled(true);
    return { ownLock: !had, faceId: true };
  }

  /** [setScreenLockPin]'in kaydettiği Face ID'yi kaldırır (önceden kayıtlıysa dokunmaz). */
  clearScreenLock(pin, previous = {}) {
    if (previous.ownLock === true) this.setFaceIdEnrolled(false);
  }

  /** Teardown: yarıda kalmış geçici kilit. iOS'ta Face ID kaydı bırakılır (önceki durum bilinmiyor). */
  clearLeftoverScreenLock() {}

  /** SpringBoard'daki sistem penceresi (Face ID / cihaz şifresi) açık mı. */
  credentialPromptShown(title) {
    let shown;
    try {
      shown = driver.request('GET', '/alerts');
    } catch {
      return false;
    }
    const texts = [...(shown.texts || []), ...(shown.alerts || [])];
    return texts.some((t) => (title && t.includes(title)) || /Face ID/.test(t))
      || (shown.buttons || []).some((b) => String(b.id || '').startsWith('com.apple.localauthentication'));
  }

  /** "PIN'i yaz": Face ID taraması eşleşir. */
  enterCredential() {
    this.notify(FACE_ID_MATCH);
  }

  /**
   * Kilit penceresini kapatır (vazgeç): tarama eşleşmez, SpringBoard'un
   * gösterdiği Vazgeç düğmesine dokunulur. Pencere kapandıysa true.
   */
  async cancelCredentialPrompt(title) {
    for (let i = 0; i < 3 && this.credentialPromptShown(title); i++) {
      this.notify(FACE_ID_NOMATCH);
      try {
        driver.request('POST', '/tapAlertButton', { id: AUTH_CANCEL_BUTTON, timeout: 6000 });
      } catch (e) {
        // Düğme yoksa ya da dokunuşla pencere kapandıysa: aşağıdaki denetim karar verir.
        if (e.code === 'DRIVER_UNAVAILABLE') throw e;
      }
      await sleep(1200);
    }
    return !this.credentialPromptShown(title);
  }

  // ── Bağlantı ─────────────────────────────────────────────────────────

  waitForDevice() {
    simctl(['bootstatus', this.udid, '-b'], { timeout: 300_000 });
  }

  /** Simülatör açık ve sürücü yanıt veriyor mu; sürücü ölmüşse yeniden başlatılır. */
  async ensureOnline(timeoutMs = 90_000) {
    const deadline = Date.now() + timeoutMs;
    let lastError;
    while (Date.now() < deadline) {
      try {
        const info = Device.info(this.udid);
        if (!info) throw new Error(`Simülatör yok: ${this.udid}`);
        if (info.state !== 'Booted') throw new Error(`Simülatör açık değil (${info.state}): ${this.udid}`);
        driver.ensure({ udid: this.udid });
        return;
      } catch (e) {
        lastError = e;
      }
      await sleep(1000);
    }
    throw new Error(`Simülatör yanıt vermiyor: ${this.udid}\n${lastError ? lastError.message : ''}`);
  }

  rootShell() {
    throw androidOnly('root kabuğu (su)');
  }

  runAs() {
    throw androidOnly('run-as');
  }

  // ── Uygulama ─────────────────────────────────────────────────────────

  appContainer(pkg = env.APP_ID) {
    if (!this._containers[pkg]) {
      try {
        this._containers[pkg] = simctl(['get_app_container', this.udid, pkg, 'data'], { timeout: 30_000 }).trim();
      } catch (e) {
        throw new Error(`${pkg} simülatörde kurulu değil (simctl get_app_container): ${e.message}`);
      }
    }
    return this._containers[pkg];
  }

  /** Android yolunun (shared_prefs/…, files/…) veri kabındaki mutlak karşılığı. */
  appPath(pkg, rel) {
    return path.join(this.appContainer(pkg), mapAppPath(rel));
  }

  stopApp(pkg = env.APP_ID) {
    try {
      simctl(['terminate', this.udid, pkg], { stdio: 'ignore', timeout: 30_000 });
    } catch {
      /* çalışmıyordu */
    }
  }

  /**
   * `pm clear` karşılığı: uygulama kapatılır, tercihleri (cfprefsd) silinir,
   * veri kabının Documents, Library ve tmp içeriği boşaltılır, simülatörün
   * Keychain'i sıfırlanır (Secure Enclave anahtarları dahil). Uygulama silinmez.
   */
  clearApp(pkg = env.APP_ID) {
    this.stopApp(pkg);
    try {
      simctl(['spawn', this.udid, 'defaults', 'delete', pkg], { stdio: 'ignore', timeout: 30_000 });
    } catch {
      /* tercih yok */
    }
    const root = this.appContainer(pkg);
    for (const dir of ['Documents', 'Library', 'tmp']) {
      const abs = path.join(root, dir);
      if (!fs.existsSync(abs)) continue;
      for (const entry of fs.readdirSync(abs)) fs.rmSync(path.join(abs, entry), { recursive: true, force: true });
    }
    simctl(['keychain', this.udid, 'reset'], { timeout: 60_000 });
  }

  /** Uygulamayı açar; [mode] verilirse açılış modu (control.json "mode", `--es mode` karşılığı). */
  startApp(mode, pkg = env.APP_ID) {
    this.writeControl({ mode, pkg });
    return simctl(['launch', this.udid, pkg], { timeout: 60_000 });
  }

  /** Kapatıp açar; keepData false ise önce veriyi siler (android.js ile aynı sıra). */
  launchApp(mode, { keepData = true, pkg = env.APP_ID } = {}) {
    this.stopApp(pkg);
    if (!keepData) this.clearApp(pkg);
    return this.startApp(mode, pkg);
  }

  installApp(file) {
    const out = simctl(['install', this.udid, file], { timeout: 300_000 });
    this._containers = {};
    const bundle = this.bundleIdOf(file);
    return `${out.trim() ? `${out.trim()}\n` : ''}Kuruldu: ${bundle} (${path.basename(file)})`;
  }

  uninstallApp(pkg = env.APP_ID) {
    const out = simctl(['uninstall', this.udid, pkg], { timeout: 120_000 });
    this._containers = {};
    delete this._deviceIds[pkg];
    fs.rmSync(this.deviceIdCacheFile(pkg), { force: true });
    return out;
  }

  /** Panellerde gösterilen kurulum komutu. */
  installCommandLabel(file) {
    return `xcrun simctl install ${this.udid} ${file}`;
  }

  bundleIdOf(appDir) {
    try {
      return execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleIdentifier', path.join(appDir, 'Info.plist')], {
        encoding: 'utf8',
      }).trim();
    } catch {
      return env.APP_ID;
    }
  }

  /** Kurulu uygulamanın yolu ve kodunun (çalıştırılabilir dosya + debug dylib + Info.plist) SHA-256'sı ("uygulama güncellenmedi" kanıtı). */
  installedAppInfo(pkg = env.APP_ID) {
    const appDir = simctl(['get_app_container', this.udid, pkg, 'app'], { timeout: 30_000 }).trim();
    return { path: appDir, sha256: require('./clientBuild').artifactHash(appDir) };
  }

  // ── E2E denetim dosyası ──────────────────────────────────────────────

  controlFile(pkg = env.APP_ID) {
    return path.join(this.appContainer(pkg), E2E_DIR, 'control.json');
  }

  /** control.json'ın içeriği: açılış modu (yalnızca açılışta), saat kaydırması, yönlendirmeler. */
  controlState(mode) {
    return {
      ...(mode ? { mode } : {}),
      clockOffsetSeconds: this.clockOffset,
      redirects: Object.fromEntries(this.netRules.map((r) => [r.from, r.to])),
    };
  }

  writeControl({ mode, pkg = env.APP_ID } = {}) {
    const file = this.controlFile(pkg);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(this.controlState(mode), null, 2)}\n`);
    return file;
  }

  /** Denetim dosyasını yazar ve uygulamaya yeniden okumasını söyler (yeni bağlantılar hemen etkilenir). */
  applyControl() {
    this.writeControl();
    this.notify(CONTROL_NOTIFICATION);
  }

  /** report.json: { deviceId, scheduledTasks, updatedAt } ya da null. */
  report(pkg = env.APP_ID) {
    try {
      return JSON.parse(fs.readFileSync(path.join(this.appContainer(pkg), E2E_DIR, 'report.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  // ── Saat ─────────────────────────────────────────────────────────────

  /**
   * Senaryodan kalmış saat kaydırmasını sıfırlar (android.js: emülatör saatini
   * Mac'e hizalar). Simülatör Mac'in saatini kullanır; yalnızca uygulamanın
   * kaydırması geri alınır. Düzeltilen saniyeyi döndürür.
   */
  syncClockToHost() {
    if (!this.clockOffset) return 0;
    const drift = -this.clockOffset;
    this.clockOffset = 0;
    try {
      this.applyControl();
    } catch {
      /* uygulama kurulu değilse açılışta yazılır */
    }
    return drift;
  }

  /** Uygulamanın saatini [seconds] kaydırır (kütüphanenin duvar saati, sertifika geçerliliği). */
  shiftClock(seconds) {
    this.clockOffset += seconds;
    this.applyControl();
  }

  // ── Ağ kuralları (control.json "redirects") ──────────────────────────

  /** [dstIp]:[dstPort]'a giden bağlantıları [toIp]:[toPort]'a yönlendirir (iptables DNAT karşılığı). */
  redirectTcp(dstIp, dstPort, toPort, toIp = dstIp) {
    this.netRules = this.netRules.filter((r) => r.from !== `${dstIp}:${dstPort}`);
    this.netRules.push({ kind: 'redirect', from: `${dstIp}:${dstPort}`, to: `${toIp}:${toPort}` });
    this.applyControl();
  }

  /**
   * [dstIp]:[dstPort]'u keser. "reject": kimsenin dinlemediği yerel porta
   * (bağlantı hemen reddedilir); "drop": bağlantıyı kabul edip hiç yanıt
   * vermeyen yerel sunucuya (lib/blackhole.js; istek zaman aşımına uğrar).
   */
  blockTcp(dstIp, dstPort, mode = 'reject') {
    const drop = mode === 'drop';
    if (drop) blackhole.start(env.BLACKHOLE_PORT);
    this.netRules = this.netRules.filter((r) => r.from !== `${dstIp}:${dstPort}`);
    this.netRules.push({
      kind: drop ? 'drop' : 'reject',
      from: `${dstIp}:${dstPort}`,
      to: `127.0.0.1:${drop ? env.BLACKHOLE_PORT : env.CLOSED_PORT}`,
    });
    this.applyControl();
  }

  /** Bu nesnenin kurduğu bütün kuralları kaldırır. */
  clearNetRules() {
    const had = this.netRules.length > 0;
    this.netRules = [];
    if (blackhole.isRunning()) blackhole.stop();
    try {
      this.applyControl();
    } catch (e) {
      if (had) throw e;
    }
  }

  /** [dstIp]:[dstPort] için kural var mı. */
  netRuleActive(dstIp, dstPort) {
    return this.netRules.some((r) => r.from === `${dstIp}:${dstPort}`);
  }

  /**
   * Kuralların kanıt paneli metni, iptables -S biçiminde (senaryolar
   * `--dport <port>` arar) + control.json'ın kendisi. [table] "nat"
   * yönlendirmeleri, "filter" engelleri listeler.
   */
  describeNetRules(table = 'nat') {
    const rules = this.netRules.filter((r) => (table === 'nat' ? r.kind === 'redirect' : r.kind !== 'redirect'));
    const lines = rules.map((r) => {
      const [ip, port] = r.from.split(':');
      if (r.kind === 'redirect') return `-A OUTPUT -p tcp -d ${ip} --dport ${port} -j DNAT --to-destination ${r.to}`;
      const target = r.kind === 'drop' ? 'DROP' : 'REJECT';
      const how = r.kind === 'drop' ? 'yanıt vermeyen yerel sunucu' : 'kapalı yerel port';
      return `-A OUTPUT -p tcp -d ${ip} --dport ${port} -j ${target}   (→ ${r.to}, ${how})`;
    });
    let file = '';
    try {
      file = fs.readFileSync(this.controlFile(), 'utf8').trim();
    } catch {
      file = '(dosya yok)';
    }
    return [
      '# iOS: iptables yok. Kurallar uygulamanın E2E denetim dosyasında (redirects);',
      `# uygulama dosyayı "${CONTROL_NOTIFICATION}" bildirimiyle yeniden okur.`,
      `-P OUTPUT ACCEPT`,
      ...lines,
      '',
      `$ cat ${E2E_DIR}/control.json`,
      file,
    ].join('\n');
  }

  // ── Uygulama verisi (veri kabı Mac'ten okunur) ───────────────────────

  /** `ls -la` (kabın köküne göre); dizinler boşlukla ayrılabilir ("shared_prefs files"). */
  appFiles(pkg, dir = '.') {
    const root = this.appContainer(pkg);
    const dirs = String(dir).split(/\s+/).filter(Boolean).map(mapAppPath);
    return execFileSync('ls', ['-la', ...dirs], { cwd: root, encoding: 'utf8', timeout: 30_000 });
  }

  /** Metin dosyası; plist'ler XML'e çevrilir (ikili plist okunabilsin). Dosya yoksa hata. */
  appFileText(pkg, file) {
    const abs = this.appPath(pkg, file);
    if (abs.endsWith('.plist')) {
      if (!fs.existsSync(abs)) throw new Error(`Dosya yok: ${abs}`);
      return execFileSync('plutil', ['-convert', 'xml1', '-o', '-', abs], { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
    }
    return fs.readFileSync(abs, 'utf8');
  }

  appFileBytes(pkg, file) {
    return fs.readFileSync(this.appPath(pkg, file));
  }

  /** Yerel dosyayı uygulamanın veri kabına kopyalar ([appPath] Android yoluyla verilir). */
  pushToApp(pkg, localFile, appPath) {
    const dest = this.appPath(pkg, appPath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(localFile, dest);
  }

  /** PinVault tercih deposunun dosya adı (pinvault_secure_config → pinvault_secure_config.plist). */
  prefsFileName(store) {
    return `${store}.plist`;
  }

  /** Tercih deposunun metni (XML plist); yoksa "(dosya yok)". */
  prefsFileText(pkg, store) {
    try {
      return this.appFileText(pkg, `shared_prefs/${store}.xml`);
    } catch {
      return '(dosya yok)\n';
    }
  }

  /** [appFileText]'in döndürdüğü tercih dosyasının kayıtları: [{ name, value, type, raw }]. */
  parsePrefs(text) {
    return parsePlistEntries(text);
  }

  /** Tercih deposunun kayıtları: [{ name, value, type, raw }]. */
  prefsEntries(pkg, store) {
    return this.parsePrefs(this.prefsFileText(pkg, store));
  }

  /** `grep -rl <pattern> <dizinler>` (Android yollarıyla); eşleşme yoksa "(eşleşme yok)". */
  appGrep(pkg, pattern, dirs = 'shared_prefs files') {
    const root = this.appContainer(pkg);
    const targets = String(dirs).split(/\s+/).filter(Boolean).map(mapAppPath).filter((d) => fs.existsSync(path.join(root, d)));
    if (!targets.length) return '(eşleşme yok)\n';
    const res = spawnSync('grep', ['-rl', pattern, ...targets], { cwd: root, encoding: 'utf8' });
    return res.status === 0 && res.stdout.trim() ? res.stdout : '(eşleşme yok)\n';
  }

  /**
   * Kanıt paneli başlığı ya da komut satırı: Android ifadesindeki run-as ve
   * Android yolları iOS karşılıklarıyla yazılır.
   */
  appLabel(text) {
    return String(text)
      .replace(/(?:adb shell )?run-as \S+/g, `simctl get_app_container ${this.udid} ${env.APP_ID} data →`)
      .replace(/adb shell su 0 iptables[^\n]*/g, `cat ${E2E_DIR}/control.json`)
      .replace(/adb push \+ /g, 'cp + ')
      .replace(/\b(?:shared_prefs|files)(?:\/[^\s)'"`,]*)?/g, (m) => mapAppPath(m));
  }

  /** Cihaz kimliği biçimi: identifierForVendor (küçük harf UUID). */
  get deviceIdPattern() {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  }

  deviceIdCacheFile(pkg) {
    return path.join(env.LOCAL_DIR, `ios-device-id-${this.udid}-${pkg}.txt`);
  }

  /**
   * Uygulamanın cihaz kimliği (identifierForVendor, küçük harf): kütüphanenin
   * kayıtta deviceUid diye gönderdiği değer. report.json'dan okunur ve
   * saklanır (veri silinince değişmez; yalnızca uygulama silinince değişir).
   * E2E_IOS_DEVICE_ID ile verilebilir.
   */
  appAndroidId(pkg = env.APP_ID) {
    if (process.env.E2E_IOS_DEVICE_ID) return process.env.E2E_IOS_DEVICE_ID.trim().toLowerCase();
    if (this._deviceIds[pkg]) return this._deviceIds[pkg];
    let id = (this.report(pkg) || {}).deviceId;
    if (!id) {
      try {
        id = fs.readFileSync(this.deviceIdCacheFile(pkg), 'utf8').trim();
      } catch {
        /* henüz okunmadı */
      }
    }
    if (!id) throw new Error(`${pkg} için cihaz kimliği yok (${E2E_DIR}/report.json); uygulama bir kez açılmış olmalı`);
    id = String(id).toLowerCase();
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(id)) throw new Error(`Beklenmeyen cihaz kimliği: ${JSON.stringify(id)}`);
    fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
    fs.writeFileSync(this.deviceIdCacheFile(pkg), id);
    this._deviceIds[pkg] = id;
    return id;
  }

  appDeviceId(pkg = env.APP_ID) {
    return this.appAndroidId(pkg);
  }

  // ── Planlı işler (uygulama içi zamanlayıcı) ──────────────────────────

  /** Etkin planlı işler (ENQUEUED/RUNNING/BLOCKED), report.json'dan; android.js'teki JobScheduler satırları gibi. */
  jobSchedulerJobs(pkg = env.APP_ID) {
    const tasks = (this.report(pkg) || {}).scheduledTasks || [];
    return tasks
      .filter((t) => ['ENQUEUED', 'RUNNING', 'BLOCKED'].includes(String(t.state)))
      .map((t) => `${t.id} state=${t.state} runAttemptCount=${t.runAttemptCount ?? '?'}`);
  }

  /** Planlı işlerin kaynağı (panel başlığı). */
  jobsSourceLabel() {
    return `cat ${E2E_DIR}/report.json → scheduledTasks (BGTaskScheduler simülatörde yok; kütüphanenin uygulama içi zamanlayıcısı)`;
  }

  /** Periyodik işi hemen çalıştırır (bildirim); etkin işlerin kimliklerini döndürür. */
  runScheduledJobs(pkg = env.APP_ID) {
    const ids = ((this.report(pkg) || {}).scheduledTasks || [])
      .filter((t) => ['ENQUEUED', 'RUNNING', 'BLOCKED'].includes(String(t.state)))
      .map((t) => String(t.id));
    this.notify(RUN_WORK_NOTIFICATION);
    return ids;
  }

  // ── Cihaz günlüğü (log show) ─────────────────────────────────────────

  /** Sonraki [logcat] çağrıları yalnızca bu andan sonraki satırları döndürür. */
  clearLogcat() {
    this._logSince = Date.now();
    return true;
  }

  /**
   * Kütüphanenin ve uygulamanın os.Logger satırları (`log show`), android.js
   * logcat'i gibi: "<AA-GG SS:DD:ss.mmm> <kategori>: <mesaj>". [tags]
   * kategori (Kotlin sınıf adı = Timber etiketi), [match] satır süzgeci.
   * [clearLogcat]'ten bu yana (yoksa son 10 dakika).
   */
  logcat({ match, tags, lines = 4000 } = {}) {
    const since = this._logSince || Date.now() - 10 * 60 * 1000;
    const predicate = `subsystem IN {${LOG_SUBSYSTEMS.map((s) => `"${s}"`).join(', ')}}`;
    let out;
    try {
      out = simctl(
        ['spawn', this.udid, 'log', 'show', '--start', localStamp(since - 1000), '--predicate', predicate, '--style', 'compact', '--info', '--debug'],
        { timeout: 120_000, stdio: ['ignore', 'pipe', 'ignore'] },
      );
    } catch (e) {
      return `${e.stdout || ''}${e.stderr || ''}`;
    }
    let rows = [];
    let last = null;
    for (const line of out.split('\n')) {
      const m = LOG_LINE.exec(line);
      if (m) {
        const [, year, month, day, time, , , category, message] = m;
        const at = new Date(`${year}-${month}-${day}T${time}`).getTime();
        last = { at, prefix: `${month}-${day} ${time.slice(0, 12)} ${category}`, category };
        rows.push({ ...last, text: `${last.prefix}: ${message}` });
      } else if (last && line.trim() && !/^Timestamp\s/.test(line) && !/^getpwuid/.test(line)) {
        // Çok satırlı mesajın devamı: logcat gibi aynı önekle ayrı satır.
        rows.push({ ...last, text: `${last.prefix}: ${line}` });
      }
    }
    rows = rows.filter((r) => r.at >= since);
    if (tags) {
      const set = Array.isArray(tags) ? tags : [tags];
      rows = rows.filter((r) => set.includes(r.category));
    }
    let texts = rows.map((r) => r.text);
    if (match) texts = texts.filter((row) => match.test(row));
    return texts.slice(-lines).join('\n').trim();
  }

  /** Simülatörü kapatır (yalnızca bu koşu açtıysa çağrılır). */
  shutdown() {
    simctl(['shutdown', this.udid], { timeout: 120_000 });
  }
}

/** Koşunun simülatöründeki uygulamanın cihaz kimliği (token'lar varsayılan olarak buna bağlanır). */
let _testDeviceUid = null;
function testDeviceUid() {
  if (_testDeviceUid) return _testDeviceUid;
  const udid = (require('./state').read() || {}).serial || env.IOS_UDID;
  _testDeviceUid = new Device(udid).appAndroidId(env.APP_ID);
  return _testDeviceUid;
}

module.exports = { Device, sleep, sleepSync, testDeviceUid, mapAppPath, parsePlistEntries };
