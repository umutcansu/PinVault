// adb üzerinden Android cihaz/emülatör sürücüsü. Uygulamaya dışarıdan, bir
// kullanıcı gibi dokunur ve ekrandaki metni UI Automator dökümünden okur;
// uygulamaya test kodu gömülmez.
const { execFileSync, spawn } = require('child_process');
const { ADB, EMULATOR } = require('./env');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// Eşzamanlı adb yardımcıları için: olay döngüsünü değil yalnızca bu akışı bekletir.
const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function adbRaw(args, opts = {}) {
  return execFileSync(ADB, args, {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
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

// Android'in XML yazıcısı değer çift tırnak içeriyorsa özniteliği tek tırnakla
// yazar (text='{"a":1}'), ve değerin içindeki ">" kaçışsız kalabilir. İki tırnak
// türü de okunur; etiket sınırı tırnaklı değerlerin dışında aranır.
const ATTR = /([\w:-]+)=(?:"([^"]*)"|'([^']*)')/g;
const NODE = /<node\b((?:\s+[\w:-]+=(?:"[^"]*"|'[^']*'))*)\s*\/?>/g;

function parseNodes(xml) {
  const nodes = [];
  let m;
  NODE.lastIndex = 0;
  while ((m = NODE.exec(xml))) {
    const attrs = {};
    for (const a of m[1].matchAll(ATTR)) {
      attrs[a[1]] = unescapeXml(a[2] !== undefined ? a[2] : a[3]);
    }
    const b = (attrs.bounds || '').match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
    nodes.push({
      id: attrs['resource-id'] || '',
      text: attrs.text || '',
      enabled: attrs.enabled === 'true',
      checked: attrs.checked === 'true',
      // Parola alanı (textPassword): dökümde metin yerine aynı uzunlukta "•" dizisi görünür.
      password: attrs.password === 'true',
      bounds: b ? b.slice(1).map(Number) : null,
    });
  }
  return nodes;
}

class Device {
  constructor(serial) {
    this.serial = serial;
  }

  /** `adb devices` içinde hazır ("device") durumdaki seri numaraları. */
  static connected() {
    return adbRaw(['devices'])
      .split('\n')
      .slice(1)
      .map((line) => line.trim().split(/\s+/))
      .filter((parts) => parts[1] === 'device')
      .map((parts) => parts[0]);
  }

  /**
   * AVD'yi pencere açmadan ve salt-okunur açar: AVD'ye kalıcı hiçbir şey
   * yazılmaz, kapatınca tüm değişiklikler gider.
   */
  static async bootEmulator(avd, { timeoutMs = 240_000 } = {}) {
    const before = new Set(Device.connected());
    const child = spawn(
      EMULATOR,
      ['-avd', avd, '-read-only', '-no-window', '-no-audio', '-no-boot-anim', '-no-snapshot-save'],
      { detached: true, stdio: 'ignore' },
    );
    child.unref();

    const deadline = Date.now() + timeoutMs;
    let serial = null;
    while (!serial && Date.now() < deadline) {
      await sleep(2000);
      serial = Device.connected().find((s) => s.startsWith('emulator-') && !before.has(s)) || null;
    }
    if (!serial) throw new Error(`Emülatör açılmadı: ${avd}`);

    const device = new Device(serial);
    while (Date.now() < deadline) {
      try {
        if (device.prop('sys.boot_completed') === '1') return device;
      } catch {
        /* henüz hazır değil */
      }
      await sleep(2000);
    }
    throw new Error(`Emülatör açılışı tamamlanmadı: ${avd}`);
  }

  isEmulator() {
    return this.serial.startsWith('emulator-');
  }

  adb(args, opts) {
    return adbRaw(['-s', this.serial, ...args], opts);
  }

  shell(command, opts) {
    return this.adb(['shell', command], opts);
  }

  prop(name) {
    return this.shell(`getprop ${name}`).trim();
  }

  /**
   * Cihazın duvar saati (epoch, ms). Emülatörün saati Mac'inkinden bir iki
   * saniye geride olabiliyor; yeni üretilmiş bir sunucu sertifikası
   * ("notBefore = şimdi") bu yüzden cihazda kısa süre "not valid until …"
   * diye reddedilebiliyor. Sertifika rotasyonu senaryoları bunu bekliyor.
   */
  epochMs() {
    return Number(this.shell('date +%s').trim()) * 1000;
  }

  /** Emülatörde animasyonları kapatır (UI dökümünü hızlandırır). Telefona dokunmaz. */
  disableAnimationsIfEmulator() {
    if (!this.isEmulator()) return;
    for (const key of ['window_animation_scale', 'transition_animation_scale', 'animator_duration_scale']) {
      this.shell(`settings put global ${key} 0`);
    }
  }

  screenshot() {
    return this.adb(['exec-out', 'screencap', '-p'], { encoding: 'buffer' });
  }

  /** Ekrandaki görünümler: resource-id, metin, etkinlik, sınırlar. */
  uiNodes() {
    let lastError;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const xml = this.shell('uiautomator dump /sdcard/pv-e2e-ui.xml >/dev/null 2>&1; cat /sdcard/pv-e2e-ui.xml');
        if (xml.includes('<hierarchy')) return parseNodes(xml);
        lastError = new Error('UI dökümü boş döndü');
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError;
  }

  /** Yazılım klavyesi açık mı (dumpsys input_method). */
  imeShown() {
    return /mInputShown=true/.test(this.shell('dumpsys input_method'));
  }

  /**
   * Yazılım klavyesini kapatır. Klavye açıkken GERİ tuşu yalnızca klavyeyi
   * kapatır (ekrandan çıkmaz); kapalıyken hiçbir şey gönderilmez, yoksa ekran
   * kapanırdı. ENTER işe yaramaz: enjekte edilen tuş IME'ye değil uygulamaya
   * gider, yani "Bitti" eylemi tetiklenmez.
   */
  hideIme() {
    for (let i = 0; i < 3 && this.imeShown(); i++) {
      this.pressBack();
      sleepSync(400);
    }
    return !this.imeShown();
  }

  /** Ekran çözünürlüğü ({ width, height }); `wm size` çıktısından. */
  screenSize() {
    if (!this._screen) {
      const m = this.shell('wm size').match(/(\d+)x(\d+)/);
      if (!m) throw new Error('Ekran boyutu okunamadı');
      this._screen = { width: Number(m[1]), height: Number(m[2]) };
    }
    return this._screen;
  }

  /** Ekranın ortasında yukarı/aşağı kaydırır ("down": içerik yukarı kayar). */
  swipeVertical(direction = 'down', fraction = 0.4, durationMs = 300) {
    const { width, height } = this.screenSize();
    const x = Math.round(width / 2);
    const delta = Math.round(height * fraction);
    // Başlangıç noktası ekranın üst yarısında: klavye açıkken bile kaydırma
    // uygulamaya gider, IME'ye değil. Uzun süre = yavaş sürükleme, fling yok.
    const [from, to] = direction === 'down'
      ? [Math.round(height * 0.45), Math.round(height * 0.45) - delta]
      : [Math.round(height * 0.25), Math.round(height * 0.25) + delta];
    this.shell(`input swipe ${x} ${from} ${x} ${to} ${durationMs}`);
  }

  tapCenter([x1, y1, x2, y2]) {
    this.shell(`input tap ${Math.round((x1 + x2) / 2)} ${Math.round((y1 + y2) / 2)}`);
  }

  /** Odaktaki alana yazar. Token'lar URL güvenli Base64'tür; tırnak gerekmez. */
  typeText(text) {
    if (!/^[A-Za-z0-9_\-.]+$/.test(text)) throw new Error(`Bu karakterler adb ile yazılamaz: ${text}`);
    this.shell(`input text ${text}`);
  }

  pressBack() {
    this.shell('input keyevent KEYCODE_BACK');
  }

  waitForDevice() {
    adbRaw(['-s', this.serial, 'wait-for-device'], { timeout: 60_000 });
  }

  /**
   * Cihaz adb komutlarına yanıt verene kadar bekler. Bir önceki test cihazı
   * geçiş halinde bıraktıysa (adbd yeniden başlıyor, emülatör meşgul) sonraki
   * testler anında düşmesin diye her test bununla başlar.
   */
  async ensureOnline(timeoutMs = 90_000) {
    const deadline = Date.now() + timeoutMs;
    let lastError;
    while (Date.now() < deadline) {
      try {
        if (this.shell('echo ok', { timeout: 10_000 }).trim() === 'ok') return;
      } catch (e) {
        lastError = e;
      }
      await sleep(1000);
    }
    throw new Error(`Cihaz yanıt vermiyor: ${this.serial}\n${lastError ? lastError.message : ''}`);
  }

  /**
   * [command]'ı root olarak çalıştırır. Yalnızca emülatör.
   *
   * userdebug emülatör imajlarındaki su, adbd'yi yeniden başlatmadan root komut
   * çalıştırır. "adb root" / "adb unroot" ise her seferinde adbd'yi yeniden
   * başlatır ve bu sırada gönderilen komut "closed" ile düşer; o yol yalnızca su
   * yoksa, modun gerçekten değiştiği doğrulanarak kullanılır.
   */
  rootShell(command) {
    if (!this.isEmulator()) throw new Error('root yalnızca emülatörde kullanılabilir');
    if (this.hasSu === undefined) {
      try {
        this.hasSu = this.shell('su 0 id -u', { timeout: 10_000 }).trim() === '0';
      } catch {
        this.hasSu = false;
      }
    }
    if (this.hasSu) return this.shell(`su 0 ${command}`);
    this.switchAdbd(true);
    try {
      return this.shell(command);
    } finally {
      this.switchAdbd(false);
    }
  }

  // ── Cihaz günlüğü (logcat) ─────────────────────────────────────────────

  /**
   * Logcat tamponunu boşaltır. Bir eylemin ürettiği satırları eskilerden
   * ayırmak için eylemden hemen önce çağrılır.
   */
  clearLogcat() {
    try {
      this.adb(['logcat', '-c'], { timeout: 20_000 });
      return true;
    } catch {
      // Bazı imajlarda "main" tamponu temizlenemez; süzme yine de çalışır.
      return false;
    }
  }

  /**
   * Logcat dökümünü döndürür (`logcat -d`). [match] verilirse yalnızca eşleşen
   * satırlar; [tags] verilirse yalnızca o etiketlerin satırları döner.
   * Kanıt paneline giren kütüphane log satırları böyle toplanır.
   */
  logcat({ match, tags, lines = 4000 } = {}) {
    let out;
    try {
      out = this.adb(['logcat', '-d', '-v', 'time', '-t', String(lines)], { timeout: 60_000 });
    } catch (e) {
      return `${e.stdout || ''}${e.stderr || ''}`;
    }
    let rows = out.split('\n');
    if (tags) {
      const set = Array.isArray(tags) ? tags : [tags];
      rows = rows.filter((row) => set.some((tag) => row.includes(`/${tag}`)));
    }
    if (match) rows = rows.filter((row) => match.test(row));
    return rows.join('\n').trim();
  }

  /** adbd'yi root ya da normal moda alır ve yeni modda yanıt verene kadar bekler. */
  switchAdbd(root) {
    const deadline = Date.now() + 90_000;
    let lastError;
    while (Date.now() < deadline) {
      try {
        // Zaten istenen moddaysa adb bunu söyleyip çıkar; tekrar istemek zararsız.
        adbRaw(['-s', this.serial, root ? 'root' : 'unroot'], { timeout: 30_000 });
        this.waitForDevice();
        const uid = this.shell('id -u', { timeout: 10_000 }).trim();
        if (root ? uid === '0' : uid !== '0') return;
      } catch (e) {
        lastError = e; // adbd yeniden başlarken bağlantı kopar ("closed")
      }
      sleepSync(1500);
    }
    throw new Error(`adbd ${root ? 'root' : 'normal'} moda geçmedi\n${lastError ? lastError.message : ''}`);
  }

  /**
   * Cihaz saatini Mac'in saatine eşitler (yalnızca emülatör).
   *
   * Emülatörün saati koşu boyunca geri kalıyor (bir de A18 gibi senaryolar
   * `auto_time`'ı kapatıp saati kaydırıyor). Onlarca saniyelik fark, sunucuda
   * o anda üretilmiş bir sertifikayı ("notBefore = şimdi") cihazda
   * "Certificate not valid until …" diye reddettiriyor: sertifika rotasyonu
   * senaryoları (A19, A20) bu yüzden ara ara düşüyordu. Fark eşiğin altındaysa
   * hiçbir şey yapılmaz.
   *
   * @return düzeltme yapıldıysa saniye cinsinden fark, yoksa 0
   */
  syncClockToHost(toleranceSeconds = 3) {
    if (!this.isEmulator()) return 0;
    try {
      const host = Math.floor(Date.now() / 1000);
      const device = Number(this.shell('date +%s', { timeout: 10_000 }).trim());
      const drift = host - device;
      if (!Number.isFinite(drift) || Math.abs(drift) <= toleranceSeconds) return 0;
      this.rootShell(`date @${host}`);
      return drift;
    } catch {
      // root yoksa ya da cihaz meşgulse senaryo yine de koşsun.
      return 0;
    }
  }

  /**
   * Cihaz saatini [seconds] kadar kaydırır (negatif geri alır). WorkManager
   * periyodik bir görevi zamanı gelmeden çalıştırmadığı için arka plan
   * güncellemesini sınamanın tek yolu budur. Yalnızca emülatör.
   */
  shiftClock(seconds) {
    this.shell('settings put global auto_time 0');
    const now = Number(this.shell('date +%s').trim());
    this.rootShell(`date @${now + seconds}`);
    const after = Number(this.shell('date +%s').trim());
    if (Math.abs(after - (now + seconds)) > 30) {
      throw new Error(`Saat kaydırılamadı: beklenen ~${now + seconds}, cihazda ${after}`);
    }
  }

  // ── Ağ kuralları (emülatör, su) ─────────────────────────────────────────

  /**
   * Telefondan [dstIp]:[dstPort]'a giden TCP'yi [toIp]:[toPort]'a yönlendirir
   * (iptables DNAT). Kurcalama vekili böyle araya girer. Kural bu nesnede
   * tutulur; [clearNetRules] geri alır.
   */
  redirectTcp(dstIp, dstPort, toPort, toIp = dstIp) {
    const spec = `-t nat OUTPUT -p tcp -d ${dstIp} --dport ${dstPort} -j DNAT --to-destination ${toIp}:${toPort}`;
    this.rootShell(`iptables ${spec.replace('OUTPUT', '-A OUTPUT')}`);
    (this.netRules ||= []).push(spec);
  }

  /**
   * [dstIp]:[dstPort]'a giden TCP'yi keser. [mode] "reject" ise bağlantı hemen
   * reddedilir, "drop" ise paketler sessizce düşer (zaman aşımı).
   */
  blockTcp(dstIp, dstPort, mode = 'reject') {
    const target = mode === 'drop' ? 'DROP' : 'REJECT';
    const spec = `OUTPUT -p tcp -d ${dstIp} --dport ${dstPort} -j ${target}`;
    this.rootShell(`iptables ${spec.replace('OUTPUT', '-A OUTPUT')}`);
    (this.netRules ||= []).push(spec);
  }

  /** Bu nesnenin eklediği bütün iptables kurallarını siler (yalnızca kendi kuralları). */
  clearNetRules() {
    const rules = this.netRules || [];
    this.netRules = [];
    for (const spec of rules.reverse()) {
      try {
        this.rootShell(`iptables ${spec.replace('OUTPUT', '-D OUTPUT')}`);
      } catch {
        /* kural zaten yok */
      }
    }
  }

  // ── Uygulama verisi (run-as; yalnızca debug derlemeleri) ───────────────

  /** Komutu uygulamanın kimliğiyle, uygulamanın veri dizininde çalıştırır. */
  runAs(pkg, command) {
    return this.shell(`run-as ${pkg} sh -c '${command.replace(/'/g, "'\\''")}'`);
  }

  /** Uygulama veri dizinindeki dosya listesi (`ls -la <dir>`). */
  appFiles(pkg, dir = '.') {
    return this.runAs(pkg, `ls -la ${dir}`);
  }

  /** Uygulama veri dizinindeki metin dosyası. */
  appFileText(pkg, file) {
    return this.runAs(pkg, `cat ${file}`);
  }

  /** Uygulama veri dizinindeki ikili dosya (Buffer). */
  appFileBytes(pkg, file) {
    return Buffer.from(this.runAs(pkg, `base64 ${file}`).replace(/\s+/g, ''), 'base64');
  }

  /**
   * Yerel dosyayı uygulamanın veri dizinine kopyalar (adb push + run-as).
   * Uygulama dizininin dışına yazamaz; [appPath] veri dizinine görelidir.
   */
  pushToApp(pkg, localFile, appPath) {
    const tmp = '/data/local/tmp/pv-e2e-push.bin';
    this.adb(['push', localFile, tmp]);
    this.shell(`chmod 644 ${tmp}`);
    this.runAs(pkg, `cp ${tmp} ${appPath}`);
    this.shell(`rm -f ${tmp}`);
  }

  /** `dumpsys jobscheduler` çıktısında paketin JobScheduler kayıt satırları (WorkManager işleri). */
  jobSchedulerJobs(pkg) {
    const dump = this.shell('dumpsys jobscheduler');
    const re = new RegExp(`JOB #u\\d+a\\d+/\\d+: \\S+ ${pkg.replace(/\./g, '\\.')}/`);
    return dump.split('\n').filter((row) => re.test(row)).map((row) => row.trim());
  }

  /** Paketin JobScheduler'daki (WorkManager) işlerini koşullara bakmadan hemen başlatır. */
  runScheduledJobs(pkg) {
    const dump = this.shell('dumpsys jobscheduler');
    const re = new RegExp(`JOB #u\\d+a\\d+/(\\d+): \\S+ ${pkg.replace(/\./g, '\\.')}/`, 'g');
    const ids = [...new Set([...dump.matchAll(re)].map((m) => m[1]))];
    for (const id of ids) this.shell(`cmd jobscheduler run -f ${pkg} ${id}`);
    return ids;
  }
}

module.exports = { Device, sleep };
