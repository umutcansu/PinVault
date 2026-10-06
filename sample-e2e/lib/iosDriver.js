// iOS UI sürücüsünün (ios-driver/, XCUITest) istemcisi: derler, arka planda
// başlatır, /health yanıt verene kadar bekler, ölmüşse yeniden başlatır ve
// koşu sonunda durdurur. İstekler eşzamanlıdır (curl): lib/ios.js'in
// yöntemleri lib/android.js'tekiler gibi eşzamanlı kalsın.
//
// Neden XCUITest: idb'nin dokunma/yazma yolu Xcode 27'de çalışmıyor
// (SimulatorKit'i eski yerinde arıyor). Sürücü bir UI test paketinin tek test
// yöntemidir; `xcodebuild test-without-building` onu çalıştırır ve test
// 127.0.0.1:<port> üzerinde HTTP isteklerini bekleyerek sürer.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync, spawn, spawnSync } = require('child_process');
const env = require('./env');

const DRIVER_DIR = path.join(env.ROOT, 'ios-driver');
const PROJECT = path.join(DRIVER_DIR, 'PinVaultDriver.xcodeproj');
const DERIVED = path.join(env.LOCAL_DIR, 'ios-driver-derived');
const STAMP = path.join(DERIVED, '.pinvault-driver-stamp');
const LOG_FILE = path.join(env.LOCAL_DIR, 'ios-driver.log');
const PID_FILE = path.join(env.LOCAL_DIR, 'ios-driver.pid');
/** XCTest'in sürücü için kurduğu çalıştırıcı uygulama. */
const RUNNER_BUNDLE = 'io.github.umutcansu.pinvault.driver.xctrunner';

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function port() {
  return env.IOS_DRIVER_PORT;
}

/** Sürücü kaynaklarının özeti: değişmediyse yeniden derlenmez. */
function sourcesHash() {
  const hash = crypto.createHash('sha256');
  const files = ['project.yml'];
  for (const dir of ['Driver', 'Host']) {
    for (const f of fs.readdirSync(path.join(DRIVER_DIR, dir)).sort()) files.push(path.join(dir, f));
  }
  for (const f of files) hash.update(`${f}\n`).update(fs.readFileSync(path.join(DRIVER_DIR, f)));
  return hash.digest('hex');
}

function xctestrun() {
  const products = path.join(DERIVED, 'Build/Products');
  if (!fs.existsSync(products)) return null;
  const file = fs.readdirSync(products).find((f) => /^PinVaultDriver_.*\.xctestrun$/.test(f));
  return file ? path.join(products, file) : null;
}

function run(file, args, opts = {}) {
  return execFileSync(file, args, {
    encoding: 'utf8',
    timeout: 15 * 60 * 1000,
    maxBuffer: 256 * 1024 * 1024,
    ...opts,
  });
}

/**
 * xcodegen + `xcodebuild build-for-testing` (.local/ios-driver-derived).
 * Kaynaklar değişmediyse ve derleme çıktısı yerindeyse hiçbir şey yapmaz.
 */
function build({ udid = env.IOS_UDID, force = false } = {}) {
  const hash = sourcesHash();
  if (!force && xctestrun() && fs.existsSync(STAMP) && fs.readFileSync(STAMP, 'utf8') === hash) {
    return '(iOS sürücüsü güncel, derlenmedi)';
  }
  try {
    run('xcodegen', ['generate', '--spec', 'project.yml', '--quiet'], { cwd: DRIVER_DIR, timeout: 120_000 });
  } catch (e) {
    throw new Error(`xcodegen çalışmadı (kurulu mu? brew install xcodegen): ${e.message}`);
  }
  let out;
  try {
    out = run('xcodebuild', [
      'build-for-testing',
      '-project', PROJECT,
      '-scheme', 'PinVaultDriver',
      '-sdk', 'iphonesimulator',
      '-destination', `platform=iOS Simulator,id=${udid}`,
      '-derivedDataPath', DERIVED,
    ], { cwd: DRIVER_DIR });
  } catch (e) {
    const log = `${e.stdout || ''}${e.stderr || ''}`;
    throw new Error(`iOS sürücüsü derlenemedi:\n${log.split('\n').filter((l) => /error|BUILD/.test(l)).slice(-30).join('\n')}`);
  }
  fs.mkdirSync(DERIVED, { recursive: true });
  fs.writeFileSync(STAMP, hash);
  return out.split('\n').filter((l) => /BUILD|warning: |error/.test(l)).slice(-10).join('\n');
}

/**
 * Sürücüye eşzamanlı bir HTTP isteği (curl). Bağlantı kurulamazsa (sürücü
 * ölmüş) bir kez yeniden başlatıp tekrar dener. HTTP ≥ 400 → hata
 * (e.status, e.body). Yanıtın JSON gövdesini döndürür.
 */
function request(method, pathname, body, { timeoutMs = 90_000, retry = true } = {}) {
  const url = `http://127.0.0.1:${port()}${pathname}`;
  const args = ['-sS', '-m', String(Math.max(1, Math.ceil(timeoutMs / 1000))), '-X', method, '-w', '\n%{http_code}'];
  if (body !== undefined) args.push('-H', 'Content-Type: application/json', '--data-binary', '@-');
  args.push(url);
  const res = spawnSync('curl', args, {
    input: body !== undefined ? JSON.stringify(body) : undefined,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs + 5000,
  });
  if (res.status !== 0) {
    // 7: bağlanılamadı, 52: boş yanıt, 56: bağlantı koptu → sürücü ölmüş olabilir.
    if (retry && [7, 52, 56].includes(res.status)) {
      ensure();
      return request(method, pathname, body, { timeoutMs, retry: false });
    }
    const e = new Error(`iOS sürücüsü: ${method} ${pathname} yanıt vermedi (curl ${res.status}): ${(res.stderr || '').trim()}`);
    e.code = 'DRIVER_UNAVAILABLE';
    throw e;
  }
  const out = res.stdout || '';
  const cut = out.lastIndexOf('\n');
  const status = Number(out.slice(cut + 1));
  let json;
  try {
    json = JSON.parse(out.slice(0, cut) || '{}');
  } catch {
    json = { raw: out.slice(0, cut) };
  }
  if (status >= 400) {
    const e = new Error(`iOS sürücüsü: ${method} ${pathname} → HTTP ${status}: ${json.error || json.raw || ''}`);
    e.status = status;
    e.body = json;
    throw e;
  }
  return json;
}

function healthy() {
  try {
    return request('GET', '/health', undefined, { timeoutMs: 3000, retry: false }).ok === true;
  } catch {
    return false;
  }
}

function readPid() {
  try {
    const pid = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function logTail(lines = 40) {
  try {
    return fs.readFileSync(LOG_FILE, 'utf8').split('\n').slice(-lines).join('\n');
  } catch {
    return '(log yok)';
  }
}

/**
 * Sürücüyü arka planda başlatır (`xcodebuild test-without-building`, çıktı
 * .local/ios-driver.log) ve /health yanıt verene kadar bekler. Zaten
 * çalışıyorsa hiçbir şey yapmaz.
 */
function start({ udid = env.IOS_UDID, timeoutMs = 180_000 } = {}) {
  if (healthy()) return;
  stop({ graceful: false });
  const testrun = xctestrun();
  if (!testrun) throw new Error(`iOS sürücüsü derlenmemiş (${DERIVED}); önce build()`);
  // Her koşu bir .xcresult bırakıyor; birikmesin.
  fs.rmSync(path.join(DERIVED, 'Logs/Test'), { recursive: true, force: true });
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  const log = fs.openSync(LOG_FILE, 'w');
  const child = spawn('xcodebuild', [
    'test-without-building',
    '-xctestrun', testrun,
    '-destination', `platform=iOS Simulator,id=${udid}`,
  ], {
    cwd: DRIVER_DIR,
    detached: true,
    stdio: ['ignore', log, log],
    env: {
      ...process.env,
      TEST_RUNNER_DRIVER_PORT: String(port()),
      TEST_RUNNER_DRIVER_BUNDLE: env.APP_ID,
      ...(process.env.E2E_IOS_DRIVER_WAIT_IDLE === '1' ? { TEST_RUNNER_DRIVER_WAIT_IDLE: '1' } : {}),
    },
  });
  child.unref();
  fs.closeSync(log);
  fs.writeFileSync(PID_FILE, String(child.pid));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (healthy()) return;
    if (!alive(child.pid)) break;
    sleepSync(500);
  }
  throw new Error(`iOS sürücüsü ${timeoutMs / 1000} sn'de açılmadı (127.0.0.1:${port()}). Log (${LOG_FILE}):\n${logTail()}`);
}

/** Sürücü yanıt vermiyorsa yeniden başlatır. */
function ensure(opts) {
  if (!healthy()) start(opts);
}

/**
 * Sürücüyü durdurur: önce /stop (test yöntemi biter, xcodebuild çıkar), olmazsa
 * xcodebuild süreç grubunu öldürür ve çalıştırıcı uygulamayı kapatır.
 */
function stop({ udid = env.IOS_UDID, graceful = true } = {}) {
  if (graceful) {
    try {
      request('POST', '/stop', {}, { timeoutMs: 5000, retry: false });
    } catch {
      /* zaten kapalı */
    }
  }
  const pid = readPid();
  if (pid) {
    const deadline = Date.now() + (graceful ? 10_000 : 0);
    while (alive(pid) && Date.now() < deadline) sleepSync(300);
    if (alive(pid)) {
      try {
        process.kill(-pid, 'SIGTERM');
      } catch {
        try {
          process.kill(pid, 'SIGTERM');
        } catch {
          /* yok */
        }
      }
    }
  }
  try {
    execFileSync('xcrun', ['simctl', 'terminate', udid, RUNNER_BUNDLE], { stdio: 'ignore', timeout: 30_000 });
  } catch {
    /* çalışmıyor */
  }
  fs.rmSync(PID_FILE, { force: true });
}

module.exports = { DRIVER_DIR, DERIVED, LOG_FILE, RUNNER_BUNDLE, build, start, ensure, stop, healthy, request, port };
