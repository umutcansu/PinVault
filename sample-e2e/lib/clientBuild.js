// sample-client'ı verilen host değerleriyle derler ve cihaza kurar.
// Kurulum yolculuğu (K06) ve sunucu sertifikası yenileme (E03) uygulamayı
// başka bir host'un değerleriyle yeniden derliyor; global setup da aynı yolu
// kullanır. iOS koşusunda (E2E_PLATFORM=ios) derleme lib/iosBuild.js'e,
// kurulum simülatöre gider.
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const env = require('./env');

/** JAVA_HOME; yoksa Android Studio'nun ya da ~/Library/Java altındaki JDK 17. */
function javaHome() {
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

/** `${env.buildCommandFor(propsFile)}`; çıktıyı döndürür. */
function build(propsFile) {
  if (env.PLATFORM === 'ios') return require('./iosBuild').build(propsFile);
  const home = javaHome();
  return execFileSync('./gradlew', [...env.GRADLE_BUILD, `-PsampleHostProps=${propsFile}`], {
    cwd: env.CLIENT_DIR,
    encoding: 'utf8',
    timeout: 15 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, ...(home ? { JAVA_HOME: home } : {}) },
  });
}

function install(device) {
  return device.installApp(env.APP_ARTIFACT);
}

function buildAndInstall(device, propsFile) {
  const out = build(propsFile);
  return `${out}\n$ ${device.installCommandLabel(path.basename(env.APP_ARTIFACT))}\n${install(device)}`;
}

// ── Derleme çıktısı (APK dosyası ya da .app dizini) ──────────────────────

/** iOS .app'in çalıştırılabilir dosyası (Info.plist → CFBundleExecutable). */
function appExecutable(appDir) {
  try {
    const name = execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', path.join(appDir, 'Info.plist')], {
      encoding: 'utf8',
    }).trim();
    return path.join(appDir, name);
  } catch {
    return null;
  }
}

/**
 * .app'in kodunu taşıyan dosyalar: çalıştırılabilir dosya ve (Debug
 * derlemesinde Xcode kodu ayrı bir "<ad>.debug.dylib"e koyar) kökteki dylib'ler.
 */
function appCodeFiles(appDir) {
  const exe = appExecutable(appDir);
  const dylibs = fs.readdirSync(appDir).filter((f) => f.endsWith('.dylib')).sort().map((f) => path.join(appDir, f));
  return [...(exe && fs.existsSync(exe) ? [exe] : []), ...dylibs];
}

/**
 * Derleme çıktısına gömülü bir sabit (ör. host.signingPublicKey) geçiyor mu:
 * APK'da dex'ler, .app'te çalıştırılabilir dosya (Swift metin sabitleri düz durur).
 */
function artifactEmbeds(file, needle) {
  if (!needle || !fs.existsSync(file)) return false;
  if (fs.statSync(file).isDirectory()) {
    const bytes = Buffer.from(needle, 'utf8');
    return appCodeFiles(file).some((f) => fs.readFileSync(f).includes(bytes));
  }
  const res = spawnSync('sh', ['-c', 'unzip -p "$1" "classes*.dex" | grep -a -c -F -- "$2"', 'sh', file, needle], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  return Number((res.stdout || '0').trim()) > 0;
}

/** Derleme çıktısının bayt kopyası (dosya ya da dizin; hedef önce silinir). */
function copyArtifact(src, dest) {
  if (fs.statSync(src).isDirectory()) {
    fs.rmSync(dest, { recursive: true, force: true });
    fs.cpSync(src, dest, { recursive: true, verbatimSymlinks: true });
  } else {
    fs.copyFileSync(src, dest);
  }
}

/** Derleme çıktısının SHA-256'sı: APK dosyası; .app için kod dosyaları + Info.plist. */
function artifactHash(file) {
  const hash = crypto.createHash('sha256');
  if (fs.statSync(file).isDirectory()) {
    for (const f of appCodeFiles(file)) hash.update(fs.readFileSync(f));
    hash.update(fs.readFileSync(path.join(file, 'Info.plist')));
  } else {
    hash.update(fs.readFileSync(file));
  }
  return hash.digest('hex');
}

module.exports = { javaHome, build, install, buildAndInstall, artifactEmbeds, copyArtifact, artifactHash, appCodeFiles };
