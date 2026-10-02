// Önceki sürüm: örnek uygulamanın PinVault 2.0.9 ile yayımlanmış ilk hâli
// (`sample-client-2.0.9` etiketi), kütüphane Maven Central'dan
// (pinvault.localPath boş) derlenir. Sürüm yükseltme senaryosu (U01) bunu
// kurup üstüne güncel APK'yı kurar.
//
// E2E_OLD_CLIENT_REF ile başka bir etiket, dal ya da commit seçilebilir;
// kütüphane sürümü o commit'teki örnek uygulamanın gradle.properties'indeki
// pinvault.version'dır.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./env');
const { javaHome } = require('./clientBuild');

const GIT = fs.existsSync('/Library/Developer/CommandLineTools/usr/bin/git')
  ? '/Library/Developer/CommandLineTools/usr/bin/git'
  : 'git';
const REF = process.env.E2E_OLD_CLIENT_REF || 'sample-client-2.0.9';
const DIR = path.join(env.LOCAL_DIR, 'upgrade');
/** Önceki sürümün worktree'si; örnek uygulama içinde [prefix] altında. */
const TREE = path.join(DIR, 'sample-client-old');

function git(args, cwd = env.CLIENT_DIR) {
  return execFileSync(GIT, args, { cwd, encoding: 'utf8', timeout: 120_000 }).trim();
}

/** Örnek uygulamanın depodaki yolu: "sample-client/" (ayrı bir depoysa ""). */
function prefix() {
  return git(['rev-parse', '--show-prefix']);
}

/** Worktree'deki örnek uygulama. */
function appDir() {
  return path.join(TREE, prefix());
}

function gradle(args) {
  const home = javaHome();
  return execFileSync('./gradlew', args, {
    cwd: appDir(),
    encoding: 'utf8',
    timeout: 15 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, ...(home ? { JAVA_HOME: home } : {}) },
  });
}

/** Önceki sürümün kaynağı: dal, commit ve kullandığı PinVault sürümü. */
function info() {
  const commit = git(['rev-parse', '--short', REF]);
  const version = (git(['show', `${commit}:${prefix()}gradle.properties`]).match(/^pinvault\.version=(\S+)$/m) || [])[1];
  if (!version) throw new Error(`${REF}:gradle.properties içinde pinvault.version yok`);
  return { ref: REF, commit, version };
}

/**
 * Önceki sürümün debug APK'sı. Yoksa derler: commit'in worktree'si, Maven
 * Central'daki kütüphane, verilen host değerleri. Önbellek anahtarı commit +
 * sürüm + host değerleri. { file, built, log, dependency, ref, commit, version }
 */
function buildApk(propsFile) {
  const src = info();
  const stamp = crypto
    .createHash('sha256')
    .update(`${src.commit}\n${src.version}\n${fs.readFileSync(propsFile, 'utf8')}`)
    .digest('hex')
    .slice(0, 12);
  const file = path.join(DIR, `sample-${src.commit}-pinvault-${src.version}-${stamp}.apk`);
  const depFile = `${file}.dependency.txt`;
  if (fs.existsSync(file) && fs.existsSync(depFile)) {
    return { ...src, file, built: false, log: '', dependency: fs.readFileSync(depFile, 'utf8') };
  }
  fs.mkdirSync(DIR, { recursive: true });
  if (!fs.existsSync(TREE)) git(['worktree', 'add', '--detach', TREE, src.commit]);
  else git(['checkout', '--detach', src.commit], TREE);
  const localProps = path.join(env.CLIENT_DIR, 'local.properties');
  if (fs.existsSync(localProps)) fs.copyFileSync(localProps, path.join(appDir(), 'local.properties'));
  // pinvault.localPath boş: settings.gradle.kts yerel kaynağı değil Maven Central'ı kullanır.
  const log = gradle(['assembleDebug', '-Ppinvault.localPath=', `-PsampleHostProps=${propsFile}`]);
  const dependency = gradle(['-q', 'app:dependencies', '--configuration', 'debugRuntimeClasspath', '-Ppinvault.localPath=', `-PsampleHostProps=${propsFile}`])
    .split('\n')
    .filter((line) => line.includes('io.github.umutcansu:pinvault'))
    .slice(0, 1)
    .join('\n')
    .trim();
  fs.copyFileSync(path.join(appDir(), 'app/build/outputs/apk/debug/app-debug.apk'), file);
  fs.writeFileSync(depFile, dependency);
  for (const f of fs.readdirSync(DIR)) {
    if (/^sample-.*\.apk(\.dependency\.txt)?$/.test(f) && !f.startsWith(path.basename(file))) fs.rmSync(path.join(DIR, f), { force: true });
  }
  return { ...src, file, built: true, log, dependency };
}

module.exports = { info, buildApk };
