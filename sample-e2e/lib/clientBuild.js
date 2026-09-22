// SamplePinVaultClient'ı verilen host değerleriyle derler ve cihaza kurar.
// Kurulum yolculuğu (K06) ve sunucu sertifikası yenileme (E03) uygulamayı
// başka bir host'un değerleriyle yeniden derliyor; global setup da aynı yolu
// kullanır.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
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

/** `./gradlew assembleDebug -PsampleHostProps=<propsFile>`; çıktıyı döndürür. */
function build(propsFile) {
  const home = javaHome();
  return execFileSync('./gradlew', ['assembleDebug', `-PsampleHostProps=${propsFile}`], {
    cwd: env.CLIENT_DIR,
    encoding: 'utf8',
    timeout: 15 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, ...(home ? { JAVA_HOME: home } : {}) },
  });
}

function install(device) {
  return device.adb(['install', '-r', '-t', env.APK]);
}

function buildAndInstall(device, propsFile) {
  const out = build(propsFile);
  return `${out}\n$ adb install -r -t app-debug.apk\n${install(device)}`;
}

module.exports = { javaHome, build, install, buildAndInstall };
