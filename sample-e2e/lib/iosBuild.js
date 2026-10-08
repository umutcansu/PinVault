// sample-client-ios'u verilen host değerleriyle derler (XcodeGen + xcodebuild)
// ve simülatöre kurar. lib/clientBuild.js iOS koşusunda buraya yönlenir.
//
//   cd sample-client-ios && xcodegen generate
//   SAMPLE_HOST_PROPS=<props> xcodebuild -project SampleClient.xcodeproj -scheme SampleClient \
//     -configuration Debug|E2E -sdk iphonesimulator -destination 'platform=iOS Simulator,id=<udid>' \
//     -derivedDataPath ../sample-e2e/.local/ios-derived build
//
// Uygulamanın derleme öncesi betiği (scripts/gen-host-config.sh) host
// değerlerini SAMPLE_HOST_PROPS'tan okur (PORTING.md §7).
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./env');

const LOG_FILE = path.join(env.LOCAL_DIR, 'ios-build.log');

function checkProject() {
  if (!fs.existsSync(env.IOS_CLIENT_DIR)) {
    throw new Error(`iOS örnek uygulaması yok: ${env.IOS_CLIENT_DIR} (E2E_IOS_CLIENT_DIR)`);
  }
}

/** project.yml varsa Xcode projesini yeniden üretir (çıktıyı döndürür). */
function generateProject() {
  checkProject();
  if (!fs.existsSync(path.join(env.IOS_CLIENT_DIR, 'project.yml'))) return '';
  try {
    return execFileSync('xcodegen', ['generate', '--quiet'], { cwd: env.IOS_CLIENT_DIR, encoding: 'utf8', timeout: 120_000 });
  } catch (e) {
    throw new Error(`xcodegen generate (${env.IOS_CLIENT_DIR}) başarısız: ${e.stderr || e.message}`);
  }
}

/**
 * Derler; çıktının özetini (props dosyası, uyarı/hata satırları, son satırlar,
 * "** BUILD SUCCEEDED **") döndürür. Tam log .local/ios-build.log'da.
 */
function build(propsFile) {
  generateProject();
  let out;
  try {
    out = execFileSync('xcodebuild', env.IOS_BUILD, {
      cwd: env.IOS_CLIENT_DIR,
      encoding: 'utf8',
      timeout: 30 * 60 * 1000,
      maxBuffer: 512 * 1024 * 1024,
      env: { ...process.env, SAMPLE_HOST_PROPS: propsFile },
    });
  } catch (e) {
    const log = `${e.stdout || ''}${e.stderr || ''}`;
    fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
    fs.writeFileSync(LOG_FILE, log);
    const errors = log.split('\n').filter((l) => /error:|BUILD FAILED|\*\* BUILD/.test(l)).slice(-40).join('\n');
    const err = new Error(`sample-client-ios derlenemedi (tam log: ${LOG_FILE}):\n${errors}`);
    err.output = log;
    throw err;
  }
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  fs.writeFileSync(LOG_FILE, out);
  if (!fs.existsSync(env.IOS_APP)) throw new Error(`Derleme bitti ama uygulama yok: ${env.IOS_APP} (E2E_IOS_APP_NAME?)`);
  const lines = out.split('\n');
  const notable = lines.filter((l) => /warning: |error:|gen-host-config|SampleHostConfig/.test(l)).slice(-15);
  return [
    `SAMPLE_HOST_PROPS=${propsFile}`,
    ...notable,
    '…',
    ...lines.filter((l) => l.trim()).slice(-3),
  ].join('\n');
}

function install(device) {
  return device.installApp(env.IOS_APP);
}

module.exports = { LOG_FILE, generateProject, build, install };
