// İmza anahtarı senaryolarının (S01–S05) ortak laboratuvarı: taze host,
// laboratuvar çevrimdışı anahtarları, bu anahtarlara güvenen "lab" APK'sı,
// operatör komutlarının kanıt paneli ve geri dönüş (ana APK, taze host'un
// ortamı ve anahtar dosyası).
//
// Neden taze host: imzalama anahtarını değiştiren ya da anahtar seti yayımlayan
// (setler sunucuda yalnızca eklenir, geri alınamaz) senaryolar ana host'ta
// koşsaydı telefondaki ana APK'nın güvendiği anahtarlar bayatlar ve bütün
// suite çökerdi.
//
// Lab APK'sının derleme değerleri taze host'un client-config.sh çıktısıdır;
// yalnızca imza katmanları ezilir:
//   host.signingPublicKeys = <taze host'un birincil anahtarı>, lab-backup, lab-second
//   host.recoveryPublicKeys = lab-recovery
// APK derleme değerlerinin (ve ana APK'nın) SHA-256'sına göre
// .local/apk-cache altında saklanır: aynı koşudaki S01–S05 tek derlemeyi
// paylaşır. Gradle çıktısı (env.APK) ana APK'nın yoludur; lab derlemesinden
// sonra ana APK'nın yedeği geri yazılır, yani env.APK her zaman ana host'a göre
// derlenmiş APK olarak kalır ve senaryolar finally'de onu kurar.
//
// iOS koşusunda "APK" derleme çıktısıdır (env.APP_ARTIFACT: .app dizini,
// .local/ios-derived altında); kopyalama, gömülü anahtar araması ve kurulum
// lib/clientBuild.js ile cihaz nesnesinden geçer.
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const env = require('./env');
const fresh = require('./freshHost');
const offlineKeys = require('./offlineKeys');
const clientBuild = require('./clientBuild');
const { attachText } = require('./evidence');

/** Laboratuvar dosyaları (props, anahtar seti JSON'ları, anahtar yedeği); git dışı. */
const LAB_DIR = path.join(env.LOCAL_DIR, 'signing-lab');
const CACHE_DIR = path.join(env.LOCAL_DIR, 'apk-cache');
const LAB_PROPS = path.join(LAB_DIR, 'lab.properties');
/** S01: taze host'un özgün birincil anahtar dosyasının kopyası (0600). */
const PRIMARY_BACKUP = path.join(LAB_DIR, 'fresh-signing-key.orig.pem');
/** Taze host dizininden (komutların cwd'si) laboratuvar dizinlerine göreli yollar. */
const REL_KEYS = path.relative(fresh.DIR, env.OFFLINE_KEYS_DIR);
const REL_LAB = path.relative(fresh.DIR, LAB_DIR);

/** Laboratuvar anahtarlarının adları (.local/offline-keys/<ad>.{pem,pub}). */
const KEYS = { backup: 'lab-backup', second: 'lab-second', recovery: 'lab-recovery', next: 'lab-next' };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

/** "abcdefghijkl…" — anahtar kimliklerinin okunur kısaltması (telefon 12 karakter gösterir). */
function short(id, n = 12) {
  return `${String(id).slice(0, n)}…`;
}

/** Bir .properties metnindeki anahtarın değeri. */
function propValue(text, key) {
  const line = text.split('\n').find((l) => l.startsWith(`${key}=`));
  return line ? line.slice(key.length + 1).trim() : '';
}

function setProp(text, key, value) {
  const re = new RegExp(`^${key.replace(/\./g, '\\.')}=.*$`, 'm');
  return re.test(text) ? text.replace(re, `${key}=${value}`) : `${text.replace(/\n*$/, '\n')}${key}=${value}\n`;
}

// ── Taze host: komutlar, ortam, yeniden başlatma ───────────────────────────

/**
 * Taze host'un betiğini kendi dizininde çalıştırır. Çevrimdışı anahtarlar
 * harness'ın dizininden okunur (OFFLINE_KEYS_DIR). Varsayılan olarak stderr
 * stdout'a yazıldığı sırayla karışır (terminalde görüneceği gibi); [merge]
 * false ise yalnızca stdout döner (ör. ayrıştırılacak .properties çıktısı).
 * Çıkış kodu ≠ 0 ise hata fırlatılır (çıktı hata nesnesinde).
 */
function run(file, args = [], { env: extra = {}, input, merge = true } = {}) {
  const [cmd, argv] = merge ? ['sh', ['-c', 'exec "$0" "$@" 2>&1', file, ...args]] : [file, args];
  const res = spawnSync(cmd, argv, {
    cwd: fresh.DIR,
    encoding: 'utf8',
    timeout: 5 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    input,
    env: { ...process.env, OFFLINE_KEYS_DIR: REL_KEYS, ...extra },
  });
  const out = merge ? res.stdout || '' : res.status === 0 ? res.stdout || '' : `${res.stdout || ''}${res.stderr || ''}`;
  if (res.error || res.status !== 0) {
    const e = new Error(`${file} ${args.join(' ')} → exit ${res.status}\n${out}${res.error ? res.error.message : ''}`);
    e.output = out;
    e.status = res.status;
    throw e;
  }
  return out;
}

/**
 * Operatör komutu: çalıştırır ve "$ <display>" + çıktıyı metin paneline
 * ekler (panel komut başarısız olsa da eklenir). [display] panelde görünen
 * komut satırıdır — gizli değer (PIN, API anahtarı) içermemeli; uzun public
 * key'ler operatörün yazacağı biçimde "$(cat …pub)" olarak gösterilir.
 * [note] panelin sonuna eklenen açıklama; fonksiyonsa komut başarılı olduktan
 * sonra çıktıyla çağrılır (ör. komutun yazdığı dosyanın özeti).
 */
async function op(testInfo, title, { display, file, args = [], env: extra, input, note }) {
  let out;
  let error;
  try {
    out = run(file, args, { env: extra, input });
  } catch (e) {
    error = e;
    out = `${e.output || e.message}\n[exit ${e.status}]`;
  }
  const noteText = typeof note === 'function' ? (error ? '' : note(out)) : note;
  const header = `(cwd: .local/host-fresh — geçici test sunucusunun dizini; OFFLINE_KEYS_DIR=${REL_KEYS})`;
  await attachText(testInfo, title, [header, `$ ${display}`, out.trimEnd(), ...(noteText ? ['', noteText] : [])].join('\n'));
  if (error) throw error;
  return out;
}

/** Container'ın o anki ortamı (docker inspect). */
function containerEnv() {
  try {
    const raw = execFileSync('docker', ['inspect', '-f', '{{json .Config.Env}}', fresh.CONTAINER], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    return Object.fromEntries(JSON.parse(raw).map((kv) => [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)]));
  } catch {
    return {};
  }
}

/** Senaryoların geçici olarak ezdiği ortam değişkenleri; biri doluysa taze host varsayılanda değil. */
const OVERRIDE_KEYS = [
  'CONFIG_SIGNERS',
  'CONFIG_SIGNATURE_CACHE',
  'RECOVERY_PUBLIC_KEYS',
  'SIGNER_COMMAND',
  'SIGNER_PUBLIC_KEY_FILE',
  'SIGNER_INPUT',
  'PKCS11_GENERATE_KEY',
];

function envOverridden() {
  const current = containerEnv();
  return OVERRIDE_KEYS.some((k) => (current[k] || '') !== '');
}

/** Taze host'un Config API dinleyicisi (6751) el sıkışıp /health'e yanıt verene kadar bekler. */
async function waitConfigApi(timeoutMs = 90_000) {
  const probe = () =>
    new Promise((resolve) => {
      const req = https.request(
        { host: 'localhost', port: fresh.PORTS.https, path: '/health', rejectUnauthorized: false, agent: false, timeout: 5000 },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200);
        },
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      req.end();
    });
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await fresh.isHealthy()) && (await probe())) return;
    await sleep(1000);
  }
  throw new Error(`Geçici test sunucusunun Config API'si (${fresh.PORTS.https}) ${timeoutMs / 1000} sn'de yanıt vermedi`);
}

/**
 * Taze host'un ortamını geçici değerlerle yeniden oluşturur
 * (scripts/env-override.sh set …). Her çağrı öncekini EZER: kalıcı olması
 * gereken değerler (ör. RECOVERY_PUBLIC_KEYS) her seferinde yeniden verilir.
 * [display] panelde görünen komut satırı. Paneli ekler, çıktıyı döndürür.
 */
async function setEnv(testInfo, title, overrides, { display, note } = {}) {
  const args = ['set', ...Object.entries(overrides).map(([k, v]) => `${k}=${v}`)];
  const out = await op(testInfo, title, {
    display: display || `./scripts/env-override.sh ${args.join(' ')}`,
    file: './scripts/env-override.sh',
    args,
    note,
  });
  await waitConfigApi();
  return out;
}

/** Taze host'u .env değerlerine döndürür (env-override.sh reset); ezme yoksa hiçbir şey yapmaz. */
async function resetEnv({ force = false } = {}) {
  if (!force && !envOverridden()) return '(ortam zaten .env değerlerinde)';
  const out = run('./scripts/env-override.sh', ['reset']);
  await waitConfigApi();
  return out.trim();
}

/** Taze host'un container'ını yeniden başlatır (docker compose restart) ve dinleyicileri bekler. */
async function restart() {
  const out = run('docker', ['compose', 'restart', 'pinvault-host']);
  await fresh.waitHealthy();
  await waitConfigApi();
  return out.trim();
}

// ── Taze host: imza durumu ─────────────────────────────────────────────────

/** GET /api/v1/signing-key (herkese açık): birincil anahtar, imzalayıcılar, set sürümü. */
async function signingKeyInfo() {
  const r = await fresh.api('/api/v1/signing-key', { withKey: false });
  if (r.status !== 200) throw new Error(`geçici test sunucusu: GET /api/v1/signing-key → HTTP ${r.status}`);
  return r.json;
}

/** GET /api/v1/signing/status (yönetici): imzalayıcı türleri, önbellek, anahtar seti. */
async function signingStatus() {
  const r = await fresh.api('/api/v1/signing/status');
  if (r.status !== 200) throw new Error(`geçici test sunucusu: GET /api/v1/signing/status → HTTP ${r.status} ${r.text}`);
  return r.json;
}

/** Sunucudaki anahtar seti tablosu yalnızca eklenir: sıradaki sürüm = son sürüm + 1. */
async function nextKeySetVersion() {
  const status = await signingStatus();
  return ((status.keySet && status.keySet.version) || 0) + 1;
}

/** İmzalayıcı listesinin okunur özeti (panel için). */
function describeSigners(signers) {
  return (signers || [])
    .map((s, i) => `  ${i === 0 ? '*' : ' '} ${String(s.name || '').padEnd(12)} ${String(s.type || '').padEnd(7)} ${short(s.keyId, 16)}  ${s.description || ''}`)
    .join('\n');
}

// ── Taze host: birincil anahtar dosyası (S01) ──────────────────────────────

const freshKeyFile = () => path.join(fresh.DIR, 'data/signing-key.pem');

/** Taze host'un birincil anahtar dosyasını yedekler; zaten yedek varsa dokunmaz (özgün olanı korur). */
function savePrimaryKeyFile() {
  fs.mkdirSync(LAB_DIR, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(PRIMARY_BACKUP)) fs.copyFileSync(freshKeyFile(), PRIMARY_BACKUP);
  fs.chmodSync(PRIMARY_BACKUP, 0o600);
  return PRIMARY_BACKUP;
}

/** Yedek varsa özgün anahtar dosyasını geri koyar ve yedeği siler; geri koyduysa true. */
function restorePrimaryKeyFile() {
  if (!fs.existsSync(PRIMARY_BACKUP)) return false;
  fs.copyFileSync(PRIMARY_BACKUP, freshKeyFile());
  fs.chmodSync(freshKeyFile(), 0o600);
  fs.rmSync(PRIMARY_BACKUP, { force: true });
  return true;
}

/**
 * Taze host'u varsayılan imza durumuna getirir: yarıda kalmış bir senaryo
 * birincil anahtarı yedekle değiştirmiş ya da ortamı ezmiş olabilir. Lab
 * APK'sı taze host'un BİRİNCİL anahtarıyla derlendiği için bu, derlemeden önce
 * yapılır.
 */
async function ensureFresh() {
  await fresh.ensure();
  let restarted = false;
  if (restorePrimaryKeyFile()) {
    await restart();
    restarted = true;
  }
  if (envOverridden()) {
    await resetEnv({ force: true });
    restarted = true;
  }
  if (!restarted) await waitConfigApi();
}

// ── Laboratuvar anahtarları ────────────────────────────────────────────────

/** [name] anahtarı; yoksa operatör betiğiyle (signing-keys.sh gen) üretilir. */
function ensureKey(name) {
  if (!fs.existsSync(path.join(env.OFFLINE_KEYS_DIR, `${name}.pem`))) {
    run('./scripts/signing-keys.sh', ['gen', name]);
  }
  return offlineKeys.ensure(name);
}

function labKeys() {
  return { backup: ensureKey(KEYS.backup), second: ensureKey(KEYS.second), recovery: ensureKey(KEYS.recovery) };
}

/**
 * Operatörün çevrimdışı anahtarı üretmesi ya da göstermesi: yoksa
 * `signing-keys.sh gen <ad>`, varsa `signing-keys.sh pub <ad>`; ardından
 * dosya izinleri. Özel yarının içeriği hiçbir zaman panele girmez.
 */
async function showKey(testInfo, name, title) {
  const exists = fs.existsSync(path.join(env.OFFLINE_KEYS_DIR, `${name}.pem`));
  const args = exists ? ['pub', name] : ['gen', name];
  const out = run('./scripts/signing-keys.sh', args);
  const key = offlineKeys.ensure(name);
  const perms = (file) => (fs.statSync(file).mode & 0o777).toString(8);
  await attachText(
    testInfo,
    title || `Çevrimdışı anahtar: ${name}`,
    [
      `(cwd: .local/host-fresh; OFFLINE_KEYS_DIR=${REL_KEYS})`,
      `$ OFFLINE_KEYS_DIR=${REL_KEYS} ./scripts/signing-keys.sh ${args.join(' ')}`,
      out.trimEnd(),
      exists ? '(anahtar daha önceki bir koşuda "gen" ile üretildi; üzerine yazılmaz)' : '',
      '',
      `$ ls -l ${REL_KEYS}/${name}.*`,
      `${perms(key.pemFile)}  ${name}.pem   ← private key: çevrimdışı kalır, sunucuya ve bu sayfaya hiç girmez`,
      `${perms(key.pubFile)}  ${name}.pub   ← APK'ya gömülen public key (Base64 SPKI)`,
      '',
      `public key     : ${key.pub.slice(0, 32)}…${key.pub.slice(-12)}`,
      `anahtar kimliği: ${key.keyId}   (SHA-256(SPKI), telefonun ve sunucunun gösterdiği biçim)`,
    ]
      .filter((l) => l !== '')
      .join('\n'),
  );
  return key;
}

// ── Lab APK'sı ─────────────────────────────────────────────────────────────

/** APK'nın dex'lerinde (iOS: .app'in çalıştırılabilir dosyasında) [needle] geçiyor mu (BuildConfig sabitleri düz metin durur). */
function apkEmbeds(apkFile, needle) {
  return clientBuild.artifactEmbeds(apkFile, needle);
}

/** Önbellekteki derleme çıktılarının uzantısı (.apk ya da .app). */
const EXT = env.APP_ARTIFACT_EXT;
const cachedName = (prefix) => new RegExp(`^${prefix}-.*\\${EXT}$`);

function mainPropsText() {
  return fs.readFileSync(env.PROPS_FILE, 'utf8');
}

/** env.APK (iOS: env.APP_ARTIFACT) ana host'a göre mi derlenmiş (ana imzalama anahtarı dex'te mi). */
function isMainApk(file = env.APP_ARTIFACT) {
  return apkEmbeds(file, propValue(mainPropsText(), 'host.signingPublicKey'));
}

/**
 * Ana APK'nın bayt kopyası (.local/apk-cache/main-<props>.apk). env.APK ana
 * derleme değilse (ör. yarıda kalmış bir lab derlemesi) önce ana değerlerle
 * yeniden derlenir.
 */
function mainApkBackup() {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  const file = path.join(CACHE_DIR, `main-${sha256Hex(mainPropsText()).slice(0, 16)}${EXT}`);
  if (!isMainApk()) {
    if (fs.existsSync(file) && isMainApk(file)) {
      clientBuild.copyArtifact(file, env.APP_ARTIFACT);
    } else {
      clientBuild.build(env.PROPS_FILE);
    }
  }
  if (!isMainApk()) throw new Error(`env.APK ana host değerleriyle derlenmiş görünmüyor: ${env.APP_ARTIFACT}`);
  clientBuild.copyArtifact(env.APP_ARTIFACT, file);
  for (const f of fs.readdirSync(CACHE_DIR)) {
    if (cachedName('main').test(f) && path.join(CACHE_DIR, f) !== file) fs.rmSync(path.join(CACHE_DIR, f), { force: true, recursive: true });
  }
  return file;
}

/**
 * Lab derleme değerleri: taze host'un client-config.sh çıktısı + imza
 * katmanlarının ezilmesi. Dosyayı (değiştiyse) yazar; { text, primary, keys }.
 */
async function writeLabProps(keys) {
  const base = run('./scripts/client-config.sh', env.CLIENT_CONFIG_ARGS, { merge: false });
  const info = await signingKeyInfo();
  const trusted = [info.publicKey, keys.backup.pub, keys.second.pub];
  let text = base;
  text = setProp(text, 'host.signingPublicKeys', trusted.join(','));
  text = setProp(text, 'host.requiredSignatures', '1');
  text = setProp(text, 'host.recoveryPublicKeys', keys.recovery.pub);
  text = `# sample-e2e lib/signingLab.js: taze host değerleri + laboratuvar imza anahtarları.\n${text}`;
  fs.mkdirSync(LAB_DIR, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(LAB_PROPS) || fs.readFileSync(LAB_PROPS, 'utf8') !== text) fs.writeFileSync(LAB_PROPS, text);
  return { text, primary: { publicKey: info.publicKey, keyId: info.keyId } };
}

/**
 * Lab APK'sını hazırlar (önbellekte yoksa derler) ve kurar. Önbellek anahtarı
 * derleme değerleri + ana APK'nın baytları: kütüphane ya da uygulama kodu
 * değişince ana APK değişir, lab APK'sı da yeniden derlenir.
 */
function installLabApk(device, propsText) {
  const mainBackup = mainApkBackup();
  const stamp = sha256Hex(`${propsText}\n${clientBuild.artifactHash(mainBackup)}`).slice(0, 16);
  const file = path.join(CACHE_DIR, `lab-${stamp}${EXT}`);
  let built = false;
  let log = '';
  if (!fs.existsSync(file)) {
    try {
      log = clientBuild.build(LAB_PROPS);
      clientBuild.copyArtifact(env.APP_ARTIFACT, file);
      built = true;
    } finally {
      // Gradle (iOS: xcodebuild) çıktısı ana APK'nın yolu: ana APK geri yazılır.
      clientBuild.copyArtifact(mainBackup, env.APP_ARTIFACT);
    }
    for (const f of fs.readdirSync(CACHE_DIR)) {
      if (cachedName('lab').test(f) && f !== path.basename(file)) fs.rmSync(path.join(CACHE_DIR, f), { force: true, recursive: true });
    }
  }
  const installOut = device.installApp(file);
  return { file, built, log, installOut };
}

/** Cihazda kurulu APK'nın yolu ve SHA-256'sı ("uygulama güncellenmedi" kanıtı). */
function installedApk(device) {
  return device.installedAppInfo(env.APP_ID);
}

/**
 * Laboratuvarı kurar: cihaz çevrimiçi ve saati hizalı, taze host varsayılan
 * imza durumunda, lab anahtarları var, lab APK'sı kurulu. Derleme değerlerini
 * ve güvenilen anahtar kimliklerini panele ekler.
 */
async function setup(device, testInfo, { title = 'Bu test için derlenen uygulama: güvendiği imza anahtarları (derleme değerleri)' } = {}) {
  await device.ensureOnline();
  device.syncClockToHost();
  await ensureFresh();
  const keys = labKeys();
  const { text, primary } = await writeLabProps(keys);
  const apk = installLabApk(device, text);
  const lines = [
    `$ ./scripts/client-config.sh --properties   (geçici test sunucusu) → ${path.relative(env.ROOT, LAB_PROPS)}`,
    '  yalnızca imzayla ilgili değerler değiştirildi:',
    `  host.signingPublicKeys = <sunucunun birincil anahtarı>,<${KEYS.backup}.pub>,<${KEYS.second}.pub>`,
    `  host.requiredSignatures = 1`,
    `  host.recoveryPublicKeys = <${KEYS.recovery}.pub>`,
    '',
    'APK\'nın güvendiği imza anahtarları (anahtar kimliği = SHA-256(SPKI)):',
    `  ${'sunucunun birincil anahtarı'.padEnd(27)} : ${primary.keyId}   (GET /api/v1/signing-key)`,
    `  ${KEYS.backup.padEnd(27)} : ${keys.backup.keyId}   (çevrimdışı yedek)`,
    `  ${KEYS.second.padEnd(27)} : ${keys.second.keyId}   (çevrimdışı, ikinci imzalayıcı)`,
    'Kurtarma anahtarı (config imzalamaz; yalnızca anahtar setini, yani telefonun güvendiği imza anahtarlarının listesini imzalar):',
    `  ${KEYS.recovery.padEnd(27)} : ${keys.recovery.keyId}`,
    '',
    apk.built
      ? `$ ${env.buildCommandFor(path.relative(env.CLIENT_DIR, LAB_PROPS))}\n${apk.log.trim().split('\n').slice(-4).join('\n')}`
      : `(uygulama bu derleme değerleriyle daha önce derlenmişti: ${path.relative(env.ROOT, apk.file)})`,
    `$ ${device.installCommandLabel(path.basename(apk.file))}`,
    apk.installOut.trim(),
  ];
  await attachText(testInfo, title, lines.join('\n'));
  return { keys, primary, props: text, apk };
}

/**
 * Ana host APK'sını (env.APK) geri kurar, verisi silinmiş açılışta ana host'a
 * karşı Hazır olduğunu doğrular ve kanıtını ekler.
 */
async function restoreMain(device, app, testInfo) {
  mainApkBackup(); // env.APK ana derleme değilse düzeltir
  const out = device.installApp(env.APP_ARTIFACT);
  app.launchFresh();
  const status = await app.waitReady();
  await app.snap('ana host için derlenen APK geri kuruldu: Hazır');
  await attachText(
    testInfo,
    'Geri dönüş: ana host için derlenen APK',
    [
      `$ ${device.installCommandLabel(path.relative(env.ROOT, env.APP_ARTIFACT) || env.APP_ARTIFACT)}`,
      out.trim(),
      `APK'da ana host'un imza anahtarı var: ${isMainApk() ? 'evet' : 'HAYIR'}`,
      '',
      `Telefon: ${status.split('\n')[0]}`,
      `Pin kaynağı: ${(status.match(/Pin kaynağı: ([^\n]+)/) || [])[1] || '?'}`,
    ].join('\n'),
  );
  return status;
}

// ── Anahtar setleri ────────────────────────────────────────────────────────

/** Laboratuvar dizininde bir dosya yolu (komutlarda cwd'ye göreli). */
function labFile(name) {
  fs.mkdirSync(LAB_DIR, { recursive: true, mode: 0o700 });
  return { abs: path.join(LAB_DIR, name), rel: path.join(REL_LAB, name) };
}

/** Kablodaki (ya da dosyadaki) anahtar setinin okunur özeti. */
function describeKeySet(wire, names = {}) {
  const payload = JSON.parse(wire.payload);
  const label = (keyId) => names[keyId] || '?';
  return [
    `payload.type    : ${payload.type}`,
    `payload.version : v${payload.version}`,
    `payload.keys    : ${payload.keys.length} anahtar`,
    ...payload.keys.map((k) => {
      const id = offlineKeys.keyIdOf(k);
      return `   • ${short(id, 16)} (${label(id)})`;
    }),
    ...(payload.requiredSignatures ? [`payload.requiredSignatures: ${payload.requiredSignatures}`] : []),
    `signatures      : ${wire.signatures.length}`,
    ...wire.signatures.map((s) => `   • keyId ${short(s.keyId, 16)} (${label(s.keyId)}) — imza ${s.signature.slice(0, 16)}… (${Buffer.from(s.signature, 'base64').length} bayt DER)`),
  ].join('\n');
}

module.exports = {
  LAB_DIR,
  LAB_PROPS,
  KEYS,
  REL_KEYS,
  REL_LAB,
  short,
  propValue,
  run,
  op,
  containerEnv,
  envOverridden,
  waitConfigApi,
  setEnv,
  resetEnv,
  restart,
  signingKeyInfo,
  signingStatus,
  nextKeySetVersion,
  describeSigners,
  savePrimaryKeyFile,
  restorePrimaryKeyFile,
  ensureFresh,
  ensureKey,
  labKeys,
  showKey,
  apkEmbeds,
  isMainApk,
  mainApkBackup,
  installLabApk,
  installedApk,
  setup,
  restoreMain,
  labFile,
  describeKeySet,
};
