// Ana host'a dokunmadan "sıfırdan kurulum" ve yıkıcı sunucu senaryolarını
// koşturmak için sample-host'un ikinci, bağımsız bir örneği.
//
// Neden: kurulum yolculuğu (K) ve sunucu operasyonlarının bir kısmı (E03 sunucu
// sertifikası yenileme, E05 Config API silme, E08 down/up) sunucunun kimliğini
// değiştirir. Ana host'un sertifikası ya da imzalama anahtarı değişirse
// telefondaki APK'nın gömülü bootstrap pin'leri ve imza public key'i geçersiz
// olur ve diğer bütün senaryolar çöker. Bu yüzden o senaryolar burada kurulan
// kopyanın üzerinde koşar.
//
// Kopya `.local/host-fresh` altına açılır (`data/` ve `.env` hariç — yani boş
// bir veritabanı, yeni bir sunucu sertifikası ve yeni bir imzalama anahtarı),
// kendi portlarını (6750–6756), kendi compose projesini (`pinvault-fresh`) ve
// kendi container adını (`pinvault-host-fresh`) kullanır. Koşu sonunda
// `docker compose down -v` ile tamamen silinir (global-teardown).
//
// Port tabanı, proje ve container adı E2E_FRESH_PORT_BASE, E2E_FRESH_PROJECT,
// E2E_FRESH_CONTAINER ile değişir (lib/env.js): aynı makinede başka bir
// oturumun koşusu (ör. Android ve iOS) varken iki kopya çakışmasın.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./env');

/** Kopyanın kök dizini; git dışı (.local). */
const DIR = path.join(env.LOCAL_DIR, 'host-fresh');
const PROJECT = env.FRESH_PROJECT;
const CONTAINER = env.FRESH_CONTAINER;
/** Ana host 6650–6656 kullanıyor; kopya çakışmasın diye varsayılan 6750–6756 (E2E_FRESH_PORT_BASE). */
const BASE = env.FRESH_PORT_BASE;
/**
 * Kopyanın Docker ağı. Docker kendi seçtiğinde 172.17–31 aralıkları dolunca
 * 192.168.0.0/20'yi veriyor: bu, ev / ofis ağını (192.168.1.x) örter ve
 * container'lar (ör. Jenkins) o ağdaki adreslere — GitLab'a, modeme — artık
 * ulaşamaz. Bu yüzden sabit, yerel ağlarla çakışmayan bir /24: varsayılan
 * 10.213.<port tabanı / 100>.0/24 (6750 → 10.213.67.0/24, 6950 → 10.213.69.0/24),
 * E2E_FRESH_SUBNET ile değişir.
 */
const SUBNET = env.FRESH_SUBNET || `10.213.${Math.floor(BASE / 100) % 256}.0/24`;
const PORTS = {
  http: BASE,
  https: BASE + 1,
  mtls: BASE + 2,
  mockTls: BASE + 3,
  mockMtls: BASE + 4,
  managementTls: BASE + 5,
  recovery: BASE + 6,
};
const WEB_URL = `http://localhost:${PORTS.http}`;
/**
 * Taze örneğin keystore parolası (.env → KEYSTORE_PASSWORD). Varsayılan
 * "changeit" yerine gerçek bir değerle kurulur ki sunucu keystore'larının bu
 * parolayla yazıldığı gösterilebilsin (E08). Gizli değil: yalnızca bu
 * kullan-at örneğe ait; yine de panellere maskeli girer.
 */
const KEYSTORE_PASSWORD = 'e2e-keystore-parolasi';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Kopyanın dizininde komut çalıştırır. */
function run(file, args, opts = {}) {
  return execFileSync(file, args, {
    cwd: DIR,
    encoding: 'utf8',
    timeout: 15 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
}

function compose(args, opts = {}) {
  return run('docker', ['compose', ...args], opts);
}

function exists() {
  return fs.existsSync(path.join(DIR, 'docker-compose.yml'));
}

/**
 * Depoyu kopyalar (`data/` ve `.env` hariç) ve kopyadaki compose dosyasında
 * container adını değiştirir; ana depo olduğu gibi kalır. (Güncel compose
 * dosyası adı HOST_CONTAINER_NAME'den alır, configureEnv onu da yazar; sabit
 * adlı eski dosya için yerinde değiştirme kalıyor.)
 */
function copyTree() {
  fs.mkdirSync(DIR, { recursive: true });
  const out = execFileSync(
    'rsync',
    ['-a', '--delete', '--exclude', 'data/', '--exclude', '.env', '--exclude', '.git/', `${env.HOST_DIR}/`, `${DIR}/`],
    { encoding: 'utf8', timeout: 120_000 },
  );
  const composeFile = path.join(DIR, 'docker-compose.yml');
  const patched = fs
    .readFileSync(composeFile, 'utf8')
    .replace(/container_name:\s*pinvault-host\s*$/m, `container_name: ${CONTAINER}`);
  if (/^networks:/m.test(patched)) throw new Error(`${composeFile}: networks bloğu zaten var; alt ağ eklenemedi`);
  // Sabit alt ağ (SUBNET'in açıklaması): Docker'ın 192.168.x'i seçmesine izin verilmez.
  const withSubnet = `${patched.replace(/\s*$/, '\n')}\nnetworks:\n  default:\n    ipam:\n      config:\n        - subnet: ${SUBNET}\n`;
  fs.writeFileSync(composeFile, withSubnet);
  fs.mkdirSync(path.join(DIR, 'data/db'), { recursive: true });
  fs.mkdirSync(path.join(DIR, 'data/certs'), { recursive: true });
  return out;
}

function envFile() {
  return path.join(DIR, '.env');
}

function readEnv() {
  const out = {};
  if (!fs.existsSync(envFile())) return out;
  for (const line of fs.readFileSync(envFile(), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

function apiKey() {
  return readEnv().API_KEY || '';
}

/**
 * setup.sh'ın ürettiği .env'i bu kopyaya göre ayarlar: portlar ana host'unkiyle
 * çakışmasın, compose projesi ayrı olsun, sunucu aynı yerel PinVault
 * kaynağından derlensin (kopya farklı bir dizinde olduğu için mutlak yol).
 */
function configureEnv() {
  const serverSrc = path.resolve(env.HOST_DIR, '../demo-server');
  const values = {
    HOST_HTTP_PORT: String(PORTS.http),
    HOST_HTTPS_PORT: String(PORTS.https),
    HOST_MTLS_PORT: String(PORTS.mtls),
    HOST_MOCK_TLS_PORT: String(PORTS.mockTls),
    HOST_MOCK_MTLS_PORT: String(PORTS.mockMtls),
    HOST_MANAGEMENT_TLS_PORT: String(PORTS.managementTls),
    HOST_RECOVERY_PORT: String(PORTS.recovery),
    COMPOSE_PROJECT_NAME: PROJECT,
    HOST_CONTAINER_NAME: CONTAINER,
    PINVAULT_SERVER_SRC: serverSrc,
    // Sertifikalar ilk açılışta bu parolayla üretilsin (sonradan değiştirmek
    // var olan JKS'leri açılamaz kılar).
    KEYSTORE_PASSWORD,
  };
  let text = fs.readFileSync(envFile(), 'utf8');
  for (const [key, value] of Object.entries(values)) {
    const line = `${key}=${value}`;
    text = new RegExp(`^${key}=.*$`, 'm').test(text)
      ? text.replace(new RegExp(`^${key}=.*$`, 'm'), line)
      : `${text.replace(/\n*$/, '\n')}${line}\n`;
  }
  fs.writeFileSync(envFile(), text, { mode: 0o600 });
  return text;
}

async function isHealthy() {
  try {
    const res = await fetch(`${WEB_URL}/health`);
    return res.status === 200;
  } catch {
    return false;
  }
}

async function waitHealthy(timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isHealthy()) return;
    await sleep(1000);
  }
  throw new Error(`Geçici test sunucusu ${timeoutMs / 1000} saniyede ayağa kalkmadı (${WEB_URL})`);
}

function isRunning() {
  try {
    return execFileSync('docker', ['inspect', '-f', '{{.State.Running}}', CONTAINER], {
      encoding: 'utf8',
      timeout: 30_000,
    }).trim() === 'true';
  } catch {
    return false;
  }
}

/**
 * Yönetim API'si (kopyanın kendi anahtarıyla). [headers] ek başlıklar (ör.
 * X-PinVault-Features); [rawBody] gövdeyi olduğu gibi gönderir (imzalı anahtar
 * seti: payload bayt bayt imzalanan metin olarak kalmalı).
 */
async function api(pathname, { method = 'GET', body, withKey = true, key, headers: extra = {}, rawBody } = {}) {
  const headers = { ...extra };
  if (withKey) headers['X-API-Key'] = key || apiKey();
  if (body !== undefined || rawBody !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(WEB_URL + pathname, {
    method,
    headers,
    body: rawBody !== undefined ? rawBody : body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, json, text, headers: Object.fromEntries(res.headers.entries()) };
}

/** Kopyanın sunucu TLS pin'leri (bootstrap). */
function hostPins() {
  return fs
    .readFileSync(path.join(DIR, 'data/certs/demo-server.pins'), 'utf8')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Kopyanın imzalama anahtarı, düz metin biçiminde: "<özel>\n<public>" (ilk satır
 * gizli!). Dosya diskte kopyanın SIGNING_KEY_PASSWORD'ıyla şifreliyse (ENCv1:,
 * setup.sh demo profilinde de parola üretir) o parolayla açılır.
 */
function signingKeyRaw() {
  return require('./signingKeyFile').read(path.join(DIR, 'data/signing-key.pem'), readEnv().SIGNING_KEY_PASSWORD).plaintext;
}

function provision() {
  return run('./scripts/provision.sh', []);
}

/** Hiç kurulmamışsa kurar, duruyorsa başlatır; kanıt üretmez (K01 üretir). */
async function ensure() {
  if (await isHealthy()) return;
  if (!exists()) {
    copyTree();
    run('./scripts/setup.sh', []);
    configureEnv();
  } else if (!fs.existsSync(envFile())) {
    run('./scripts/setup.sh', []);
    configureEnv();
  }
  compose(['up', '-d', '--build']);
  await waitHealthy();
  // Sunucu TLS sertifikasını ilk açılışta üretiyor ve notBefore = "şimdi"
  // oluyor. Emülatörün saati Mac'in saatinden bir saniye geride olabildiği
  // için telefon hemen bağlanırsa sertifikayı "not valid until …" diye
  // reddediyor (A19'da görülen yarış). Küçük bir pay bırak.
  await sleep(5000);
  provision();
}

/**
 * Taze örneğin dashboard'unu ayrı bir sayfada açar. Ana host'un sayfası
 * (fixture'daki `dashboard`) bozulmadan ikinci bir tarayıcı sekmesi kullanılır.
 * [withKey] false ise API anahtarı yazılmaz: dashboard ilk açılışta sorar.
 */
async function openDashboard(browser, testInfo, { withKey = true } = {}) {
  const { Dashboard } = require('./dashboard');
  const page = await browser.newPage();
  const dashboard = new Dashboard(page, testInfo, { baseUrl: `${WEB_URL}/` });
  Dashboard.attachDialogs(page, dashboard);
  if (withKey) {
    await Dashboard.seedApiKey(page, apiKey());
    await dashboard.open();
  }
  return dashboard;
}

/** Kopyayı tamamen siler: container, ağ, volume ve dizin. */
async function destroy() {
  if (exists()) {
    try {
      compose(['down', '-v', '--remove-orphans']);
    } catch {
      /* zaten yok */
    }
  }
  try {
    execFileSync('docker', ['rm', '-f', CONTAINER], { stdio: 'ignore', timeout: 60_000 });
  } catch {
    /* container yok */
  }
  fs.rmSync(DIR, { recursive: true, force: true });
}

module.exports = {
  DIR,
  PROJECT,
  SUBNET,
  CONTAINER,
  PORTS,
  WEB_URL,
  KEYSTORE_PASSWORD,
  run,
  compose,
  exists,
  copyTree,
  configureEnv,
  envFile,
  readEnv,
  apiKey,
  isHealthy,
  waitHealthy,
  isRunning,
  api,
  hostPins,
  signingKeyRaw,
  provision,
  ensure,
  openDashboard,
  destroy,
};
