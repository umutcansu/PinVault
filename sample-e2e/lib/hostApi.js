// Host'un yönetim API'si. Testlerde web'deki işlemler HER ZAMAN arayüzden
// yapılır; burası yalnızca hazırlık, temizlik ve web'de görüleni API'den de
// doğrulamak (kayıt bu teste mi ait?) içindir.
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');
const tls = require('tls');
const { execFileSync } = require('child_process');
const env = require('./env');

/**
 * Yönetim API'sine istek. [key] verilirse o yönetici anahtarıyla (ADMIN_KEYS),
 * yoksa .env'deki paylaşılan API_KEY ile gider. [headers] ek başlıklar;
 * dönen nesnede yanıt başlıkları da vardır (ör. X-PinVault-Live-Check).
 */
async function api(pathname, { method = 'GET', body, withKey = true, key, headers: extra = {}, rawBody } = {}) {
  const headers = { ...extra };
  if (withKey) headers['X-API-Key'] = key || env.API_KEY;
  if (body !== undefined || rawBody !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(env.WEB_URL + pathname, {
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

async function isHealthy() {
  try {
    return (await api('/health', { withKey: false })).status === 200;
  } catch {
    return false;
  }
}

async function mtlsApiRunning() {
  try {
    const r = await api('/api/v1/all-configs');
    return (r.json || []).some((a) => a.id === env.MTLS_API && a.running);
  } catch {
    return false;
  }
}

/** mTLS Config API'yi ve host'un kendi pin kaydını açar (host scripts/provision.sh). */
function provision() {
  execFileSync(path.join(env.HOST_DIR, 'scripts/provision.sh'), { stdio: 'inherit', timeout: 180_000 });
}

async function getConfig() {
  const r = await api('/api/v1/certificate-config?signed=false', { withKey: false });
  if (r.status !== 200) throw new Error(`Config okunamadı: HTTP ${r.status}`);
  return r.json;
}

/** Host TLS sertifikasının pin'leri, host dosyasından. */
function hostPins() {
  return fs.readFileSync(env.HOST_PINS_FILE, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean).slice(0, 2);
}

/**
 * Varsayılan Config API'yi temel duruma getirir: [baseline]'daki her host bu
 * pin'lerle kayıtlı, force update kapalı. Eksik host'ları geri ekler, diğer
 * host'lara dokunmaz. Zaten o durumdaysa hiçbir şey yazmaz. Pin değişikliği
 * host sürümünü artırır; istemciler sürüm düşüşünü reddettiği için geri alma
 * her zaman ileri doğrudur.
 */
async function restoreBaseline(baseline) {
  const cfg = await getConfig();
  const pins = cfg.pins.map((p) => (baseline[p.hostname] ? { ...p, sha256: baseline[p.hostname], forceUpdate: false } : p));
  for (const [hostname, sha256] of Object.entries(baseline)) {
    if (!pins.some((p) => p.hostname === hostname)) pins.push({ hostname, sha256, forceUpdate: false });
  }
  const unchanged = pins.every((p) => {
    const current = cfg.pins.find((c) => c.hostname === p.hostname);
    return current && JSON.stringify(current.sha256) === JSON.stringify(p.sha256) && !current.forceUpdate;
  });
  if (unchanged && !cfg.forceUpdate) return;
  const r = await api('/api/v1/certificate-config', {
    method: 'PUT',
    body: { version: 0, pins, forceUpdate: false },
  });
  if (r.status !== 200) throw new Error(`Pin'ler geri yüklenemedi: HTTP ${r.status} ${r.text}`);
}

async function connectionHistory(hostname) {
  return (await api(`/api/v1/connection-history/${encodeURIComponent(hostname)}`)).json || [];
}

/**
 * Bütün kaynakların (web / android / config_update) bağlantı geçmişi;
 * dashboard'ın "Bağlantı Geçmişi" bölümü bunu gösterir. Config güncelleme
 * raporlarının hostname'i boş olduğu için host bazlı uçta görünmezler.
 */
async function allConnectionHistory() {
  return (await api('/api/v1/connection-history')).json || [];
}

/** Cihazın config güncelleme raporları (config_updated / _unchanged / _failed). */
async function configUpdateReports(deviceModel) {
  return (await allConnectionHistory()).filter(
    (e) => e.source === 'config_update' && (!deviceModel || e.deviceModel === deviceModel),
  );
}

// ── Vault ─────────────────────────────────────────────────────────────────

const vaultBase = (apiId) => `/api/v1/config-apis/${encodeURIComponent(apiId)}/vault`;

async function deleteVaultFile(apiId, key) {
  await api(`${vaultBase(apiId)}/${encodeURIComponent(key)}`, { method: 'DELETE' });
}

async function vaultFiles(apiId) {
  return (await api(vaultBase(apiId))).json || [];
}

/** Kapsamın dağıtım istatistikleri (`…/vault/stats`). */
async function vaultStats(apiId) {
  const r = await api(`${vaultBase(apiId)}/stats`);
  if (r.status !== 200) throw new Error(`Vault istatistikleri okunamadı: HTTP ${r.status}`);
  return r.json;
}

/** Kapsamın bütün dağıtım kayıtları; [key] verilirse yalnızca o dosyanınkiler. */
async function vaultDistributions(apiId, key) {
  const path = key ? `${vaultBase(apiId)}/distributions/${encodeURIComponent(key)}` : `${vaultBase(apiId)}/distributions`;
  return (await api(path)).json || [];
}

/** Bir cihazın bütün dağıtım kayıtları (dashboard'daki cihaz detayının kaynağı). */
async function vaultDistributionsByDevice(apiId, deviceId) {
  return (await api(`${vaultBase(apiId)}/distributions/device/${encodeURIComponent(deviceId)}`)).json || [];
}

/** Dosyanın içeriğine dokunmadan politikasını/şifrelemesini değiştirir (temizlik için). */
async function setVaultPolicy(apiId, key, { policy, encryption }) {
  const r = await api(`${vaultBase(apiId)}/${encodeURIComponent(key)}/policy`, {
    method: 'PUT',
    body: { access_policy: policy, encryption },
  });
  if (r.status !== 200) throw new Error(`Politika değiştirilemedi: HTTP ${r.status} ${r.text}`);
  return r.json;
}

/** Config API'nin `vault_enabled` bayrağı. */
async function vaultEnabled(apiId) {
  const r = await api(`/api/v1/config-apis/${encodeURIComponent(apiId)}/vault-enabled`);
  return r.json && r.json.vault_enabled === 'true';
}

/** `vault_enabled` bayrağını yazar (temizlik için; senaryo bunu arayüzden yapar). */
async function setVaultEnabled(apiId, enabled) {
  const r = await api(`/api/v1/config-apis/${encodeURIComponent(apiId)}/vault-enabled`, {
    method: 'PUT',
    body: { enabled },
  });
  if (r.status !== 200) throw new Error(`vault_enabled yazılamadı: HTTP ${r.status} ${r.text}`);
  return r.json;
}

// ── Sunucu veritabanı (SQLite) ────────────────────────────────────────────

/**
 * Sunucunun SQLite veritabanında sorgu çalıştırır.
 *
 * Container'da `sqlite3` yok; `/data` Mac'e bind-mount edildiği için dosya
 * doğrudan okunur. Yazma YOK — yalnızca kanıt okuması (vault blob'u diskte
 * şifreli mi, cihazın public key'i kayıtlı mı).
 */
function dbQuery(sql, { mode = 'list' } = {}) {
  return execFileSync('sqlite3', ['-readonly', `-${mode}`, env.DB_FILE, sql], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  }).trim();
}

/** Vault dosyasının veritabanındaki HAM blob'u (Buffer) — at_rest kanıtı. */
function vaultBlobFromDb(apiId, key) {
  const hex = dbQuery(
    `SELECT hex(content) FROM vault_files WHERE config_api_id='${apiId}' AND key='${key}';`,
  );
  if (!hex) throw new Error(`Veritabanında vault kaydı yok: ${apiId}/${key}`);
  return Buffer.from(hex, 'hex');
}

/** Cihazın sunucuda kayıtlı RSA public key'i (PEM) — yoksa null. */
function devicePublicKeyPem(deviceId, apiId) {
  const pem = dbQuery(
    `SELECT public_key_pem FROM device_public_keys WHERE device_id='${deviceId}' AND config_api_id='${apiId}';`,
  );
  return pem || null;
}

/**
 * Config API'den ham vault indirmesi: kabloda ne gittiğini görmek için.
 * Sunucu sertifikası sistem güvenine değil, host'un pin'ine göre doğrulanır.
 *
 * Seçenekler:
 *   port      — hangi dinleyici (varsayılan TLS Config API; mTLS için MTLS_API_PORT)
 *   token     — X-Vault-Token (token / token_mtls politikaları)
 *   apiKey    — X-API-Key (api_key politikası; cihazın ASLA göndermediği başlık)
 *   version   — ?version= (304 kısayolunu denemek için)
 *   certFile / keyFile — istemci sertifikası PEM'leri (mTLS dinleyicisi)
 */
function rawVaultDownload(key, deviceId, opts = {}) {
  const { port = env.CONFIG_API_PORT, token, apiKey, version, certFile, keyFile } = opts;
  const expectedPins = hostPins();
  const headers = {};
  if (deviceId) headers['X-Device-Id'] = deviceId;
  if (token) headers['X-Vault-Token'] = token;
  if (apiKey) headers['X-API-Key'] = apiKey;
  const query = version === undefined ? '' : `?version=${encodeURIComponent(version)}`;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: 'localhost',
        port,
        path: `/api/v1/vault/${encodeURIComponent(key)}${query}`,
        method: 'GET',
        headers,
        // Self-signed: güven pin kontrolünden gelir (aşağıda).
        rejectUnauthorized: false,
        // Her çağrı yeni bir TLS el sıkışması yapsın: Node'un global agent'ı
        // bağlantıyı yeniden kullandığında getPeerCertificate() boş dönüyor ve
        // pin kontrolü yapılamıyor (kanıtın kendisi kayboluyor).
        agent: false,
        ...(certFile ? { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) } : {}),
      },
      (res) => {
        const pin = spkiPin(res.socket.getPeerCertificate().raw);
        if (!expectedPins.includes(pin)) {
          res.destroy();
          reject(new Error(`Host pin'i tutmadı: ${pin}`));
          return;
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ── Pin'ler ───────────────────────────────────────────────────────────────

function spkiPin(der) {
  const spki = new crypto.X509Certificate(der).publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spki).digest('base64');
}

/** Hedefin canlı sertifika zincirinden [yaprak, ara sertifika] SPKI pin'leri. */
function livePins(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname }, () => {
      const pins = [];
      let cert = socket.getPeerCertificate(true);
      while (cert && cert.raw && pins.length < 2) {
        pins.push(spkiPin(cert.raw));
        const issuer = cert.issuerCertificate;
        if (!issuer || issuer.fingerprint256 === cert.fingerprint256) break;
        cert = issuer;
      }
      socket.end();
      if (pins.length === 2) resolve(pins);
      else reject(new Error(`${hostname}: zincirde iki sertifika bulunamadı`));
    });
    socket.setTimeout(10_000, () => socket.destroy(new Error(`${hostname}: TLS zaman aşımı`)));
    socket.on('error', reject);
  });
}

/**
 * [host]:[port] üzerindeki sunucunun sunduğu YAPRAK sertifikanın SPKI pin'i.
 *
 * Mock host'lar yalnızca container'ın yayımladığı portta ve kendi adlarıyla
 * (SNI) servis ediliyor; Mac'te o adlar DNS'te olmadığı için bağlantı
 * localhost'a kurulup [servername] ayrıca veriliyor. Sertifika rotasyonundan
 * sonra "dinleyici yeni sertifikayla gerçekten ayağa kalktı mı" sorusunu
 * yanıtlar — telefon istek atmadan önce beklemek için.
 */
function servedCert(port, servername, host = 'localhost') {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.raw) reject(new Error(`${servername}:${port} sertifika vermedi`));
      else resolve({ pin: spkiPin(cert.raw), validFromMs: Date.parse(cert.valid_from) });
    });
    socket.setTimeout(10_000, () => socket.destroy(new Error(`${servername}:${port} TLS zaman aşımı`)));
    socket.on('error', reject);
  });
}

/** [host]:[port]'un sunduğu zincirin SPKI pin'leri, yapraktan başlayarak (en fazla 4). */
function servedChainPins(port, servername, host = 'localhost') {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false }, () => {
      const pins = [];
      let cert = socket.getPeerCertificate(true);
      while (cert && cert.raw && pins.length < 4) {
        pins.push(spkiPin(cert.raw));
        const issuer = cert.issuerCertificate;
        if (!issuer || issuer.fingerprint256 === cert.fingerprint256) break;
        cert = issuer;
      }
      socket.end();
      resolve(pins);
    });
    socket.setTimeout(10_000, () => socket.destroy(new Error(`${servername}:${port} TLS zaman aşımı`)));
    socket.on('error', reject);
  });
}

/** [servedCert] ile aynı, yalnızca pin döner. */
async function servedPin(port, servername, host = 'localhost') {
  return (await servedCert(port, servername, host)).pin;
}

/** Biçimce geçerli (32 bayt, Base64) ama hiçbir sertifikaya ait olmayan pin. */
function randomPin() {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Config API'nin CİHAZA servis ettiği imzalı config zarfı (telefonun aldığı
 * baytların aynısı): { payload, signature, config }. `config` payload'ın
 * ayrıştırılmış hali — `issuedAt`/`expiresAt` yalnızca bu yolda dolu, yönetim
 * portundaki `?signed=false` kopyasında değil.
 */
function signedConfig({ port = env.CONFIG_API_PORT, currentVersion = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: 'localhost',
        port,
        path: `/api/v1/certificate-config?currentVersion=${currentVersion}`,
        method: 'GET',
        rejectUnauthorized: false,
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve({ ...envelope, config: JSON.parse(envelope.payload) });
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ── Kapsamlı (Config API bazlı) config ────────────────────────────────────

/**
 * Bir Config API'nin kendi pin config'i. Yönetim portundaki
 * `/api/v1/certificate-config` HER ZAMAN `default-tls` kapsamını okur; başka
 * bir kapsam yalnızca buradan görülebilir.
 */
async function scopedConfig(apiId) {
  const r = await api(`/api/v1/config/${encodeURIComponent(apiId)}`);
  if (r.status !== 200) throw new Error(`${apiId} config okunamadı: HTTP ${r.status}`);
  return r.json;
}

/** Kapsamın pin config'ini doğrudan yazar (sürüm watermark'ı korunur). */
async function setScopedConfig(apiId, { pins, forceUpdate = false }) {
  const r = await api(`/api/v1/config/${encodeURIComponent(apiId)}/update`, {
    method: 'POST',
    body: { version: 0, pins, forceUpdate },
  });
  if (r.status !== 200) throw new Error(`${apiId} config yazılamadı: HTTP ${r.status} ${r.text}`);
  return r.json;
}

/** Kapsamdaki bütün host'ları kaldırır (temizlik; `hosts` kayıtları kalır). */
async function clearScopedHosts(apiId) {
  const cfg = await scopedConfig(apiId);
  if (!cfg.pins || cfg.pins.length === 0) return false;
  await setScopedConfig(apiId, { pins: [] });
  return true;
}

/**
 * Varsayılan kapsamdaki bir host'un mTLS bayrağını ve `clientCertVersion`
 * alanını temizler. Fixture'ın `restoreBaseline`'ı yalnızca pin'lere bakar, bu
 * iki alanı olduğu gibi bırakır; B02/B03 sonrası temel duruma dönmek için.
 */
async function clearHostMtlsFlags(hostname) {
  const cfg = await getConfig();
  const pin = cfg.pins.find((p) => p.hostname === hostname);
  if (!pin || (!pin.mtls && pin.clientCertVersion == null)) return false;
  const pins = cfg.pins.map((p) =>
    p.hostname === hostname
      ? { hostname: p.hostname, sha256: p.sha256, version: p.version, forceUpdate: false }
      : p,
  );
  const r = await api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, pins, forceUpdate: false } });
  if (r.status !== 200) throw new Error(`mTLS bayrağı temizlenemedi: HTTP ${r.status} ${r.text}`);
  return true;
}

// ── mTLS ──────────────────────────────────────────────────────────────────

/** Sunucudaki istemci sertifikaları (etkin + iptal edilmiş). */
async function clientCerts() {
  return (await api('/api/v1/client-certs')).json || [];
}

/** Kayıt token'ları (düz metin değil: maskeli önek + kullanıldı bayrağı). */
async function enrollmentTokens() {
  return (await api('/api/v1/enrollment-tokens')).json || [];
}

/** Host'a özel istemci sertifikası bilgisi (yoksa null). */
async function hostClientCertInfo(apiId, hostname) {
  const r = await api(
    `/api/v1/hosts/${encodeURIComponent(hostname)}/client-cert/info?configApiId=${encodeURIComponent(apiId)}`,
  );
  return r.status === 200 ? r.json : null;
}

/** Container'daki bir keystore dosyasını yerel yola kopyalar (docker cp). */
function exportKeystore(name, destFile) {
  fs.mkdirSync(path.dirname(destFile), { recursive: true });
  execFileSync('docker', ['cp', `${env.CONTAINER}:/data/certs/${name}`, destFile], {
    encoding: 'utf8',
    timeout: 60_000,
  });
  return destFile;
}

/**
 * Test yarıda kalırsa bıraktığı istemci sertifikasını iptal eder. Sertifika yoksa
 * ya da zaten iptal edildiyse bir şey yapmaz.
 */
async function revokeClientCertIfActive(id) {
  const certs = (await api('/api/v1/client-certs')).json || [];
  const cert = certs.find((c) => c.id === id);
  if (!cert || cert.revoked) return false;
  await api(`/api/v1/client-certs/${encodeURIComponent(id)}`, { method: 'DELETE' });
  return true;
}

/**
 * Host'un sertifikasını sunucuda yeniler (POST …/hosts/{host}/regenerate-cert):
 * yeni anahtar çifti, pin sürümü +1, çalışan mock dinleyici yeni keystore ile.
 * Yeni pin'leri döndürür. Temizlik için (senaryolar bunu arayüzden yapar).
 */
async function regenerateHostCert(hostname, apiId = env.VAULT_API) {
  const r = await api(
    `/api/v1/hosts/${encodeURIComponent(hostname)}/regenerate-cert?configApiId=${encodeURIComponent(apiId)}`,
    { method: 'POST' },
  );
  if (r.status !== 200) throw new Error(`Sertifika yenilenemedi (${hostname}): HTTP ${r.status} ${r.text}`);
  return r.json.sha256Pins;
}

// ── İmza anahtarları, anahtar setleri, yönetişim ─────────────────────────

/** GET /api/v1/signing-key (herkese açık): birincil anahtar, imzalayıcılar, anahtar seti sürümü. */
async function signingKeyInfo() {
  const r = await api('/api/v1/signing-key', { withKey: false });
  if (r.status !== 200) throw new Error(`GET /api/v1/signing-key → HTTP ${r.status}`);
  return r.json;
}

/** GET /api/v1/signing/status (yönetici): imzalayıcı türleri, önbellek sayaçları, anahtar seti durumu. */
async function signingStatus(key) {
  const r = await api('/api/v1/signing/status', { key });
  if (r.status !== 200) throw new Error(`GET /api/v1/signing/status → HTTP ${r.status} ${r.text}`);
  return r.json;
}

/** PUT /api/v1/signing-keyset — {status, json, text}; reddi senaryo kendisi değerlendirir. */
function uploadKeySet(wire, key) {
  return api('/api/v1/signing-keyset', { method: 'PUT', body: wire, key });
}

/** Cihazın aldığı imzalı zarf, istenen X-PinVault-Features başlığıyla (önbellek kanıtı için). */
async function rawSignedConfig({ features } = {}) {
  const r = await api('/api/v1/certificate-config', {
    withKey: false,
    headers: features ? { 'X-PinVault-Features': features } : {},
  });
  if (r.status !== 200) throw new Error(`imzalı config okunamadı: HTTP ${r.status}`);
  return r.json;
}

async function adminMe(key) {
  return (await api('/api/v1/admin/me', { key })).json;
}

async function auditLog({ limit = 20, action, key } = {}) {
  const q = new URLSearchParams({ limit: String(limit) });
  if (action) q.set('action', action);
  const r = await api(`/api/v1/audit-log?${q}`, { key });
  if (r.status !== 200) throw new Error(`denetim kaydı okunamadı: HTTP ${r.status}`);
  return r.json;
}

async function verifyAudit(key) {
  return (await api('/api/v1/audit-log/verify', { key })).json;
}

async function changeRequests(status = 'pending', key) {
  return (await api(`/api/v1/change-requests?status=${encodeURIComponent(status)}`, { key })).json || [];
}

function approveChange(id, key) {
  return api(`/api/v1/change-requests/${id}/approve`, { method: 'POST', key });
}

function rejectChange(id, reason, key) {
  return api(`/api/v1/change-requests/${id}/reject`, { method: 'POST', body: { reason }, key });
}

/** POST /api/v1/pins/live-check — kuru çalıştırma: host'un şu an sunduğu yaprak yeni sette mi. */
async function liveCheck(pins, key) {
  return (await api('/api/v1/pins/live-check', { method: 'POST', body: { pins }, key })).json;
}

async function notifications(key) {
  return (await api('/api/v1/notifications', { key })).json;
}

module.exports = {
  api,
  isHealthy,
  mtlsApiRunning,
  provision,
  getConfig,
  hostPins,
  restoreBaseline,
  connectionHistory,
  allConnectionHistory,
  configUpdateReports,
  deleteVaultFile,
  vaultFiles,
  vaultStats,
  vaultDistributions,
  vaultDistributionsByDevice,
  setVaultPolicy,
  vaultEnabled,
  setVaultEnabled,
  dbQuery,
  vaultBlobFromDb,
  devicePublicKeyPem,
  rawVaultDownload,
  revokeClientCertIfActive,
  regenerateHostCert,
  spkiPin,
  livePins,
  servedCert,
  servedPin,
  servedChainPins,
  randomPin,
  signedConfig,
  scopedConfig,
  setScopedConfig,
  clearScopedHosts,
  clearHostMtlsFlags,
  clientCerts,
  enrollmentTokens,
  hostClientCertInfo,
  exportKeystore,
  signingKeyInfo,
  signingStatus,
  uploadKeySet,
  rawSignedConfig,
  adminMe,
  auditLog,
  verifyAudit,
  changeRequests,
  approveChange,
  rejectChange,
  liveCheck,
  notifications,
};
