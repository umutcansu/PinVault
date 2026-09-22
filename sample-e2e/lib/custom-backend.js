// "Kendi backend'in" örneği: PinVault'un rehberdeki (SERVER_IMPLEMENTATION_GUIDE)
// uçlarını, varsayılan yollar yerine özel yollarla sunan küçük bir Node HTTPS
// sunucusu. Uygulamanın CUSTOM_BACKEND modu buna bağlanır ve şunları gösterir:
// özel uç yolları, kendi ECDSA anahtarıyla imzalı config, kendi vault dosyası.
//
// Anahtar ve sertifikalar .local/custom-backend altında bir kez üretilir
// (openssl) ve derlemeye gömülür; böylece APK ile sunucu aynı pin'lerde anlaşır.
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const env = require('./env');

const DIR = path.join(env.LOCAL_DIR, 'custom-backend');
const FILES = {
  key: path.join(DIR, 'server-key.pem'),
  cert: path.join(DIR, 'server-cert.pem'),
  backupKey: path.join(DIR, 'backup-key.pem'),
  backupCert: path.join(DIR, 'backup-cert.pem'),
  signingKey: path.join(DIR, 'signing-key.pem'),
};

const openssl = (args, opts = {}) =>
  execFileSync('openssl', args, { encoding: 'utf8', timeout: 60_000, ...opts });

/** Sertifikanın SPKI SHA-256 pin'i (Base64) — kütüphanedeki biçimle aynı. */
function pinOf(certPem) {
  const spki = new crypto.X509Certificate(certPem).publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spki).digest('base64');
}

function generate() {
  fs.mkdirSync(DIR, { recursive: true });
  const subj = '/CN=custom-backend.sample';
  const ext = `subjectAltName=IP:${env.LAN_IP},DNS:localhost,IP:127.0.0.1`;
  for (const [keyFile, certFile] of [[FILES.key, FILES.cert], [FILES.backupKey, FILES.backupCert]]) {
    if (fs.existsSync(keyFile) && fs.existsSync(certFile)) continue;
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '825',
      '-keyout', keyFile, '-out', certFile, '-subj', subj, '-addext', ext]);
    fs.chmodSync(keyFile, 0o600);
  }
  if (!fs.existsSync(FILES.signingKey)) {
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', FILES.signingKey]);
    fs.chmodSync(FILES.signingKey, 0o600);
  }
}

/**
 * Uygulamanın derlemeye gömeceği değerler: taban adres, bootstrap pin'leri
 * (birincil + yedek) ve imzalama public key'i (X.509 SPKI, Base64).
 */
function material() {
  generate();
  const signingDer = openssl(['pkey', '-in', FILES.signingKey, '-pubout', '-outform', 'DER'],
    { encoding: 'buffer' });
  return {
    baseUrl: `https://${env.LAN_IP}:${env.CUSTOM_BACKEND_PORT}/`,
    pins: [pinOf(fs.readFileSync(FILES.cert)), pinOf(fs.readFileSync(FILES.backupCert))],
    signingPublicKey: Buffer.from(signingDer).toString('base64'),
  };
}

function sign(payload) {
  const key = crypto.createPrivateKey(fs.readFileSync(FILES.signingKey));
  return crypto.createSign('SHA256').update(payload).end().sign(key).toString('base64');
}

/**
 * Vault dosyası içerik imzası. Kütüphanenin beklediği kanonik metin
 * (ConfigSignatureVerifier.verifyVaultFile) sunucudakiyle birebir aynı:
 * `pinvault-vault-file:v1:<key>:<version>:<sha256hex(düz metin)>`.
 * İmzalama public key'i blokta tanımlı olduğu için imzasız dosya reddedilir
 * (fail-closed) — bu başlık olmadan indirme hiç çalışmaz.
 */
function signVaultFile(key, version, plaintext) {
  const digest = crypto.createHash('sha256').update(plaintext).digest('hex');
  return sign(`pinvault-vault-file:v1:${key}:${version}:${digest}`);
}

/**
 * Backend'i başlatır. [pins] hedef host için dağıtılacak pin listesi;
 * [vaultFiles] anahtar → içerik. Dönen nesne: { url, stop(), requests, log,
 * setPins(), setVaultFile(), version, fileVersion() }.
 *
 * Uçlar (uygulamadaki ConfigApiBlock ile aynı özel yollar):
 *   GET  /ping                 sağlık
 *   GET  /ssl/pins             imzalı config { payload, signature }
 *   GET  /files/<key>          vault dosyası (X-Vault-Version, X-Vault-Signature)
 *   POST /analytics/vault      vault indirme raporu
 *   POST /auth/register        kayıt (bu örnekte 501)
 */
async function start({ targetHost = env.TARGET_HOST, pins, vaultFiles = {}, port = env.CUSTOM_BACKEND_PORT } = {}) {
  generate();
  const state = {
    version: 1,
    pins: pins || [],
    files: Object.fromEntries(Object.entries(vaultFiles).map(([k, v]) => [k, { content: Buffer.from(v), version: 1 }])),
    requests: [],
    log: [],
  };

  const configPayload = () => {
    const now = Date.now();
    return JSON.stringify({
      version: state.version,
      pins: [{ hostname: targetHost, sha256: state.pins, version: state.version, forceUpdate: false, mtls: false, clientCertVersion: null }],
      forceUpdate: false,
      issuedAt: now,
      expiresAt: now + 3600_000,
    });
  };

  const server = https.createServer(
    { key: fs.readFileSync(FILES.key), cert: fs.readFileSync(FILES.cert) },
    (req, res) => {
      req.on('error', () => { /* istemci kesti */ });
      const url = new URL(req.url, 'https://backend');
      state.requests.push(`${req.method} ${url.pathname}${url.search}`);
      state.log.push({ method: req.method, path: url.pathname, search: url.search, at: Date.now() });
      const json = (code, body) => {
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === '/ping') return json(200, { status: 'ok' });
      if (url.pathname === '/ssl/pins') {
        const payload = configPayload();
        return json(200, { payload, signature: sign(payload) });
      }
      if (url.pathname.startsWith('/files/')) {
        const key = decodeURIComponent(url.pathname.slice('/files/'.length));
        const entry = state.files[key];
        if (!entry) return json(404, { error: 'not found' });
        const asked = Number(url.searchParams.get('version') || '0');
        const headers = {
          'X-Vault-Version': String(entry.version),
          'X-Vault-Encryption': 'plain',
          'X-Vault-Signature': signVaultFile(key, entry.version, entry.content),
        };
        if (asked === entry.version) {
          res.writeHead(304, headers);
          return res.end();
        }
        res.writeHead(200, { ...headers, 'Content-Type': 'application/octet-stream' });
        return res.end(entry.content);
      }
      if (url.pathname === '/analytics/vault') {
        req.resume();
        return json(200, { ok: true });
      }
      if (url.pathname === '/auth/register') {
        req.resume();
        return json(501, { error: 'enrollment not supported' });
      }
      req.resume();
      return json(404, { error: 'unknown endpoint' });
    },
  );
  server.on('tlsClientError', () => { /* pinlemeyi tutmayan istemci */ });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', resolve);
  });

  return {
    url: `https://${env.LAN_IP}:${port}/`,
    requests: state.requests,
    log: state.log,
    setPins(next) {
      state.pins = next;
      state.version += 1;
    },
    setVaultFile(key, content) {
      const previous = state.files[key];
      state.files[key] = { content: Buffer.from(content), version: previous ? previous.version + 1 : 1 };
    },
    fileVersion(key) {
      return state.files[key] ? state.files[key].version : 0;
    },
    get version() {
      return state.version;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

module.exports = { material, start, pinOf, signVaultFile, FILES };
