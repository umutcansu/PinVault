// Kurcalama vekili: telefon ile host arasına girer. İki çalışma biçimi var.
//
//  1. Sahte anahtar ("rogue"): kendi ürettiği sertifikayla dinler. Gerçek bir
//     araya girme denemesidir; pinleme çalışıyorsa telefon hiçbir isteği
//     geçirmez.
//  2. Host'un kendi anahtarı ("trusted"): scripts/export-server-key.sh ile
//     dışa aktarılan anahtar/sertifika ile dinler, yani TLS pin'i tutar. Böylece
//     pin'in ötesindeki savunmalar sınanabilir: imza bozma, replay, sürüm
//     düşürme, başlık silme. Yalnızca laboratuvar.
//
// Trafiği vekile emülatördeki iptables DNAT yönlendirir (Device.redirectTcp).
// Vekil isteği gerçek host'a iletir ve yanıtı [mutate] ile değiştirir.
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const env = require('./env');
const signingKeyFile = require('./signingKeyFile');

const ROGUE_DIR = path.join(env.LOCAL_DIR, 'proxy-rogue');

/**
 * Yanıtta taşınması anlamsız ya da zararlı olan başlıklar. Gövdeyi
 * değiştirdiğimiz için uzunluk yeniden hesaplanır; chunked/keep-alive
 * pazarlığı vekilin kendi bağlantısına aittir, yukarı akıştan taşınmaz.
 */
const HOP_BY_HOP = ['content-length', 'transfer-encoding', 'connection', 'keep-alive', 'proxy-connection'];

/** Sahte (pinlenmemiş) anahtar çifti; bir kez üretilir. */
function rogueMaterial() {
  const key = path.join(ROGUE_DIR, 'key.pem');
  const cert = path.join(ROGUE_DIR, 'cert.pem');
  if (!fs.existsSync(key) || !fs.existsSync(cert)) {
    fs.mkdirSync(ROGUE_DIR, { recursive: true });
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '825',
      '-keyout', key, '-out', cert, '-subj', '/CN=rogue.sample',
      '-addext', `subjectAltName=IP:${env.LAN_IP},DNS:localhost,IP:127.0.0.1`],
      { encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'ignore', 'ignore'] });
    fs.chmodSync(key, 0o600);
  }
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function trustedMaterial() {
  if (!fs.existsSync(env.PROXY_KEY_FILE) || !fs.existsSync(env.PROXY_CERT_FILE)) {
    throw new Error(
      `Araya giren proxy için sunucu anahtarı yok: ${env.PROXY_KEY_FILE}\n` +
      `Üret: cd ${env.HOST_DIR} && ./scripts/export-server-key.sh`,
    );
  }
  return { key: fs.readFileSync(env.PROXY_KEY_FILE), cert: fs.readFileSync(env.PROXY_CERT_FILE) };
}

/**
 * Host'un sunduğu sertifika yenilenmişse dışa aktarılmış kopya eskir; o zaman
 * "trusted" kimlik de pin tutmaz ve senaryo yanlış nedenle düşer. Vekil
 * başlarken kontrol edilir.
 */
function assertTrustedPinMatches() {
  const pin = certPin('trusted');
  const known = fs.existsSync(env.HOST_PINS_FILE)
    ? fs.readFileSync(env.HOST_PINS_FILE, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)
    : [];
  if (known.length && !known.includes(pin)) {
    throw new Error(
      `Araya giren proxy'nin sertifikası host'un pin dosyasıyla eşleşmiyor (${pin}).\n` +
      `Yeniden dışa aktar: cd ${env.HOST_DIR} && ./scripts/export-server-key.sh`,
    );
  }
}

/**
 * Vekili başlatır.
 *
 * @param {object} opts
 * @param {'trusted'|'rogue'} opts.identity Hangi anahtarla dinleneceği.
 * @param {number} opts.upstreamPort Gerçek host portu (varsayılan Config API).
 * @param {string} opts.upstreamHost Gerçek host adresi (varsayılan 127.0.0.1).
 * @param {number} opts.port Vekilin dinlediği port (varsayılan env.PROXY_PORT).
 * @param {function} opts.mutate ({ path, method, status, headers, body, requestBody }) →
 *        aynı şekil ya da undefined (değiştirme). body ve requestBody Buffer'dır
 *        (requestBody: telefonun gönderdiği istek gövdesi, salt okunur).
 * @returns {{port, identity, requests, handshakeErrors, stop, setMutate}}
 */
async function start({
  identity = 'trusted',
  upstreamPort = env.CONFIG_API_PORT,
  upstreamHost = '127.0.0.1',
  port = env.PROXY_PORT,
  mutate,
  /** Kendi anahtar/sertifika zinciri ({ key, cert }; cert birden çok PEM içerebilir). */
  material: custom,
} = {}) {
  const material = custom || (identity === 'rogue' ? rogueMaterial() : trustedMaterial());
  if (!custom && identity === 'trusted') assertTrustedPinMatches();
  const state = { mutate, requests: [], handshakeErrors: [] };

  const server = https.createServer({ key: material.key, cert: material.cert }, (req, res) => {
    const chunks = [];
    req.on('error', () => { /* telefon bağlantıyı kesti */ });
    res.on('error', () => { /* yanıt yazılamadı */ });
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const requestBody = Buffer.concat(chunks);
      state.requests.push(`${req.method} ${req.url}`);
      // Gövdeyi değiştirebilmek için yukarı akıştan hep düz (sıkıştırılmamış)
      // yanıt isteriz: OkHttp'nin "Accept-Encoding: gzip" başlığı iletilirse
      // gövde gzip gelir ve JSON kurcalamaları gövdeyi ayrıştıramaz.
      const upstreamHeaders = { ...req.headers, host: `${env.LAN_IP}:${upstreamPort}` };
      delete upstreamHeaders['accept-encoding'];
      const upstream = https.request(
        {
          host: upstreamHost,
          port: upstreamPort,
          method: req.method,
          path: req.url,
          headers: upstreamHeaders,
          // Host self-signed; güven zinciri değil, vekilin kendi işi.
          rejectUnauthorized: false,
        },
        (up) => {
          const upChunks = [];
          up.on('data', (c) => upChunks.push(c));
          up.on('end', () => {
            let answer = {
              path: req.url,
              method: req.method,
              status: up.statusCode,
              headers: { ...up.headers },
              body: Buffer.concat(upChunks),
              requestBody,
            };
            if (state.mutate) {
              try {
                answer = state.mutate(answer) || answer;
              } catch (e) {
                answer = { ...answer, status: 500, body: Buffer.from(`proxy mutate error: ${e.message}`) };
              }
            }
            const headers = { ...answer.headers };
            for (const name of HOP_BY_HOP) delete headers[name];
            headers['content-length'] = Buffer.byteLength(answer.body);
            try {
              res.writeHead(answer.status, headers);
              res.end(answer.body);
            } catch {
              /* telefon kapatmış */
            }
          });
        },
      );
      upstream.on('error', (e) => {
        try {
          res.writeHead(502, { 'Content-Type': 'text/plain' });
          res.end(`proxy upstream error: ${e.message}`);
        } catch {
          /* telefon kapatmış */
        }
      });
      if (requestBody.length) upstream.write(requestBody);
      upstream.end();
    });
  });

  // Telefonun sertifikayı reddedip el sıkışmayı kesmesi ("rogue" senaryosu)
  // burada görünür; dinleyici olmazsa Node soketi sessizce kapatır ve kanıt
  // kaybolur.
  server.on('tlsClientError', (e) => {
    state.handshakeErrors.push(e.message);
  });
  server.on('clientError', (e, socket) => {
    state.handshakeErrors.push(e.message);
    try {
      socket.destroy();
    } catch {
      /* zaten kapalı */
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', resolve);
  });

  return {
    port,
    identity,
    requests: state.requests,
    handshakeErrors: state.handshakeErrors,
    setMutate(fn) {
      state.mutate = fn;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

// ── Sık kullanılan kurcalamalar ────────────────────────────────────────────

const isConfig = (answer) => answer.path.startsWith('/api/v1/certificate-config');
/** Vault dosyası indirme (rapor ve public-key POST'ları hariç). */
const isVaultDownload = (answer) =>
  answer.method === 'GET' && answer.path.startsWith('/api/v1/vault/');

/** Yanıtı [store] dizisine kaydeder, gövdeyi değiştirmez (replay için). */
const capture = (store, match = isConfig) => (answer) => {
  if (match(answer)) store.push({ path: answer.path, status: answer.status, headers: { ...answer.headers }, body: answer.body });
  return answer;
};

/** İmzalı config yanıtındaki imzanın son baytını bozar. */
const breakConfigSignature = (answer) => {
  if (!isConfig(answer)) return answer;
  const json = JSON.parse(answer.body.toString('utf8'));
  const sig = Buffer.from(json.signature, 'base64');
  sig[sig.length - 1] ^= 0xff;
  json.signature = sig.toString('base64');
  return { ...answer, body: Buffer.from(JSON.stringify(json)) };
};

/** Daha önce yakalanan imzalı config yanıtını olduğu gibi tekrar oynatır. */
const replayConfig = (captured) => (answer) =>
  isConfig(answer) ? { ...answer, body: Buffer.from(captured) } : answer;

/**
 * İmzalı config'in payload'ındaki per-host sürümleri [delta] kadar düşürür.
 * İmza payload ile tutmayacağı için istemci bunu zaten imza hatasıyla
 * reddeder; sürüm düşürme kontrolünü ayrıca görmek için imzayı da yeniler
 * ([sign] verilirse — laboratuvar anahtarı).
 */
const downgradeConfig = (delta = 1, sign) => (answer) => {
  if (!isConfig(answer)) return answer;
  const json = JSON.parse(answer.body.toString('utf8'));
  const payload = JSON.parse(json.payload);
  payload.pins = payload.pins.map((p) => ({ ...p, version: Math.max(0, p.version - delta) }));
  payload.version = Math.max(0, payload.version - delta);
  const nextPayload = JSON.stringify(payload);
  return {
    ...answer,
    body: Buffer.from(JSON.stringify({ payload: nextPayload, signature: sign ? sign(nextPayload) : json.signature })),
  };
};

/**
 * İmzalı config zarfına [wire] imzalama anahtarı setini ekler (varsa
 * değiştirir): { payload, signatures: [{ keyId, signature }] }. Config'in kendi
 * imzasına dokunmaz — set ayrıca kurtarma anahtar(lar)ıyla imzalı olmalıdır;
 * sahte set denemeleri bunu sınar. [seen] verilirse kablodaki önceki/sonraki
 * gövdeler kanıt için oraya yazılır.
 */
const injectKeySet = (wire, seen) => (answer) => {
  if (!isConfig(answer) || answer.status !== 200) return answer;
  const before = answer.body.toString('utf8');
  const json = JSON.parse(before);
  json.signingKeys = wire;
  const after = JSON.stringify(json);
  if (seen) seen.push({ path: answer.path, before, after });
  return { ...answer, body: Buffer.from(after) };
};

/**
 * Kayıt (CSR) yanıtındaki sertifika zincirini saldırganın ürettiği bir zincirle
 * değiştirir. Sunucu telefonun anahtarı için gerçek bir sertifika verdi; telefon
 * yanıtta saldırganınkini görür. Üç biçim:
 *
 *   'other-key'   : [yaprak, saldırgan CA]; yaprak saldırganın kendi anahtarı
 *                   için (telefonun anahtarı değil). Kurulsaydı telefonun
 *                   kimliği saldırganın elindeki anahtara bağlanırdı.
 *   'self-signed' : tek sertifikalık, kendinden imzalı zincir (CA yok).
 *   'rogue-ca'    : [yaprak, saldırgan CA]; yaprak TELEFONUN anahtarı için
 *                   (istekteki CSR'dan alınır) ama sunucunun istemci CA'sı değil
 *                   saldırganın CA'sı imzalar. Bunu yalnızca istemci CA pin'i
 *                   (clientCaPins) yakalar.
 *
 * [seen] verilirse değişiklik kanıt için oraya yazılır: { path, mode, before:
 * [{subject, issuer, spki}], after: [...] }. openssl ile üretilir (eşzamanlı).
 */
const forgeEnrollmentChain = (mode, seen) => (answer) => {
  if (!answer.path.includes('/client-certs/enroll') || answer.status !== 200) return answer;
  let json;
  try {
    json = JSON.parse(answer.body.toString('utf8'));
  } catch {
    return answer; // P12 ya da başka bir yanıt: bu kurcalamanın konusu değil
  }
  if (!Array.isArray(json.chain)) return answer;
  const forged = forgedChain(mode, answer.requestBody);
  // openssl (LibreSSL) yeni sertifikanın başlangıcını "şimdi"ye koyar ve geri
  // alamaz; emülatörün saati Mac'inkinden bir iki saniye geride olabildiği için
  // telefon zinciri asıl incelenen kontrolden (anahtar, CA) önce "henüz geçerli
  // değil" diye reddedebiliyordu. Yanıt birkaç saniye bekletilir.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5000);
  if (seen) seen.push({ path: answer.path, mode, before: describeChain(json.chain), after: describeChain(forged) });
  return { ...answer, body: Buffer.from(JSON.stringify({ ...json, chain: forged })) };
};

/** Saldırganın CA'sı ve zinciri (openssl, .local/proxy-rogue/enroll-* altında). */
function forgedChain(mode, requestBody) {
  fs.mkdirSync(ROGUE_DIR, { recursive: true });
  const dir = fs.mkdtempSync(path.join(ROGUE_DIR, 'enroll-'));
  const ossl = (args) => execFileSync('openssl', args, { cwd: dir, encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'ignore'] });
  const serial = () => `0x${crypto.randomBytes(8).toString('hex')}`;
  try {
    if (mode === 'self-signed') {
      ossl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.pem',
        '-days', '30', '-subj', '/CN=PinVault Client: saldirgan']);
      return [fs.readFileSync(path.join(dir, 'leaf.pem'), 'utf8')];
    }
    ossl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
      '-days', '30', '-subj', '/CN=Saldirgan Istemci CA']);
    if (mode === 'rogue-ca') {
      // Telefonun kendi CSR'ı: yaprak onun anahtarı için, saldırganın CA'sıyla imzalı.
      const csr = JSON.parse(requestBody.toString('utf8')).csr;
      if (!csr) throw new Error('kayıt isteğinde CSR yok');
      fs.writeFileSync(path.join(dir, 'device.csr'), Buffer.from(csr, 'base64'));
      // LibreSSL'in x509 -req'i DER okumuyor: önce PEM'e çevrilir.
      ossl(['req', '-inform', 'DER', '-in', 'device.csr', '-out', 'device.pem']);
      ossl(['x509', '-req', '-in', 'device.pem', '-CA', 'ca.pem', '-CAkey', 'ca.key',
        '-set_serial', serial(), '-days', '30', '-out', 'leaf.pem']);
    } else if (mode === 'other-key') {
      ossl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'other.key', '-out', 'other.csr',
        '-subj', '/CN=PinVault Client: saldirgan']);
      ossl(['x509', '-req', '-in', 'other.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
        '-set_serial', serial(), '-days', '30', '-out', 'leaf.pem']);
    } else {
      throw new Error(`bilinmeyen zincir kurcalaması: ${mode}`);
    }
    return [fs.readFileSync(path.join(dir, 'leaf.pem'), 'utf8'), fs.readFileSync(path.join(dir, 'ca.pem'), 'utf8')];
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Zincirdeki sertifikaların konu, yayımcı ve SPKI pin'i (kanıt paneli için). */
function describeChain(pems) {
  return pems.map((pem) => {
    const cert = new crypto.X509Certificate(pem);
    const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    return {
      subject: cert.subject.replace(/\n/g, ', '),
      issuer: cert.issuer.replace(/\n/g, ', '),
      spki: crypto.createHash('sha256').update(spki).digest('base64'),
    };
  });
}

/**
 * Vault imza başlıkları: v1 (X-Vault-Signature) ve Config API'yi adlandıran v2
 * (X-Vault-Signature-V2; serverScope'lu blok yalnızca bunu okur). Çoğul
 * biçimler (X-Vault-Signatures[-V2], birden çok imzalayıcı) varsa kütüphane
 * onları tercih eder; kurcalamalar onları siler, tekil başlık belirleyici olur.
 */
const VAULT_SIGNATURE_HEADERS = ['x-vault-signature', 'x-vault-signature-v2'];
const VAULT_SIGNATURES_HEADERS = ['x-vault-signatures', 'x-vault-signatures-v2'];

/** Vault yanıtının içerik imzasını (v1 ve v2) bozar ya da siler. */
const breakVaultSignature = ({ remove = false } = {}) => (answer) => {
  if (!isVaultDownload(answer)) return answer;
  const headers = { ...answer.headers };
  for (const name of VAULT_SIGNATURES_HEADERS) delete headers[name];
  for (const name of VAULT_SIGNATURE_HEADERS) {
    if (remove) delete headers[name];
    else if (headers[name]) {
      const sig = Buffer.from(headers[name], 'base64');
      sig[sig.length - 1] ^= 0xff;
      headers[name] = sig.toString('base64');
    }
  }
  return { ...answer, headers };
};

/**
 * Vault yanıtındaki sürümü düşürür (X-Vault-Version).
 *
 * Sürüm imzanın kanonik metnine giriyor: yalnızca başlığı değiştirmek imzayı
 * da bozar, yani istemci "signature verification FAILED" der. Sürüm düşürme
 * kapısını ayrıca görmek için [sign] verilir (bkz. [vaultSigner]); o zaman
 * imza düşük sürüm için geçerlidir ve reddin nedeni sürümün kendisidir.
 * [sign] gövdeyi düz metin kabul eder — cihaza özel şifreli dosyalarda imza
 * zarfın değil düz metnin üstündedir, bu yardımcı o dosyalar için uygun değil.
 */
const downgradeVaultVersion = (version, sign, { scope = env.VAULT_API } = {}) => (answer) => {
  if (!isVaultDownload(answer)) return answer;
  const headers = { ...answer.headers, 'x-vault-version': String(version) };
  if (sign) {
    const key = decodeURIComponent(answer.path.replace(/^\/api\/v1\/vault\//, '').split('?')[0]);
    for (const name of VAULT_SIGNATURES_HEADERS) delete headers[name];
    headers['x-vault-signature'] = sign(key, version, answer.body);
    // v2: imza Config API kimliğini de kapsar ([scope], varsayılan Config API portunun kapsamı).
    if (headers['x-vault-signature-v2']) headers['x-vault-signature-v2'] = sign(key, version, answer.body, scope);
  }
  return { ...answer, headers };
};

/** Sağlık ucuna hata döndürür (güncelleme sonrası doğrulama sınaması). */
const failHealth = (answer) =>
  answer.path.startsWith('/health') ? { ...answer, status: 500, body: Buffer.from('{"status":"down"}') } : answer;

/** Birkaç kurcalamayı sırayla uygular. */
const chain = (...fns) => (answer) => fns.reduce((acc, fn) => fn(acc) || acc, answer);

// ── Laboratuvar imzalayıcıları (host'un kendi ECDSA anahtarı) ──────────────

/**
 * Host'un imzalama anahtarı. Dosya diskte SIGNING_KEY_PASSWORD ile şifreli
 * (ENCv1:); vekil onu .env'deki parolayla açar (lib/signingKeyFile.js).
 */
function signingKey() {
  return signingKeyFile.privateKey(env.SIGNING_KEY_FILE, env.SIGNING_KEY_PASSWORD);
}

/** Vekilin ECDSA imzası (laboratuvar): host'un imzalama anahtarıyla imzalar. */
function hostSigner() {
  const key = signingKey();
  return (payload) => crypto.createSign('SHA256').update(payload).end().sign(key).toString('base64');
}

/**
 * Vault dosyası imzalayıcısı (laboratuvar). Sunucudaki
 * ConfigSigningService.signVaultFile ile aynı kanonik metni kurar:
 * `pinvault-vault-file:v1:<key>:<version>:<sha256hex(düz metin)>`, [configApiId]
 * verilirse v2: `pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256hex>`
 */
function vaultSigner() {
  const key = signingKey();
  return (fileKey, version, plaintext, configApiId) => {
    const digest = crypto.createHash('sha256').update(plaintext).digest('hex');
    const canonical = configApiId
      ? `pinvault-vault-file:v2:${configApiId}:${fileKey}:${version}:${digest}`
      : `pinvault-vault-file:v1:${fileKey}:${version}:${digest}`;
    return crypto.createSign('SHA256').update(canonical).end().sign(key).toString('base64');
  };
}

/** Vekilin sunduğu sertifikanın pin'i (kanıt panelinde gösterilir). */
function certPin(identity = 'trusted') {
  const material = identity === 'rogue' ? rogueMaterial() : trustedMaterial();
  const spki = new crypto.X509Certificate(material.cert).publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spki).digest('base64');
}

/** Vekilin sunduğu sertifikanın özeti (konu, geçerlilik) — kanıt paneli için. */
function certSummary(identity = 'trusted') {
  const material = identity === 'rogue' ? rogueMaterial() : trustedMaterial();
  const cert = new crypto.X509Certificate(material.cert);
  return {
    subject: cert.subject.replace(/\n/g, ', '),
    issuer: cert.issuer.replace(/\n/g, ', '),
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    pin: certPin(identity),
  };
}

module.exports = {
  start,
  certPin,
  certSummary,
  hostSigner,
  vaultSigner,
  capture,
  breakConfigSignature,
  replayConfig,
  downgradeConfig,
  injectKeySet,
  forgeEnrollmentChain,
  describeChain,
  breakVaultSignature,
  downgradeVaultVersion,
  failHealth,
  chain,
};
