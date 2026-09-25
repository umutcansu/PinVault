// Ara sertifika (CA) pini senaryosu için küçük bir test CA'sı (openssl).
//
//  - ca.pem / ca.key     : "PinVault E2E Test CA" (CA:TRUE). Pin'i bu sertifikaya konur.
//  - leaf.pem / leaf.key : mock host'un sertifikası, CA'nın imzasıyla.
//  - bundle.p12          : leaf + CA zinciri, dashboard'dan yüklenir (parola changeit).
//  - forged.pem / .key   : saldırganın sertifikası. Veren adı gerçek CA'yla aynı,
//                          ama saldırganın KENDİ anahtarıyla imzalı; saldırgan bunun
//                          arkasına gerçek CA sertifikasını ekler.
//
// Her çağrıda yeniden üretilir: sertifikaların başlangıç saati "şimdi"dir,
// senaryo emülatörün saatinin bunu geçmesini bekler.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const env = require('./env');

const DIR = path.join(env.LOCAL_DIR, 'chain-ca');
const CA_SUBJECT = '/CN=PinVault E2E Test CA/O=PinVault E2E';
const P12_PASSWORD = 'changeit';

function openssl(args) {
  return execFileSync('openssl', args, { cwd: DIR, encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'] });
}

function selfSignedCa(name) {
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '825',
    '-keyout', `${name}.key`, '-out', `${name}.pem`, '-subj', CA_SUBJECT,
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
}

function serverCert(name, host, caName) {
  fs.writeFileSync(path.join(DIR, `${name}.ext`), [
    'basicConstraints=CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    `subjectAltName=DNS:${host}`,
  ].join('\n'));
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${host}/O=PinVault E2E`]);
  openssl(['x509', '-req', '-in', `${name}.csr`, '-CA', `${caName}.pem`, '-CAkey', `${caName}.key`,
    '-set_serial', String(Date.now()), '-days', '365', '-sha256', '-extfile', `${name}.ext`, '-out', `${name}.pem`]);
}

const pem = (name) => fs.readFileSync(path.join(DIR, `${name}.pem`), 'utf8');
const pinOf = (name) => {
  const spki = new crypto.X509Certificate(pem(name)).publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spki).digest('base64');
};

/** Test CA'sını, [host] için gerçek ve sahte sertifikaları üretir. */
function create(host) {
  fs.rmSync(DIR, { recursive: true, force: true });
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  selfSignedCa('ca');
  serverCert('leaf', host, 'ca');
  openssl(['pkcs12', '-export', '-inkey', 'leaf.key', '-in', 'leaf.pem', '-certfile', 'ca.pem',
    '-name', 'server', '-out', 'bundle.p12', '-passout', `pass:${P12_PASSWORD}`]);
  // Saldırgan: aynı adda kendi CA'sı; bu yüzden sahte sertifikanın "veren"i gerçeğinkiyle aynı.
  selfSignedCa('attacker-ca');
  serverCert('forged', host, 'attacker-ca');

  const describe = (name) => {
    const x = new crypto.X509Certificate(pem(name));
    return { subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), pin: pinOf(name) };
  };
  return {
    dir: DIR,
    p12: path.join(DIR, 'bundle.p12'),
    p12Password: P12_PASSWORD,
    ca: describe('ca'),
    leaf: describe('leaf'),
    forged: describe('forged'),
    attackerCa: describe('attacker-ca'),
    /** Saldırganın sunduğu zincir: sahte sertifika + GERÇEK CA sertifikası. */
    forgedMaterial: () => ({
      key: fs.readFileSync(path.join(DIR, 'forged.key')),
      cert: pem('forged') + pem('ca'),
    }),
  };
}

module.exports = { create, DIR };
