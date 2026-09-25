// Harness'ın çevrimdışı imza anahtarları: yedek imza anahtarı, kurtarma
// anahtarları ve ek imzalayıcılar. Host'un scripts/signing-keys.sh betiğiyle
// aynı biçimde (<ad>.pem PKCS#8, <ad>.pub Base64 SPKI) .local/offline-keys
// altında durur; senaryolar betiği OFFLINE_KEYS_DIR ile buraya yönlendirip
// operatörün kullanacağı komutların kendisini çalıştırır.
//
// Bir kez üretilir ve koşular arasında korunur: ana host'a göre derlenen
// APK'ya gömülü oldukları için her koşuda değişirlerse APK her seferinde
// yeniden derlenirdi.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const env = require('./env');

const DIR = env.OFFLINE_KEYS_DIR;

/** Base64 SPKI → anahtar kimliği (Base64 SHA-256; cihaz ve sunucu aynısını gösterir). */
function keyIdOf(pubB64) {
  return crypto.createHash('sha256').update(Buffer.from(pubB64, 'base64')).digest('base64');
}

/** [name] anahtarını (yoksa üretip) döndürür: { name, pem, pub, keyId, privateKey }. */
function ensure(name) {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const pemFile = path.join(DIR, `${name}.pem`);
  const pubFile = path.join(DIR, `${name}.pub`);
  if (!fs.existsSync(pemFile)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    fs.writeFileSync(pemFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(pubFile, `${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}\n`);
  }
  const pem = fs.readFileSync(pemFile, 'utf8');
  const pub = fs.readFileSync(pubFile, 'utf8').trim();
  return { name, pemFile, pubFile, pub, keyId: keyIdOf(pub), privateKey: crypto.createPrivateKey(pem) };
}

/** [payload]'ı [key] ile imzalar (Base64 DER), cihazın doğruladığı biçimde. */
function sign(key, payload) {
  return crypto.createSign('SHA256').update(payload).end().sign(key.privateKey).toString('base64');
}

/**
 * Bir imzalama anahtarı seti: {payload, signatures}. Host'un
 * `signing-keys.sh keyset` çıktısıyla aynı; burada Node ile üretmek sahte
 * setleri (yanlış anahtarla imzalı, bozuk) kurmayı kolaylaştırır.
 */
function keySet({ version, keys, signers, requiredSignatures }) {
  const payload = JSON.stringify({
    type: 'pinvault-signing-keys',
    version,
    keys: [...new Set(keys)].sort(),
    ...(requiredSignatures ? { requiredSignatures } : {}),
  });
  return { payload, signatures: signers.map((k) => ({ keyId: k.keyId, signature: sign(k, payload) })) };
}

module.exports = { DIR, ensure, keyIdOf, sign, keySet };
