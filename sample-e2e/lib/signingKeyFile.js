// Sunucunun imzalama anahtarı dosyası (data/signing-key.pem) — okuma ve yazma.
//
// Dosyanın iki biçimi var (demo-server LocalFileSigner):
//   düz metin : "<PKCS#8 özel anahtar, Base64>\n<X.509 public key, Base64>"
//   şifreli   : "ENCv1:" + Base64( [16 bayt salt][12 bayt IV][AES-256-GCM şifreli metin + 16 bayt etiket] )
//               anahtar = PBKDF2-HMAC-SHA256(SIGNING_KEY_PASSWORD, salt, 200.000 tur, 32 bayt)
//
// sample-host artık demo profilinde de SIGNING_KEY_PASSWORD üretiyor; sunucu
// düz metin bir dosyayı ilk açılışta şifreler. Laboratuvar araçları (kurcalama
// vekilinin yeniden imzalaması, kanıt panelleri) anahtarı buradan, .env'deki
// parolayla açar. Parola ve özel anahtar hiçbir panele girmez.
const crypto = require('crypto');
const fs = require('fs');

const PREFIX = 'ENCv1:';
const PBKDF2_ITERATIONS = 200_000;

/** Dosya içeriği şifreli mi ("ENCv1:")? */
function isEncrypted(text) {
  return text.trim().startsWith(PREFIX);
}

/** "ENCv1:…" metnini [password] ile açar; düz metin biçimini döndürür. */
function decrypt(text, password) {
  if (!password) {
    throw new Error(
      'İmzalama anahtarı diskte şifreli (ENCv1:) ama SIGNING_KEY_PASSWORD bilinmiyor. ' +
        'sample-host/.env içinde olmalı (./scripts/setup.sh üretir).',
    );
  }
  const blob = Buffer.from(text.trim().slice(PREFIX.length), 'base64');
  if (blob.length <= 28 + 16) throw new Error('Şifreli imzalama anahtarı kısa (bozuk dosya)');
  const salt = blob.subarray(0, 16);
  const iv = blob.subarray(16, 28);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(28, blob.length - 16);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** Düz metin biçimini [password] ile "ENCv1:" biçimine çevirir (sunucunun yazdığıyla aynı düzen). */
function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return PREFIX + Buffer.concat([salt, iv, ciphertext, cipher.getAuthTag()]).toString('base64');
}

/**
 * Anahtar dosyasını okur. Şifreliyse [password] ile açar.
 * { encrypted, text (dosyadaki ham metin), plaintext ("özel\npublic"),
 *   privateKeyBase64, publicKeyBase64 }
 */
function read(file, password) {
  const text = fs.readFileSync(file, 'utf8');
  const encrypted = isEncrypted(text);
  const plaintext = (encrypted ? decrypt(text, password) : text).trim();
  const lines = plaintext.split('\n').map((s) => s.trim()).filter(Boolean);
  if (lines.length !== 2) throw new Error(`İmzalama anahtarı dosyası beklenen biçimde değil: ${file}`);
  return { encrypted, text, plaintext, privateKeyBase64: lines[0], publicKeyBase64: lines[1] };
}

/** Dosyadaki özel anahtar (Node KeyObject). */
function privateKey(file, password) {
  const { privateKeyBase64 } = read(file, password);
  return crypto.createPrivateKey({ key: Buffer.from(privateKeyBase64, 'base64'), format: 'der', type: 'pkcs8' });
}

/** Dosyadaki public key (Base64 X.509 SPKI; APK'ya gömülen değer). */
function publicKeyBase64(file, password) {
  return read(file, password).publicKeyBase64;
}

module.exports = { isEncrypted, decrypt, encrypt, read, privateKey, publicKeyBase64 };
