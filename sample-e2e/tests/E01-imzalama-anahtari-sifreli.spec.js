// E1: SIGNING_KEY_PASSWORD ile imzalama anahtarı diskte AES-256-GCM ile
// şifrelenir (dosya "ENCv1:" ile başlar), düz metin anahtar otomatik göç eder,
// anahtar çifti değişmediği için telefondaki imza doğrulaması çalışmaya devam
// eder. Sonunda anahtar düz metin haline ve sunucu .env değerlerine döner.
//
// Ana host üzerinde koşar (telefonun gerçekten imzalı config aldığı örnek).
// Anahtar dosyasının yedeği alınır: parola kaldırıldığında dosya şifreli
// kalırsa sunucu bir daha açılmaz.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const PASSWORD = 'e2e-imzalama-parolasi';
const BACKUP = path.join(env.LOCAL_DIR, 'signing-key.backup.pem');

/** İmzalı config'in ECDSA imzasını verilen SPKI public key ile doğrular. */
function verifySignedConfig(signed, publicKeyBase64) {
  const key = crypto.createPublicKey({
    key: Buffer.from(publicKeyBase64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify('sha256', Buffer.from(signed.payload, 'utf8'), key, Buffer.from(signed.signature, 'base64'));
}

test('Sunucu: SIGNING_KEY_PASSWORD anahtarı diskte şifreler; imzalı config doğrulanmaya devam eder', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);

  const plaintext = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
  const publicKey = plaintext.split('\n')[1].trim();
  fs.writeFileSync(BACKUP, plaintext, { mode: 0o600 });
  let overridden = false;

  try {
    await test.step('Sunucu: parola yokken anahtar düz metin (başlangıç)', async () => {
      await attachText(
        testInfo,
        'data/signing-key.pem (parola yok)',
        [
          `satır 1 (private, gizli): ${plaintext.split('\n')[0].slice(0, 12)}… (${plaintext.split('\n')[0].length} karakter Base64)`,
          `satır 2 (public)        : ${publicKey}`,
          `izinler                 : ${(fs.statSync(env.SIGNING_KEY_FILE).mode & 0o777).toString(8)}`,
        ].join('\n'),
      );
      expect(plaintext.startsWith('ENCv1:')).toBe(false);
    });

    await test.step('Sunucu: SIGNING_KEY_PASSWORD ayarlanır → dosya "ENCv1:" olur', async () => {
      await hostControl.setEnv({ SIGNING_KEY_PASSWORD: PASSWORD });
      overridden = true;
      const encrypted = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
      await attachText(
        testInfo,
        'data/signing-key.pem (SIGNING_KEY_PASSWORD ayarlı)',
        [
          `ilk 32 karakter : ${encrypted.slice(0, 32)}…`,
          `uzunluk         : ${encrypted.trim().length} karakter`,
          `izinler         : ${(fs.statSync(env.SIGNING_KEY_FILE).mode & 0o777).toString(8)}`,
          '',
          'Biçim: "ENCv1:" + Base64( [16 bayt salt][12 bayt IV][AES-256-GCM şifreli metin+etiket] )',
          'Anahtar PBKDF2-HMAC-SHA256 (200.000 tur) ile paroladan türetilir.',
        ].join('\n'),
      );
      expect(encrypted.startsWith('ENCv1:')).toBe(true);
      expect((fs.statSync(env.SIGNING_KEY_FILE).mode & 0o777).toString(8)).toBe('600');
    });

    await test.step('Sunucu: otomatik göç logu ve değişmeyen public key', async () => {
      const logs = hostControl.logs(200);
      const migration = logs.split('\n').filter((l) => /signing|ENCv1|Re-encrypt/i.test(l)).join('\n');
      const served = await hostApi.api('/api/v1/signing-key', { withKey: false });
      await attachText(
        testInfo,
        'docker compose logs | ConfigSigningService + GET /api/v1/signing-key',
        [migration, '', `HTTP ${served.status}`, served.text].join('\n'),
      );
      expect(migration).toContain('Re-encrypting plaintext signing key');
      // Anahtar çifti aynı: APK'ya gömülü public key hâlâ geçerli.
      expect(served.json.publicKey).toBe(publicKey);
    });

    await test.step('Web: İmzalama sekmesi aynı public key\'i gösteriyor', async () => {
      // Container yeniden oluşturuldu; sayfa yeniden yüklenip sekme açılır.
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible({ timeout: 20_000 });
      const shown = await dashboard.signingPublicKey(env.VAULT_API);
      await dashboard.snap('İmzalama sekmesi: anahtar diskte şifreliyken public key aynı');
      expect(shown).toBe(publicKey);
    });

    await test.step('Sunucu: imzalı config aynı anahtarla doğrulanıyor', async () => {
      const signed = (await hostApi.api('/api/v1/certificate-config', { withKey: false })).json;
      const ok = verifySignedConfig(signed, publicKey);
      const payload = JSON.parse(signed.payload);
      await attachText(
        testInfo,
        'GET /api/v1/certificate-config (imzalı) — ECDSA doğrulaması',
        [
          `imza (Base64, kısaltıldı): ${signed.signature.slice(0, 24)}…`,
          `payload sürümü           : v${payload.version}`,
          `issuedAt / expiresAt     : ${new Date(payload.issuedAt).toISOString()} → ${new Date(payload.expiresAt).toISOString()}`,
          `SHA256withECDSA doğrulama: ${ok ? 'GEÇTİ' : 'KALDI'} (APK'daki public key ile)`,
        ].join('\n'),
      );
      expect(ok).toBe(true);
    });

    await test.step('Mobil: telefon imzalı config\'i kabul etmeye devam ediyor', async () => {
      const status = await app.refreshConfig();
      await app.snap('anahtar diskte şifreliyken config doğrulandı');
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    // Parola kaldırılınca dosya şifreli kalırsa sunucu açılmaz: önce düz metin
    // yedeği geri koy, sonra ortam değişkenini sıfırla.
    fs.writeFileSync(env.SIGNING_KEY_FILE, plaintext, { mode: 0o600 });
    if (overridden) await hostControl.resetEnv();
    fs.rmSync(BACKUP, { force: true });
    const restored = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
    await attachText(
      testInfo,
      'Geri alma: düz metin anahtar + .env değerleri',
      [
        `dosya "ENCv1:" ile başlıyor mu: ${restored.startsWith('ENCv1:')}`,
        `public key                    : ${restored.split('\n')[1].trim() === publicKey ? 'aynı' : 'DEĞİŞTİ'}`,
        `sunucu sağlığı                : ${(await hostApi.isHealthy()) ? 'ok' : 'YANIT YOK'}`,
      ].join('\n'),
    );
    expect(restored.startsWith('ENCv1:')).toBe(false);
  }
});
