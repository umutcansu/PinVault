// E1: imzalama anahtarı diskte AES-256-GCM ile şifreli (dosya "ENCv1:" ile
// başlar). Sunucu SIGNING_KEY_PASSWORD olmadan açılmıyor; sample-host'un
// setup.sh'ı parolayı demo profilinde de üretiyor, yani anahtar baştan beri
// şifreli. Diskte düz metin bir anahtar dosyası kalmışsa (eski kurulum, elle
// kurulan yedek anahtar) sunucu onu ilk açılışta şifreliyor; anahtar çifti
// değişmediği için telefondaki imza doğrulaması çalışmaya devam ediyor.
//
// Ana host üzerinde koşar (telefonun gerçekten imzalı config aldığı örnek).
// Şifreli dosyanın yedeği alınır; sonunda dosya yine şifreli olmalı, değilse
// yedek geri konur.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const signingKeyFile = require('../lib/signingKeyFile');
const env = require('../lib/env');

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

const mode = () => (fs.statSync(env.SIGNING_KEY_FILE).mode & 0o777).toString(8);

test('Sunucu: imzalama anahtarı diskte şifreli (SIGNING_KEY_PASSWORD); düz metin kalmış bir anahtar ilk açılışta şifreleniyor, imzalı config doğrulanmaya devam ediyor', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  expect(env.SIGNING_KEY_PASSWORD, 'sample-host/.env içinde SIGNING_KEY_PASSWORD yok — ./scripts/setup.sh çalıştır').not.toBe('');

  const original = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  fs.writeFileSync(BACKUP, original, { mode: 0o600 });
  let publicKey;
  let plaintext;
  let restarted = false;

  try {
    await test.step('Sunucu: anahtar dosyası diskte şifreli ("ENCv1:"), yalnızca sahibine açık; .env\'deki parolayla açılınca public key sunucunun yayımladığıyla aynı', async () => {
      const key = signingKeyFile.read(env.SIGNING_KEY_FILE, env.SIGNING_KEY_PASSWORD);
      publicKey = key.publicKeyBase64;
      plaintext = key.plaintext;
      const served = await hostApi.signingKeyInfo();
      await attachText(
        testInfo,
        'data/signing-key.pem (SIGNING_KEY_PASSWORD ayarlı)',
        [
          `ilk 32 karakter : ${original.slice(0, 32)}…`,
          `uzunluk         : ${original.trim().length} karakter`,
          `izinler         : ${mode()}`,
          '',
          'Biçim: "ENCv1:" + Base64( [16 bayt salt][12 bayt IV][AES-256-GCM şifreli metin+etiket] )',
          'Anahtar PBKDF2-HMAC-SHA256 (200.000 tur) ile paroladan türetilir. Parola .env\'de',
          '(SIGNING_KEY_PASSWORD, setup.sh üretir); sunucu onsuz açılmaz.',
          '',
          `parolayla açılan public key : ${publicKey}`,
          `GET /api/v1/signing-key     : ${served.publicKey}  → ${served.publicKey === publicKey ? 'aynı ✓' : 'FARKLI ✗'}`,
        ].join('\n'),
      );
      expect(key.encrypted).toBe(true);
      expect(mode()).toBe('600');
      expect(served.publicKey).toBe(publicKey);
    });

    await test.step('Sunucu: diske düz metin anahtar konup container yeniden başlatılınca dosya kendiliğinden şifreleniyor (log: "Re-encrypting"); public key değişmedi', async () => {
      // Eski bir kurulumdan kalan ya da elle kurulan (signing-keys.sh install) anahtar böyle durur.
      fs.writeFileSync(env.SIGNING_KEY_FILE, `${plaintext}\n`, { mode: 0o600 });
      const before = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
      restarted = true;
      await hostControl.stop();
      await hostControl.start();
      const after = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
      const logs = hostControl.logs(200);
      const migration = logs.split('\n').filter((l) => /signing|ENCv1|Re-encrypt/i.test(l)).join('\n');
      const served = await hostApi.api('/api/v1/signing-key', { withKey: false });
      await attachText(
        testInfo,
        'Düz metin anahtar → yeniden başlatma → şifreli dosya',
        [
          `önce : "ENCv1:" ile başlıyor mu = ${signingKeyFile.isEncrypted(before)}  (düz metin, 2 satır Base64)`,
          '$ docker stop pinvault-host && docker start pinvault-host',
          `sonra: "ENCv1:" ile başlıyor mu = ${signingKeyFile.isEncrypted(after)}, izinler ${mode()}`,
          '',
          'docker logs | ConfigSigningService',
          migration,
          '',
          `GET /api/v1/signing-key → HTTP ${served.status}`,
          served.text,
        ].join('\n'),
      );
      expect(signingKeyFile.isEncrypted(before)).toBe(false);
      expect(signingKeyFile.isEncrypted(after)).toBe(true);
      expect(mode()).toBe('600');
      expect(migration).toContain('Re-encrypting plaintext signing key');
      // Anahtar çifti aynı: APK'ya gömülü public key hâlâ geçerli.
      expect(served.json.publicKey).toBe(publicKey);
      expect(signingKeyFile.publicKeyBase64(env.SIGNING_KEY_FILE, env.SIGNING_KEY_PASSWORD)).toBe(publicKey);
    });

    await test.step('Web: İmzalama sekmesi aynı public key\'i gösteriyor', async () => {
      // Container yeniden başladı; sayfa yeniden yüklenip sekme açılır.
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
    // Dosya şifreli değilse (senaryo yarıda kaldı) ya da sunucu açılmadıysa
    // yedeği (aynı anahtar, aynı parolayla şifreli) geri koy.
    const now = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
    const healthy = await hostApi.isHealthy();
    let restoredFromBackup = false;
    if (!signingKeyFile.isEncrypted(now) || !healthy) {
      fs.writeFileSync(env.SIGNING_KEY_FILE, original, { mode: 0o600 });
      restoredFromBackup = true;
      if (restarted) {
        await hostControl.stop().catch(() => {});
        await hostControl.start();
      }
    }
    fs.rmSync(BACKUP, { force: true });
    const final = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8');
    await attachText(
      testInfo,
      'Son durum: anahtar dosyası',
      [
        `yedek geri kondu mu           : ${restoredFromBackup ? 'evet' : 'gerek yok'}`,
        `dosya "ENCv1:" ile başlıyor mu: ${signingKeyFile.isEncrypted(final)}`,
        `public key                    : ${publicKey && signingKeyFile.publicKeyBase64(env.SIGNING_KEY_FILE, env.SIGNING_KEY_PASSWORD) === publicKey ? 'aynı' : 'DEĞİŞTİ'}`,
        `sunucu sağlığı                : ${(await hostApi.isHealthy()) ? 'ok' : 'YANIT YOK'}`,
      ].join('\n'),
    );
    expect(signingKeyFile.isEncrypted(final)).toBe(true);
  }
});
