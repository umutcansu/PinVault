// C10 — Uçtan uca şifrelemede cihaz anahtarı kayıtlı değilse.
//
// `end_to_end` dosyayı sunucu her cihaz için ayrı sarmalıyor: AES-256-GCM
// oturum anahtarı, cihazın kaydettiği RSA public key'le RSA-OAEP ile
// sarılıyor. Anahtarı kayıtlı olmayan bir istek sarmalanamaz — sunucu 412
// dönüp ne yapılması gerektiğini söylüyor. Telefon anahtarını init sırasında
// kaydettiği için aynı dosyayı alıp çözebiliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, describeResponse, hexdump } = require('../lib/evidence');
const crypto = require('crypto');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.e2e;

test('Vault uçtan uca şifreleme: public key\'i kayıtlı olmayan cihaz 412 alıyor, telefon dosyayı çözüyor', async ({
  app,
  dashboard,
}, testInfo) => {
  const plaintext = `bilinmeyen-cihaz-denemesi-${Date.now()}`;
  const unknownDevice = `e2e-bilinmeyen-${Date.now()}`;
  let deviceId;
  let version;

  try {
    await test.step('Web: dosya end_to_end şifrelemeyle yüklenir', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, plaintext, {
        policy: 'public',
        encryption: 'end_to_end',
      });
      const cells = await dashboard.vaultRowCells(KEY);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları — end_to_end');
      expect(cells.encryption).toContain('end_to_end');
    });

    await test.step('Ağ trafiği: public key\'i kayıtlı olmayan cihaz 412 alıyor', async () => {
      const res = await hostApi.rawVaultDownload(KEY, unknownDevice);
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — X-Device-Id: ${unknownDevice} (hiç kaydı olmayan cihaz)`,
        [
          describeResponse(res, { maxBody: 300 }),
          '',
          'Politika public: erişim kontrolü yok. Reddin nedeni yetki değil; sunucunun',
          'içeriği bu cihaz için şifreleyeceği public key\'in olmaması. Yanıt 412',
          'Precondition Failed ve yapılması gereken çağrı mesajda yazılı.',
        ].join('\n'),
      );
      expect(res.status).toBe(412);
      expect(res.body.toString('utf8')).toContain('public key');
      expect(res.body.toString('utf8')).toContain('/public-key');
      // Şifreli içerik hiç üretilmedi: gövdede düz metin de yok.
      expect(res.body.includes(Buffer.from(plaintext, 'utf8'))).toBe(false);
    });

    await test.step('Ağ trafiği: cihaz kimliği hiç gönderilmezse 401', async () => {
      const res = await hostApi.rawVaultDownload(KEY, null);
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — X-Device-Id başlığı yok`,
        [
          describeResponse(res, { maxBody: 200 }),
          '',
          'Kimlik yoksa içeriğin hangi cihazın anahtarıyla şifreleneceği belli değil;',
          'sunucu düz metin göndermiyor, isteği reddediyor (şüphede izin vermez).',
        ].join('\n'),
      );
      expect(res.status).toBe(401);
      expect(res.body.toString('utf8')).toContain('X-Device-Id required');
    });

    await test.step('Mobil: telefon kendi anahtarıyla aynı dosyayı çözüyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      await app.snap('kendi anahtarıyla çözüldü');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain('cihaz anahtarıyla çözüldü');
      expect(status).toContain(plaintext);
    });

    await test.step('Ağ trafiği: telefonun kimliğiyle yapılan istek bu cihaza özel şifrelenmiş içerik alıyor', async () => {
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      const wrappedKeyLength = res.body.readUInt32BE(0);
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — X-Device-Id: ${deviceId} (telefonun kimliği)`,
        [
          describeResponse(res, { bodyHex: true, maxBody: 64 }),
          '',
          `gövde düzeni: [4B uzunluk=${wrappedKeyLength}][RSA-OAEP ile şifrelenmiş AES anahtarı]` +
            '[12B IV][AES-256-GCM şifreli metin + etiket]',
          `düz metin gövdede geçiyor mu: ${res.body.includes(Buffer.from(plaintext, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          hexdump(res.body, 80),
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(res.headers['x-vault-encryption']).toBe('end_to_end');
      expect(wrappedKeyLength).toBe(256);
      expect(res.body.includes(Buffer.from(plaintext, 'utf8'))).toBe(false);
    });

    await test.step('Sunucu: kayıtlı cihaz public key\'leri tablosu', async () => {
      await attachCommand(
        testInfo,
        'sqlite3 — device_public_keys',
        'sqlite3',
        ['-readonly', '-line', env.DB_FILE,
          'SELECT device_id, config_api_id, algorithm, registered_at, length(public_key_pem) AS pem_bayt FROM device_public_keys;'],
      );
      const pem = hostApi.devicePublicKeyPem(deviceId, env.VAULT_API);
      const unknownPem = hostApi.devicePublicKeyPem(unknownDevice, env.VAULT_API);
      const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64');
      await attachText(
        testInfo,
        'Telefonun kayıtlı public key\'i',
        [
          `cihaz: ${deviceId}`,
          `SPKI: ${der.length} bayt, SHA-256 = ${crypto.createHash('sha256').update(der).digest('hex')}`,
          `bilinmeyen cihaz (${unknownDevice}) kaydı: ${unknownPem ? 'VAR ✗' : 'yok ✓'}`,
          '',
          'Kütüphane init sırasında (uçtan uca dosya tanımlıysa) Android Keystore\'daki',
          'RSA anahtarını üretip public yarısını her Config API\'ye kaydediyor;',
          'private yarısı cihazdan hiç çıkmıyor.',
        ].join('\n'),
      );
      expect(pem).toContain('BEGIN PUBLIC KEY');
      expect(unknownPem).toBeNull();
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
