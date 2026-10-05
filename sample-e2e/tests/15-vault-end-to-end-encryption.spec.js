// Web → Mobil (gizli dosya, cihaza özel şifreleme): sample-e2e uygulamada
// mTLS bloğunda, token_mtls politikasıyla ve ekran kilidi arkasında tanımlı
// (encryption END_TO_END + userAuth REQUIRED). Sunucu dosyayı cihazın RSA
// anahtarıyla şifreler; telefon çözer ve hemen ekran kilidi anahtarıyla
// yeniden kilitleyip saklar. İçerik yalnızca "Aç" + ekran kilidiyle görünür.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const secureVault = require('../lib/secureVault');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.e2e;
const API = env.SECURE_VAULT_API;

test('Vault cihaza özel şifreleme (gizli dosya): cihaz anahtarıyla şifreli gelir, telefonda kilitli durur, ekran kilidiyle açılır', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const plaintext = `uçtan uca gizli: ${Date.now()}`;
  const sv = { clientId: `t15-cihaz-${Date.now()}` };
  let deviceId;

  try {
    await test.step('Hazırlık: telefona ekran kilidi, cihaz mTLS\'e kayıt olur', async () => {
      await secureVault.prepare({ app, device, dashboard }, sv);
    });

    await test.step('Web: dosya sample-mtls\'e token_mtls + end_to_end ile yüklenir, cihaza token üretilir', async () => {
      await dashboard.uploadVaultText(API, KEY, plaintext, { policy: 'token_mtls', encryption: 'end_to_end' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${KEY} token_mtls + end_to_end ile yüklendi`);
      await app.openVault();
      deviceId = app.deviceId();
      const token = await dashboard.generateVaultToken(API, KEY, deviceId);
      await app.saveVaultToken(token, KEY);
    });

    await test.step('Mobil: dosya iner, cihaz anahtarıyla çözülür ve kilitlenir; içerik gösterilmez', async () => {
      const status = await app.fetchVault(KEY);
      await app.snap('cihaza özel şifreli dosya indi — kilitli');
      expect(status).toContain('indirildi');
      expect(status).toContain('cihaz anahtarıyla çözüldü');
      expect(status).toContain('Kilitli');
      expect(status).not.toContain(plaintext);
    });

    await test.step('Mobil: "Aç" + ekran kilidi → içerik görünüyor', async () => {
      const status = await app.unlockVault(KEY);
      await app.snap('ekran kilidiyle açıldı');
      expect(status).toContain('açıldı');
      expect(status).toContain(plaintext);
    });

    await test.step('Sunucu: dosya diskte şifreli, cihazın RSA anahtarı kayıtlı', async () => {
      const blob = hostApi.vaultBlobFromDb(API, KEY);
      const pem = hostApi.devicePublicKeyPem(deviceId, API);
      await attachText(
        testInfo,
        `vault_files (${API}/${KEY}) ve device_public_keys (${deviceId})`,
        [
          `veritabanındaki blob: ${blob.length} bayt, düz metin içinde geçiyor mu: ${blob.includes(Buffer.from(plaintext, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          `cihazın kayıtlı RSA public key'i: ${pem ? 'var ✓' : 'YOK ✗'}`,
          '',
          'Dosya ağda cihazın RSA anahtarıyla şifreli gider ([4B uzunluk][RSA-OAEP ile',
          'sarılmış AES anahtarı][12B IV][AES-GCM]); token_mtls olduğu için bu cihazın',
          'sertifikası olmadan Mac\'ten indirilemiyor (C10 aynı şifrelemeyi herkese',
          'açık bir dosyayla ağ trafiğinde gösterir). Şifrelemeyi sunucu yapar, yani',
          'içeriği sunucu görür; user_auth da öyle, ama orada içerik telefona kilitli',
          'gelir ve uygulama belleğinden geçmez.',
        ].join('\n'),
      );
      expect(blob.includes(Buffer.from(plaintext, 'utf8'))).toBe(false);
      expect(pem).toContain('BEGIN PUBLIC KEY');
    });

    await test.step('Web: dağıtım geçmişinde indirme görünür', async () => {
      await dashboard.expectDistribution(API, { key: KEY, deviceModel: run.model, status: 'downloaded' });
      await dashboard.snap('dağıtım geçmişi');
    });
  } finally {
    await hostApi.deleteVaultFile(API, KEY).catch(() => {});
    await secureVault.cleanup({ device }, sv);
  }
});
