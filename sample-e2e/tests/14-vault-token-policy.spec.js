// Web ↔ Mobil (vault token): token politikalı dosya token olmadan inmez.
// Dashboard'da bu cihaz için üretilen token'la iner; token iptal edilince
// yine reddedilir.
const { test, expect } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.secret;

test('Vault token: token yokken reddedilir, cihaz için üretilen token\'la iner, iptalde reddedilir', async ({
  app,
  dashboard,
  run,
}) => {
  const secret = `gizli-${Date.now()}`;
  let deviceId;
  let token;

  try {
    await test.step('Web: dosya token politikasıyla yüklenir', async () => {
      await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, { policy: 'token' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${KEY} token politikasıyla yüklendi`);
    });

    await test.step('Mobil: token olmadan indirme reddedilir', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
      await app.snap('token yok, reddedildi');
    });

    await test.step('Web: bu cihaz için token üretilir', async () => {
      token = await dashboard.generateVaultToken(env.VAULT_API, KEY, deviceId);
      expect(token).toMatch(/^[A-Za-z0-9_-]{32,}$/);
      await dashboard.snap('cihaz için token üretildi');
    });

    await test.step('Mobil: token girilir, dosya iner', async () => {
      await app.saveVaultToken(token);
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} v`);
      expect(status).toContain('indirildi');
      expect(status).toContain(secret);
      await app.snap('token ile indirildi');
    });

    await test.step('Web: dağıtım geçmişinde token ile başarılı indirme', async () => {
      await dashboard.expectDistribution(env.VAULT_API, { key: KEY, deviceModel: run.model, status: 'downloaded' });
      await dashboard.snap('dağıtım geçmişi: token ile indirildi');
    });

    await test.step('Web: token iptal edilir', async () => {
      await dashboard.revokeVaultTokens(env.VAULT_API, KEY);
      await dashboard.snap('token iptal edildi');
    });

    await test.step('Mobil: iptal edilen token ile indirme reddedilir', async () => {
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
      await app.snap('iptal sonrası reddedildi');
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY);
  }
});
