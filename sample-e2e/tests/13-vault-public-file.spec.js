// Web → Mobil (vault): dashboard'da yüklenen dosya mobilde iner ve içerik imzası
// doğrulanır; indirme dashboard'un dağıtım geçmişinde görünür. Dosya
// güncellenince mobil yeni sürümü alır.
const { test, expect } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

test('Vault: web\'de yüklenen dosya mobilde iner, imzası doğrulanır; güncellenince yeni sürüm gelir', async ({
  app,
  dashboard,
  run,
}) => {
  const first = `{"feature":"on","run":"${Date.now()}"}`;
  const second = `{"feature":"off","run":"${Date.now()}"}`;
  let v1;

  try {
    await test.step('Web: dosya herkese açık olarak yüklenir', async () => {
      v1 = await dashboard.uploadVaultText(env.VAULT_API, KEY, first, { policy: 'public' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları');
    });

    await test.step('Mobil: dosya iner, imza doğrulanır, içerik aynı', async () => {
      await app.openVault();
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} v${v1} indirildi`);
      expect(status).toContain('imza doğrulandı');
      expect(status).toContain(first);
      await app.snap(`v${v1} indirildi`);
    });

    await test.step('Web: dağıtım geçmişinde cihazın indirmesi görünür', async () => {
      await dashboard.expectDistribution(env.VAULT_API, { key: KEY, deviceModel: run.model, status: 'downloaded', version: v1 });
      await dashboard.snap('dağıtım geçmişi');
    });

    await test.step('Web: dosya güncellenir', async () => {
      expect(await dashboard.uploadVaultText(env.VAULT_API, KEY, second, { policy: 'public' })).toBe(v1 + 1);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${KEY} v${v1 + 1} yüklendi`);
    });

    await test.step('Mobil: yeni sürüm iner', async () => {
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} v${v1 + 1} indirildi`);
      expect(status).toContain(second);
      await app.snap(`v${v1 + 1} indirildi`);
    });

    await test.step('Mobil: tekrar indirme denenir; dosya zaten güncel', async () => {
      expect(await app.fetchVault(KEY)).toContain(`${KEY} güncel (v${v1 + 1})`);
      await app.snap(`tekrar indirme: güncel (v${v1 + 1})`);
    });

    await test.step('Web: dosya silinir', async () => {
      await dashboard.deleteVaultFile(env.VAULT_API, KEY);
      await dashboard.snap(`vault sekmesi: ${KEY} silindi`);
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY);
  }
});
