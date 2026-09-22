// Web → Mobil: dashboard'da host silinince mobil o host'a güvenmeyi bırakır
// (pin kaydı olmayan host'a bağlanılmaz). Geri eklenince sürüm kaldığı yerden
// devam eder ve mobil tekrar bağlanır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { SampleApp } = require('../lib/sampleApp');
const env = require('../lib/env');

test('Web\'de host silinir → mobil o host\'a bağlanmaz; geri eklenince sürüm devam eder', async ({
  app,
  dashboard,
  run,
}) => {
  let v0;

  await test.step('Web: hedef host silinir', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.deleteHost(TARGET_HOST);
    await dashboard.snap('host silindi');
  });

  await test.step('Mobil: config yenilenir, hedef artık config\'te yok', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Yeni config uygulandı');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBeNull();
    await app.snap('config yenilendi: hedef host listede yok');
  });

  await test.step('Mobil: pin kaydı olmayan hedefe istek reddedilir', async () => {
    const status = await app.testLibraryClient();
    expect(status).toContain('Bağlantı başarısız');
    expect(status).toContain('No pin entry');
    await app.snap('pin kaydı yok, bağlantı reddedildi');
  });

  await test.step('Web: host aynı pin\'lerle yeniden eklenir, sürüm kaldığı yerden devam eder', async () => {
    await dashboard.addHostManual(env.VAULT_API, TARGET_HOST, run.goodPins);
    await dashboard.openHost(TARGET_HOST);
    expect(await dashboard.version()).toBe(v0 + 1);
    await dashboard.snap(`host geri eklendi, v${v0 + 1}`);
  });

  await test.step('Mobil: yenile → hedef geri geldi, istek başarılı', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap(`hedef geri geldi, v${v0 + 1}`);
  });
});
