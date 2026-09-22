// Web → Mobil: dashboard'da bütün host'lar silinince sunucu boş bir config
// yayınlar. Mobil boş config'i reddeder ve eski güvenli config'le çalışmaya
// devam eder; host'lar geri eklenince sürüm geri gitmediği için güncellenir.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { SampleApp } = require('../lib/sampleApp');
const env = require('../lib/env');

test('Web\'de tüm host\'lar silinir → mobil boş config\'i reddeder, eski config\'le çalışır', async ({
  app,
  dashboard,
  run,
}) => {
  let targetVersion;

  await test.step('Web: iki host da silinir, config boş kalır', async () => {
    await dashboard.openHost(TARGET_HOST);
    targetVersion = await dashboard.version();
    // Host'un kendi kaydı ve mock hedefler de dahil hepsi silinir.
    await dashboard.deleteAllHosts();
    await dashboard.snap('config boş');
  });

  await test.step('Mobil: yenile → boş config reddedilir, eski sürüm kalır', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Config yenilenemedi');
    expect(status).toContain('at least one pin');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(targetVersion);
    await app.snap('boş config reddedildi');
  });

  await test.step('Mobil: hedefe istek eski pin\'lerle başarılı', async () => {
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap(`eski config (v${targetVersion}) ile bağlantı sürüyor`);
  });

  await test.step('Web: host\'lar geri eklenir', async () => {
    for (const [hostname, pins] of Object.entries(run.baseline)) {
      await dashboard.addHostManual(env.VAULT_API, hostname, pins);
    }
    await dashboard.openHost(TARGET_HOST);
    expect(await dashboard.version()).toBe(targetVersion + 1);
    await dashboard.snapHostSummary(`host'lar geri eklendi, v${targetVersion + 1}`);
  });

  await test.step('Mobil: yenile → sürüm geri gitmez, yeni config uygulanır', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Yeni config uygulandı');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(targetVersion + 1);
    await app.snap(`host'lar geri geldi, v${targetVersion + 1}`);
  });
});
