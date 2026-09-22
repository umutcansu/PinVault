// Web → Mobil: force update açıkken mobil config'i sürüm değişmese de yeniden
// uygular; kapatılınca normale döner.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { SampleApp } = require('../lib/sampleApp');

test('Web\'de force update → mobil config\'i aynı sürümle yeniden uygular; kapatılınca normale döner', async ({
  app,
  dashboard,
}) => {
  let version;

  await test.step('Mobil: başlangıçta config güncel', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Config güncel');
    version = SampleApp.hostVersion(status, TARGET_HOST);
    await app.snap(`başlangıç: config güncel, v${version}`);
  });

  await test.step('Web: force update açılır, sürüm değişmez', async () => {
    await dashboard.openHost(TARGET_HOST);
    await dashboard.setForce(TARGET_HOST, true);
    expect(await dashboard.version()).toBe(version);
    await dashboard.snap('force update aktif');
  });

  await test.step('Mobil: yenile → config zorla yeniden uygulanır', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Yeni config uygulandı');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    await app.snap('force ile yeniden uygulandı');
  });

  await test.step('Web: force update kapatılır', async () => {
    await dashboard.setForce(TARGET_HOST, false);
    await dashboard.snap('force update pasif');
  });

  await test.step('Mobil: yenile → config güncel', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Config güncel');
    await app.snap('normale döndü');
  });
});
