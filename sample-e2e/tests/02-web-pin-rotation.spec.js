// Web → Mobil: dashboard'da pin seti değişince mobil yeni sürümü alır ve
// bağlantı kesintisiz sürer. Yedek pin eklemek, gerçek bir sertifika
// rotasyonunun ilk adımıdır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const { SampleApp } = require('../lib/sampleApp');

test('Web\'de yedek pin eklenir → mobil yeni sürümü alır; kaldırılınca yine günceller', async ({
  app,
  dashboard,
  run,
}) => {
  const backupPin = hostApi.randomPin();
  let v0;

  await test.step('Web: host açılır, mobil ile aynı sürümde', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    expect(SampleApp.hostVersion(app.status(), TARGET_HOST)).toBe(v0);
    await dashboard.snap(`rotasyon öncesi, v${v0}`);
  });

  await test.step('Web: üçüncü (yedek) pin eklenir', async () => {
    await dashboard.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
    await dashboard.snapHostSummary(`yeni pin seti, v${v0 + 1}`);
  });

  await test.step('Mobil: config yenilenir, yeni sürüm uygulanır', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    await app.snap(`config v${v0 + 1}`);
  });

  await test.step('Mobil: iki client da yeni pin setiyle bağlanır', async () => {
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    expect(await app.testProductionStyle()).toContain('Production-style bağlantı başarılı');
    await app.snap('iki client da başarılı');
  });

  await test.step('Web: cihaz yeni sürümde, pin geçmişinde değişiklik kaydı', async () => {
    await dashboard.expectClientRow(run.model, { version: v0 + 1, status: 'healthy' });
    await expect(dashboard.page.locator('#pin-history-card tbody tr').first()).toContainText(`v${v0 + 1}`);
    await dashboard.snapCard('#client-devices-card', `cihaz v${v0 + 1}`);
    await dashboard.snapCard('#pin-history-card', 'pin geçmişi');
  });

  await test.step('Web: yedek pin kaldırılır', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
  });

  await test.step('Mobil: yenile → bir sonraki sürüm, bağlantı sürer', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 2);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap(`config v${v0 + 2}`);
  });
});
