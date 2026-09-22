// Web → Mobil (arka plan): dashboard'daki değişiklik, uygulamada hiçbir düğmeye
// basılmadan WorkManager'ın periyodik göreviyle cihaza ulaşır.
//
// WorkManager periyodik bir görevi zamanı gelmeden çalıştırmaz (zorlansa bile
// ertelenir). Bu yüzden emülatörün saati bir periyot (15 dk) ileri alınıp görev
// zorlanır; sonunda saat geri alınır. Fiziksel telefonda saat değiştirilemediği
// için bu senaryo yalnızca emülatörde koşar.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const PERIOD_PLUS_MARGIN_S = 16 * 60;

test('Web\'deki değişiklik, düğmeye basmadan arka plan göreviyle mobile ulaşır', async ({
  app,
  dashboard,
  device,
  run,
}) => {
  test.skip(!device.isEmulator(), 'Saat yalnızca emülatörde ileri alınabilir');
  let v0;

  await test.step('Web: yedek pin eklenir', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.setPins(TARGET_HOST, [...run.goodPins, hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
  });

  await test.step('Mobil: bir periyot sonra arka plan görevi config\'i uygular', async () => {
    device.shiftClock(PERIOD_PLUS_MARGIN_S);
    try {
      const jobs = device.runScheduledJobs(env.APP_ID);
      expect(jobs.length, 'WorkManager görevi planlı').toBeGreaterThan(0);
      await app.waitForEvent(`[config] UPDATED v${v0 + 1}`, 60_000);
      await app.snap('arka plan görevi yeni config\'i uyguladı');
    } finally {
      device.shiftClock(-PERIOD_PLUS_MARGIN_S);
    }
  });

  await test.step('Mobil: istek yeni sürümle yapılır (elle yenileme yok)', async () => {
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.waitForEvent(`[✓] ${TARGET_HOST}  pin v${v0 + 1}`);
    await app.snap(`istek pin v${v0 + 1} ile başarılı`);
  });

  await test.step('Web: yedek pin kaldırılır', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
  });
});
