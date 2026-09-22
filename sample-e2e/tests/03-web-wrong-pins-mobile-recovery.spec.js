// Web → Mobil → Web: dashboard'da yanlış pin girilince mobil bağlantıyı
// reddeder ve uyuşmazlığı raporlar; pin'ler düzeltilince mobil elle
// yenilemeye gerek kalmadan kendiliğinden toparlanır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const { SampleApp } = require('../lib/sampleApp');

test('Web\'de yanlış pin → mobilde uyuşmazlık ve web\'de rapor; düzeltilince otomatik kurtarma', async ({
  app,
  dashboard,
  run,
}) => {
  const startedAt = Date.now() - 5000;
  let v0;

  await test.step('Web: pin\'ler yanlış değerlerle değiştirilir', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.setPins(TARGET_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
    await dashboard.snapHostSummary(`yanlış pinler, v${v0 + 1}`);
  });

  await test.step('Mobil: yeni config alınır (imzası geçerli, pin\'leri yanlış)', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    await app.snap(`yanlış pin'li config v${v0 + 1} uygulandı`);
  });

  await test.step('Mobil: pinli istek reddedilir', async () => {
    const status = await app.testLibraryClient();
    expect(status).toContain('Bağlantı başarısız');
    await app.waitForEvent(`[✗ UYUŞMAZLIK] ${TARGET_HOST}`);
    await app.snap('pin uyuşmazlığı');
  });

  await test.step('Web: cihazın uyuşmazlık raporu görünür', async () => {
    await dashboard.expectLatestConnection(run.model, { status: 'pin_mismatch' });
    await dashboard.snapCard('#conn-history-card', 'uyuşmazlık raporu');
    const entries = await hostApi.connectionHistory(TARGET_HOST);
    const fresh = entries.filter(
      (e) => e.deviceModel === run.model && e.status === 'pin_mismatch' && Date.parse(e.timestamp) >= startedAt,
    );
    expect(fresh.length, 'bu testte oluşan pin_mismatch kaydı').toBeGreaterThan(0);
  });

  await test.step('Web: doğru pin\'ler geri yüklenir', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
  });

  await test.step('Mobil: elle yenilemeden istek → otomatik kurtarma', async () => {
    const status = await app.testLibraryClient();
    expect(status).toContain('Pinned bağlantı başarılı');
    // Kurtarma interceptor'ı yeni config'i çekip isteği tekrarladı.
    await app.waitForEvent(`[config] UPDATED v${v0 + 2}`);
    await app.snap('otomatik kurtarma');
  });

  await test.step('Web: cihaz yeniden sağlıklı ve yeni sürümde', async () => {
    await dashboard.expectClientRow(run.model, { version: v0 + 2, status: 'healthy' });
    await dashboard.snapCard('#client-devices-card', `cihaz v${v0 + 2}, healthy`);
  });
});
