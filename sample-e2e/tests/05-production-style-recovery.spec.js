// Web → Mobil: PinVault'u import etmeyen bir network katmanı (OkHttp
// CertificatePinner) da web'den gelen pin değişikliğini alır; yanlış pin'de
// reddeder, düzeltilince kendi interceptor'ıyla elle yenilemeden toparlanır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const { SampleApp } = require('../lib/sampleApp');

test('Production-style client: web\'de pin yanlışsa bağlanmaz; düzeltilince kendi interceptor\'ıyla toparlanır', async ({
  app,
  dashboard,
  run,
}) => {
  let v0;

  await test.step('Mobil: production-style client (PinVault\'u import etmeyen OkHttp client\'ı) başlangıçta bağlanır', async () => {
    expect(await app.testProductionStyle()).toContain('Production-style bağlantı başarılı');
    await app.snap('production-style client bağlandı');
  });

  await test.step('Web: pin\'ler yanlış değerlerle değiştirilir', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.setPins(TARGET_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
  });

  await test.step('Mobil: config yenilenir, yanlış pin\'ler production-style client\'a da geçer', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    await app.snap(`yanlış pin'li config v${v0 + 1} uygulandı`);
  });

  await test.step('Mobil: production-style client\'ın isteği reddedilir', async () => {
    const status = await app.testProductionStyle();
    expect(status).toContain('Production-style bağlantı başarısız');
    await app.snap('production-style bağlantı başarısız');
  });

  await test.step('Web: doğru pin\'ler geri yüklenir', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
  });

  await test.step('Mobil: elle yenilemeden istek yapılır; interceptor yeni config\'i çekip isteği tekrarlar', async () => {
    const status = await app.testProductionStyle();
    expect(status).toContain('Production-style bağlantı başarılı');
    await app.snap('production-style toparlandı');
  });
});
