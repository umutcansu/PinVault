// Web: hatalı biçimli pin dashboard'da reddedilir, başarı mesajı gösterilmez
// ve hiçbir şey kaydedilmez; mobil etkilenmez.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const { SampleApp } = require('../lib/sampleApp');
const { attachText } = require('../lib/evidence');

test('Web\'de hatalı biçimli pin reddedilir; mobil etkilenmez', async ({ app, dashboard, run }, testInfo) => {
  let v0;

  await test.step('Web: geçersiz pin kaydedilmeye çalışılır → yalnızca hata mesajı', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.setPins(TARGET_HOST, ['bu-bir-pin-degil', run.goodPins[1]], { expectSaved: false });
    await expect(dashboard.page.locator('.toast.error').first()).toBeVisible();
    await expect(dashboard.page.locator('.toast.success')).toHaveCount(0);
    await dashboard.snap('geçersiz pin reddedildi');
  });

  await test.step('Sunucu: config değişmedi', async () => {
    const pin = (await hostApi.getConfig()).pins.find((p) => p.hostname === TARGET_HOST);
    await attachText(
      testInfo,
      'GET /api/v1/certificate-config?signed=false (reddedilen denemeden sonra)',
      [
        `${TARGET_HOST} → v${pin.version} (dashboard'daki sürüm: v${v0})`,
        `pin'ler: ${pin.sha256.join(', ')}`,
        `beklenen (canlı pin'ler): ${run.goodPins.join(', ')}`,
      ].join('\n'),
    );
    expect(pin.version).toBe(v0);
    expect(pin.sha256).toEqual(run.goodPins);
  });

  await test.step('Mobil: yenile → config güncel, sürüm aynı', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Config güncel');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0);
    await app.snap('mobil etkilenmedi');
  });
});
