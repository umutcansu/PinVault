// E8: telemetri ve cihaz listeleri. Telefonun ürettiği kayıtlar dashboard'un
// "Bağlantı Geçmişi" ve "Bağlı Cihazlar" kartlarında görünür; tablo sayfalanır;
// rapor ucu HTML metakarakteri içeren cihaz adlarını 400 ile reddeder;
// cihaz listesi ucu API anahtarı ister.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

/** Rapor ucuna doğrudan (cihaz gibi) istek. */
async function clientReport(body) {
  const res = await fetch(`${env.WEB_URL}/api/v1/connection-history/client-report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, text: (await res.text()).trim() };
}

test('Sunucu: telefonun telemetrisi listelenir, bozuk rapor reddedilir, cihaz listesi anahtar ister', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);

  await test.step('Mobil: telefon pinli istek yapar (telemetri üretir)', async () => {
    const status = await app.testLibraryClient();
    await app.snap('pinli istek — telemetri gönderildi');
    expect(status).toContain('Pinned bağlantı başarılı');
  });

  await test.step('Web: Bağlantı Geçmişi ve Bağlı Cihazlar kartları', async () => {
    await dashboard.openHost(env.TARGET_HOST);
    await dashboard.expectLatestConnection(run.model, { status: '✓' });
    await dashboard.snapCard('#conn-history-card', 'bağlantı geçmişi: telefonun kaydı');
    await dashboard.expectClientRowPresent(run.model);
    await dashboard.snapCard('#client-devices-card', 'bağlı cihazlar');

    const history = await hostApi.connectionHistory(env.TARGET_HOST);
    const android = history.filter((e) => e.source === 'android');
    await attachText(
      testInfo,
      `GET /api/v1/connection-history/${env.TARGET_HOST} (android kayıtları)`,
      [
        `toplam kayıt: ${history.length} · android: ${android.length}`,
        '',
        ...android.slice(0, 5).map(
          (e) => `${e.timestamp}  ${e.status}  pinMatched=${e.pinMatched}  v${e.pinVersion}  ${e.deviceManufacturer} ${e.deviceModel}`,
        ),
      ].join('\n'),
    );
    expect(android.length).toBeGreaterThan(0);
  });

  await test.step('Web: bağlantı geçmişi tablosu sayfalanır', async () => {
    const counter = dashboard.page.locator('#conn-history-card').locator('text=/\\d+-\\d+ \\/ \\d+/').first();
    await expect(counter).toBeVisible();
    const before = (await counter.innerText()).trim();
    await dashboard.page.locator('#conn-history-card select[data-action-change="pagSizeChange"]').first().selectOption('25');
    const after = (await dashboard.page.locator('#conn-history-card').locator('text=/\\d+-\\d+ \\/ \\d+/').first().innerText()).trim();
    await dashboard.snapCard('#conn-history-card', `sayfa boyutu 25 (${after})`);
    await attachText(testInfo, 'Sayfalama', `10 satır: ${before}\n25 satır: ${after}`);
  });

  await test.step('Sunucu: bozuk biçimli cihaz raporu 400 ile reddedilir', async () => {
    const good = await clientReport({
      hostname: env.TARGET_HOST,
      status: 'healthy',
      responseTimeMs: 11,
      deviceManufacturer: 'Harness',
      deviceModel: 'E2E-Probe',
    });
    const badModel = await clientReport({
      hostname: env.TARGET_HOST,
      status: 'healthy',
      responseTimeMs: 11,
      deviceManufacturer: 'Harness',
      deviceModel: '<img src=x onerror=alert(1)>',
    });
    const badHost = await clientReport({
      hostname: '<script>alert(1)</script>',
      status: 'healthy',
      responseTimeMs: 11,
      deviceModel: 'E2E-Probe',
    });
    await attachText(
      testInfo,
      'POST /api/v1/connection-history/client-report (giriş doğrulama)',
      [
        `geçerli rapor                       → HTTP ${good.status} ${good.text}`,
        `deviceModel="<img src=x onerror=…>" → HTTP ${badModel.status} ${badModel.text}`,
        `hostname="<script>alert(1)</script>"→ HTTP ${badHost.status} ${badHost.text}`,
        '',
        'Kabul edilen biçim: ^[A-Za-z0-9._:\\- ]{1,128}$ — dashboard innerHTML\'ine HTML sızmaz.',
      ].join('\n'),
    );
    expect(good.status).toBe(200);
    expect(badModel.status).toBe(400);
    expect(badHost.status).toBe(400);
  });

  await test.step('Sunucu: cihaz listesi ucu anahtarsız 401, anahtarla liste döner', async () => {
    const none = await hostApi.api('/api/v1/client-devices?configApiId=default-tls', { withKey: false });
    const withKey = await hostApi.api('/api/v1/client-devices?configApiId=default-tls');
    await attachText(
      testInfo,
      'GET /api/v1/client-devices',
      [
        `anahtarsız → HTTP ${none.status} ${none.text.trim()}`,
        `anahtarla  → HTTP ${withKey.status}`,
        ...(withKey.json || []).map(
          (d) => `  ${d.device_id || d.deviceId} · ${d.deviceManufacturer || d.manufacturer || ''} ${d.deviceModel || d.model || ''}`,
        ),
      ].join('\n'),
    );
    expect(none.status).toBe(401);
    expect(withKey.status).toBe(200);
    expect(Array.isArray(withKey.json)).toBe(true);
  });
});
