// Mobil → Web: telefonda yapılan pinli istek, host dashboard'unda cihaz ve
// bağlantı kaydı olarak görünür.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const { SampleApp } = require('../lib/sampleApp');
const { attachText } = require('../lib/evidence');

test('Mobilde pinli istek yapılır → web\'de cihaz ve bağlantı kaydı görünür', async ({ app, dashboard, run }, testInfo) => {
  // Container saatiyle küçük bir kaymaya pay.
  const startedAt = Date.now() - 5000;
  let version;

  await test.step('Mobil: config hazır', async () => {
    version = SampleApp.hostVersion(app.status(), TARGET_HOST);
    expect(version, 'mobil ekranda hedef host sürümü').toBeGreaterThan(0);
    await app.snap('config hazır');
  });

  await test.step('Mobil: "Library client ile test" düğmesiyle pinli istek', async () => {
    const status = await app.testLibraryClient();
    expect(status).toContain('Pinned bağlantı başarılı');
    await app.waitForEvent(`[✓] ${TARGET_HOST}`);
    await app.snap('pinli istek başarılı');
  });

  await test.step('Web: cihaz "Bağlı Cihazlar" kartında, telefondakiyle aynı pin sürümüyle görünür', async () => {
    await dashboard.openHost(TARGET_HOST);
    await dashboard.expectClientRow(run.model, { version, status: 'healthy' });
    await dashboard.snapCard('#client-devices-card', 'Bağlı Cihazlar');
  });

  await test.step('Web: "Bağlantı Geçmişi" kartında başarılı bağlantı kaydı görünür', async () => {
    await dashboard.expectLatestConnection(run.model, { status: 'healthy' });
    await dashboard.snapCard('#conn-history-card', 'Bağlantı Geçmişi');
  });

  await test.step('API: kayıt bu test sırasında oluşmuş', async () => {
    const entries = await hostApi.connectionHistory(TARGET_HOST);
    const fresh = entries.filter(
      (e) => e.deviceModel === run.model && e.status === 'healthy' && Date.parse(e.timestamp) >= startedAt,
    );
    // Web'de görülen kayıt bu koşuya ait mi: API'den aynı pencerenin kayıtları.
    await attachText(
      testInfo,
      `GET /api/v1/connection-history/${TARGET_HOST} — bu test sırasında oluşan kayıtlar`,
      [
        `cihaz: ${run.model} · test başlangıcı: ${new Date(startedAt).toISOString()}`,
        `test başladığından beri healthy kayıt: ${fresh.length}`,
        '',
        ...fresh.slice(0, 5).map((x) => `  ${x.timestamp}  ${x.status}  pin v${x.pinVersion ?? '—'}  ${x.deviceModel}`),
        '',
        'Dashboard\'daki "Bağlantı Geçmişi" satırları bu kayıtlardan geliyor.',
      ].join('\n'),
    );
    expect(fresh.length, 'bu testte oluşan healthy kayıt').toBeGreaterThan(0);
  });
});
