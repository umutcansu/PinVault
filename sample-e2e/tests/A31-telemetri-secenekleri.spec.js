// A31: cihaz raporu (telemetri) seçenekleri (PinVaultBackendReporter).
//
//  • reportSuccessEvents=false: sağlıklı el sıkışmalar hiç raporlanmaz,
//    yalnızca anomaliler (pin uyuşmazlığı, config güncelleme hatası) gider.
//  • dedupWindowMs > 0: aynı (host, pin sürümü, sunucu sertifikası) üçlüsü
//    için pencere içindeki tekrarlar tek kayda iner.
//  • Config güncelleme sonuçları ayrı bir uca raporlanır ve dashboard'ın
//    "Bağlantı Geçmişi" bölümünde config_updated / config_update_failed
//    olarak görünür.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/device');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const DEDUP_MS = 60_000;

/** Bu cihazın hedefe ait, [since]'ten yeni bağlantı raporları. */
async function reportsSince(model, since, status) {
  const rows = await hostApi.connectionHistory(TARGET_HOST);
  return rows.filter(
    (e) => e.deviceModel === model && Date.parse(e.timestamp) >= since && (!status || e.status === status),
  );
}

/** Bu cihazın [since]'ten yeni config güncelleme raporları. */
async function configReportsSince(model, since) {
  const rows = await hostApi.configUpdateReports(model);
  return rows.filter((e) => Date.parse(e.timestamp) >= since);
}

test('Mobil+Web: cihaz raporları (telemetri) — başarı raporunu kapatma, tekrarları tek kayda indirme, config kayıtları', async ({
  app,
  dashboard,
  device,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);

  let v0;
  const summary = [];

  await test.step('Mobil: başarılı bağlantıların raporlanması kapatılır (tekrar bastırma: 0 ms)', async () => {
    v0 = SampleApp.hostVersion(app.status(), TARGET_HOST);
    await app.openSettings();
    const applied = await app.setTelemetry({ reportSuccess: false, dedupMs: 0 });
    await app.snapResult('rapor ayarı: başarı raporu kapalı');
    expect(applied).toContain('Başarı raporu: hayır');
    expect(applied).toContain('tekrar bastırma: 0 ms');
    await app.backToMain();
  });

  await test.step('Mobil+Sunucu: üç başarılı istek → sunucuya hiç "healthy" kaydı gelmiyor', async () => {
    const marker = Date.now();
    await sleep(2000);
    for (let i = 0; i < 3; i++) {
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    }
    await app.snap('üç başarılı istek (raporlama kapalı)');
    await sleep(6000);
    const healthy = await reportsSince(run.model, marker, 'healthy');
    summary.push(`başarı raporu kapalı, tekrar bastırma 0 ms  : 3 başarılı istek → ${healthy.length} healthy kaydı`);
    await dashboard.openHost(TARGET_HOST);
    await dashboard.snapCard('#conn-history-card', 'raporlama kapalıyken bağlantı geçmişi');
    expect(healthy.length).toBe(0);
  });

  await test.step('Mobil: raporlama açılır, tekrar bastırma 60 sn (aynı rapor 60 sn içinde bir kez gider)', async () => {
    await app.openSettings();
    const applied = await app.setTelemetry({ reportSuccess: true, dedupMs: DEDUP_MS });
    await app.snapResult('rapor ayarı: raporlama açık, tekrar bastırma 60 sn');
    expect(applied).toContain('Başarı raporu: evet');
    expect(applied).toContain(`tekrar bastırma: ${DEDUP_MS} ms`);
    await app.backToMain();
  });

  await test.step('Mobil+Web: aynı hedefe üç başarılı istek → 60 sn içinde tek kayıt', async () => {
    const marker = Date.now();
    await sleep(2000);
    for (let i = 0; i < 3; i++) {
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    }
    await app.snap('üç başarılı istek (tekrar bastırma açık)');
    await expect
      .poll(async () => (await reportsSince(run.model, marker, 'healthy')).length, { timeout: 30_000 })
      .toBeGreaterThan(0);
    await sleep(5000);
    const healthy = await reportsSince(run.model, marker, 'healthy');
    summary.push(`başarı raporu açık, tekrar bastırma ${DEDUP_MS} ms: 3 başarılı istek → ${healthy.length} healthy kaydı`);
    await dashboard.openHost(TARGET_HOST);
    await dashboard.expectClientRow(run.model, { version: v0, status: 'healthy' });
    await dashboard.expectLatestConnection(run.model, { status: 'healthy' });
    await dashboard.snapCard('#conn-history-card', 'tekrar bastırma: üç istek, bağlantı geçmişinde bu sürede tek healthy kaydı');
    await attachText(
      testInfo,
      `GET /api/v1/connection-history/${TARGET_HOST} — tekrar bastırma süresi (${DEDUP_MS} ms)`,
      [
        `ölçüm başlangıcı: ${new Date(marker).toISOString()}`,
        `3 başarılı istek → bu sürede healthy kayıt: ${healthy.length}`,
        ...healthy.map((x) => `  ${x.timestamp}  ${x.status}  pin v${x.pinVersion ?? '—'}`),
        '',
        'Host, pin sürümü ve sunucu sertifikası aynı olan bağlantı bu süre içinde',
        'yeniden raporlanmıyor; kartta bu süreye ait tek satır var.',
      ].join('\n'),
    );
    expect(healthy.length).toBe(1);
  });

  let mismatchMarker;

  await test.step('Web: pin\'ler bozulur → Mobil: pin uyuşmazlığı (hata raporları hiç bastırılmaz)', async () => {
    await dashboard.setPins(TARGET_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
    await dashboard.snapHostSummary(`yanlış pinler, v${v0 + 1}`);

    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    mismatchMarker = Date.now();
    await sleep(2000);
    expect(await app.testLibraryClient()).toContain('Bağlantı başarısız');
    await app.snap('pin uyuşmazlığı');
    await expect
      .poll(async () => (await reportsSince(run.model, mismatchMarker, 'pin_mismatch')).length, { timeout: 30_000 })
      .toBeGreaterThan(0);
    summary.push('hata raporu (pin_mismatch)                  : bu iki ayardan etkilenmiyor → raporlandı');
    await dashboard.expectLatestConnection(run.model, { status: 'pin_mismatch' });
    await dashboard.snapCard('#conn-history-card', 'uyuşmazlık raporlandı');
  });

  if (device.isEmulator()) {
    await test.step('Terminal+Mobil: Config API\'ye erişim kesilir → güncelleme hatası telefonun olay listesinde; rapor aynı porttan gittiği için sunucuya ulaşamıyor', async () => {
      // Kurtarma interceptor'ı config'i tazelemeye çalışır; Config API portu
      // kapalı olduğu için güncelleme başarısız olur. Cihaz raporları da aynı
      // porttan gider (telefon yönetim portuna bağlanmaz): kesinti sürerken
      // hata raporu sunucuya ulaşamaz, hata telefonun kendi kaydında görünür.
      device.blockTcp(env.LAN_IP, env.CONFIG_API_PORT, 'reject');
      const marker = Date.now();
      await sleep(2000);
      const result = await app.testLibraryClient();
      await app.snap('config API kapalı: kurtarma başarısız');
      const eventLog = await app.waitForEvent('[config] FAILED', 40_000);
      const arrived = (await configReportsSince(run.model, marker)).filter((e) => e.status === 'config_update_failed');
      await attachText(
        testInfo,
        `iptables: ${env.LAN_IP}:${env.CONFIG_API_PORT} REJECT → config güncelleme hatası`,
        [
          `Telefondaki sonuç:\n${result.split('\n').slice(0, 3).join('\n')}`,
          '',
          'Telefonun olay listesi:',
          eventLog.split('\n').filter((row) => row.includes('[config]')).slice(0, 3).join('\n'),
          '',
          `Sunucuya bu sürede ulaşan config_update_failed raporu: ${arrived.length}`,
          '',
          `Cihaz raporları (telemetri) Config API portundan (${env.REPORT_PORT}) gider; kesilen de o port.`,
          'Sunucuya ulaşılamadığını sunucuya bildirmenin yolu yoktur: hata telefonun kendi',
          'kaydında durur, sunucu tarafında ise cihazın raporlarının kesilmesi görülür.',
        ].join('\n'),
      );
      device.clearNetRules();
      expect(result).toContain('Bağlantı başarısız');
      expect(eventLog).toContain('[config] FAILED');
      expect(arrived.length, 'port kesikken hata raporu sunucuya ulaşamaz').toBe(0);
      summary.push('config güncelleme hatası (Config API kesik)  : telefonun olay listesinde; rapor aynı porttan gittiği için sunucuya ulaşmadı');
    });
  }

  await test.step('Web+Mobil: pin\'ler düzeltilir → kurtarma → config_updated raporu', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
    const marker = Date.now();
    await sleep(2000);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.waitForEvent(`[config] UPDATED v${v0 + 2}`);
    await app.snap('kurtarma sonrası bağlantı');
    await expect
      .poll(async () => (await configReportsSince(run.model, marker)).filter((e) => e.status === 'config_updated').length,
        { timeout: 40_000 })
      .toBeGreaterThan(0);
    summary.push(`config güncelleme                           : config_updated v${v0 + 2} raporlandı`);
  });

  await test.step('Web: "Bağlantı Geçmişi" bölümünde config güncelleme kayıtları', async () => {
    await dashboard.openHealth();
    // Genel geçmişte web / android / config_update kayıtları karışık; sayfa
    // boyutu büyütülmezse config satırları ilk sayfada kalmayabiliyor.
    await dashboard.setPageSize(100);
    const updatedRow = dashboard.page.locator('tbody tr', { hasText: 'Config Güncellendi' }).first();
    await expect(updatedRow).toBeVisible({ timeout: 20_000 });
    await dashboard.snap('Bağlantı Geçmişi: config güncelleme kayıtları');
    const reports = await hostApi.configUpdateReports(run.model);
    await attachText(
      testInfo,
      'Rapor ayarlarının (telemetri) etkisi',
      [
        ...summary,
        '',
        'Son config güncelleme raporları (kaynak: config_update):',
        ...reports.slice(0, 6).map((e) => `  ${e.timestamp}  ${e.status}  v${e.pinVersion ?? '—'}`),
        '',
        'PinVaultBackendReporter: reportSuccessEvents neyin raporlanacağını,',
        'dedupWindowMs ne sıklıkla raporlanacağını belirler. İkisi de yalnızca',
        'başarılı bağlantılara uygulanır; pin uyuşmazlığı ve config güncelleme',
        'hatası her durumda gönderilir.',
      ].join('\n'),
    );
    expect(reports.some((e) => e.status === 'config_updated')).toBe(true);
  });
});
