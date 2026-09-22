// E7: pin değişiklik geçmişi ve sürüm watermark'ı. Bir host eklenir,
// pin'leri değiştirilir, silinip geri eklenir; sürüm sıfırlanmaz, kaldığı
// yerden devam eder. Dashboard'daki "Değişiklik Geçmişi" kartı ve
// GET /api/v1/certificate-config/history/{host} aynı kayıtları gösterir.
//
// Ana host üzerinde, kendi geçici host'uyla koşar: telefonun bağlandığı
// host'lara dokunmaz, senaryo sonunda geçici host silinir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const HOST = 'e06-watermark.sample';

async function historyOf(host) {
  return (await hostApi.api(`/api/v1/certificate-config/history/${encodeURIComponent(host)}`)).json || [];
}

async function versionOf(host) {
  const cfg = await hostApi.getConfig();
  const entry = cfg.pins.find((p) => p.hostname === host);
  return entry ? entry.version : null;
}

test('Sunucu: host silinip geri eklenince sürüm kaldığı yerden devam eder; pin geçmişi kaydeder', async ({
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const first = [hostApi.randomPin(), hostApi.randomPin()];
  const second = [first[0], hostApi.randomPin()];
  const versions = {};

  try {
    await test.step('Web: geçici host eklenir (v1)', async () => {
      await dashboard.addHostManual(env.VAULT_API, HOST, first);
      await dashboard.openHost(HOST);
      versions.created = await dashboard.version();
      await dashboard.snap(`host eklendi: v${versions.created}`);
      await attachText(
        testInfo,
        'Eklenen host\'un sürümü',
        [
          `${HOST} → v${versions.created}`,
          versions.created > 1
            ? 'Not: bu ad daha önce de kullanılmış; sunucu watermark\'ı sakladığı için sürüm v1\'den başlamadı.'
            : 'İlk kez eklendi: v1.',
        ].join('\n'),
      );
      expect(versions.created).toBeGreaterThanOrEqual(1);
    });

    await test.step('Web: yedek pin değiştirilir → sürüm artar', async () => {
      await dashboard.setPins(HOST, second);
      // Kaydın sunucuya işlenmesi bir an sürebiliyor; sürüm artışını bekle.
      await expect.poll(() => versionOf(HOST), { timeout: 20_000 }).toBeGreaterThan(versions.created);
      versions.edited = await versionOf(HOST);
      // Kaydetmeden sonra kart yeniden çiziliyor; host sayfasını yeniden aç.
      await dashboard.openHost(HOST);
      await dashboard.snapHostSummary(`pin değişti: v${versions.edited}`);
    });

    await test.step('Web: "Değişiklik Geçmişi" kartı', async () => {
      await dashboard.openHost(HOST);
      await dashboard.snapCard('#pin-history-card', 'pin değişiklik geçmişi');
      const history = await historyOf(HOST);
      await attachText(
        testInfo,
        `GET /api/v1/certificate-config/history/${HOST}`,
        history
          .map((h) => `v${h.version}  ${h.changeType || h.change_type}  ${h.timestamp || h.changedAt}  ${h.pinPreview || ''}`)
          .join('\n'),
      );
      expect(history.length).toBeGreaterThanOrEqual(2);
    });

    await test.step('Web: host silinir', async () => {
      await dashboard.deleteHost(HOST);
      await dashboard.snap('host silindi');
      expect(await versionOf(HOST)).toBeNull();
    });

    await test.step('Web: host geri eklenince sürüm sıfırlanmaz (watermark)', async () => {
      await dashboard.addHostManual(env.VAULT_API, HOST, first);
      await dashboard.openHost(HOST);
      versions.readded = await dashboard.version();
      await dashboard.snap(`host geri eklendi: v${versions.readded}`);
      const history = await historyOf(HOST);
      await attachText(
        testInfo,
        'Sürüm çizgisi',
        [
          `eklendi        : v${versions.created}`,
          `pin değişti    : v${versions.edited}`,
          `silindi        : config'ten çıktı`,
          `geri eklendi   : v${versions.readded}  (v1'e dönmedi)`,
          '',
          'Geçmiş kayıtları:',
          ...history.map((h) => `  v${h.version}  ${h.changeType || h.change_type}`),
        ].join('\n'),
      );
      expect(versions.readded).toBeGreaterThan(versions.edited);
    });
  } finally {
    const cfg = await hostApi.getConfig();
    if (cfg.pins.some((p) => p.hostname === HOST)) {
      await hostApi.api('/api/v1/certificate-config', {
        method: 'PUT',
        body: { version: 0, forceUpdate: false, pins: cfg.pins.filter((p) => p.hostname !== HOST) },
      });
    }
  }
});
