// F02: kurtarmadaki yeniden deneme freni (üst üste hatalardan sonra bir süre
// denemez). Pin uyuşmazlığında kütüphane config'i tazeleyip isteği
// tekrarlar; ama gerçekten bozuk pin yayınlayan bir backend istemciyi sıkı
// bir yeniden deneme döngüsüne sokmamalı. Bu yüzden kurtarma
// host bazlı sayılır: 5 dakikalık pencerede 3 başarısız kurtarma denemesinden
// sonra o host 10 dakika soğumaya alınır ve interceptor artık updater'a hiç
// uğramadan özgün hatayı fırlatır.
//
// Kanıt: dördüncü istekte telefonun olay listesinde yeni bir [config] satırı
// çıkmıyor ve sunucuya yeni bir config güncelleme raporu düşmüyor — yani
// config yenileme isteği hiç yapılmadı.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/android');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');

/** Olay listesindeki config güncelleme satırları (en yeni başta). */
function configLines(eventLog) {
  return eventLog.split('\n').filter((l) => l.includes('[config]'));
}

/** Bu cihazın [since]'ten yeni config güncelleme raporları. */
async function configReportsSince(model, since) {
  return (await hostApi.configUpdateReports(model)).filter((e) => Date.parse(e.timestamp) >= since);
}

test('Mobil+Sunucu: üç başarısız kurtarmadan sonra yeniden deneme freni devreye giriyor, dördüncü istek config yenilemeye gitmiyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);

  let v0;
  let marker;
  const attempts = [];

  await test.step('Web: hedefin pin\'leri kalıcı olarak yanlış değerlerle değiştirilir', async () => {
    await dashboard.openHost(TARGET_HOST);
    v0 = await dashboard.version();
    await dashboard.setPins(TARGET_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
    await dashboard.snapHostSummary(`yanlış pinler, v${v0 + 1}`);
  });

  await test.step('Mobil: yanlış config uygulanır, ölçüm başlar (olay listesi temizlenir)', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    await app.tapButton('clearLogButton');
    await app.waitFor('eventLogView', (n) => n.text.includes('henüz olay yok'), { what: 'olay listesi boş' });
    marker = Date.now();
    await sleep(2000);
    await app.snap('ölçüm başlangıcı: olay listesi temiz');
  });

  await test.step('Mobil: ilk üç istek — her biri config\'i yenilemeyi deniyor ve başarısız oluyor', async () => {
    for (let i = 1; i <= 3; i++) {
      const result = await app.testLibraryClient();
      expect(result, `${i}. istek reddedilmeli`).toContain('Bağlantı başarısız');
      // Kurtarma senkron: sonuç geldiğinde config denemesi de bitmiş oluyor.
      await app.waitForEvent('[config] ', 30_000);
      const lines = configLines(app.eventLog());
      attempts.push(`${i}. istek → reddedildi, config yenileme denemesi: ${lines.length}`);
      expect(lines.length, `${i}. istekten sonra config denemesi sayısı`).toBe(i);
    }
    await app.snap('üç deneme: her birinde config yenileme var');
  });

  await test.step('Mobil: dördüncü istek — fren devrede, config yenileme denenmiyor', async () => {
    const before = configLines(app.eventLog()).length;
    const startedAt = Date.now();
    const result = await app.testLibraryClient();
    const elapsed = Date.now() - startedAt;
    // Yeni bir config satırı çıkacaksa çoktan çıkardı; yine de bekleyip bakalım.
    await sleep(8000);
    const after = configLines(app.eventLog()).length;
    await app.snap('dördüncü istek: config yenileme yok');
    attempts.push(`4. istek → reddedildi, config yenileme denemesi: ${after} (değişmedi)`);
    await attachText(
      testInfo,
      'Yeniden deneme freni (PinRecoveryInterceptor)',
      [
        ...attempts,
        '',
        `Dördüncü isteğin toplam süresi (test tarafında ölçüldü, ekranı okuma süresi dahil): ${elapsed} ms`,
        '',
        'Telefonun olay listesi:',
        app.eventLog(),
        '',
        'Kural: MAX_ATTEMPTS_PER_WINDOW=3, ATTEMPT_WINDOW_MS=5 dk, COOLDOWN_MS=10 dk.',
        'Üçüncü başarısız kurtarmada host 10 dakikalık beklemeye alınıyor; sonraki',
        'isteklerde interceptor config\'i yenilemeyi hiç denemeden asıl SSL hatasını',
        'fırlatıyor. Başarılı bir kurtarma sayacı SIFIRLAMIYOR (recordSuccess bilerek',
        'hiçbir şey yapmıyor): araya giren bir saldırgan arada geçerli bağlantılara izin',
        'vererek sayacı sürekli sıfırlayıp sunucuyu istediği hızda isteğe boğamasın diye.',
      ].join('\n'),
    );
    expect(result).toContain('Bağlantı başarısız');
    expect(after, 'dördüncü istekte yeni config yenileme denemesi olmamalı').toBe(before);
  });

  await test.step('Sunucu: config güncelleme raporu üçte kaldı', async () => {
    const reports = await configReportsSince(run.model, marker);
    await attachText(
      testInfo,
      'GET /api/v1/connection-history (source=config_update)',
      [
        `Ölçüm başladığından beri bu cihazdan gelen config güncelleme raporu: ${reports.length}`,
        ...reports.map((e) => `  ${e.timestamp}  ${e.status}  v${e.pinVersion ?? '—'}`),
        '',
        'Dört pinli istek yapıldı, yalnızca üçü config API\'ye gitti.',
      ].join('\n'),
    );
    expect(reports.length).toBe(3);
    expect(reports.every((e) => e.status === 'config_unchanged')).toBe(true);
  });

  await test.step('Web: doğru pin\'ler geri yüklenir', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
    await dashboard.snapHostSummary(`doğru pinler geri, v${v0 + 2}`);
  });

  await test.step('Mobil: bekleme süresi dolmadan otomatik kurtarma yok — istek hâlâ reddediliyor', async () => {
    const before = configLines(app.eventLog()).length;
    const result = await app.testLibraryClient();
    await sleep(5000);
    const after = configLines(app.eventLog()).length;
    await app.snap('bekleme sürüyor: sunucu düzeldi ama istek reddediliyor');
    await attachText(
      testInfo,
      'Bekleme süresindeki davranış',
      [
        `Sunucudaki pin sürümü : v${v0 + 2} (doğru pin'ler)`,
        `Telefondaki pin sürümü: v${v0 + 1} (yanlış pin'ler)`,
        `Sonuç: ${result.split('\n')[0]}`,
        `Config yenileme denemesi: ${before} → ${after}`,
        '',
        'Fren yalnızca OTOMATİK kurtarmayı durduruyor; elle çağrılan',
        'updateNow() (aşağıdaki "Config\'i şimdi yenile") hâlâ çalışıyor.',
      ].join('\n'),
    );
    expect(result).toContain('Bağlantı başarısız');
    expect(after).toBe(before);
  });

  await test.step('Mobil: elle yenileme frenden etkilenmiyor → bağlantı geri geliyor', async () => {
    const status = await app.refreshConfig();
    expect(status).toContain('Yeni config uygulandı');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 2);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap('elle yenileme sonrası bağlantı başarılı');
  });
});
