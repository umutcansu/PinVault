// A26: `PinVault.reset()` ve çift init koruması.
//
//  • reset() aktif pinlemeyi ve saklı config'i siler. Sonrasında pinli istemci
//    kurulamaz bile — kütüphane "başlatılmadı" der ve TLS'e hiç çıkılmaz
//    (şüphede bağlantıya izin verilmez; sistem sertifikalarına geri dönülmez).
//  • "Sıfırla ve başlat" kütüphaneyi baştan kurar: config sunucudan yeniden
//    çekilir, uygulama Hazır olur.
//  • init() ikinci kez çağrıldığında kütüphane hiçbir iş yapmadan hemen
//    Ready döner: ne ağ isteği, ne yeni TLS el sıkışması.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const { sleep } = require('../lib/device');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

/** Bu cihazın host'a (config API) yaptığı, [since]'ten yeni el sıkışma kayıtları. */
async function handshakesSince(model, since) {
  const rows = await hostApi.connectionHistory(env.LAN_IP);
  return rows.filter((e) => e.deviceModel === model && Date.parse(e.timestamp) >= since);
}

test('Mobil: reset sonrası pinli istek reddediliyor, "Sıfırla ve başlat" ile düzeliyor, ikinci init ağa çıkmıyor', async ({
  app,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);

  let version;

  await test.step('Mobil: başlangıçta hazır ve pinli istek geçiyor', async () => {
    version = SampleApp.hostVersion(app.status(), TARGET_HOST);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap(`başlangıç: Hazır, pin v${version}`);
  });

  await test.step('Mobil: Ayarlar → "Sıfırla" → pinli istek reddediliyor (şüphede bağlantıya izin yok)', async () => {
    await app.openSettings();
    const result = await app.resetAndProbe();
    await app.snapResult('reset sonrası pinli istek reddedildi');
    await attachText(
      testInfo,
      'reset() sonrası pinli istek denemesi',
      [
        result,
        '',
        'PinVault.reset(): aktif config bellekten atılır, şifreli config deposu silinir',
        've "initialized" bayrağı sıfırlanır. Sonrasında applyTo()/getClient() çağrısı',
        'checkInitialized() kontrolünde duruyor; yani istemci KURULAMIYOR bile,',
        'sunucuyla hiç TLS el sıkışması denenmiyor.',
        '',
        'PLAN.md bu adımda "No pins configured" bekliyordu; o mesaj bir sonraki',
        'kontrolden (config yokken el sıkışmayı reddeden dinamik trust manager) gelir',
        've E09\'da (izin listesi boşken sıfır pin) görülüyor. İki yolda da şüphede',
        'bağlantıya izin verilmiyor.',
      ].join('\n'),
    );
    expect(result).toContain('PinVault sıfırlandı');
    expect(result).toContain('Pinli istek reddedildi');
    expect(result).not.toContain('İSTEK GEÇTİ');
  });

  await test.step('Mobil: ana ekran reset durumunu gösteriyor, istek düğmeleri kilitli', async () => {
    await app.backToMain();
    const status = app.status();
    await app.snap('reset: istek düğmeleri kilitli');
    expect(status).toContain('PinVault başlatılamadı');
    expect(status).toContain('config yok, TLS reddedilir');
    expect(app.node('testButton').enabled, 'library client düğmesi').toBe(false);
    expect(app.node('prodStyleButton').enabled, 'production-style düğmesi').toBe(false);
  });

  let fullInitHandshakes;

  await test.step('Mobil+Sunucu: "Sıfırla ve başlat" → Hazır, sunucuda yeni el sıkışma', async () => {
    await app.openSettings();
    const marker = Date.now() - 1000;
    const result = await app.restart();
    await app.snapResult('sıfırlandı ve yeniden başlatıldı');
    await expect
      .poll(async () => (await handshakesSince(run.model, marker)).length, { timeout: 40_000 })
      .toBeGreaterThan(0);
    fullInitHandshakes = (await handshakesSince(run.model, marker)).length;
    await attachText(
      testInfo,
      'Ayarlar → "Sıfırla ve başlat" (tam init)',
      [
        result,
        '',
        `Sunucudaki yeni el sıkışma kaydı (${env.LAN_IP}, ${run.model}): ${fullInitHandshakes}`,
        'Tam init pinli istemciyi baştan kurup config\'i sunucudan çekiyor.',
      ].join('\n'),
    );
    expect(result).toContain('Sıfırlandı ve yeniden başlatıldı');
    expect(result).toMatch(/Hazır — config v\d+/);
  });

  let scheduleEvent;

  await test.step('Mobil: "İşi planla" tek başına da bir config güncellemesi çalıştırıyor (karşılaştırma için)', async () => {
    // İkinci init'ten sonra olay listesinde çıkacak [config] satırının kaynağı
    // burada belirleniyor: uygulamanın onResult'ta çağırdığı
    // schedulePeriodicUpdates(REPLACE) WorkManager'da yeni periyodik işi hemen
    // bir kez koşturuyor. Bu satır kütüphanenin init'inden gelmiyor.
    await app.backToMain();
    await app.tapButton('clearLogButton');
    await app.waitFor('eventLogView', (n) => n.text.includes('henüz olay yok'), { what: 'olay listesi boş' });
    await app.openSettings();
    const result = await app.scheduleWork();
    await app.backToMain();
    scheduleEvent = await app.waitForEvent('[config] ', 60_000);
    await app.snap('WorkManager yeniden planlandı → bir güncelleme çalıştı');
    await attachText(
      testInfo,
      'Yalnızca "İşi planla" (init yok) → olay listesinde config satırı',
      [result.split('\n').slice(0, 3).join('\n'), '', `Olay listesi:\n${scheduleEvent}`].join('\n'),
    );
    expect(scheduleEvent).toMatch(/\[config\] (UNCHANGED|UPDATED)/);
  });

  await test.step('Mobil+Sunucu: "init tekrar" ağ isteği yapmadan hemen dönüyor', async () => {
    // Ölçüm penceresi: olay listesi temizlenir, sunucudaki el sıkışma kayıtları
    // işaretlenir. Bundan sonra yeni bir el sıkışma olursa iki tarafta da görünür.
    await app.tapButton('clearLogButton');
    await app.waitFor('eventLogView', (n) => n.text.includes('henüz olay yok'), { what: 'olay listesi boş' });
    const marker = Date.now();
    // Telemetri asenkron: işaretten hemen önceki raporlar da düşebilir.
    await sleep(3000);
    const before = await handshakesSince(run.model, marker);

    await app.openSettings();
    const result = await app.reinit();
    await app.snapResult('init tekrar: ağ isteği yok');
    await app.backToMain();
    await sleep(8000);
    const after = await handshakesSince(run.model, marker);
    const eventLog = app.eventLog();

    await attachText(
      testInfo,
      'İkinci init: yeni TLS el sıkışması yok',
      [
        result,
        '',
        `Telefonun olay listesi (init tekrar sonrası):\n${eventLog}`,
        '',
        `Sunucudaki el sıkışma kaydı (${env.LAN_IP}, ${run.model}):`,
        `  tam init ("Sıfırla ve başlat")     : ${fullInitHandshakes} yeni kayıt`,
        `  ikinci init ("init tekrar") öncesi : ${before.length}`,
        `  ikinci init sonrası                : ${after.length}`,
        '',
        'PinVault.setup(): initialized=true ise "PinVault already initialized —',
        'skipping" loglanır ve callback anında InitResult.Ready ile çağrılır;',
        'kütüphane config API\'ye tek bir istek bile göndermez.',
        '',
        'Olay listesindeki tek satır bir [config] güncellemesi; yeni el sıkışma',
        '([✓] <host>) satırı yok. O satırın kaynağı bir önceki adımda ayrıca',
        'gösterildi: örnek uygulama init callback\'inde schedulePeriodicUpdates()',
        'çağırıyor ve WorkManager REPLACE edilen periyodik işi hemen bir kez',
        'çalıştırıyor; bu kütüphanenin init akışı değil, uygulamanın kendi tercihi.',
      ].join('\n'),
    );
    expect(result).toContain('zaten başlatılmış, ağ isteği yok');
    expect(result).toMatch(/Hazır — config v\d+/);
    expect(eventLog, 'ikinci init yeni TLS el sıkışması yapmadı').not.toContain('[✓]');
    expect(after.length).toBe(before.length);
  });

  await test.step('Mobil: pinli istek yine başarılı, sürüm korunuyor', async () => {
    // Durum kutusu son işlemin sonucunu gösterdiği için sürüm listesi
    // yenileme çıktısından okunur.
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    const result = await app.testLibraryClient();
    await app.snap('reset döngüsünden sonra bağlantı');
    expect(result).toContain('Pinned bağlantı başarılı');
  });
});
