// F01: forceUpdate + sunucuya ulaşılamıyor. Kütüphane, saklı config'te
// "zorunlu güncelleme" işaretliyken backend'e ulaşamazsa açılışı BAŞARISIZ
// sayar (ForceUpdateFailedException): operatör "bu config artık geçersiz"
// dediyse istemci eski config'le çalışmaya devam etmemelidir.
//
// Senaryo iki yolu da gösteriyor:
//   1. Config genelindeki bayrak yazıldığında (yönetim API'si) init gerçekten
//      başarısız oluyor; host dönünce "Tekrar dene" toparlıyor.
//   2. Dashboard'daki host bazlı "Force Update" anahtarı da aynı kapıyı
//      açıyor: sunucu servis ettiği config'i PinConfig.hasAnyForceUpdate() ile
//      damgalıyor. (Bu senaryo ilk yazıldığında damga yoktu ve arayüzden bu
//      kapı hiç açılamıyordu — bulgu düzeltildikten sonra beklenti güncellendi.)
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');

/** Config genelindeki forceUpdate bayrağını yazar (dashboard'da karşılığı yok). */
async function setGlobalForce(value) {
  const cfg = await hostApi.getConfig();
  const res = await hostApi.api('/api/v1/certificate-config', {
    method: 'PUT',
    body: { version: 0, pins: cfg.pins, forceUpdate: value },
  });
  if (res.status !== 200) throw new Error(`forceUpdate yazılamadı: HTTP ${res.status} ${res.text}`);
  return res;
}

test('Web+Sunucu+Mobil: zorunlu güncelleme işaretliyken sunucuya ulaşılamazsa uygulama başlatılamaz', async ({
  app,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);

  let version;

  try {
    await test.step('Mobil: başlangıç durumu', async () => {
      version = SampleApp.hostVersion(app.status(), TARGET_HOST);
      expect(version).toBeGreaterThan(0);
      await app.snap(`başlangıç: Hazır, pin v${version}`);
    });

    await test.step('Sunucu: config geneline zorunlu güncelleme yazılır', async () => {
      const res = await setGlobalForce(true);
      const cfg = await hostApi.getConfig();
      await attachText(
        testInfo,
        'PUT /api/v1/certificate-config { forceUpdate: true }',
        [
          `HTTP ${res.status}`,
          `Config geneli forceUpdate : ${cfg.forceUpdate}`,
          `Host bazlı forceUpdate    : ${cfg.pins.map((p) => `${p.hostname}=${p.forceUpdate}`).join(', ')}`,
          '',
          'Kütüphanenin init kapısı (SSLCertificateUpdater.initializeAndUpdate →',
          'storedConfig.forceUpdate) config GENELİNDEKİ alana bakıyor. Bu alan',
          'yönetim API\'sinden doğrudan yazılabiliyor; dashboard ise host satırındaki',
          'bayrağı yazıyor ve sunucu servis ederken ikisini PinConfig.hasAnyForceUpdate()',
          'ile birleştiriyor (aşağıdaki ikinci senaryo bunu gösteriyor).',
        ].join('\n'),
      );
      expect(cfg.forceUpdate).toBe(true);
    });

    await test.step('Mobil: config zorunlu güncelleme bayrağıyla alınır', async () => {
      const status = await app.refreshConfig();
      await app.snap('zorunlu güncelleme işaretli config alındı');
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    });

    await test.step('Terminal: host durdurulur', async () => {
      await hostControl.stop();
      await attachText(
        testInfo,
        'docker stop pinvault-host',
        `Container çalışıyor mu: ${hostControl.isRunning()}\nSağlık ucu: ${(await hostApi.isHealthy()) ? 'açık' : 'kapalı'}`,
      );
      expect(await hostApi.isHealthy()).toBe(false);
    });

    await test.step('Mobil: uygulama yeniden açılır → başlatılamıyor (zorunlu güncelleme)', async () => {
      // Veri korunur: saklı config var ama "zorunlu güncelleme" işaretli.
      app.relaunch();
      const status = await app.waitInitFailed();
      await app.snap('zorunlu güncelleme + host kapalı: başlatılamadı');
      await attachText(testInfo, 'Telefondaki hata', status);
      expect(status).toContain('PinVault başlatılamadı');
      expect(status).toContain('Force update required but backend unreachable');
      expect(app.node('testButton').enabled, 'library client düğmesi').toBe(false);
      expect(app.node('refreshButton').text).toMatch(/tekrar dene/i);
    });

    await test.step('Terminal: host geri açılır → "Tekrar dene" ile toparlanır', async () => {
      await hostControl.start();
      await app.tapButton('refreshButton');
      const status = await app.waitReady();
      await app.snap('host döndü: Tekrar dene → Hazır');
      expect(status).toMatch(/Hazır — config v\d+/);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Sunucu: zorunlu güncelleme kapatılır → yeniden açılış normal', async () => {
      await setGlobalForce(false);
      await app.refreshConfig();
      app.relaunch();
      const status = await app.waitReady();
      await app.snap('force kapalı: normal açılış');
      expect(status).toMatch(/Hazır — config v\d+/);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    });
  } finally {
    await hostControl.ensureUp();
    await setGlobalForce(false).catch(() => {});
  }
});

test('Web+Mobil: dashboard\'ın host bazlı "Force Update" anahtarı init kapısını açıyor', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);

  let version;

  await test.step('Web: host bazlı "Force Update" açılır', async () => {
    await dashboard.openHost(TARGET_HOST);
    version = await dashboard.version();
    await dashboard.setForce(TARGET_HOST, true);
    await dashboard.snap('host bazlı force update aktif');
    const cfg = await hostApi.getConfig();
    await attachText(
      testInfo,
      'Dashboard "Force Update" → sunucudaki durum',
      [
        `onay metni: ${dashboard.lastDialog()}`,
        `Config geneli forceUpdate: ${cfg.forceUpdate}`,
        `${TARGET_HOST} forceUpdate: ${cfg.pins.find((p) => p.hostname === TARGET_HOST).forceUpdate}`,
        '',
        'Dashboard yalnızca host satırındaki bayrağı yazıyor (POST .../force-update/{host}),',
        'ama servis edilen config CertificateConfigRoute içinde',
        'forceUpdate = hasAnyForceUpdate() ile damgalanıyor: kütüphanenin baktığı config',
        'geneli alanı da true oluyor. Bu senaryo ilk yazıldığında damga yoktu ve arayüzden',
        'init kapısı hiç açılamıyordu (o bulgu düzeltildi).',
      ].join('\n'),
    );
    expect(cfg.pins.find((p) => p.hostname === TARGET_HOST).forceUpdate).toBe(true);
    expect(cfg.forceUpdate).toBe(true);
  });

  await test.step('Mobil: config zorla yeniden uygulanır (sürüm değişmeden)', async () => {
    const status = await app.refreshConfig();
    await app.snap('host bazlı force ile yeniden uygulandı');
    expect(status).toContain('Yeni config uygulandı');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
  });

  await test.step('Terminal+Mobil: host kapalıyken yeniden açılış → başlatılamıyor', async () => {
    await hostControl.stop();
    app.relaunch();
    const status = await app.waitInitFailed();
    await app.snap('host bazlı force + host kapalı: başlatılamadı');
    await attachText(
      testInfo,
      'Host bazlı force bayrağı init kapısını açıyor',
      [
        status,
        '',
        'Saklı config\'te forceUpdate=true olduğu için SSLCertificateUpdater',
        '.initializeAndUpdate backend\'e ulaşamayınca ForceUpdateFailedException ile',
        'başarısız dönüyor — operatör "bu config geçersiz" dediyse istemci eski',
        'config\'le çalışmaya devam etmiyor.',
        '',
        'Bu adım senaryo ilk yazıldığında "Hazır" veriyordu: dashboard yalnızca host',
        'satırındaki bayrağı yazıyor, kütüphane ise config genelindeki alana bakıyordu.',
        'Sunucu artık servis ettiği config\'i hasAnyForceUpdate() ile damgalıyor.',
      ].join('\n'),
    );
    expect(status).toContain('PinVault başlatılamadı');
    expect(status).toContain('Force update required but backend unreachable');
  });

  await test.step('Terminal+Mobil: host geri açılır → "Tekrar dene" toparlıyor', async () => {
    await hostControl.start();
    await app.tapButton('refreshButton');
    const status = await app.waitReady();
    await app.snap('host döndü: Tekrar dene → Hazır');
    expect(status).toMatch(/Hazır — config v\d+/);
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
  });

  await test.step('Web: force update kapatılır', async () => {
    await dashboard.page.reload();
    await dashboard.openHost(TARGET_HOST);
    await dashboard.setForce(TARGET_HOST, false);
    await dashboard.snap('force update pasif');
    const status = await app.refreshConfig();
    expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
    const cfg = await hostApi.getConfig();
    await attachText(
      testInfo,
      'Force kapatıldıktan sonra servis edilen config',
      `Config geneli forceUpdate: ${cfg.forceUpdate}\n${TARGET_HOST} forceUpdate: ${
        cfg.pins.find((p) => p.hostname === TARGET_HOST).forceUpdate
      }`,
    );
    expect(cfg.forceUpdate).toBe(false);
  });
});
