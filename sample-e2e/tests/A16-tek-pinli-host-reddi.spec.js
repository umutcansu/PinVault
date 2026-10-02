// A16: bir host'a tek pin bırakılamaz. Yedek pin olmadan sertifika rotasyonu
// kilitlenir (birincil sertifika değişince istemci hiçbir şeye bağlanamaz), bu
// yüzden üç katman da ≥2 pin şartını uygular: dashboard formu kaydetmeyi
// reddeder, sunucu doğrudan gelen isteği HTTP 400 ile reddeder, kütüphane de
// gelen config'i doğrularken aynı kuralı arar. Telefon bu denemelerden
// etkilenmez: sürüm ve pin'ler yerinde kalır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, describeResponse } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');

test('Web+Sunucu: tek pin\'li ya da aynı pini iki kez yazan host kaydedilemiyor (en az 2 farklı pin kuralı), telefon etkilenmiyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  let version;
  let pins;

  await test.step('Web: host\'un mevcut pin\'leri ve sürümü', async () => {
    await dashboard.openHost(TARGET_HOST);
    version = await dashboard.version();
    pins = await dashboard.viewedPins(TARGET_HOST);
    await dashboard.snapHostSummary(`iki pin, v${version}`);
    expect(pins.length).toBe(2);
    expect(SampleApp.hostVersion(app.status(), TARGET_HOST)).toBe(version);
  });

  await test.step('Web: yedek pin boşaltılıp kaydedilmek istenir → dashboard reddeder', async () => {
    // İkinci alan boşaltılır: "x" düğmesi zaten iki pin'in altına inmeye izin
    // vermiyor, tek yol alanı boş bırakmak.
    await dashboard.setPins(TARGET_HOST, [pins[0], ''], { expectSaved: false });
    // Red toast'ı (sağ altta) ekrandayken sayfa görüntüsü; metni de panele girer.
    await dashboard.snapWithToast('tek pin denemesi: "En az iki farklı pin gerekir" uyarısıyla reddedildi (sağ altta)');
    const toast = await dashboard.toastText();
    await attachText(
      testInfo,
      'Dashboard\'ın yanıtı (Pinleri Düzenle → Kaydet)',
      [
        `Gönderilmek istenen: 1 pin (${pins[0].slice(0, 12)}…)`,
        `toast: ${toast || '(toast görünmedi)'}`,
        '',
        'app-hosts.js/saveInlinePins: boş alanlar atılır; kalan farklı pin sayısı 2\'nin',
        'altındaysa istek sunucuya hiç gönderilmez.',
      ].join('\n'),
    );
    expect(toast).toMatch(/en az iki farklı pin|at least two different pins/i);
    await dashboard.cancelEditPins(TARGET_HOST);
    expect(await dashboard.viewedPins(TARGET_HOST)).toEqual(pins);
    expect(await dashboard.version()).toBe(version);
  });

  await test.step('Web: aynı pin iki kez yazılıp kaydedilmek istenir → dashboard reddeder', async () => {
    // Aynı pinin iki kopyası yedek değildir: sertifika değişince ikisi birden tutmaz.
    await expect(dashboard.page.locator('.toast')).toHaveCount(0, { timeout: 15_000 });
    await dashboard.setPins(TARGET_HOST, [pins[0], pins[0]], { expectSaved: false });
    await dashboard.snapWithToast('aynı pin iki kez: "En az iki farklı pin gerekir" uyarısıyla reddedildi (sağ altta)');
    const toast = await dashboard.toastText();
    await attachText(
      testInfo,
      'Dashboard\'ın yanıtı (aynı pin iki kez → Kaydet)',
      [`Gönderilmek istenen: ${pins[0].slice(0, 12)}… iki kez`, `toast: ${toast || '(toast görünmedi)'}`].join('\n'),
    );
    expect(toast).toMatch(/en az iki farklı pin|at least two different pins/i);
    await dashboard.cancelEditPins(TARGET_HOST);
    expect(await dashboard.viewedPins(TARGET_HOST)).toEqual(pins);
    expect(await dashboard.version()).toBe(version);
  });

  await test.step('Sunucu: aynı istek doğrudan yönetim API\'sine gönderilir → HTTP 400', async () => {
    const cfg = await hostApi.getConfig();
    const single = cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: [pins[0]] } : p));
    const res = await hostApi.api('/api/v1/certificate-config', {
      method: 'PUT',
      body: { version: 0, pins: single, forceUpdate: false },
    });
    await attachText(
      testInfo,
      'PUT /api/v1/certificate-config (hedef host\'a tek pin)',
      [
        `gövde: { pins: [ … { "hostname": "${TARGET_HOST}", "sha256": ["${pins[0].slice(0, 12)}…"] } … ] }`,
        '',
        describeResponse({ status: res.status, headers: {}, body: res.text }),
        '',
        'Kütüphane tarafında da en az 2 pin kuralı var: SSLCertificateUpdater.validateConfig',
        '→ require(pin.sha256.size >= 2) { "Host … must have at least 2 pins (primary + backup)" }',
      ].join('\n'),
    );
    expect(res.status).toBe(400);
    expect(res.text).toContain('en az 2 pin olmali');

    // Aynı pin iki kez: sayı 2 ama farklı pin 1.
    const twice = cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: [pins[0], pins[0]] } : p));
    const dup = await hostApi.api('/api/v1/certificate-config', {
      method: 'PUT',
      body: { version: 0, pins: twice, forceUpdate: false },
    });
    await attachText(
      testInfo,
      'PUT /api/v1/certificate-config (hedef host\'a aynı pin iki kez)',
      [
        `gövde: { pins: [ … { "hostname": "${TARGET_HOST}", "sha256": ["${pins[0].slice(0, 12)}…", "${pins[0].slice(0, 12)}…"] } … ] }`,
        '',
        describeResponse({ status: dup.status, headers: {}, body: dup.text }),
      ].join('\n'),
    );
    expect(dup.status).toBe(400);
    expect(dup.text).toContain('farkli');
  });

  await test.step('Sunucu: sürüm ve pin\'ler değişmedi', async () => {
    const cfg = await hostApi.getConfig();
    const stored = cfg.pins.find((p) => p.hostname === TARGET_HOST);
    await attachText(
      testInfo,
      'GET /api/v1/certificate-config?signed=false (reddedilen istekten sonra)',
      `${TARGET_HOST} → v${stored.version}, ${stored.sha256.length} pin`,
    );
    expect(stored.sha256).toEqual(run.goodPins);
    expect(stored.version).toBe(version);
  });

  await test.step('Mobil: telefon etkilenmedi — sürüm aynı, pinli istek geçiyor', async () => {
    const status = await app.refreshConfig();
    await app.snap('tek pin denemesinden sonra telefon');
    expect(status).toContain('Config güncel');
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
  });
});
