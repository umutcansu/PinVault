// A20: gerçek sertifika rotasyonu. Dashboard'dan mock TLS host'un sertifikası
// yenilenir: sunucu yeni bir anahtar çifti üretir, host'un pin'lerini ve
// sürümünü artırır ve mock dinleyiciyi yeni sertifikayla yeniden başlatır.
// Telefon eski pin'leriyle artık el sıkışamaz: istek pin uyuşmazlığına düşer,
// kütüphanenin kurtarma interceptor'ı config'i tazeleyip isteği tekrarlar ve
// bağlantı elle yenileme olmadan yeni pin'lerle kurulur.
//
// Ana host'un KENDİ sertifikasına dokunulmaz (o E03'ün işi ve APK'nın gömülü
// bootstrap pin'lerini bayatlatır); rotasyon mock hedef host üzerinde yapılır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const state = require('../lib/state');
const env = require('../lib/env');

const MOCK = env.MOCK_TLS_HOST;

test('Web+Mobil: mock host sertifikası yenilenince telefon kurtarma ile yeni pinlere geçiyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);

  let v0;
  let oldPins;
  let newPins;

  await test.step('Web: mock host\'un sertifikası ve pin\'leri (rotasyon öncesi)', async () => {
    await dashboard.openHost(MOCK);
    v0 = await dashboard.version();
    oldPins = await dashboard.viewedPins(MOCK);
    await dashboard.snapCard('#cert-info-card', `${MOCK} sertifikası (rotasyon öncesi)`);
    await dashboard.snapHostSummary(`${MOCK} pinleri, v${v0}`);
    expect(oldPins).toEqual(run.baseline[MOCK]);
  });

  await test.step('Mobil: telefon mock TLS host\'a eski pin\'lerle bağlanıyor', async () => {
    expect(SampleApp.hostVersion(app.status(), MOCK)).toBe(v0);
    await app.openMtls();
    const result = await app.mockTls();
    await app.snap(`mock TLS host bağlantısı (pin v${v0})`);
    expect(result).toContain('host bağlantısı başarılı');
    await app.backToMain();
  });

  await test.step('Web: "Sertifikayı Yenile" → yeni pin\'ler, sürüm artar', async () => {
    const toast = await dashboard.renewHostCert(MOCK);
    await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(v0 + 1);
    newPins = await dashboard.viewedPins(MOCK);
    await dashboard.snapCard('#cert-info-card', `${MOCK} sertifikası (rotasyon sonrası)`);
    await dashboard.snapHostSummary(`${MOCK} yeni pinleri, v${v0 + 1}`);
    await expect(dashboard.page.locator('#pin-history-card tbody tr').first()).toContainText('cert_regenerated');
    await dashboard.snapCard('#pin-history-card', 'pin geçmişi: cert_regenerated');
    await attachText(
      testInfo,
      `${MOCK} sertifika rotasyonu`,
      [
        `onay : ${dashboard.lastDialog()}`,
        `toast: ${toast}`,
        '',
        `eski pin'ler (v${v0}) : ${oldPins.join('\n                      ')}`,
        `yeni pin'ler (v${v0 + 1}) : ${newPins.join('\n                      ')}`,
        '',
        'POST /api/v1/hosts/<host>/regenerate-cert: yeni anahtar çifti üretilir,',
        'host\'u barındıran bütün Config API kapsamlarının pin kayıtları güncellenir',
        've çalışan mock dinleyici yeni keystore ile yeniden başlatılır.',
      ].join('\n'),
    );
    expect(newPins).not.toEqual(oldPins);
    // Bundan sonraki senaryolar (ve teardown) yeni pin'leri temel almalı:
    // eski pin'ler artık mock host'un sertifikasına uymuyor.
    run.baseline[MOCK] = newPins;
    state.write(run);
  });

  await test.step('Mobil: istek elle yenileme olmadan kendiliğinden toparlanıyor', async () => {
    // İki şeyi bekle:
    //  1. Mock dinleyici yeni keystore ile gerçekten ayağa kalksın (pin kaydı
    //     anında güncelleniyor, dinleyicinin yeniden başlaması sürüyor).
    //  2. Emülatörün saati yeni sertifikanın notBefore'unu geçsin. Cihaz saati
    //     Mac'ten bir iki saniye geride olabiliyor; o aralıkta el sıkışma
    //     "Certificate not valid until …" ile düşüyor. Kütüphane bunu artık
    //     CertificateValidityException olarak ayırıyor ve pin uyuşmazlığı
    //     saymıyor (config tazelemek geçerlilik penceresini düzeltmez), ama
    //     istek yine de düşer — bu yüzden saatin geçmesi bekleniyor.
    let validFromMs = 0;
    await expect
      .poll(
        async () => {
          const cert = await hostApi.servedCert(env.MOCK_TLS_PORT, MOCK).catch(() => null);
          validFromMs = cert ? cert.validFromMs : 0;
          return cert && cert.pin;
        },
        { timeout: 60_000, intervals: [500, 1000, 2000] },
      )
      .toBe(newPins[0]);
    await expect
      .poll(() => device.epochMs(), { timeout: 30_000, intervals: [1000] })
      .toBeGreaterThan(validFromMs + 1000);
    await app.openMtls();
    const result = await app.mockTls();
    await app.snap('yeni sertifika: kurtarma ile bağlantı başarılı');
    await attachText(
      testInfo,
      'Telefondaki sonuç (elle yenileme yapılmadan)',
      [
        result,
        '',
        `Telefonun elindeki pin sürümü rotasyondan önce v${v0} idi; sunucudaki`,
        `sertifika artık v${v0 + 1}. İstek önce pin uyuşmazlığına düştü, kütüphanenin`,
        'kurtarma interceptor\'ı config\'i tazeledi ve isteği TEKRARLADI; kullanıcıya',
        'yalnızca başarılı sonuç göründü.',
        '',
        'Tekrar, çağıranın kendi istemci zincirinde yapılıyor; bu yüzden uygulamanın',
        'mock host adlarını host IP\'sine çözen özel Dns ayarı korunuyor. (Daha önce',
        'tekrar PinVault\'un iç istemcisiyle yapıldığı için bu ayar kayboluyor ve',
        'kurtarma UnknownHostException ile düşüyordu.)',
      ].join('\n'),
    );
    expect(result).toContain('host bağlantısı başarılı');
    await app.backToMain();
  });

  await test.step('Mobil: kurtarma config sürümünü de güncellemiş', async () => {
    const status = await app.refreshConfig();
    await app.snap(`mock host pin v${v0 + 1}`);
    await attachText(
      testInfo,
      'Telefondaki durum kutusu (kurtarmadan sonra)',
      [
        status,
        '',
        'Kurtarma sırasında uygulanan config zaten yeni sürüm olduğu için elle',
        'yenileme "Config güncel" diyor.',
      ].join('\n'),
    );
    expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
    expect(SampleApp.hostVersion(status, MOCK)).toBe(v0 + 1);
  });

  await test.step('Mobil: yeni pinlerle bağlantı kalıcı olarak çalışıyor', async () => {
    await app.openMtls();
    const result = await app.expectRepeated(() => app.mockTls(), 'host bağlantısı başarılı', 30_000);
    await app.snap(`yeni sertifikayla bağlantı (pin v${v0 + 1})`);
    expect(result).toContain('host bağlantısı başarılı');
    await app.backToMain();
  });

  await test.step('Sunucu: rotasyon kalıcı — config\'teki pin\'ler yeni sertifikanın pin\'leri', async () => {
    const cfg = await hostApi.getConfig();
    const stored = cfg.pins.find((p) => p.hostname === MOCK);
    await attachText(
      testInfo,
      'GET /api/v1/certificate-config?signed=false',
      `${MOCK} → v${stored.version}, pin'ler:\n  ${stored.sha256.join('\n  ')}`,
    );
    expect(stored.sha256).toEqual(newPins);
    expect(stored.version).toBe(v0 + 1);
  });
});
