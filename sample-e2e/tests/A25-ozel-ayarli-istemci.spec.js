// A25: `PinVault.getClient(HttpConnectionSettings)` — özel zaman aşımlarıyla
// pinlenmiş istemci. Pinleme aynı kaynaktan (aktif config) okunur, ama bu
// aşırı yükleme kurtarma interceptor'ını KURMAZ: pin uyuşmazlığı çağırana
// olduğu gibi döner, kütüphane config'i kendiliğinden tazeleyip isteği
// tekrarlamaz.
//
// Senaryo farkı gösterir: sunucudaki pin'ler düzeltildikten sonra bile özel
// ayarlı istemci reddetmeye devam eder; aynı anda ana ekrandaki `applyTo()`
// istemcisi kendiliğinden toparlanır ve ortak config'i tazeleyince özel ayarlı
// istemci de geçer.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');

test('Mobil: özel bağlantı ayarlı istemci pin\'leri uyguluyor ama kendiliğinden toparlanmıyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);

  let v0;
  const log = [];

  await test.step('Mobil: Ayarlar → "Özel ayarlı istemci" pinli istekte başarılı', async () => {
    v0 = SampleApp.hostVersion(app.status(), TARGET_HOST);
    await app.openSettings();
    const result = await app.settingsClientTest();
    await app.snapResult(`özel ayarlı istemci başarılı (pin v${v0})`);
    log.push(`1) doğru pin'ler (v${v0}) → ${result.split('\n')[0]}`);
    expect(result).toContain('Özel ayarlı istemci bağlandı');
    expect(result).toContain('kurtarma yok');
    await app.backToMain();
  });

  await test.step('Web: hedefin pin\'leri yanlış değerlerle değiştirilir', async () => {
    await dashboard.openHost(TARGET_HOST);
    await dashboard.setPins(TARGET_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    await expect.poll(() => dashboard.version()).toBe(v0 + 1);
    await dashboard.snapHostSummary(`yanlış pinler, v${v0 + 1}`);
  });

  await test.step('Mobil: yanlış config uygulanır → özel ayarlı istemci reddediyor', async () => {
    const status = await app.refreshConfig();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    await app.openSettings();
    const first = await app.settingsClientTest();
    await app.snapResult('özel ayarlı istemci: pin uyuşmazlığı (1. deneme)');
    // İkinci deneme de aynı: kurtarma yok, config kendiliğinden tazelenmiyor.
    const second = await app.settingsClientTest();
    log.push(`2) yanlış pin'ler (v${v0 + 1}) → ${first.split('\n')[1]}`);
    log.push(`3) aynı istek tekrar        → ${second.split('\n')[1]}`);
    expect(first).toContain('Özel ayarlı istemci başarısız');
    expect(second).toContain('Özel ayarlı istemci başarısız');
    await app.backToMain();
  });

  await test.step('Web: doğru pin\'ler geri yüklenir', async () => {
    await dashboard.setPins(TARGET_HOST, run.goodPins);
    await expect.poll(() => dashboard.version()).toBe(v0 + 2);
    await dashboard.snapHostSummary(`doğru pinler geri, v${v0 + 2}`);
  });

  await test.step('Mobil: sunucu düzeldi ama özel ayarlı istemci HÂLÂ reddediyor', async () => {
    await app.openSettings();
    const result = await app.settingsClientTest();
    await app.snapResult('kurtarma yok: sunucu düzeldi ama hâlâ reddediliyor (yeni deneme)');
    log.push(`4) sunucu düzeldi (v${v0 + 2}), telefon hâlâ v${v0 + 1} → ${result.split('\n')[1]}`);
    expect(result).toContain('Özel ayarlı istemci başarısız');
    await app.backToMain();
  });

  await test.step('Mobil: ana ekrandaki applyTo() istemcisi aynı durumda kendiliğinden toparlanıyor', async () => {
    const result = await app.testLibraryClient();
    await app.snap('applyTo() istemcisi otomatik kurtardı');
    await app.waitForEvent(`[config] UPDATED v${v0 + 2}`);
    log.push(`5) applyTo() istemcisi     → ${result.split('\n')[0]} (kurtarma interceptor'ı config'i v${v0 + 2}'ye güncelledi)`);
    expect(result).toContain('Pinned bağlantı başarılı');
  });

  await test.step('Mobil: config yenilenince özel ayarlı istemci de geçiyor', async () => {
    await app.openSettings();
    const result = await app.settingsClientTest();
    await app.snapResult('config yenilendi: özel ayarlı istemci başarılı');
    log.push(`6) ortak config v${v0 + 2} → ${result.split('\n')[0]}`);
    await attachText(
      testInfo,
      'getClient(HttpConnectionSettings) — pinleme var, kurtarma yok',
      [
        ...log,
        '',
        'Pin kaynağı aynı (aktif config her el sıkışmada yeniden okunuyor), davranış',
        'farklı: getClient\'ın bu çeşidi PinRecoveryInterceptor eklemiyor; bu yüzden',
        'uyuşmazlık uygulamaya SSLPeerUnverifiedException olarak dönüyor. Hem özel',
        'zaman aşımı hem otomatik kurtarma isteyen uygulama kendi builder\'ına',
        'applyTo(builder) uygulamalı.',
      ].join('\n'),
    );
    expect(result).toContain('Özel ayarlı istemci bağlandı');
    await app.backToMain();
  });
});
