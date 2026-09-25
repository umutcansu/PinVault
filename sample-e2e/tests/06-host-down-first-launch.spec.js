// Host kapalıyken ilk açılış: saklı config yokken uygulama pinsiz bağlantıya
// düşmez, başlatılamadığını söyler ve istek yapılmasına izin vermez. Host
// dönünce "Tekrar dene" ile toparlanır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostControl = require('../lib/hostControl');

test('Host kapalıyken ilk açılış: uygulama pinsiz bağlanmaya geçmez; host açılınca toparlanır', async ({
  app,
  device,
}, testInfo) => {
  await test.step('Host durdurulur', async () => {
    await hostControl.stop();
    await attachText(testInfo, 'docker stop pinvault-host', await hostControl.describeState());
  });

  await test.step('Mobil: verisi silinmiş uygulama açılır → başlatılamaz, istek düğmeleri kilitli', async () => {
    // Kütüphanenin yeniden deneme satırları (3 deneme, 2 s·n gecikme) bu
    // açılışa ait olsun diye günlük önce boşaltılır.
    device.clearLogcat();
    app.launchFresh();
    const status = await app.waitInitFailed();
    expect(status).toContain('PinVault başlatılamadı');
    expect(app.node('testButton').enabled, 'library client düğmesi').toBe(false);
    expect(app.node('prodStyleButton').enabled, 'production-style düğmesi').toBe(false);
    const retry = app.node('refreshButton');
    expect(retry.text).toMatch(/tekrar dene/i);
    expect(retry.enabled).toBe(true);
    await app.snap('host kapalı, başlatılamadı');

    const retries = device.logcat({ match: /Update attempt \d+\/\d+|Attempt \d+ failed, retrying in \d+ms/ });
    await attachText(
      testInfo,
      'logcat — başlatma 3 kez deneniyor; aralarda 2 sn ve 4 sn bekleniyor',
      [
        retries || '(ilgili satır yok)',
        '',
        'SSLCertificateUpdater.updateWithRetry: DEFAULT_MAX_RETRY=3,',
        'RETRY_BASE_DELAY_MS=2000 → 1. denemeden sonra 2000 ms, 2. denemeden',
        'sonra 4000 ms bekleniyor; üçüncü deneme de olmazsa init başarısız sayılıyor.',
      ].join('\n'),
    );
    expect(retries).toContain('Update attempt 1/3');
    expect(retries).toContain('Update attempt 3/3');
    expect(retries).toMatch(/Attempt 1 failed, retrying in 2000ms/);
    expect(retries).toMatch(/Attempt 2 failed, retrying in 4000ms/);
  });

  await test.step('Host başlatılır', async () => {
    await hostControl.start();
    await attachText(testInfo, 'docker start pinvault-host', await hostControl.describeState());
  });

  await test.step('Mobil: "Tekrar dene" düğmesine basılınca uygulama hazır, pinli istek başarılı', async () => {
    await app.tapButton('refreshButton');
    await app.waitReady();
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.snap('host geri geldi, bağlantı başarılı');
  });
});
