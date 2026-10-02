// Host kapalıyken sonraki açılış: uygulama saklı (imzası daha önce doğrulanmış)
// config ile açılır ve hedefe pinli bağlanmaya devam eder.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostControl = require('../lib/hostControl');
const { SampleApp } = require('../lib/sampleApp');

test('Host kapalıyken sonraki açılış: saklı config ile çalışmaya devam eder', async ({ app }, testInfo) => {
  let version;

  await test.step('Mobil: config alındı ve cihazda saklandı', async () => {
    version = SampleApp.hostVersion(app.status(), TARGET_HOST);
    expect(version).toBeGreaterThan(0);
    await app.snap(`config v${version} alındı ve saklandı`);
  });

  await test.step('Host durdurulur', async () => {
    await hostControl.stop();
    await attachText(testInfo, 'docker stop pinvault-host', await hostControl.describeState());
  });

  await test.step('Mobil: uygulama kapatılıp açılır (veri korunur) → saklı config ile hazır', async () => {
    app.relaunch();
    const status = await app.waitReady();
    expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    await app.snap('host kapalı, saklı config ile hazır');
  });

  await test.step('Mobil: host kapalıyken hedefe pinli istek başarılı', async () => {
    expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    await app.waitForEvent(`[✓] ${TARGET_HOST}`);
    await app.snap('host kapalıyken bağlantı');
  });

  await test.step('Host başlatılır', async () => {
    await hostControl.start();
    await attachText(testInfo, 'docker start pinvault-host', await hostControl.describeState());
  });
});
