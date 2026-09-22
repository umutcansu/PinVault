// Kurulum yolculuğu K10–K12: host değerlerinin istemciye aktarılması
// (client-config.sh --properties), uygulamanın bu değerlerle derlenip
// kurulması, ilk açılışta "Hazır — config vN" ve dashboard'daki "Bağlı
// Cihazlar" / "Bağlantı Geçmişi" kayıtları.
//
// Telefon bu senaryoda TAZE host'a bakar. Senaryo sonunda uygulama MUTLAKA
// ana host'un değerleriyle yeniden derlenip kurulur (finally) — yoksa diğer
// bütün senaryolar kırılır.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const clientBuild = require('../lib/clientBuild');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

const FRESH_PROPS = path.join(env.LOCAL_DIR, 'host-fresh.properties');

test('Kurulum: istemci taze host değerleriyle derlenir, telefon bağlanır ve dashboard\'da görünür', async ({ device, run, browser }, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  await fresh.ensure();

  const app = new SampleApp(device, testInfo);
  let dashboard;

  try {
    await test.step('Terminal: client-config.sh --properties — istemci değerleri (K10)', async () => {
      const out = fresh.run('./scripts/client-config.sh', ['--properties']);
      fs.writeFileSync(FRESH_PROPS, out);
      await attachText(testInfo, 'scripts/client-config.sh --properties (taze host)', `$ ./scripts/client-config.sh --properties\n${out}`);
      expect(out).toContain(`host.httpsPort=${fresh.PORTS.https}`);
      expect(out).toContain(`host.bootstrapPinPrimary=${fresh.hostPins()[0]}`);
      expect(out).toContain(`host.signingPublicKey=${fresh.signingKeyRaw().split('\n')[1].trim()}`);
    });

    await test.step('Terminal: network_security_config.xml düz HTTP telemetriye izin verir (K10)', async () => {
      const file = path.join(env.CLIENT_DIR, 'app/src/main/res/xml/network_security_config.xml');
      const xml = fs.readFileSync(file, 'utf8');
      await attachText(testInfo, 'app/src/main/res/xml/network_security_config.xml', xml);
      expect(xml).toContain(env.LAN_IP);
    });

    await test.step('Terminal: derleme ve kurulum (K11)', async () => {
      const out = clientBuild.buildAndInstall(device, FRESH_PROPS);
      await attachText(
        testInfo,
        'gradlew assembleDebug -PsampleHostProps=… + adb install',
        `$ ./gradlew assembleDebug -PsampleHostProps=${FRESH_PROPS}\n${out}`,
      );
      expect(out).toContain('host-fresh.properties');
      expect(out).toMatch(/BUILD SUCCESSFUL/);
      expect(out).toContain('Success');
    });

    await test.step('Mobil: ilk açılış — "Hazır — config vN" (K12)', async () => {
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('taze host ile ilk açılış');
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toMatch(/Hazır — config v\d+/);
      // Taze host'un config'indeki host'lar telefonda görünür.
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).not.toBeNull();
    });

    await test.step('Web: taze dashboard\'da Bağlı Cihazlar ve Bağlantı Geçmişi (K12)', async () => {
      dashboard = await fresh.openDashboard(browser, testInfo);
      await dashboard.openHost(env.LAN_IP);
      await dashboard.expectClientRowPresent(run.model);
      await dashboard.snapCard('#client-devices-card', 'taze host: Bağlı Cihazlar');
      await dashboard.expectLatestConnection(run.model, { status: '✓' });
      await dashboard.snapCard('#conn-history-card', 'taze host: Bağlantı Geçmişi');
    });
  } finally {
    // Ana host'un değerlerine dönüş: bundan sonraki senaryolar ana host'la çalışır.
    const restore = clientBuild.buildAndInstall(device, env.PROPS_FILE);
    await attachText(
      testInfo,
      'Ana host değerleriyle yeniden derleme ve kurulum',
      `$ ./gradlew assembleDebug -PsampleHostProps=${env.PROPS_FILE}\n${restore}`,
    );
    app.launchFresh();
    const status = await app.waitReady();
    await app.snap('ana host değerleriyle geri yüklendi');
    expect(status).toMatch(/Hazır — config v\d+/);
    expect(SampleApp.hostVersion(status, env.TARGET_HOST)).not.toBeNull();
    if (dashboard) await dashboard.page.close();
  }
});
