// E3: sunucunun kendi TLS sertifikası (bootstrap) dashboard'dan yenilenir.
// APK'ya gömülü eski pin'lerle derlenmiş uygulama artık bağlanamaz
// ("başlatılamadı"); client-config.sh yeni değerleri verir, uygulama yeniden
// derlenip kurulunca bağlantı döner. Sunucunun IP'si/sertifikası değişen
// kurulumların akışı.
//
// Geçici test sunucusunda çalışır: ana host'un sertifikası değişirse
// telefondaki bütün senaryolar kırılır. Senaryo sonunda uygulama ana host
// değerleriyle yeniden derlenip kurulur.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const clientBuild = require('../lib/clientBuild');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const UPLOAD_JKS = 'e03-upload-source.jks';

const FRESH_PROPS = path.join(env.LOCAL_DIR, 'host-fresh.properties');

function writeFreshProps() {
  const out = fresh.run('./scripts/client-config.sh', env.CLIENT_CONFIG_ARGS);
  fs.writeFileSync(FRESH_PROPS, out);
  return out;
}

test('Sunucu: sunucu sertifikası (bootstrap) yenilenince eski APK bağlanamıyor, yeni değerlerle derlenen APK bağlanıyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(25 * 60 * 1000);
  await fresh.ensure();

  const app = new SampleApp(device, testInfo);
  const dashboard = await fresh.openDashboard(browser, testInfo);
  let oldPins;

  try {
    await test.step('Terminal: uygulama geçici test sunucusunun şu anki değerleriyle derlenip kurulur', async () => {
      const props = writeFreshProps();
      oldPins = fresh.hostPins().slice(0, 2);
      clientBuild.buildAndInstall(device, FRESH_PROPS);
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('eski sertifikayla bağlı');
      await attachText(
        testInfo,
        'Uygulamaya gömülen ilk pin\'ler (bootstrap)',
        `${props.split('\n').filter((l) => l.startsWith('host.bootstrapPin')).join('\n')}\n\nTelefon: ${status.split('\n')[0]}`,
      );
      expect(status).toMatch(/Hazır — config v\d+/);
    });

    await test.step('Web: "Bootstrap Pin" sekmesinde "Sertifikayı Yenile" ile sunucu sertifikası yenilenir', async () => {
      const before = await dashboard.bootstrapPins('default-tls');
      await dashboard.snap('yenilemeden önceki pin\'ler');
      const toast = await dashboard.regenerateBootstrapCert('default-tls');
      const after = await dashboard.bootstrapPins('default-tls');
      await dashboard.snap('yenilemeden sonraki pin\'ler');
      await attachText(
        testInfo,
        'Sunucu TLS pin\'leri: önce / sonra',
        [
          `önce : ${before.join('\n       ')}`,
          `sonra: ${after.join('\n       ')}`,
          `onay : ${dashboard.lastDialog()}`,
          `toast: ${toast}`,
        ].join('\n'),
      );
      expect(after[0]).not.toBe(before[0]);
      expect(before.slice(0, 2)).toEqual(oldPins);
    });

    await test.step('Terminal: sunucu yeniden başlatılır, host\'un pin kaydı güncellenir', async () => {
      // /server-tls-pins/regenerate "restartRequired: true" döner: dinleyiciler
      // eski sertifikayı belleğinde tutuyor.
      fresh.compose(['restart']);
      await fresh.waitHealthy();
      const provision = fresh.provision();
      await attachText(testInfo, 'docker compose restart + scripts/provision.sh', provision);
      expect(provision).toContain(env.LAN_IP);
    });

    await test.step('Mobil: eski pin\'lerle derlenmiş uygulama başlatılamıyor', async () => {
      app.launchFresh();
      const status = await app.waitInitFailed();
      await app.snap('uygulamaya gömülü eski pin tutmuyor: başlatılamadı');
      await attachText(testInfo, 'Telefondaki hata', status);
      expect(status).toContain('başlatılamadı');
    });

    await test.step('Terminal: client-config.sh yeni değerleri verir, uygulama yeniden derlenir', async () => {
      const props = writeFreshProps();
      const newPins = fresh.hostPins().slice(0, 2);
      await attachText(
        testInfo,
        'scripts/client-config.sh --properties (yenilemeden sonra)',
        [
          props.split('\n').filter((l) => l.startsWith('host.bootstrapPin')).join('\n'),
          '',
          `eski pin'ler: ${oldPins.join(', ')}`,
        ].join('\n'),
      );
      expect(newPins).not.toEqual(oldPins);
      clientBuild.buildAndInstall(device, FRESH_PROPS);
    });

    await test.step('Mobil: yeni değerlerle bağlantı döner', async () => {
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('yeni sertifikayla bağlı');
      expect(status).toMatch(/Hazır — config v\d+/);
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
    });

    await test.step('Web: "Bootstrap Pin" sekmesi → "JKS Yükle": sunucu sertifikası dışarıda üretilmiş bir anahtar çiftine geçer', async () => {
      // Dışarıda (container'daki keytool ile) üretilmiş, SAN'ında LAN IP olan
      // bir anahtar çifti; server-tls-pins/upload ile bootstrap sertifikası
      // yapılır. Sunucu dosyayı kendi KEYSTORE_PASSWORD'üyle yeniden yazar.
      fs.rmSync(path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), { force: true });
      fresh.compose([
        'exec', '-T', 'pinvault-host', 'keytool', '-genkeypair',
        '-alias', 'server', '-keyalg', 'RSA', '-keysize', '2048',
        '-dname', `CN=${env.LAN_IP}, O=PinVault E2E`,
        '-ext', `SAN=ip:${env.LAN_IP},dns:localhost`,
        '-validity', '365',
        '-keystore', `/data/certs/${UPLOAD_JKS}`,
        '-storepass', 'changeit', '-keypass', 'changeit',
      ]);
      const pem = fresh.compose([
        'exec', '-T', 'pinvault-host', 'keytool', '-exportcert', '-rfc',
        '-alias', 'server', '-keystore', `/data/certs/${UPLOAD_JKS}`, '-storepass', 'changeit',
      ]);
      const uploadedPin = hostApi.spkiPin(new crypto.X509Certificate(pem).raw);
      const pinsBefore = fresh.hostPins().slice(0, 2);

      const res = await dashboard.uploadBootstrapCert('default-tls', path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), 'changeit');
      const pinsAfter = fresh.hostPins();
      await dashboard.snap('"Bootstrap Pin" sekmesi: yüklenen JKS\'nin pin\'leri');

      // Dinleyiciler eski sertifikayı bellekte tutuyor (restartRequired).
      fresh.compose(['restart']);
      await fresh.waitHealthy();
      const provision = fresh.provision();
      const served = await hostApi.servedPin(fresh.PORTS.https, 'localhost');
      await attachText(
        testInfo,
        'POST /api/v1/server-tls-pins/upload ("Bootstrap Pin" sekmesi → "JKS Yükle")',
        [
          `yüklenen JKS: ${UPLOAD_JKS} (keytool, RSA 2048, SAN=ip:${env.LAN_IP},dns:localhost, parola changeit)`,
          `yüklenen sertifikanın SPKI pin'i: ${uploadedPin}`,
          '',
          `HTTP ${res.status} ${res.body}`,
          '',
          `data/certs/demo-server.pins önce : ${pinsBefore.join(' | ')}`,
          `data/certs/demo-server.pins sonra: ${pinsAfter.join(' | ')}`,
          `docker compose restart + provision.sh → :${fresh.PORTS.https} sunulan sertifikanın pin'i: ${served}`,
          '',
          'Yedek pin, sunucunun yüklenen sertifika için ürettiği ve sakladığı yedek anahtara',
          'ait (data/certs/demo-server.backup.jks); "Yedek Anahtara Geç" onunla çalışır.',
          'Telefon tarafı yukarıdaki "Sertifikayı Yenile" akışıyla aynı: yeni pin\'lerle',
          'yeniden derlenmeyen APK bağlanamaz.',
        ].join('\n'),
      );
      expect(res.json.uploaded).toBe(true);
      expect(res.json.restartRequired).toBe(true);
      expect(res.json.primaryPin).toBe(uploadedPin);
      expect(pinsAfter[0]).toBe(uploadedPin);
      expect(pinsAfter[1]).not.toBe(uploadedPin);
      expect(pinsAfter[0]).not.toBe(pinsBefore[0]);
      expect(served).toBe(uploadedPin);
      expect(provision).toContain(env.LAN_IP);
    });
  } finally {
    fs.rmSync(path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), { force: true });
    const restore = clientBuild.buildAndInstall(device, env.PROPS_FILE);
    await attachText(testInfo, 'Ana host değerleriyle yeniden derleme ve kurulum', restore);
    app.launchFresh();
    const status = await app.waitReady();
    await app.snap('ana host değerleriyle geri yüklendi');
    expect(status).toMatch(/Hazır — config v\d+/);
    await dashboard.page.close();
  }
});
