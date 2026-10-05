// E10: sertifikanın saklı yedek anahtarına geçiş. Sunucu bir sertifika
// ürettiğinde iki anahtar üretir: biri sertifikayı sunar, diğerinin (yedek)
// pin'i listeye girer ve anahtarın kendisi `<id>.backup.jks` dosyasında
// saklanır. "Yedek Anahtara Geç" sertifikayı bu yedek anahtarla yeniden üretir
// ve yeni bir yedek hazırlar. Telefon yedeğin pin'ini zaten tuttuğu için
// bağlantı kesilmez:
//   - config sunucusunun kendi sertifikasında uygulamaya gömülü ilk pin'ler
//     (bootstrap) geçerli kalır; uygulama yeniden derlenmeden bağlanır (E03'te
//     sertifika yenilenince eski uygulama başlatılamıyor),
//   - hedef host'ta pin uyuşmazlığı olmadan, config'i yenilemeden bağlanır
//     (A20'de istek önce uyuşmazlığa düşüp kurtarmayla tekrarlanıyor).
// Düzeltmeden önce yedek anahtar üretilip atılıyordu: yayımlanan yedek pin'i
// hiçbir sertifika sunamıyordu.
//
// Geçici test sunucusunda çalışır (bkz. E03). Sunucunun sertifikası yedek
// anahtarlar saklanmadan önce üretilmişse (eski bir veri dizini) senaryo önce
// geçişin reddedildiğini gösterir, sonra sertifikayı bir kez yeniden üretir.
// Sonunda uygulama ana host değerleriyle yeniden derlenip kurulur.
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

const MOCK = env.MOCK_TLS_HOST;
const FRESH_PROPS = path.join(env.LOCAL_DIR, 'host-fresh.properties');

function writeFreshProps() {
  const out = fresh.run('./scripts/client-config.sh', env.CLIENT_CONFIG_ARGS);
  fs.writeFileSync(FRESH_PROPS, out);
  return out;
}

const BACKUP_FILE = path.join(fresh.DIR, 'data/certs/demo-server.backup.jks');

/** Container'da saklanan yedek anahtarın pin'i (keystore parolası panele girmez). */
function storedBackupPin(id) {
  const pem = fresh.compose([
    'exec', '-T', 'pinvault-host', 'keytool', '-exportcert', '-rfc',
    '-alias', 'backup', '-keystore', `/data/certs/${id}.backup.jks`, '-storepass', fresh.KEYSTORE_PASSWORD,
  ]);
  return hostApi.spkiPin(new crypto.X509Certificate(pem).raw);
}

test('Sunucu: sertifika saklı yedek anahtara geçince aynı uygulama bağlanmaya devam ediyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(25 * 60 * 1000);
  await fresh.ensure();

  const app = new SampleApp(device, testInfo);
  const dashboard = await fresh.openDashboard(browser, testInfo);
  let apkPins;

  try {
    if (!fs.existsSync(BACKUP_FILE)) {
      await test.step('Web: sunucu sertifikasının saklı yedeği yok → "Yedek Anahtara Geç" reddediliyor; sertifika bir kez yeniden üretilir', async () => {
        const before = await dashboard.bootstrapPins('default-tls');
        const refusal = await dashboard.rotateBootstrapToBackup('default-tls');
        await dashboard.snap('saklı yedek anahtar yok: geçiş reddedildi');
        const unchanged = await dashboard.bootstrapPins('default-tls');
        await expect(dashboard.page.locator('.toast')).toHaveCount(0, { timeout: 15_000 });
        const toast = await dashboard.regenerateBootstrapCert('default-tls');
        const after = await dashboard.bootstrapPins('default-tls');
        await dashboard.snap('sertifika yeniden üretildi: yedek anahtar saklandı');
        fresh.compose(['restart']);
        await fresh.waitHealthy();
        const provision = fresh.provision();
        await attachText(
          testInfo,
          'Yedek anahtarı saklanmamış sertifika',
          [
            `önce : ${before.join(' | ')}`,
            `"Yedek Anahtara Geç" → ${refusal}`,
            `pin'ler değişmedi: ${unchanged.join(' | ')}`,
            '',
            `"Sertifikayı Yenile" → ${toast}`,
            `sonra: ${after.join(' | ')}`,
            `data/certs/demo-server.backup.jks: ${fs.existsSync(BACKUP_FILE) ? 'var' : 'yok'}`,
            'docker compose restart + scripts/provision.sh',
            '',
            'Bu sertifika, sunucu yedek anahtarları saklamaya başlamadan önce üretilmiş.',
            'Yedek ancak sertifika sunucuda yeniden üretilince oluşuyor.',
            'Config sunucusunda bu bir kez daha uygulama güncellemesi demek; bu senaryoda',
            'uygulama zaten bir sonraki adımda yeni değerlerle derleniyor.',
          ].join('\n'),
        );
        expect(refusal).toContain('saklanmış yedek anahtar yok');
        expect(unchanged).toEqual(before);
        expect(after[0]).not.toBe(before[0]);
        expect(fs.existsSync(BACKUP_FILE)).toBe(true);
        expect(provision).toContain(env.LAN_IP);
      });
    }

    await test.step('Terminal: uygulama geçici test sunucusunun değerleriyle derlenip kurulur; yedek anahtar sunucuda saklı', async () => {
      const props = writeFreshProps();
      apkPins = fresh.hostPins().slice(0, 2);
      const backupPin = storedBackupPin('demo-server');
      const certFiles = fs.readdirSync(path.join(fresh.DIR, 'data/certs')).filter((f) => f.startsWith('demo-server'));
      clientBuild.buildAndInstall(device, FRESH_PROPS);
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('uygulama geçici sunucuya bağlı');
      await attachText(
        testInfo,
        'Uygulamaya gömülen ilk pin\'ler ve sunucuda saklanan yedek anahtar',
        [
          props.split('\n').filter((l) => l.startsWith('host.bootstrapPin')).join('\n'),
          '',
          `data/certs: ${certFiles.join(', ')}`,
          `demo-server.backup.jks içindeki anahtarın pin'i: ${backupPin}`,
          '(keytool -exportcert -alias backup; keystore parolası KEYSTORE_PASSWORD)',
          '',
          'Yayımlanan yedek pin, sunucuda saklanan bir anahtara ait. Düzeltmeden önce',
          'bu anahtar üretilip atılıyordu; yedek pin\'i hiçbir sertifika sunamazdı.',
          '',
          `Telefon: ${status.split('\n')[0]}`,
        ].join('\n'),
      );
      expect(backupPin).toBe(apkPins[1]);
      expect(status).toMatch(/Hazır — config v\d+/);
    });

    await test.step('Web: "Bootstrap Pin" sekmesi → "Yedek Anahtara Geç"', async () => {
      const before = await dashboard.bootstrapPins('default-tls');
      await dashboard.snap('geçişten önceki pin\'ler');
      const toast = await dashboard.rotateBootstrapToBackup('default-tls');
      const after = await dashboard.bootstrapPins('default-tls');
      await dashboard.snap('geçişten sonraki pin\'ler: eski yedek artık birincil');
      await attachText(
        testInfo,
        'Sunucu TLS pin\'leri: önce / sonra',
        [
          `önce : ${before.join('\n       ')}`,
          `sonra: ${after.join('\n       ')}`,
          `onay : ${dashboard.lastDialog()}`,
          `toast: ${toast}`,
          '',
          'Eski yedek birincil oldu, yeni bir yedek hazırlandı; eski birincil listeden çıktı.',
        ].join('\n'),
      );
      expect(before.slice(0, 2)).toEqual(apkPins);
      expect(after[0]).toBe(before[1]);
      expect(after[1]).not.toBe(before[0]);
      expect(after[1]).not.toBe(before[1]);
      expect(storedBackupPin('demo-server')).toBe(after[1]);
    });

    await test.step('Terminal: sunucu yeniden başlatılır; artık yedek anahtarı sunuyor', async () => {
      // rotate-to-backup "restartRequired: true" döner: dinleyiciler eski
      // sertifikayı belleğinde tutuyor.
      fresh.compose(['restart']);
      await fresh.waitHealthy();
      const provision = fresh.provision();
      const served = await hostApi.servedPin(fresh.PORTS.https, 'localhost');
      const pinsFile = fresh.hostPins();
      await attachText(
        testInfo,
        'docker compose restart + scripts/provision.sh',
        [
          `:${fresh.PORTS.https} sunulan sertifikanın pin'i: ${served}`,
          `data/certs/demo-server.pins: ${pinsFile.join(' | ')}`,
          '',
          `uygulamaya gömülü pin'ler: ${apkPins.join(' | ')}`,
          'Sunulan anahtar, uygulamanın yedek olarak taşıdığı pin\'e ait.',
        ].join('\n'),
      );
      expect(served).toBe(apkPins[1]);
      expect(pinsFile[0]).toBe(apkPins[1]);
      expect(provision).toContain(env.LAN_IP);
    });

    let v0;
    let configVersion;
    let mockPins;

    await test.step('Mobil: aynı uygulama (yeniden derlenmeden) sıfırdan başlatılıyor ve bağlanıyor', async () => {
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('yeniden derlenmeyen uygulama bağlandı');
      await attachText(
        testInfo,
        'Telefondaki durum (uygulama verisi silinip açıldı)',
        [
          status,
          '',
          'Uygulama config sunucusuna gömülü ilk pin\'lerle bağlandı: sunucu, yedek pin\'in',
          'anahtarını sunuyor. E03\'te sertifika yenilenince aynı adımda "başlatılamadı" görülüyor.',
        ].join('\n'),
      );
      expect(status).toMatch(/Hazır — config v\d+/);
      configVersion = Number(/config v(\d+)/.exec(status)[1]);
      v0 = SampleApp.hostVersion(status, MOCK);
      expect(v0).not.toBeNull();
    });

    await test.step('Mobil: telefon mock TLS host\'a (test için kurulan hedef sunucu) bağlanıyor', async () => {
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap(`mock TLS host bağlantısı (pin v${v0})`);
      expect(result).toContain('host bağlantısı başarılı');
      await app.backToMain();
    });

    await test.step('Web: mock host → "Yedek Anahtara Geç"; pin\'ler değişir, sürüm artar', async () => {
      // Bootstrap sekmesi adımları Config API ağacını aç/kapa yaptığı için host
      // kapsamın ağacından açılır.
      await dashboard.openHostIn('default-tls', MOCK);
      const oldPins = await dashboard.viewedPins(MOCK);
      const toast = await dashboard.rotateHostToBackup(MOCK, 'default-tls');
      await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(v0 + 1);
      mockPins = await dashboard.viewedPins(MOCK);
      await dashboard.snapHostSummary(`${MOCK} pin'leri, v${v0 + 1}`);
      await expect(dashboard.page.locator('#pin-history-card tbody tr').first()).toContainText('cert_rotated_to_backup');
      await dashboard.snapCard('#pin-history-card', 'pin geçmişi: cert_rotated_to_backup');
      await attachText(
        testInfo,
        `${MOCK}: yedek anahtara geçildi`,
        [
          `onay : ${dashboard.lastDialog()}`,
          `toast: ${toast}`,
          '',
          `önceki pin'ler (v${v0}) : ${oldPins.join('\n                     ')}`,
          `yeni pin'ler  (v${v0 + 1}) : ${mockPins.join('\n                     ')}`,
          '',
          'POST /api/v1/hosts/<host>/rotate-to-backup: sertifika saklı yedek anahtarla',
          'yeniden üretilir, yeni bir yedek hazırlanır ve çalışan mock sunucu yeni',
          'keystore ile yeniden başlatılır.',
        ].join('\n'),
      );
      expect(mockPins[0]).toBe(oldPins[1]);
      expect(mockPins[1]).not.toBe(oldPins[0]);
    });

    await test.step('Mobil: config yenilenmeden bağlantı sürüyor, pin uyuşmazlığı yok', async () => {
      // Mock dinleyici yeni keystore ile ayağa kalksın ve emülatörün saati
      // yeni sertifikanın notBefore'unu geçsin (bkz. A20).
      let validFromMs = 0;
      await expect
        .poll(
          async () => {
            const cert = await hostApi.servedCert(fresh.PORTS.mockTls, MOCK).catch(() => null);
            validFromMs = cert ? cert.validFromMs : 0;
            return cert && cert.pin;
          },
          { timeout: 60_000, intervals: [500, 1000, 2000] },
        )
        .toBe(mockPins[0]);
      await expect
        .poll(() => device.epochMs(), { timeout: 30_000, intervals: [1000] })
        .toBeGreaterThan(validFromMs + 1000);

      await app.tapButton('clearLogButton');
      device.clearLogcat();
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap('yedek anahtara geçen host\'a bağlantı başarılı');
      await app.backToMain();
      // Olay satırındaki "pin vN" config'in genel sürümü (host'unki değil).
      const eventLog = await app.waitForEvent(`[✓] ${MOCK}  pin v${configVersion}  sha256/${mockPins[0].slice(0, 12)}`);
      await app.snap(`olay listesi: eski config (v${configVersion}), sunulan anahtar yedek pin`);
      const log = device.logcat({ tags: ['SSLCertificateUpdater', 'DynamicSSLManager', 'PinRecoveryInterceptor'] });
      await attachText(
        testInfo,
        'Telefondaki olay listesi ve kütüphane günlüğü (bağlantıdan önce temizlendi)',
        [
          eventLog,
          '',
          log,
          '',
          `Telefon hâlâ config v${configVersion} ile çalışıyor (${MOCK} pin v${v0}). Sunucunun sunduğu anahtar`,
          `(sha256/${mockPins[0].slice(0, 12)}…) o config'te yedek pin olarak zaten var: el sıkışma ilk denemede`,
          'geçti, pin uyuşmazlığı ve kurtarma olmadı, config yenilenmedi. A20\'de sertifika',
          'yenilenince istek önce "✗ UYUŞMAZLIK" ile düşüp kurtarmayla tekrarlanıyor.',
        ].join('\n'),
      );
      expect(result).toContain('host bağlantısı başarılı');
      expect(eventLog).not.toContain('UYUŞMAZLIK');
      expect(eventLog).not.toContain('[config]');
      expect(log).toContain(`Pin verified ✓ — host=${MOCK}`);
      expect(log).not.toMatch(/Pin mismatch|Config updated/);
    });

    await test.step('Mobil: config yenilenince yeni yedek pin telefona geliyor', async () => {
      const status = await app.refreshConfig();
      await app.snap(`mock host pin v${v0 + 1}`);
      await attachText(testInfo, 'Telefondaki durum kutusu (config yenilendikten sonra)', status);
      expect(status).toMatch(/Yeni config uygulandı/);
      expect(SampleApp.hostVersion(status, MOCK)).toBe(v0 + 1);
    });
  } finally {
    const restore = clientBuild.buildAndInstall(device, env.PROPS_FILE);
    await attachText(testInfo, 'Ana host değerleriyle yeniden derleme ve kurulum', restore);
    app.launchFresh();
    const status = await app.waitReady();
    await app.snap('ana host değerleriyle geri yüklendi');
    expect(status).toMatch(/Hazır — config v\d+/);
    await dashboard.page.close();
  }
});
