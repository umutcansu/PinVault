// G03 — Eski ama geçerli imzalı config'in tekrar oynatılması (replay).
//
// İmza doğrulaması tek başına yetmiyor: saldırgan sunucunun DAHA ÖNCE
// gönderdiği, imzası kusursuz bir yanıtı saklayıp tekrar oynatabilir. Böylece
// geri alınmış (ör. sızmış bir sertifikaya ait) pin'leri cihaza yeniden
// yutturmaya çalışır.
//
// Sunucu her imzalı config'i `issuedAt` (Unix epoch ms) ile damgalıyor;
// kütüphane uyguladığı son config'in `issuedAt`ını saklıyor ve gelen yanıtın
// kesinlikle daha yeni olmasını şart koşuyor (SSLCertificateUpdater). Bu
// senaryo tam olarak bunu kabloda gösteriyor:
//
//   1. vekil saydam geçerken telefonun uyguladığı yanıt yakalanır,
//   2. sunucuda pin sürümü ilerletilir,
//   3. yakalanan ESKİ yanıt aynen tekrar oynatılır → telefon reddeder,
//   4. kurcalama kalkınca güncel sürüm iner.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const iso = (ms) => new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');

test('Kablo: eski imzalı config tekrar oynatılınca telefon issuedAt gerilemesi diye reddediyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  const backupPin = hostApi.randomPin();
  const captured = [];
  let mitm;
  let applied; // telefonun uyguladığı (ve sonra tekrar oynatılacak) zarf
  let appliedRaw;
  let v0;

  try {
    await test.step('Web: hedef host\'un güncel sürümü okunur', async () => {
      await dashboard.openHost(TARGET_HOST);
      v0 = await dashboard.version();
      await dashboard.snap(`başlangıç: ${TARGET_HOST} v${v0} (tam sayfa)`);
    });

    await test.step('Vekil: saydam araya girilir ve telefonun uyguladığı imzalı yanıt yakalanır', async () => {
      mitm = await proxy.start({ identity: 'trusted', mutate: proxy.capture(captured) });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      // Uygulama verisi silinerek açılır: saklanan issuedAt tam da az sonra
      // tekrar oynatacağımız yanıtın issuedAt'i olsun.
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('saydam vekil: config indi ve uygulandı');
      expect(captured.length, 'vekil imzalı config yanıtını görmeli').toBeGreaterThan(0);
      // İlk yanıt uygulanan yanıttır; arkasından WorkManager'ın ilk turu da bir
      // istek atıyor ama o "AlreadyCurrent" dönüp kaydedilmiyor, yani saklanan
      // issuedAt ilk yanıtınki olarak kalıyor.
      appliedRaw = captured[0].body;
      applied = JSON.parse(appliedRaw.toString('utf8'));
      const payload = JSON.parse(applied.payload);
      await attachText(
        testInfo,
        'Yakalanan yanıt (telefonun uyguladığı config)',
        [
          `sürüm      : v${payload.version}`,
          `issuedAt   : ${payload.issuedAt}  (${iso(payload.issuedAt)})`,
          `expiresAt  : ${payload.expiresAt}  (${iso(payload.expiresAt)})`,
          `signature  : ${redact(applied.signature, 20)}`,
          `hedef host : ${TARGET_HOST} → v${(payload.pins.find((p) => p.hostname === TARGET_HOST) || {}).version}`,
          '',
          `telefonun ekranı: ${ready.split('\n')[0]}`,
          '',
          'Kütüphane bu yanıtı uygularken issuedAt değerini de şifreli config',
          'deposuna yazdı (CertificateConfigStore.KEY_ISSUED_AT).',
        ].join('\n'),
      );
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).toBe(v0);
    });

    await test.step('Web: sunucuda pin sürümü ilerletilir (yeni issuedAt, yeni sürüm)', async () => {
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      await dashboard.snapHostSummary(`sunucuda güncel: v${v0 + 1}`);
    });

    await test.step('Vekil: eski yanıt aynen tekrar oynatılır → telefon reddediyor', async () => {
      mitm.setMutate(proxy.replayConfig(appliedRaw));
      const status = await app.refreshConfig();
      await app.snap('replay: config yenilenemedi');
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/replay rejected/i);

      const current = await hostApi.signedConfig();
      const old = JSON.parse(applied.payload);
      await attachText(
        testInfo,
        'Kabloda ne var: tekrar oynatılan yanıt vs. sunucunun güncel yanıtı',
        [
          'TEKRAR OYNATILAN (vekilin sakladığı eski yanıt)',
          `  sürüm    : v${old.version}`,
          `  issuedAt : ${old.issuedAt}  (${iso(old.issuedAt)})`,
          `  imza     : ${redact(applied.signature, 20)} — kriptografik olarak GEÇERLİ`,
          '',
          'SUNUCUNUN ŞU AN VERDİĞİ',
          `  sürüm    : v${current.config.version}`,
          `  issuedAt : ${current.config.issuedAt}  (${iso(current.config.issuedAt)})`,
          `  imza     : ${redact(current.signature, 20)}`,
          '',
          `fark: ${current.config.issuedAt - old.issuedAt} ms daha yeni bir config bekleniyordu`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'İmza doğrulaması bu saldırıyı yakalayamaz (imza gerçekten sunucunun).',
          'Yakalayan şey issuedAt tekdüzeliği: gelen config, uygulanmış olandan',
          'kesinlikle daha yeni olmak zorunda.',
        ].join('\n'),
      );
      expect(current.config.issuedAt).toBeGreaterThan(old.issuedAt);
    });

    await test.step('Mobil: saklı config bozulmadı, pinli istek sürüyor', async () => {
      const status = app.status();
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.snap('replay sonrası: eski config ile bağlantı sürüyor');
    });

    await test.step('Vekil: kurcalama kalkınca güncel sürüm iniyor', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap(`replay kalktı: config v${v0 + 1}`);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      expect(await app.waitReady()).toContain('Hazır — config v');
      await app.snap('vekil kapandı: doğrudan sunucuyla Hazır');
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
