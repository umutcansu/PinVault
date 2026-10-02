// G03 — Eski ama geçerli imzalı config'in tekrar gönderilmesi (replay).
//
// İmza doğrulaması tek başına yetmiyor: saldırgan sunucunun DAHA ÖNCE
// gönderdiği, imzası kusursuz bir yanıtı saklayıp tekrar gönderebilir. Böylece
// geri alınmış (ör. sızmış bir sertifikaya ait) pin'leri cihaza yeniden
// yutturmaya çalışır.
//
// Sunucu her imzalı config'i `issuedAt` (Unix epoch ms) ile damgalıyor;
// kütüphane uyguladığı son config'in `issuedAt`ını saklıyor. Daha ESKİ bir
// `issuedAt` taşıyan yanıt reddedilir. Birebir aynı imzalı yanıtın yeniden
// gelmesi ise saldırı değil: değişiklik kaydedilir kaydedilmez bir kez imzalayan
// (HSM/KMS, imza önbelleği, CDN) sunucular tam olarak bunu yapar; kütüphane
// bunu "zaten güncel" sayar ve hiçbir şeyi değiştirmez. Senaryo ikisini de ağ
// trafiğinde gösteriyor:
//
//   1. saldırgan proxy trafiği değiştirmeden geçirirken telefonun uyguladığı
//      yanıtı kaydeder,
//   2. sunucuda pin sürümü ilerletilir,
//   3. kaydedilen yanıt aynen yeniden verilir → telefon "güncel" der, değişmez,
//   4. telefon yeni sürümü alır,
//   5. kaydedilen ESKİ yanıt tekrar gönderilir → telefon reddeder,
//   6. saklı (yeni) config bozulmaz.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const iso = (ms) => new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');

test('Saldırı: aynı imzalı yanıt tekrar gelirse "güncel" sayılıyor; daha eski bir imzalı config tekrar gönderilirse eski tarihli olduğu için reddediliyor', async ({
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

    await test.step('Saldırgan: araya girer, trafiği değiştirmeden geçirir ve telefonun uyguladığı imzalı yanıtı kaydeder', async () => {
      mitm = await proxy.start({ identity: 'trusted', mutate: proxy.capture(captured) });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      // Uygulama verisi silinerek açılır: saklanan issuedAt tam da az sonra
      // tekrar oynatacağımız yanıtın issuedAt'i olsun.
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: config indi ve uygulandı');
      expect(captured.length, 'vekil imzalı config yanıtını görmeli').toBeGreaterThan(0);
      // İlk yanıt uygulanan yanıttır; arkasından WorkManager'ın ilk turu da bir
      // istek atıyor ama o "AlreadyCurrent" dönüp kaydedilmiyor, yani saklanan
      // issuedAt ilk yanıtınki olarak kalıyor.
      appliedRaw = captured[0].body;
      applied = JSON.parse(appliedRaw.toString('utf8'));
      const payload = JSON.parse(applied.payload);
      await attachText(
        testInfo,
        'Saldırganın kaydettiği yanıt (telefonun uyguladığı config)',
        [
          `sürüm      : v${payload.version}`,
          `issuedAt   : ${payload.issuedAt}  (${iso(payload.issuedAt)})`,
          `expiresAt  : ${payload.expiresAt}  (${iso(payload.expiresAt)})`,
          `signature  : ${redact(applied.signature, 20)}`,
          `hedef host : ${TARGET_HOST} → v${(payload.pins.find((p) => p.hostname === TARGET_HOST) || {}).version}`,
          '',
          `telefonun ekranı: ${ready.split('\n')[0]}`,
          '',
          'Kütüphane bu yanıtı uygularken issuedAt değerini (yanıtın üretildiği an)',
          'de şifreli config deposuna yazdı (CertificateConfigStore.KEY_ISSUED_AT).',
        ].join('\n'),
      );
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).toBe(v0);
    });

    await test.step('Web: sunucuda pin sürümü bir artırılır (yeni sürüm, daha yeni issuedAt)', async () => {
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      await dashboard.snapHostSummary(`sunucuda güncel: v${v0 + 1}`);
    });

    await test.step('Saldırgan: telefonun zaten uyguladığı imzalı yanıtı birebir tekrar gönderir → telefon "güncel" diyor, hiçbir şey değişmiyor', async () => {
      mitm.setMutate(proxy.replayConfig(appliedRaw));
      const status = await app.refreshConfig();
      await app.snap('birebir aynı imzalı yanıt geldi: config güncel');
      expect(status).toContain('Config güncel');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0);
      const old = JSON.parse(applied.payload);
      await attachText(
        testInfo,
        'Birebir aynı imzalı yanıt: saldırı sayılmıyor, "zaten güncel"',
        [
          `tekrar gelen yanıtın issuedAt'i   : ${old.issuedAt}  (${iso(old.issuedAt)})`,
          'telefonun sakladığı issuedAt      : aynısı (telefon bu yanıtı zaten uygulamıştı)',
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
          '',
          'Aynı issuedAt + aynı host/sürüm/pin → AlreadyCurrent: hiçbir şey yazılmadı,',
          'force bayrağı yeniden uygulanmadı. Değişiklik kaydedilir kaydedilmez bir kez',
          'imzalayan bir sunucu (HSM/KMS, CONFIG_SIGNATURE_CACHE, CDN) tam olarak bunu gönderir.',
        ].join('\n'),
      );
    });

    await test.step('Saldırgan: trafiği yine değiştirmeden geçirir → telefon sunucunun yeni sürümünü alıyor', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap(`yeni config uygulandı: v${v0 + 1}`);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Saldırgan: kaydettiği ESKİ yanıtı tekrar gönderir → telefon daha eski tarihli olduğu için reddediyor', async () => {
      mitm.setMutate(proxy.replayConfig(appliedRaw));
      const status = await app.refreshConfig();
      await app.snap('eski yanıt tekrar gönderildi: config yenilenemedi');
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/replay rejected/i);

      const current = await hostApi.signedConfig();
      const old = JSON.parse(applied.payload);
      await attachText(
        testInfo,
        'Saldırganın tekrar gönderdiği eski yanıt ve sunucunun güncel yanıtı',
        [
          'TEKRAR GÖNDERİLEN (saldırganın kaydettiği eski yanıt)',
          `  sürüm    : v${old.version}`,
          `  issuedAt : ${old.issuedAt}  (${iso(old.issuedAt)})`,
          `  imza     : ${redact(applied.signature, 20)} — kriptografik olarak GEÇERLİ`,
          '',
          'SUNUCUNUN ŞU AN VERDİĞİ',
          `  sürüm    : v${current.config.version}`,
          `  issuedAt : ${current.config.issuedAt}  (${iso(current.config.issuedAt)})`,
          `  imza     : ${redact(current.signature, 20)}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'İmza doğrulaması bu saldırıyı yakalayamaz (imza gerçekten sunucunun).',
          'Yakalayan şey issuedAt\'in geriye gidememesi: telefon v' + (v0 + 1) + "'i uyguladıktan sonra",
          'ondan daha eski tarihli (issuedAt) bir config kabul edilmez.',
        ].join('\n'),
      );
      expect(current.config.issuedAt).toBeGreaterThan(old.issuedAt);
    });

    await test.step('Mobil: saklı (yeni) config bozulmadı, pinli istek sürüyor', async () => {
      const status = app.status();
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.snap(`eski yanıt reddedildikten sonra: v${v0 + 1} ile bağlantı sürüyor`);
      mitm.setMutate(null);
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      expect(await app.waitReady()).toContain('Hazır — config v');
      await app.snap('saldırgan proxy kapandı: doğrudan sunucuyla Hazır');
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
