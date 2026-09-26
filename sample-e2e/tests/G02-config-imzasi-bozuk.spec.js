// G02 — Ağ trafiğindeki imzalı config'in imzası bozulursa.
//
// Bu kez saldırgan proxy host'un KENDİ TLS anahtarıyla dinliyor (export-server-key.sh),
// yani pin tutuyor ve el sıkışma geçiyor. Pinlemenin ötesindeki katman
// sınanıyor: config gövdesi ECDSA ile imzalı ve imza APK'ya gömülü public
// key'le doğrulanıyor. İmzanın tek baytını bozmak yetiyor —
//
//   • telefon yeni config'i uygulamıyor ("Config yenilenemedi"),
//   • saklı config ve onunla kurulan pinli bağlantı bozulmuyor,
//   • saldırgan değiştirmeyi bırakınca bekleyen sürüm sorunsuz iniyor.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test("Saldırı: config'in imzası bozulursa telefon onu uygulamıyor, önceki config'le çalışmaya devam ediyor", async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  const backupPin = hostApi.randomPin();
  const wire = { before: null, after: null };
  let mitm;
  let v0;

  /** İmzanın son baytını bozar ve kablodaki iki gövdeyi kanıt için saklar. */
  const tamperSignature = (answer) => {
    const mutated = proxy.breakConfigSignature(answer);
    if (mutated !== answer) {
      wire.before = answer.body.toString('utf8');
      wire.after = mutated.body.toString('utf8');
    }
    return mutated;
  };

  try {
    await test.step('Web: sunucuda yeni bir pin sürümü yayınlanır (telefon henüz almadı)', async () => {
      await dashboard.openHost(TARGET_HOST);
      v0 = await dashboard.version();
      expect(SampleApp.hostVersion(app.status(), TARGET_HOST)).toBe(v0);
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      await dashboard.snapHostSummary(`sunucuda bekleyen sürüm v${v0 + 1}`);
    });

    await test.step('Saldırgan: sunucunun kendi anahtarıyla araya girer; pin tutuyor ve yanıtlar şimdilik değiştirilmeden geçiyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      // Yeni bağlantı kurulsun diye uygulama yeniden açılır (saklı config
      // korunur); OkHttp'nin havuzundaki canlı bağlantı DNAT'ı atlardı.
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: pin tutuyor, config indi');
      await attachText(
        testInfo,
        'Saldırganın kimliği (test gereği sunucunun gerçek TLS anahtarını kullanıyor)',
        [
          `saldırganın pin'i   : ${proxy.certPin('trusted')}`,
          `host'un pin dosyası : ${hostApi.hostPins().join(', ')}`,
          'eşleşme             : var ✓ — TLS katmanı bu kez itiraz etmiyor',
          '',
          'Bundan sonrası pinlemenin ÖTESİNDEKİ savunma: config gövdesi ECDSA ile',
          'imzalı ve imza APK\'ya gömülü public key ile doğrulanıyor.',
          '',
          `telefonun ekranı: ${ready.split('\n')[0]}`,
          `hedef host sürümü: v${SampleApp.hostVersion(ready, TARGET_HOST)}`,
        ].join('\n'),
      );
      // Saydam vekil üzerinden bekleyen sürüm indi.
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Web: bir sürüm daha yayınlanır (saldırganın bozacağı sürüm bu)', async () => {
      await dashboard.setPins(TARGET_HOST, run.goodPins);
      await expect.poll(() => dashboard.version()).toBe(v0 + 2);
      await dashboard.snapHostSummary(`saldırganın bozacağı sürüm v${v0 + 2}`);
    });

    await test.step('Saldırgan: imzanın son baytını değiştirir → telefon config\'i reddediyor', async () => {
      mitm.setMutate(tamperSignature);
      const status = await app.refreshConfig();
      await app.snap('bozuk imza: config yenilenemedi');
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/signature verification failed/i);

      const before = JSON.parse(wire.before);
      const after = JSON.parse(wire.after);
      await attachText(
        testInfo,
        'Saldırganın yaptığı değişiklik (GET /api/v1/certificate-config)',
        [
          'SUNUCUNUN GÖNDERDİĞİ',
          `  payload  : ${before.payload.length} bayt`,
          `  signature: ${redact(before.signature, 24)}`,
          '',
          'TELEFONUN ALDIĞI (saldırgan değiştirdi)',
          `  payload  : ${after.payload.length} bayt (aynı: ${before.payload === after.payload ? 'evet' : 'HAYIR'})`,
          `  signature: ${redact(after.signature, 24)}`,
          '',
          `imzanın son baytı: 0x${Buffer.from(before.signature, 'base64').slice(-1).toString('hex')}` +
            ` → 0x${Buffer.from(after.signature, 'base64').slice(-1).toString('hex')}`,
          '',
          'Telefonun ekranı:',
          status.split('\n').slice(0, 3).join('\n'),
        ].join('\n'),
      );
      expect(before.payload).toBe(after.payload);
      expect(before.signature).not.toBe(after.signature);
    });

    await test.step('Mobil: saklı config bozulmadı — eski sürüm yerinde, pinli istek sürüyor', async () => {
      const status = app.status();
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');

      await app.backToMain();
      await app.openStorage();
      const storage = await app.storageText();
      await app.snap('bozuk imza sonrası depolama');
      await attachText(
        testInfo,
        'Cihazdaki config deposu (Depolama ekranı)',
        [
          storage.split('\n').filter((line) => /pinvault_secure_config|düz metin|Mod:/.test(line)).join('\n'),
          '',
          `telefondaki hedef sürümü: v${SampleApp.hostVersion(status, TARGET_HOST)}`,
          `sunucudaki sürüm        : v${v0 + 2}`,
          '',
          'Reddedilen config kaydedilmiyor: SSLCertificateUpdater imza hatasını',
          'yakalayıp UpdateResult.Failed dönüyor, configStore.save() hiç çağrılmıyor.',
        ].join('\n'),
      );
      expect(storage).toContain('pinvault_secure_config.xml');
      await app.backToMain();
    });

    await test.step('Saldırgan: değiştirmeyi bırakır → bekleyen sürüm sorunsuz iniyor', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap(`saldırgan değiştirmeyi bıraktı: config v${v0 + 2}`);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 2);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuya', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan proxy kapandı: doğrudan sunucuyla Hazır');
      expect(ready).toContain('Hazır — config v');
      expect(device.rootShell('iptables -t nat -S OUTPUT')).not.toContain(`--dport ${env.CONFIG_API_PORT}`);
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
