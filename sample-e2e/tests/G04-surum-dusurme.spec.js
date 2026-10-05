// G04 — Eski sürüme geri döndürme: imza geçerli, sürüm eski.
//
// G03'teki "eski yanıtı tekrar gönderme"nin daha inceltilmiş hali. Bu kez
// saldırgan payload'ı GERÇEKTEN değiştiriyor (per-host sürümleri bir geri
// alıyor) ve — test gereği — sunucunun imzalama anahtarıyla YENİDEN İMZALIYOR.
// Yani:
//
//   • TLS pin'i tutuyor (host'un kendi anahtarıyla dinleniyor),
//   • ECDSA imzası geçerli (harness imzayı yerel olarak da doğruluyor),
//   • issuedAt taze (yanıt sunucudan yeni geldi, eski yanıtın tekrarı değil),
//   • tek anormallik: per-host sürümler cihazdakinden düşük.
//
// Kütüphanenin üçüncü kontrolü tam da bunu yakalıyor: SSLCertificateUpdater
// gelen her pin girdisinin sürümünü saklı sürümle karşılaştırıyor ve sürüm
// geriye gidiyorsa config'i hiç uygulamıyor. Gerçek hayattaki karşılığı: geri
// çekilmiş (ör. sızmış anahtara ait) pin'lerin cihaza yeniden yutturulması.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');
const crypto = require('crypto');
const signingKeyFile = require('../lib/signingKeyFile');

/** Payload'ı host'un imzalama public key'i ile doğrular (kanıt paneli için). */
function verifyWithHostKey(payload, signature) {
  // Dosya diskte şifreli (ENCv1:); public yarısı .env'deki parolayla açılarak okunur.
  const pub = signingKeyFile.publicKeyBase64(env.SIGNING_KEY_FILE, env.SIGNING_KEY_PASSWORD);
  const key = crypto.createPublicKey({ key: Buffer.from(pub, 'base64'), format: 'der', type: 'spki' });
  return crypto.createVerify('SHA256').update(payload).end().verify(key, Buffer.from(signature, 'base64'));
}

const versionsOf = (payload) => payload.pins.map((p) => `${p.hostname}=v${p.version}`).join(', ');

test("Saldırı: config'in sürümü geri alınıp yeniden imzalanır → imza geçerli olsa da telefon eski sürüme dönmeyi reddediyor", async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  const wire = { before: null, after: null };
  let mitm;
  let v0;

  try {
    await test.step('Web: hedef host\'un güncel sürümü okunur', async () => {
      await dashboard.openHost(TARGET_HOST);
      v0 = await dashboard.version();
      await dashboard.snapHostSummary(`sunucudaki sürüm: v${v0}`);
    });

    await test.step('Saldırgan: sunucunun kendi anahtarıyla araya girer, henüz bir şey değiştirmiyor → telefon normal çalışıyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: telefon Hazır');
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).toBe(v0);
    });

    await test.step("Saldırgan: sürüm numaralarını bir geri alır ve config'i YENİDEN İMZALAR → telefon reddediyor", async () => {
      const downgrade = proxy.downgradeConfig(1, proxy.hostSigner());
      mitm.setMutate((answer) => {
        const mutated = downgrade(answer);
        if (mutated !== answer) {
          wire.before = answer.body.toString('utf8');
          wire.after = mutated.body.toString('utf8');
        }
        return mutated;
      });

      const status = await app.refreshConfig();
      await app.snap('eski sürüme geri döndürme: config yenilenemedi');
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/downgrade rejected/i);

      const before = JSON.parse(wire.before);
      const after = JSON.parse(wire.after);
      const beforePayload = JSON.parse(before.payload);
      const afterPayload = JSON.parse(after.payload);
      await attachText(
        testInfo,
        'Saldırganın yaptığı değişiklik (GET /api/v1/certificate-config)',
        [
          'SUNUCUNUN GÖNDERDİĞİ',
          `  version   : ${beforePayload.version}`,
          `  per-host  : ${versionsOf(beforePayload)}`,
          `  issuedAt  : ${beforePayload.issuedAt}`,
          `  imza geçerli mi: ${verifyWithHostKey(before.payload, before.signature) ? 'evet' : 'hayır'}`,
          '',
          'TELEFONUN ALDIĞI (saldırgan değiştirdi ve yeniden imzaladı)',
          `  version   : ${afterPayload.version}`,
          `  per-host  : ${versionsOf(afterPayload)}`,
          `  issuedAt  : ${afterPayload.issuedAt} (değişmedi — eski yanıtın tekrarı değil, taze yanıt)`,
          `  imza geçerli mi: ${verifyWithHostKey(after.payload, after.signature) ? 'evet ✓ (test gereği sunucunun imzalama anahtarıyla yeniden imzalandı)' : 'hayır'}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Pin listesi aynı kaldı; değişen tek şey sürüm numaraları. İmza ve tarih',
          'kontrollerini geçen bu yanıtı sürüm kontrolü durduruyor (sürüm geriye gidemez).',
        ].join('\n'),
      );
      expect(verifyWithHostKey(after.payload, after.signature)).toBe(true);
      expect(afterPayload.issuedAt).toBe(beforePayload.issuedAt);
      expect(afterPayload.version).toBe(beforePayload.version - 1);
    });

    await test.step('Mobil: saklı config bozulmadı — sürüm aynı, pinli istek sürüyor', async () => {
      const status = app.status();
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.snap('geri döndürme denemesinden sonra: config v' + v0 + ' yerinde');
      await attachText(
        testInfo,
        'Sunucu ile telefon aynı sürümde',
        [
          `sunucudaki hedef sürümü : v${(await hostApi.signedConfig()).config.pins.find((p) => p.hostname === TARGET_HOST).version}`,
          `telefondaki hedef sürümü: v${SampleApp.hostVersion(status, TARGET_HOST)}`,
          '',
          'Reddedilen config kaydedilmedi; depo ve pinli istemci dokunulmadan kaldı.',
        ].join('\n'),
      );
    });

    await test.step('Saldırgan: değiştirmeyi bırakınca config yenileme yine çalışıyor', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap('saldırgan değiştirmeyi bıraktı: config güncel');
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
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
