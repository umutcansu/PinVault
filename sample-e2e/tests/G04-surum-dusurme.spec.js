// G04 — Sürüm düşürme: imza geçerli, sürüm eski.
//
// G03'teki replay'in daha inceltilmiş hali. Bu kez saldırgan payload'ı
// GERÇEKTEN değiştiriyor (per-host sürümleri bir geri alıyor) ve — laboratuvar
// koşulu olarak — sunucunun imzalama anahtarıyla YENİDEN İMZALIYOR. Yani:
//
//   • TLS pin'i tutuyor (host'un kendi anahtarıyla dinleniyor),
//   • ECDSA imzası geçerli (harness imzayı yerel olarak da doğruluyor),
//   • issuedAt taze (yanıt sunucudan yeni geldi, replay değil),
//   • tek anormallik: per-host sürümler cihazdakinden düşük.
//
// Kütüphanenin üçüncü kapısı tam da bunu kapatıyor: SSLCertificateUpdater
// gelen her pin girdisinin sürümünü saklı sürümle karşılaştırıyor ve gerileme
// varsa config'i hiç uygulamıyor. Gerçek hayattaki karşılığı: geri çekilmiş
// (ör. sızmış anahtara ait) pin'lerin cihaza yeniden yutturulması.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');
const crypto = require('crypto');
const fs = require('fs');

/** Payload'ı host'un imzalama public key'i ile doğrular (kanıt paneli için). */
function verifyWithHostKey(payload, signature) {
  const pub = fs.readFileSync(env.SIGNING_KEY_FILE, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)[1];
  const key = crypto.createPublicKey({ key: Buffer.from(pub, 'base64'), format: 'der', type: 'spki' });
  return crypto.createVerify('SHA256').update(payload).end().verify(key, Buffer.from(signature, 'base64'));
}

const versionsOf = (payload) => payload.pins.map((p) => `${p.hostname}=v${p.version}`).join(', ');

test('Kablo: imzası geçerli ama sürümü düşük config → telefon sürüm gerilemesini reddediyor', async ({
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

    await test.step("Vekil: host'un anahtarıyla saydam araya girilir → telefon normal çalışıyor", async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saydam vekil: telefon Hazır');
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).toBe(v0);
    });

    await test.step('Vekil: sürümler bir geri alınıp YENİDEN İMZALANIR → telefon reddediyor', async () => {
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
      await app.snap('sürüm düşürme: config yenilenemedi');
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/downgrade rejected/i);

      const before = JSON.parse(wire.before);
      const after = JSON.parse(wire.after);
      const beforePayload = JSON.parse(before.payload);
      const afterPayload = JSON.parse(after.payload);
      await attachText(
        testInfo,
        'Kablodaki fark (GET /api/v1/certificate-config)',
        [
          'SUNUCUNUN GÖNDERDİĞİ',
          `  version   : ${beforePayload.version}`,
          `  per-host  : ${versionsOf(beforePayload)}`,
          `  issuedAt  : ${beforePayload.issuedAt}`,
          `  imza geçerli mi: ${verifyWithHostKey(before.payload, before.signature) ? 'evet' : 'hayır'}`,
          '',
          'TELEFONUN ALDIĞI (vekil değiştirdi ve yeniden imzaladı)',
          `  version   : ${afterPayload.version}`,
          `  per-host  : ${versionsOf(afterPayload)}`,
          `  issuedAt  : ${afterPayload.issuedAt} (değişmedi — replay değil, taze yanıt)`,
          `  imza geçerli mi: ${verifyWithHostKey(after.payload, after.signature) ? 'evet ✓ (laboratuvar: host anahtarıyla yeniden imzalandı)' : 'hayır'}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Pin listesi aynı kaldı; değişen tek şey sürüm numaraları. İmza ve',
          'tazelik kapılarını geçen bu yanıtı sürüm tekdüzeliği durduruyor.',
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
      await app.snap('sürüm düşürme sonrası: config v' + v0 + ' yerinde');
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

    await test.step('Vekil: kurcalama kalkınca yenileme yine çalışıyor', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap('kurcalama kalktı: config güncel');
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
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
