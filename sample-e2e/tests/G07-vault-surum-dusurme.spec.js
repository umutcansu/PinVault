// G07 — Vault dosyasının sürümünü geri almak.
//
// Saldırganın amacı cihazdaki güncel dosyayı ESKİ bir sürümle değiştirmek
// (geri çekilmiş bir bayrak dosyası, iptal edilmiş bir kural seti, eski bir ML
// modeli…). İki kontrol var ve ikisi de bu senaryoda ayrı ayrı gösteriliyor:
//
//   1. Sürüm, imzalanan standart metnin içinde
//      (pinvault-vault-file:v1:<anahtar>:<sürüm>:<sha256>). Yalnızca
//      X-Vault-Version başlığını değiştirmek imzayı da bozuyor → dosya
//      reddediliyor. Yani sürüm "örtük olarak imzalı".
//   2. Saldırgan sunucunun imzalama anahtarına sahip olsa bile (test gereği
//      saldırgan proxy eski sürüm için YENİDEN imzalıyor) kütüphanenin ayrı
//      sürüm kontrolü devrede: saklı sürümden düşük bir sürüm kaydedilmiyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

test('Saldırı: vault dosyası eski sürüme döndürülür → telefon önce imza, sonra sürüm kontrolüyle reddediyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  const stamp = Date.now();
  const contents = { v1: `birinci-${stamp}`, v2: `ikinci-${stamp}`, v3: `ucuncu-${stamp}` };
  let mitm;
  let v1;
  let v2;
  let v3;

  try {
    await test.step('Web: dosyanın ilk sürümü yayınlanır', async () => {
      v1 = await dashboard.uploadVaultText(env.VAULT_API, KEY, contents.v1, { policy: 'public', encryption: 'plain' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `vault dosyası v${v1}`);
    });

    await test.step('Saldırgan+Web: saldırgan sunucunun kendi anahtarıyla araya girer ama henüz bir şey değiştirmiyor; ikinci sürüm yayınlanır, telefon iki sürümü de alıyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      await app.waitReady();
      await app.openVault();
      expect(await app.fetchVault(KEY)).toContain(`${KEY} v${v1} indirildi`);

      v2 = await dashboard.uploadVaultText(env.VAULT_API, KEY, contents.v2, { policy: 'public', encryption: 'plain' });
      expect(v2).toBe(v1 + 1);
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap(`saldırgan henüz bir şey değiştirmiyor: ${KEY} v${v2} indi`);
      expect(status).toContain(`${KEY} v${v2} indirildi`);
      expect(status).toContain(contents.v2);
    });

    await test.step('Web: üçüncü sürüm yayınlanır (saldırgan bunu eski sürüm gibi gösterecek)', async () => {
      v3 = await dashboard.uploadVaultText(env.VAULT_API, KEY, contents.v3, { policy: 'public', encryption: 'plain' });
      expect(v3).toBe(v2 + 1);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `vault dosyası v${v3}`);
    });

    await test.step('Saldırgan: yalnızca X-Vault-Version başlığını eski sürüme çeker → imza artık tutmuyor, telefon reddediyor', async () => {
      const wire = {};
      const downgrade = proxy.downgradeVaultVersion(v1);
      mitm.setMutate((answer) => {
        const mutated = downgrade(answer);
        if (mutated !== answer && answer.headers['x-vault-signature']) {
          wire.version = answer.headers['x-vault-version'];
          wire.fakeVersion = mutated.headers['x-vault-version'];
          wire.signature = answer.headers['x-vault-signature'];
        }
        return mutated;
      });

      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('sürüm başlığı değişti: imza tutmuyor');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toMatch(/signature verification FAILED/i);

      await attachText(
        testInfo,
        `Saldırganın yaptığı değişiklik: yalnızca sürüm başlığı (GET /api/v1/vault/${KEY})`,
        [
          `X-Vault-Version  : ${wire.version} → ${wire.fakeVersion}`,
          `X-Vault-Signature: ${redact(wire.signature, 22)} (dokunulmadı)`,
          'gövde            : sunucunun gönderdiği düz metin (dokunulmadı)',
          '',
          'İmzalanan standart metin sürümü içerdiği için başlığı değiştirmek imzayı da',
          `bozuyor: telefon "pinvault-vault-file:v1:${KEY}:${wire.fakeVersion}:…"`,
          `hesaplıyor, sunucu ise "…:${wire.version}:…" imzalamıştı.`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
        ].join('\n'),
      );
      expect(wire.fakeVersion).toBe(String(v1));
    });

    await test.step('Saldırgan: eski sürümü YENİDEN İMZALAR → bu kez imza tutuyor ama sürüm kontrolü reddediyor', async () => {
      const wire = {};
      const downgrade = proxy.downgradeVaultVersion(v1, proxy.vaultSigner());
      mitm.setMutate((answer) => {
        const mutated = downgrade(answer);
        if (mutated !== answer && answer.headers['x-vault-signature']) {
          wire.version = answer.headers['x-vault-version'];
          wire.fakeVersion = mutated.headers['x-vault-version'];
          wire.before = answer.headers['x-vault-signature'];
          wire.after = mutated.headers['x-vault-signature'];
        }
        return mutated;
      });

      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('yeniden imzalanmış eski sürüm: reddedildi');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toMatch(/downgrade rejected/i);

      await attachText(
        testInfo,
        'Saldırganın yaptığı değişiklik: sürüm geri alındı ve yeniden imzalandı',
        [
          `X-Vault-Version  : ${wire.version} → ${wire.fakeVersion}`,
          `X-Vault-Signature: ${redact(wire.before, 18)} → ${redact(wire.after, 18)}`,
          '                   (test gereği sunucunun imzalama anahtarıyla, eski sürüm için yeniden imzalandı)',
          '',
          `cihazdaki saklı sürüm      : v${v2}`,
          `saldırganın söylediği sürüm: v${v1}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
          '',
          'İmza artık geçerli; reddin nedeni imza değil, sürümün saklı sürümden',
          'düşük olması (VaultFileRouter\'daki eski sürüm kontrolü).',
        ].join('\n'),
      );
      expect(wire.after).not.toBe(wire.before);
    });

    await test.step('Mobil: saklı sürüm ve içerik korunuyor', async () => {
      const info = await app.vaultInfo(KEY);
      await app.snap('geri döndürme denemelerinden sonra: v' + v2 + ' yerinde');
      expect(info).toContain(`sürüm: v${v2}`);
      expect(info).toContain(contents.v2);
      expect(info).not.toContain(contents.v1);
      await attachText(
        testInfo,
        'Cihazdaki dosya (uygulamanın Bilgi düğmesi — sunucuya gidilmedi)',
        [
          info.split('\n').slice(0, 5).join('\n'),
          '',
          `sunucudaki güncel sürüm: v${v3}`,
          `saldırganın iki denemesinden sonra cihazdaki sürüm: v${v2}`,
        ].join('\n'),
      );
    });

    await test.step('Saldırgan: değiştirmeyi bırakınca güncel sürüm iniyor', async () => {
      mitm.setMutate(null);
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap(`saldırgan değiştirmeyi bıraktı: ${KEY} v${v3} indi`);
      expect(status).toContain(`${KEY} v${v3} indirildi`);
      expect(status).toContain(contents.v3);
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
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
