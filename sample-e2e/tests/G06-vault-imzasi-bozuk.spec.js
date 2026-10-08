// G06 — Vault dosyasının içerik imzası bozulur ya da silinirse.
//
// Vault dosyaları da Config API'nin ECDSA anahtarıyla imzalanıyor; imza
// `X-Vault-Signature` başlığında ve imzalanan standart metin (anahtar + sürüm +
// düz metnin SHA-256'sı) üzerinde. Cihaz imzayı dosyayı SAKLAMADAN ÖNCE
// doğruluyor (VaultFileRouter).
//
// İki değiştirme gösteriliyor:
//   • imzanın son baytı bozulur → "signature verification FAILED",
//   • imza başlığı tamamen silinir → "no X-Vault-Signature … refusing
//     (fail-closed)" — başlık yoksa dosya kabul edilmiyor, "imzasız da olur"
//     diye bir yol yok.
//
// İkisinde de saklı sürüm ve içerik değişmiyor: cihaz eski, doğrulanmış
// kopyayla çalışmaya devam ediyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

test('Saldırı: vault dosyasının imzası bozulur ya da silinir → telefon dosyayı kaydetmiyor, eski sürümle devam ediyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  const stamp = Date.now();
  const first = `guvenli-icerik-${stamp}`;
  const second = `yeni-icerik-${stamp}`;
  const wire = {};
  let mitm;
  let v1;
  let v2;

  try {
    await test.step('Web: vault dosyası yüklenir (public, plain)', async () => {
      v1 = await dashboard.uploadVaultText(env.VAULT_API, KEY, first, { policy: 'public', encryption: 'plain' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `vault dosyası v${v1}`);
    });

    await test.step('Saldırgan: sunucunun kendi anahtarıyla araya girer, henüz bir şey değiştirmiyor; dosya bu yoldan iniyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      await app.waitReady();
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap(`saldırgan henüz bir şey değiştirmiyor: ${KEY} v${v1} indi`);
      expect(status).toContain(`${KEY} v${v1} indirildi`);
      expect(status).toContain('imza doğrulandı');
      expect(status).toContain(first);
    });

    await test.step('Web: dosyanın yeni sürümü yayınlanır (telefon henüz almadı)', async () => {
      v2 = await dashboard.uploadVaultText(env.VAULT_API, KEY, second, { policy: 'public', encryption: 'plain' });
      expect(v2).toBe(v1 + 1);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `vault dosyası v${v2}`);
    });

    await test.step('Saldırgan: imzanın son baytını değiştirir → telefon dosyayı kaydetmiyor', async () => {
      const breaker = proxy.breakVaultSignature({ remove: false });
      mitm.setMutate((answer) => {
        const mutated = breaker(answer);
        if (mutated !== answer && answer.headers['x-vault-signature']) {
          wire.before = answer.headers['x-vault-signature'];
          wire.after = mutated.headers['x-vault-signature'];
          wire.version = answer.headers['x-vault-version'];
          wire.length = answer.body.length;
        }
        return mutated;
      });

      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('bozuk vault imzası: indirilemedi');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toMatch(/signature verification FAILED/i);

      await attachText(
        testInfo,
        `Saldırganın yaptığı değişiklik (GET /api/v1/vault/${KEY})`,
        [
          `X-Vault-Version : ${wire.version}`,
          `gövde           : ${wire.length} bayt (düz metin, dokunulmadı)`,
          '',
          `sunucunun imzası: ${redact(wire.before, 22)}`,
          `telefonun aldığı: ${redact(wire.after, 22)}`,
          `son bayt        : 0x${Buffer.from(wire.before, 'base64').slice(-1).toString('hex')}` +
            ` → 0x${Buffer.from(wire.after, 'base64').slice(-1).toString('hex')}`,
          '',
          'İmzalanan standart metin: pinvault-vault-file:v1:<anahtar>:<sürüm>:<sha256(düz metin)>',
          '— yani imza dosya adını (anahtar), sürümü ve içeriği birbirine bağlıyor.',
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
        ].join('\n'),
      );
      expect(wire.before).not.toBe(wire.after);
    });

    await test.step('Mobil: saklı sürüm ve içerik değişmedi', async () => {
      const info = await app.vaultInfo(KEY);
      await app.snap('bozuk imza sonrası: eski sürüm yerinde');
      expect(info).toContain(`sürüm: v${v1}`);
      expect(info).toContain(first);
      expect(info).not.toContain(second);

      await app.backToMain();
      await app.openStorage();
      const storage = await app.storageText();
      await attachText(
        testInfo,
        'Cihazdaki vault deposu (Depolama ekranı)',
        [
          storage
            .split('\n')
            .filter((line, i, all) => /pinvault_secure_vault_files/.test(line) || /pinvault_secure_vault_files/.test(all[i - 1] || '') || /pinvault_secure_vault_files/.test(all[i - 2] || ''))
            .join('\n'),
          '',
          `sunucudaki sürüm    : v${v2}`,
          `cihazdaki sürüm     : v${v1}  (uygulamanın "Bilgi" düğmesi: ${info.split('\n')[1]})`,
          `cihazdaki içerik    : v${v1}'in metni (yeni metin cihazda yok)`,
          '',
          'sample-flags ENCRYPTED_PREFS ile saklanıyor: hem içerik hem sürüm',
          `kaydı ${device.prefsFileName('pinvault_secure_vault_files')} içinde şifreli; dosyada anahtar adı bile`,
          'düz geçmiyor. Sürümü bu yüzden uygulamanın kendi "Bilgi" ekranından',
          'okuyoruz.',
          '',
          'Doğrulama kaydetmeden önce yapılıyor: imza tutmayınca storage.save()',
          'hiç çağrılmıyor, yani yarım/değiştirilmiş içerik diske yazılmıyor.',
        ].join('\n'),
      );
      expect(storage).toContain(device.prefsFileName('pinvault_secure_vault_files'));
      await app.backToMain();
    });

    await test.step('Saldırgan: imza başlığını tamamen siler → telefon imzasız dosyayı da reddediyor', async () => {
      const remover = proxy.breakVaultSignature({ remove: true });
      const removed = {};
      mitm.setMutate((answer) => {
        const mutated = remover(answer);
        if (mutated !== answer && answer.headers['x-vault-signature']) {
          removed.before = answer.headers['x-vault-signature'];
          removed.after = mutated.headers['x-vault-signature'];
        }
        return mutated;
      });

      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('imza başlığı silinmiş: indirilemedi');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toMatch(/X-Vault-Signature/i);

      const info = await app.vaultInfo(KEY);
      await attachText(
        testInfo,
        'İmza başlığı silinince',
        [
          `sunucunun gönderdiği X-Vault-Signature: ${redact(removed.before, 22)}`,
          `telefonun aldığı                      : ${removed.after === undefined ? '(yok)' : removed.after}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
          '',
          'Cihazdaki dosya:',
          info.split('\n').slice(0, 3).join('\n'),
          '',
          'Config API bloğunda signaturePublicKey tanımlı olduğu için imzasız dosya kabul',
          'edilmiyor. İmzasız çalışmak ancak allowUnsigned() ile mümkün ve o da',
          'üretim için değil.',
        ].join('\n'),
      );
      expect(removed.after).toBeUndefined();
      expect(info).toContain(`sürüm: v${v1}`);
    });

    await test.step('Saldırgan: değiştirmeyi bırakınca yeni sürüm sorunsuz iniyor', async () => {
      mitm.setMutate(null);
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap(`saldırgan değiştirmeyi bıraktı: ${KEY} v${v2} indi`);
      expect(status).toContain(`${KEY} v${v2} indirildi`);
      expect(status).toContain(second);
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
