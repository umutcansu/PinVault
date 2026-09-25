// C11 — Sunucunun `X-Vault-Encryption` başlığı uygulamadaki yapılandırmayı eziyor.
//
// `sample-flags` uygulamada şifrelemesiz (VaultFileEncryption.PLAIN) tanımlı.
// Dosyanın şifrelemesi dashboard'dan `end_to_end` yapılınca kütüphane kendi
// yapılandırmasına değil sunucunun başlığına bakıyor (VaultFileRouter: önce
// response.encryption, yoksa file.encryption) ve şifreli içeriği cihaz anahtarıyla
// çözüyor. İçerik imzası düz metin üzerinden olduğu için doğrulama da geçiyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, describeResponse, hexdump } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

test('Vault şifreleme başlığı: sunucu end_to_end derse kütüphane uygulama ayarına bakmıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const body = `basligin-ezdigi-icerik-${Date.now()}`;
  let version;
  let deviceId;

  try {
    await test.step('Web: dosya şifresiz (plain) yüklenir', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, body, { policy: 'public', encryption: 'plain' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları — plain');
      await attachText(
        testInfo,
        'Uygulamadaki tanım (App.java)',
        [
          `.vaultFile("${KEY}") { endpoint(…) }  → encryption çağrısı YOK`,
          'Varsayılan: VaultFileEncryption.PLAIN. Uygulama bu dosyayı şifresiz bekliyor.',
        ].join('\n'),
      );
    });

    await test.step('Mobil: dosya şifresiz iniyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      await app.snap('plain: dosya indi');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain(body);
    });

    await test.step('Web: şifreleme dashboard\'dan end_to_end yapılır (içerik değişmeden)', async () => {
      const summary = await dashboard.setVaultPolicy(env.VAULT_API, KEY, {
        policy: 'public',
        encryption: 'end_to_end',
      });
      await dashboard.snapVaultPolicy('şifreleme end_to_end yapıldı');
      expect(summary).toEqual({ policy: 'public', encryption: 'end_to_end' });
      await dashboard.openConfigApiTab(env.VAULT_API, 'vault');
      const cells = await dashboard.vaultRowCells(KEY);
      expect(Number(cells.version.replace(/\D/g, ''))).toBe(version);
      expect(cells.encryption).toContain('end_to_end');
    });

    await test.step('Ağ trafiği: aynı dosya artık cihaza özel şifrelenmiş geliyor', async () => {
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      const wrappedKeyLength = res.body.readUInt32BE(0);
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — şifreleme değiştikten sonra`,
        [
          describeResponse(res, { bodyHex: true, maxBody: 64 }),
          '',
          hexdump(res.body, 64),
          '',
          `şifrelenmiş AES anahtarı: ${wrappedKeyLength} bayt (RSA-2048 OAEP)`,
          `düz metin gövdede geçiyor mu: ${res.body.includes(Buffer.from(body, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
        ].join('\n'),
      );
      expect(res.headers['x-vault-encryption']).toBe('end_to_end');
      expect(wrappedKeyLength).toBe(256);
      expect(res.body.includes(Buffer.from(body, 'utf8'))).toBe(false);
    });

    await test.step('Mobil: kütüphane sunucunun başlığına göre davranıp dosyayı çözüyor', async () => {
      device.clearLogcat();
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('başlık end_to_end: içerik çözüldü');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain('imza doğrulandı');
      expect(status).toContain(body);
      const log = device.logcat({ match: /Vault (fetch|file)/ });
      await attachText(
        testInfo,
        'Telefon sonucu ve cihaz günlüğü',
        [
          status,
          '',
          log || '(ilgili satır yok)',
          '',
          'VaultFileRouter:',
          '  VaultFileEncryption.entries.find { it.name.equals(response.encryption, …) }',
          '      ?: file.encryption',
          'Yani önce sunucunun X-Vault-Encryption başlığına bakılıyor; uygulamadaki ayar yalnızca yedek.',
          '',
          'Doğrulama: içerik imzası DÜZ METİN üzerinden atıldığı için, çözme başarısız',
          'olsaydı imza da tutmaz ve dosya kaydedilmezdi. "imza doğrulandı" satırı',
          'çözmenin gerçekten yapıldığını gösteriyor.',
        ].join('\n'),
      );
      expect(log).toContain('encryption=end_to_end');
    });

    await test.step('Sunucu: davranışın değerlendirmesi', async () => {
      await attachText(
        testInfo,
        'Sunucu başlığının uygulamadaki ayarın önüne geçmesi — değerlendirme',
        [
          'Artı: operatör dosyanın şifrelemesini uygulamayı yeniden derlemeden',
          'değiştirebiliyor; eski sürüm uygulamalar da yeni modu anlıyor. Uygulamadaki',
          '`encryption(...)` çağrısı bir beklenti değil, yalnızca sunucu başlık',
          'vermezse kullanılacak yedek.',
          '',
          'Eksi: ters yön için bir kontrol yok — sunucu end_to_end bir dosyayı plain',
          'olarak gönderse kütüphane sorgusuz kabul eder. Burada gerçek bir gizlilik',
          'kaybı yok (düz metin zaten sunucuda, bağlantı da TLS ve pin ile korunuyor),',
          'ama uygulama "bu dosya uçtan uca şifreli gelmeli" diye bir kural koyamıyor.',
          '',
          'Öneri: VaultFileConfig\'e `requireEncryption(...)` gibi katı bir seçenek',
          'eklensin: açıkken sunucunun başlığı beklenenden zayıfsa sonuç',
          'VaultFileResult.Failed olsun. Bugünkü davranış varsayılan kalabilir.',
        ].join('\n'),
      );
    });

    await test.step('Web: şifreleme plain\'e geri alınır, telefon yine iniyor', async () => {
      const summary = await dashboard.setVaultPolicy(env.VAULT_API, KEY, { policy: 'public', encryption: 'plain' });
      await dashboard.snapVaultPolicy('şifreleme plain\'e döndü');
      expect(summary.encryption).toBe('plain');
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      expect(res.headers['x-vault-encryption']).toBe('plain');
      expect(res.body.toString('utf8')).toBe(body);
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('plain\'e dönüldü: dosya indi');
      expect(status).toContain(body);
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
