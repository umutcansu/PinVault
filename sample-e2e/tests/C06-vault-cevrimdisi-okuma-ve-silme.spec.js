// C06 — Çevrimdışı okuma ve silme.
//
// İndirilen vault dosyası cihazda şifreli duruyor: host kapalıyken "Bilgi"
// (PinVault.hasFile / fileVersion / loadFileAsString) içeriği sunucuya hiç
// gitmeden veriyor, aynı anda "İndir" ağ hatasıyla düşüyor. "Sil"
// (PinVault.clearFile) hem şifreli dosyayı hem Keystore anahtarını hem de
// şifreli tercih kaydını kaldırıyor; dosya yeniden indirilince içerik tam
// geliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const MODEL = env.VAULT_KEYS.model;
const FLAGS = env.VAULT_KEYS.flags;
const ENC_FILE = `files/vault_files/${MODEL}.enc`;

test('Vault çevrimdışı: host kapalıyken saklı içerik okunuyor, "Sil" geride iz bırakmıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const stamp = Date.now();
  const modelBody = `model-icerigi-${stamp}`;
  const flagsBody = `{"bayrak":"acik","kosu":"${stamp}"}`;
  let modelVersion;
  let flagsVersion;
  let hostDown = false;

  try {
    await test.step('Web: iki dosya yüklenir', async () => {
      modelVersion = await dashboard.uploadVaultText(env.VAULT_API, MODEL, modelBody, { policy: 'public' });
      flagsVersion = await dashboard.uploadVaultText(env.VAULT_API, FLAGS, flagsBody, { policy: 'public' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları');
    });

    await test.step('Mobil: iki dosya da indirilir', async () => {
      await app.openVault();
      expect(await app.fetchVault(MODEL)).toContain(`${MODEL} v${modelVersion} indirildi`);
      expect(await app.fetchVault(FLAGS)).toContain(`${FLAGS} v${flagsVersion} indirildi`);
      await app.snap('iki dosya indirildi');
    });

    await test.step('Sunucu: host durduruluyor', async () => {
      await hostControl.stop();
      hostDown = true;
      const healthy = await hostApi.isHealthy();
      await attachText(
        testInfo,
        'docker stop pinvault-host',
        [
          `sağlık kontrolü yanıt veriyor mu: ${healthy ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Bundan sonraki telefon adımlarında sunucuya hiçbir istek gidemez.',
        ].join('\n'),
      );
      expect(healthy).toBe(false);
    });

    await test.step('Mobil: "Bilgi" saklı içeriği sunucuya gitmeden veriyor', async () => {
      const modelInfo = await app.vaultInfo(MODEL);
      await app.snap('host kapalı — dosya deposundan okundu');
      expect(modelInfo).toContain('saklı: var');
      expect(modelInfo).toContain(`sürüm: v${modelVersion}`);
      expect(modelInfo).toContain(modelBody);
      expect(modelInfo).toContain('sunucuya gidilmedi');

      const flagsInfo = await app.vaultInfo(FLAGS);
      await app.snap('host kapalı — şifreli SharedPreferences\'tan okundu');
      expect(flagsInfo).toContain(`sürüm: v${flagsVersion}`);
      expect(flagsInfo).toContain(flagsBody);
      await attachText(
        testInfo,
        'Host kapalıyken "Bilgi" çıktıları',
        [`${MODEL} (ENCRYPTED_FILE):`, modelInfo, '', `${FLAGS} (ENCRYPTED_PREFS):`, flagsInfo].join('\n'),
      );
    });

    await test.step('Mobil: aynı anda "İndir" ağ hatası yüzünden başarısız oluyor', async () => {
      const status = await app.fetchVault(MODEL);
      await app.snap('host kapalı — indirme başarısız');
      expect(status).toContain(`${MODEL} indirilemedi`);
      await attachText(
        testInfo,
        'Host kapalıyken indirme denemesi',
        [status, '', 'Okuma cihazın içinde yapılıyor, indirme ağa çıkıyor: ikisi birbirinden ayrı.'].join('\n'),
      );
    });

    await test.step('Sunucu: host geri açılıyor', async () => {
      await hostControl.start();
      hostDown = false;
      await attachText(testInfo, 'docker start pinvault-host', await hostControl.describeState());
      expect(await hostApi.isHealthy()).toBe(true);
    });

    await test.step('Mobil: "Sil" sonrası "Bilgi" boş', async () => {
      expect(await app.vaultClear(MODEL)).toContain(`${MODEL} silindi`);
      await app.snap(`${MODEL} silindi`);
      const info = await app.vaultInfo(MODEL);
      expect(info).toContain('saklı: yok');
      expect(info).toContain('sürüm: v0');
      expect(info).not.toContain(modelBody);
      expect(await app.vaultClear(FLAGS)).toContain(`${FLAGS} silindi`);
      const flagsInfo = await app.vaultInfo(FLAGS);
      expect(flagsInfo).toContain('saklı: yok');
      await app.snap('iki dosya da silindi');
      await attachText(testInfo, 'Silme sonrası "Bilgi"', [info, '', flagsInfo].join('\n'));
    });

    await test.step('Cihaz: .enc dosyası ve SharedPreferences kaydı gerçekten silindi', async () => {
      const listing = device.appFiles(env.APP_ID, 'files/vault_files');
      const versions = device.appFileText(env.APP_ID, 'shared_prefs/pinvault_vault_file_versions.xml');
      const prefs = device.appFileText(env.APP_ID, 'shared_prefs/pinvault_vault_files.xml');
      // Geriye yalnızca iki Tink keyset'i kalmalı (ad ve değer şifrelemesi);
      // hiçbir vault_data_/vault_ver_ kaydı kalmamalı.
      const prefNames = [...prefs.matchAll(/<string name="([^"]+)"/g)].map((m) => m[1]);
      const dataNames = prefNames.filter((n) => !n.startsWith('__androidx_security_crypto'));
      await attachText(
        testInfo,
        `adb shell run-as ${env.APP_ID} — silme sonrası depo`,
        [
          `$ ls -la files/vault_files`,
          listing.trim(),
          '',
          '$ cat shared_prefs/pinvault_vault_file_versions.xml',
          versions.trim(),
          '',
          `${MODEL}.enc dosyası duruyor mu: ${listing.includes(`${MODEL}.enc`) ? 'EVET ✗' : 'hayır ✓'}`,
          `sürüm kaydı duruyor mu: ${versions.includes(`vault_file_ver_${MODEL}`) ? 'EVET ✗' : 'hayır ✓'}`,
          '$ cat shared_prefs/pinvault_vault_files.xml (kayıt adları)',
          prefNames.map((n) => `  ${n.slice(0, 60)}${n.length > 60 ? '…' : ''}`).join('\n'),
          `veri kaydı kaldı mı: ${dataNames.length === 0 ? 'hayır ✓ (yalnızca iki Tink keyset\'i)' : `EVET ✗ (${dataNames.length})`}`,
          '',
          'clearFile ayrıca Android Keystore\'daki pinvault_vault_' + MODEL + ' anahtarını',
          'da siliyor — dosya bir yerden geri gelse bile çözülemez.',
        ].join('\n'),
      );
      expect(listing).not.toContain(`${MODEL}.enc`);
      expect(versions).not.toContain(`vault_file_ver_${MODEL}`);
      expect(dataNames).toHaveLength(0);

      await app.backToMain();
      await app.openStorage();
      const storage = await app.refreshStorage();
      await app.snap('Depolama ekranı — silme sonrası');
      expect(storage).toContain('(dosya yok)');
      expect(storage).not.toContain(`pinvault_vault_${MODEL}`);
      await app.backToMain();
    });

    await test.step('Mobil: yeniden indirilince içerik tam geliyor', async () => {
      await app.openVault();
      const status = await app.fetchVault(MODEL);
      await app.snap('silinen dosya yeniden indirildi');
      expect(status).toContain(`${MODEL} v${modelVersion} indirildi`);
      expect(status).toContain(modelBody);
      const blob = device.appFileBytes(env.APP_ID, ENC_FILE);
      await attachText(
        testInfo,
        'Yeniden indirme sonrası .enc dosyası',
        [
          `${blob.length} bayt, [iv_len=${blob[0]}]`,
          `düz metin dosyada geçiyor mu: ${blob.includes(Buffer.from(modelBody, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Yeni Keystore anahtarı üretildi; sürüm yine v' + modelVersion + '.',
        ].join('\n'),
      );
      expect(blob.includes(Buffer.from(modelBody, 'utf8'))).toBe(false);
    });
  } finally {
    if (hostDown) await hostControl.start().catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, MODEL).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, FLAGS).catch(() => {});
  }
});
