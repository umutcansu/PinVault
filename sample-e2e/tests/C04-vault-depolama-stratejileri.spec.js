// C04 — Vault depolama stratejileri: ENCRYPTED_FILE ve ENCRYPTED_PREFS.
//
// `sample-model` StorageStrategy.ENCRYPTED_FILE ile tanımlı: içerik
// files/vault_files/<anahtar>.enc dosyasına AES-256-GCM ile yazılıyor, anahtar
// Android Keystore'da (alias pinvault_vault_<anahtar>). Diğer dosyalar
// varsayılan ENCRYPTED_PREFS yolunu kullanıyor: içerik
// shared_prefs/pinvault_secure_vault_files.xml içinde duruyor (değer
// AES-256-GCM, kayıt adı HMAC; ikisinin anahtarı da Android Keystore'da).
//
// Kanıt: run-as dosya dökümü + Depolama ekranının telefon görüntüsü.
const { test, expect } = require('../lib/fixtures');
const { attachText, hexdump } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const MODEL = env.VAULT_KEYS.model;
const FLAGS = env.VAULT_KEYS.flags;
const ENC_FILE = `files/vault_files/${MODEL}.enc`;
const PREFS_FILE = 'shared_prefs/pinvault_secure_vault_files.xml';

test('Vault depolama: ENCRYPTED_FILE şifreli .enc dosyası, ENCRYPTED_PREFS şifreli tercih dosyası', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  const modelBody = `MODEL-GOVDESI-${Date.now()}-` + 'A'.repeat(200);
  const flagsBody = `{"bayrak":"acik","kosu":"${Date.now()}"}`;
  let modelVersion;
  let flagsVersion;

  try {
    await test.step('Web: uygulamada farklı saklama yöntemiyle tanımlı iki dosya yüklenir', async () => {
      modelVersion = await dashboard.uploadVaultText(env.VAULT_API, MODEL, modelBody, { policy: 'public' });
      flagsVersion = await dashboard.uploadVaultText(env.VAULT_API, FLAGS, flagsBody, { policy: 'public' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları');
      expect(modelVersion).toBeGreaterThan(0);
      expect(flagsVersion).toBeGreaterThan(0);
    });

    await test.step('Mobil: iki dosya da iniyor', async () => {
      await app.openVault();
      expect(await app.fetchVault(MODEL)).toContain(`şifreli dosya deposu: ${device.appLabel('files/vault_files')}`);
      await app.snap(`${MODEL} v${modelVersion} indirildi (dosya deposu)`);
      expect(await app.fetchVault(FLAGS)).toContain(`${FLAGS} v${flagsVersion} indirildi`);
      await app.snap(`${FLAGS} v${flagsVersion} indirildi (şifreli SharedPreferences)`);
    });

    await test.step('Cihaz: ENCRYPTED_FILE — .enc dosyası şifreli, başında PVF2 [sürüm][iv_len][iv] var', async () => {
      const listing = device.appFiles(env.APP_ID, 'files/vault_files');
      const blob = device.appFileBytes(env.APP_ID, ENC_FILE);
      const magic = blob.subarray(0, 4).toString('latin1');
      const storedVersion = blob.readInt32BE(4);
      const ivLen = blob[8];
      const bodyLen = blob.length - 9 - ivLen;
      await attachText(
        testInfo,
        device.appLabel(`adb shell run-as ${env.APP_ID} ls -la files/vault_files`),
        listing,
      );
      await attachText(
        testInfo,
        `${device.appLabel(ENC_FILE)} — ham içerik`,
        [
          `düz metin: ${modelBody.length} bayt, dosya: ${blob.length} bayt`,
          `başlık: ${magic} [sürüm=${storedVersion}] [iv_len=${ivLen}] iv=${blob.subarray(9, 9 + ivLen).toString('hex')}`,
          `şifreli gövde + GCM etiketi: ${bodyLen} bayt (düz metin + 16 bayt etiket)`,
          '',
          hexdump(blob, 96),
          '',
          `Düz metin ("${modelBody.slice(0, 24)}…") dosyada geçiyor mu: ` +
            `${blob.includes(Buffer.from(modelBody, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Dosyanın adı ve sürümü GCM etiketinin kapsadığı ek veride: dosya başka bir',
          'adın yerine taşınır ya da sürümü değiştirilirse çözülmüyor, silinip yeniden iniyor.',
          'Şifreleme anahtarı dosyada değil, Android Keystore\'da (alias: pinvault_vault_' + MODEL + ';',
          'Depolama ekranında listeleniyor). Dosya başka bir cihaza kopyalansa açılamaz.',
        ].join('\n'),
      );
      expect(magic).toBe('PVF2');
      expect(storedVersion).toBe(Number(modelVersion));
      expect(ivLen).toBe(12);
      expect(blob.length).toBe(4 + 4 + 1 + 12 + modelBody.length + 16);
      expect(blob.includes(Buffer.from(modelBody, 'utf8'))).toBe(false);
      expect(listing).toContain(`${MODEL}.enc`);

      // Sürüm artık düz bir tercih kaydında tutulmuyor (uygulamanın depolamasına
      // yazabilen biri onu değiştirebiliyordu); dosyanın kendisinden okunuyor.
      let versions = '';
      try {
        versions = device.appFileText(env.APP_ID, 'shared_prefs/pinvault_vault_file_versions.xml');
      } catch {
        versions = '(dosya yok)';
      }
      await attachText(
        testInfo,
        device.appLabel('shared_prefs/pinvault_vault_file_versions.xml (eski sürüm tablosu)'),
        [
          versions.trim(),
          '',
          `vault_file_ver_${MODEL} kaydı var mı: ${versions.includes(`vault_file_ver_${MODEL}`) ? 'EVET ✗' : 'hayır ✓'}`,
          'Sürüm şifreli dosyanın başlığında ve GCM etiketinin kapsamında.',
        ].join('\n'),
      );
      expect(versions).not.toContain(`vault_file_ver_${MODEL}`);
      expect(versions).not.toContain(modelBody.slice(0, 24));
    });

    await test.step('Cihaz: ENCRYPTED_PREFS — SharedPreferences dosyasında ad da değer de şifreli', async () => {
      const xml = device.appFileText(env.APP_ID, PREFS_FILE);
      const entryNames = device.parsePrefs(xml).filter((e) => e.type === 'string' && e.name).map((e) => e.name);
      await attachText(
        testInfo,
        device.appLabel(`adb shell run-as ${env.APP_ID} cat ${PREFS_FILE}`),
        [
          xml.length > 1200 ? `${xml.slice(0, 1200)}\n… (${xml.length - 1200} karakter daha)` : xml,
          '',
          `kayıt adları (HMAC): ${entryNames.join(', ')}`,
          `"vault_data_${FLAGS}" adı dosyada düz geçiyor mu: ${xml.includes(`vault_data_${FLAGS}`) ? 'EVET ✗' : 'hayır ✓'}`,
          `dosya içeriği düz geçiyor mu: ${xml.includes(flagsBody) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Kayıt adı HMAC\'le gizli, değer AES-256-GCM ile şifreli; iki anahtar da Android',
          'Keystore\'da üretiliyor ve oradan hiç çıkmıyor.',
        ].join('\n'),
      );
      expect(entryNames.length).toBeGreaterThan(0);
      expect(xml).not.toContain(`vault_data_${FLAGS}`);
      expect(xml).not.toContain(FLAGS);
      expect(xml).not.toContain(flagsBody);
      expect(xml).not.toContain('bayrak');
    });

    await test.step('Mobil: Depolama ekranı iki depoyu da gösteriyor', async () => {
      await app.backToMain();
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — vault depoları');
      await attachText(testInfo, 'Depolama ekranı dökümü', text);
      expect(text).toContain(`${MODEL}.enc`);
      expect(text).toContain(`PVF2 [sürüm=${modelVersion}] [iv_len=12]`);
      expect(text).toContain(device.prefsFileName('pinvault_secure_vault_files'));
      expect(text).toContain('kayıt adları okunabilir mi: hayır ✓');
      expect(text).toContain('düz metin sızıntısı (host adı, IP, pin): yok');
      expect(text).toContain(`pinvault_vault_${MODEL}`);
      await app.backToMain();
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, MODEL).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, FLAGS).catch(() => {});
  }
});
