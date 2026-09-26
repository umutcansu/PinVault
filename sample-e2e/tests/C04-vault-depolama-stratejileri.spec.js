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
      expect(await app.fetchVault(MODEL)).toContain('şifreli dosya deposu: files/vault_files');
      await app.snap(`${MODEL} v${modelVersion} indirildi (dosya deposu)`);
      expect(await app.fetchVault(FLAGS)).toContain(`${FLAGS} v${flagsVersion} indirildi`);
      await app.snap(`${FLAGS} v${flagsVersion} indirildi (şifreli SharedPreferences)`);
    });

    await test.step('Cihaz: ENCRYPTED_FILE — .enc dosyası şifreli, başında [iv_len][iv] var', async () => {
      const listing = device.appFiles(env.APP_ID, 'files/vault_files');
      const blob = device.appFileBytes(env.APP_ID, ENC_FILE);
      const ivLen = blob[0];
      await attachText(
        testInfo,
        `adb shell run-as ${env.APP_ID} ls -la files/vault_files`,
        listing,
      );
      await attachText(
        testInfo,
        `${ENC_FILE} — ham içerik`,
        [
          `düz metin: ${modelBody.length} bayt, dosya: ${blob.length} bayt`,
          `başlık: [iv_len=${ivLen}] iv=${blob.subarray(1, 1 + ivLen).toString('hex')}`,
          `şifreli gövde + GCM etiketi: ${blob.length - 1 - ivLen} bayt (düz metin + 16 bayt etiket)`,
          '',
          hexdump(blob, 96),
          '',
          `Düz metin ("${modelBody.slice(0, 24)}…") dosyada geçiyor mu: ` +
            `${blob.includes(Buffer.from(modelBody, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Şifreleme anahtarı dosyada değil, Android Keystore\'da (alias: pinvault_vault_' + MODEL + ';',
          'Depolama ekranında listeleniyor). Dosya başka bir cihaza kopyalansa açılamaz.',
        ].join('\n'),
      );
      expect(ivLen).toBe(12);
      expect(blob.length).toBe(1 + 12 + modelBody.length + 16);
      expect(blob.includes(Buffer.from(modelBody, 'utf8'))).toBe(false);
      expect(listing).toContain(`${MODEL}.enc`);

      const versions = device.appFileText(env.APP_ID, 'shared_prefs/pinvault_vault_file_versions.xml');
      await attachText(
        testInfo,
        'shared_prefs/pinvault_vault_file_versions.xml (dosya deposunun sürüm tablosu)',
        [
          versions.trim(),
          '',
          'Sürüm numarası şifresiz: gizli bir bilgi değil ve sunucunun "değişmedi" (304)',
          'yanıtı için gerekli. İçerik burada yok.',
        ].join('\n'),
      );
      expect(versions).toContain(`vault_file_ver_${MODEL}`);
      expect(versions).toContain(`value="${modelVersion}"`);
      expect(versions).not.toContain(modelBody.slice(0, 24));
    });

    await test.step('Cihaz: ENCRYPTED_PREFS — SharedPreferences dosyasında ad da değer de şifreli', async () => {
      const xml = device.appFileText(env.APP_ID, PREFS_FILE);
      const entryNames = [...xml.matchAll(/<string name="([^"]+)"/g)].map((m) => m[1]);
      await attachText(
        testInfo,
        `adb shell run-as ${env.APP_ID} cat ${PREFS_FILE}`,
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
      expect(text).toContain('[iv_len=12]');
      expect(text).toContain('pinvault_secure_vault_files.xml');
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
