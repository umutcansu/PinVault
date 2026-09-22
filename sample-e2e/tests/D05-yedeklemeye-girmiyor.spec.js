// D05 — PinVault verisi cihaz yedeğine girmiyor.
//
// Kütüphane manifest'inde `fullBackupContent` (API ≤30) ve
// `dataExtractionRules` (API 31+) kuralları var: istemci sertifikası, pin
// config'i ve vault blob'ları hem bulut yedeğinden hem cihazdan cihaza
// transferden çıkarılıyor. Örnek uygulama ayrıca `allowBackup="false"` diyor.
//
// Kara kutu kanıtı: emülatörde yerel yedekleme transport'u seçilip yedek
// istendiğinde sistem paketi "Backup is not allowed" ile geri çeviriyor.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');

const PINVAULT_DIR = process.env.E2E_PINVAULT_DIR || path.resolve(env.ROOT, '..', 'PinVault');
const RULES_DIR = path.join(PINVAULT_DIR, 'pinvault/src/main/res/xml');
const MERGED_MANIFEST = path.join(
  env.CLIENT_DIR,
  'app/build/intermediates/merged_manifests/debug/processDebugManifest/AndroidManifest.xml',
);

/** `bmgr list transports` çıktısındaki seçili (yıldızlı) transport. */
function selectedTransport(text) {
  const line = text.split('\n').find((l) => l.trim().startsWith('*'));
  return line ? line.replace('*', '').trim() : null;
}

test('Depolama: uygulama verisi cihaz yedeğine alınmıyor', async ({ app, device }, testInfo) => {
  test.skip(!device.isEmulator(), 'Yerel yedekleme transport\'u yalnızca emülatörde seçilebilir');
  test.setTimeout(8 * 60 * 1000);
  let originalTransport = null;
  let backupWasEnabled = false;

  try {
    await test.step('Mobil: cihazda saklanacak veri üretilir', async () => {
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — yedeklenmemesi gereken dosyalar');
      await attachText(
        testInfo,
        'Yedek dışı tutulması gereken veri',
        [text, '', 'Hepsi Android Keystore\'a bağlı: başka bir cihazda zaten çözülemezler.'].join('\n'),
      );
      expect(text).toContain('ssl_cert_config_sample-host.xml');
      await app.backToMain();
    });

    await test.step('Cihaz: yerel yedekleme transport\'u seçilir', async () => {
      const before = device.shell('bmgr list transports');
      originalTransport = selectedTransport(before);
      backupWasEnabled = device.shell('bmgr enabled').includes('currently enabled');
      const enable = device.shell('bmgr enable true');
      const select = device.shell('bmgr transport com.android.localtransport/.LocalTransport');
      await attachText(
        testInfo,
        'adb shell bmgr — yedekleme altyapısı',
        [
          '$ bmgr list transports',
          before.trim(),
          '',
          `$ bmgr enabled → ${backupWasEnabled ? 'açık' : 'kapalı'}`,
          `$ bmgr enable true → ${enable.trim()}`,
          `$ bmgr transport com.android.localtransport/.LocalTransport → ${select.trim()}`,
          '',
          'Yerel transport yedeği cihazda /data/backup altına yazar; bulut hesabı',
          'gerekmez, yani gerçek bir yedek denemesi yapılabiliyor.',
        ].join('\n'),
      );
      expect(select).toContain('LocalTransport');
    });

    await test.step('Cihaz: yedek isteği "Backup is not allowed" ile reddediliyor', async () => {
      const now = device.shell(`bmgr backupnow ${env.APP_ID}`);
      const full = device.shell(`bmgr fullbackup ${env.APP_ID}`);
      await attachText(
        testInfo,
        `adb shell bmgr backupnow ${env.APP_ID}`,
        [
          `$ bmgr backupnow ${env.APP_ID}`,
          now.trim(),
          '',
          `$ bmgr fullbackup ${env.APP_ID}`,
          full.trim(),
          '',
          'Sistem paketi yedeğe hiç almıyor: uygulamanın manifest\'inde',
          'android:allowBackup="false" var. Yedek alınmadığı için PinVault\'un',
          'şifreli tercihleri, istemci sertifikası ve vault blob\'ları da hiçbir',
          'yedeğe düşmüyor.',
        ].join('\n'),
      );
      expect(now).toContain('Backup is not allowed');
      // Yedek reddedildi; uygulama etkilenmedi: ana ekran hâlâ Hazır, pinli istek geçiyor.
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.snap('yedek denemesi reddedildi — uygulama çalışmaya devam ediyor');
    });

    await test.step('Cihaz: birleştirilmiş manifest ve APK\'daki kural dosyaları', async () => {
      const merged = fs.readFileSync(MERGED_MANIFEST, 'utf8');
      const attrs = (merged.match(/android:(allowBackup|fullBackupContent|dataExtractionRules)="[^"]*"/g) || [])
        .filter((v, i, a) => a.indexOf(v) === i);
      const apkEntries = require('child_process')
        .execFileSync('unzip', ['-l', env.APK], { encoding: 'utf8' })
        .split('\n')
        .filter((l) => /res\/xml\/pinvault_(backup_rules|data_extraction_rules)\.xml/.test(l))
        .map((l) => l.trim());
      await attachText(
        testInfo,
        'Birleştirilmiş manifest (app + kütüphane)',
        [
          `dosya: ${MERGED_MANIFEST.replace(env.CLIENT_DIR + '/', '')}`,
          ...attrs.map((a) => `  ${a}`),
          '',
          'APK içindeki kural dosyaları:',
          ...apkEntries.map((e) => `  ${e}`),
          '',
          'fullBackupContent ve dataExtractionRules kütüphanenin manifest\'inden',
          'geliyor (manifest merger); allowBackup="false" örnek uygulamanın kendi',
          'kararı.',
        ].join('\n'),
      );
      expect(attrs.join(' ')).toContain('android:allowBackup="false"');
      expect(attrs.join(' ')).toContain('@xml/pinvault_backup_rules');
      expect(attrs.join(' ')).toContain('@xml/pinvault_data_extraction_rules');
      expect(apkEntries).toHaveLength(2);
    });

    await test.step('Kaynak: kütüphanenin yedekleme kuralları ve bir bulgu', async () => {
      const backupRules = fs.readFileSync(path.join(RULES_DIR, 'pinvault_backup_rules.xml'), 'utf8');
      const extractionRules = fs.readFileSync(path.join(RULES_DIR, 'pinvault_data_extraction_rules.xml'), 'utf8');
      const excluded = [...extractionRules.matchAll(/path="([^"]+)"/g)].map((m) => m[1]);
      const appApis = ['sample-host', 'sample-mtls'];
      const covered = appApis.filter((id) => extractionRules.includes(`ssl_cert_config_${id}.xml`));
      await attachText(
        testInfo,
        'pinvault_backup_rules.xml (API ≤ 30)',
        backupRules.trim(),
      );
      await attachText(
        testInfo,
        'pinvault_data_extraction_rules.xml (API 31+)',
        extractionRules.trim(),
      );
      await attachText(
        testInfo,
        'Bulgu: kurallar Config API kimliklerini elle sayıyor',
        [
          `kuralların dışladığı yollar: ${[...new Set(excluded)].join(', ')}`,
          '',
          `Bu uygulamanın Config API kimlikleri: ${appApis.join(', ')}`,
          `kurallarda karşılığı olan: ${covered.length === 0 ? '(hiçbiri)' : covered.join(', ')}`,
          '',
          'Saklı pin config\'i her Config API için ayrı dosyada tutuluyor',
          '(ssl_cert_config_<id>.xml) ve Android yedekleme kurallarında joker',
          'desteklenmiyor. Kütüphane yalnızca `default-tls` ve `secure-mtls`',
          'kimliklerini sayıyor; kendi kimliğini kullanan bir uygulamanın pin',
          'config\'i — M-07\'de tam da engellenmek istenen pin downgrade senaryosu —',
          'yedeğe girerdi. Kural dosyasındaki yorum bunu kabul ediyor ("apps that',
          'register custom ids must add their own excludes here").',
          '',
          'Bu örnek uygulamada risk yok: allowBackup="false" bütün yedeği kapatıyor.',
          '',
          'Öneri: kütüphane belgelerinde "kendi configApiId\'ni kullanıyorsan ya',
          'allowBackup=false ya da dataExtractionRules\'a kendi dosyanı ekle" uyarısı;',
          'ya da saklı config tek bir dosyada (ör. pinvault_configs.xml) toplanıp',
          'kurallarda tek bir yol dışlansın.',
        ].join('\n'),
      );
      expect(backupRules).toContain('pinvault_client_cert.xml');
      expect(extractionRules).toContain('<cloud-backup>');
      expect(extractionRules).toContain('<device-transfer>');
      expect(covered).toHaveLength(0);
    });

    await test.step('Neden daha ileri gidilemiyor — sınır notu', async () => {
      await attachText(
        testInfo,
        'Kara kutu sınırı',
        [
          'Kuralların ayrı ayrı etkisi (hangi dosyanın yedeğe girip girmediği) bu',
          'uygulamayla gösterilemiyor: allowBackup="false" olduğu için sistem hiç',
          'yedek üretmiyor — yukarıdaki "Backup is not allowed" satırı bunun kanıtı.',
          '',
          'Göstermek için allowBackup="true" ile derlenmiş ikinci bir APK gerekir;',
          'o zaman `bmgr backupnow` sonrası /data/backup altındaki tar dökümünde',
          'hangi shared_prefs dosyalarının bulunduğu sayılabilirdi. Bu, örnek',
          'uygulamanın güvenlik duruşunu testin lehine zayıflatmak olurdu; bu yüzden',
          'yapılmadı ve sınır burada belgelendi.',
        ].join('\n'),
      );
    });
  } finally {
    try {
      if (originalTransport) device.shell(`bmgr transport ${originalTransport}`);
      if (!backupWasEnabled) device.shell('bmgr enable false');
    } catch {
      /* emülatör kapanmış olabilir */
    }
  }
});
