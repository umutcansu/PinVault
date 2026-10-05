// D05 — PinVault verisi cihaz yedeğine girmiyor.
//
// Kütüphane manifest'inde `fullBackupContent` (API ≤30) ve
// `dataExtractionRules` (API 31+) kuralları var: istemci sertifikası, pin
// config'i ve vault blob'ları hem bulut yedeğinden hem cihazdan cihaza
// transferden çıkarılıyor. Örnek uygulama ayrıca `allowBackup="false"` diyor
// ve kütüphanenin kurallarının yerine kendi kural dosyalarını koyuyor
// (sample_*_rules.xml): kütüphanenin kurallarının hepsi + elle yüklenen
// istemci sertifikasının dosyaları.
//
// Kara kutu kanıtı: emülatörde yerel yedekleme transport'u seçilip yedek
// istendiğinde sistem paketi "Backup is not allowed" ile geri çeviriyor.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');

// sample-e2e PinVault deposunun içinde (2026-10-02'den beri): kütüphane bir üst dizinde.
const PINVAULT_DIR = process.env.E2E_PINVAULT_DIR || path.resolve(env.ROOT, '..');
const RULES_DIR = path.join(PINVAULT_DIR, 'pinvault/src/main/res/xml');
const VARIANT_TASK = env.VARIANT.charAt(0).toUpperCase() + env.VARIANT.slice(1);
const MERGED_MANIFEST = path.join(
  env.CLIENT_DIR,
  `app/build/intermediates/merged_manifests/${env.VARIANT}/process${VARIANT_TASK}Manifest/AndroidManifest.xml`,
);
// Örnek uygulama kütüphanenin kurallarının yerine kendi kural dosyalarını koyar
// (tools:replace): kütüphanenin bütün kurallarını aynen içerirler, üstüne elle
// yüklenen istemci sertifikasının dosyalarını da dışarıda tutarlar.
const APP_RULES_DIR = path.join(env.CLIENT_DIR, 'app/src/main/res/xml');
const RULE_RESOURCES = ['xml/sample_backup_rules', 'xml/sample_data_extraction_rules'];
/** Örnek uygulamanın kendi hassas dosyaları (files/ altında; ManualP12Store). */
const APP_FILES = ['manual-client.sealed', 'manual-client.p12'];
/** Kütüphanenin şifreli depo dosyaları (SecurePreferences). */
const STORE_FILES = ['pinvault_secure_config.xml', 'pinvault_secure_client_cert.xml', 'pinvault_secure_signing_keys.xml', 'pinvault_secure_vault_files.xml'];

/**
 * Kural dosyalarının APK içindeki yolları, kaynak tablosundan. Release
 * derlemesinde kaynak küçültme yolları kısaltır (res/xml/pinvault_backup_rules.xml
 * → res/In.xml gibi); manifest dosyaya kimlikle bağlı olduğu için ad önemsiz.
 */
function ruleFilesInApk() {
  const table = require('child_process').execFileSync(env.AAPT2, ['dump', 'resources', env.APK], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const listing = require('child_process').execFileSync('unzip', ['-l', env.APK], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return RULE_RESOURCES.map((name) => {
    const m = table.match(new RegExp(`resource 0x[0-9a-f]+ ${name}\\s+\\(\\) \\(file\\) (\\S+)`));
    const file = m ? m[1] : null;
    return { name, file, inApk: !!file && listing.split('\n').some((l) => l.trim().endsWith(` ${file}`)) };
  });
}

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
        'Yedeğe girmemesi gereken veriler',
        [text, '', 'Hepsi Android Keystore\'a bağlı: başka bir cihazda zaten çözülemezler.'].join('\n'),
      );
      expect(text).toContain('pinvault_secure_config.xml');
      await app.backToMain();
    });

    await test.step('Cihaz: yerel yedekleme (LocalTransport) seçilir', async () => {
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
          'LocalTransport yedeği cihazda /data/backup altına yazar; bulut hesabı',
          'gerekmez, yani gerçek bir yedekleme denenebiliyor.',
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
          'Android bu uygulamayı hiç yedeklemiyor: uygulamanın manifest\'inde',
          'android:allowBackup="false" var. Yedek alınmadığı için PinVault\'un',
          'şifreli SharedPreferences dosyaları, istemci sertifikası ve vault dosyaları',
          'da hiçbir yedeğe girmiyor.',
        ].join('\n'),
      );
      expect(now).toContain('Backup is not allowed');
      // Yedek reddedildi; uygulama etkilenmedi: ana ekran hâlâ Hazır, pinli istek geçiyor.
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.snap('yedek denemesi reddedildi — uygulama çalışmaya devam ediyor');
    });

    await test.step('Cihaz: birleştirilmiş manifest ve APK içindeki yedekleme kuralı dosyaları', async () => {
      const merged = fs.readFileSync(MERGED_MANIFEST, 'utf8');
      const attrs = (merged.match(/android:(allowBackup|fullBackupContent|dataExtractionRules)="[^"]*"/g) || [])
        .filter((v, i, a) => a.indexOf(v) === i);
      const rules = ruleFilesInApk();
      await attachText(
        testInfo,
        'Birleştirilmiş manifest (app + kütüphane)',
        [
          `dosya: ${MERGED_MANIFEST.replace(env.CLIENT_DIR + '/', '')}`,
          ...attrs.map((a) => `  ${a}`),
          '',
          `APK içindeki kural dosyaları (${path.basename(env.APK)}, aapt2 dump resources + unzip -l):`,
          ...rules.map((r) => `  ${r.name} → ${r.file || '(kaynak yok)'}${r.inApk ? '' : '  APK\'DA YOK'}`),
          '',
          'fullBackupContent ve dataExtractionRules örnek uygulamanın kendi kural',
          'dosyaları (kütüphanenin kurallarının yerine, tools:replace); allowBackup="false" de',
          'uygulamanın kararı.',
        ].join('\n'),
      );
      expect(attrs.join(' ')).toContain('android:allowBackup="false"');
      expect(attrs.join(' ')).toContain('@xml/sample_backup_rules');
      expect(attrs.join(' ')).toContain('@xml/sample_data_extraction_rules');
      expect(rules.filter((r) => r.inApk)).toHaveLength(2);
    });

    await test.step('Kaynak: kütüphanenin yedekleme kuralları bütün Config API bloklarını kapsıyor', async () => {
      const backupRules = fs.readFileSync(path.join(RULES_DIR, 'pinvault_backup_rules.xml'), 'utf8');
      const extractionRules = fs.readFileSync(path.join(RULES_DIR, 'pinvault_data_extraction_rules.xml'), 'utf8');
      const count = (xml, file) => xml.split(`<exclude domain="sharedpref" path="${file}" />`).length - 1;
      const rows = STORE_FILES.map((file) => ({ file, backup: count(backupRules, file), extraction: count(extractionRules, file) }));
      const prefs = device.appFiles(env.APP_ID, 'shared_prefs');
      const legacy = (prefs.match(/ssl_cert_config\S*\.xml/g) || []);
      await attachText(testInfo, 'pinvault_backup_rules.xml (API ≤ 30)', backupRules.trim());
      await attachText(testInfo, 'pinvault_data_extraction_rules.xml (API 31+)', extractionRules.trim());
      await attachText(
        testInfo,
        'Her depo dosyası kurallarda adıyla yer alıyor',
        [
          'dosya                                  API ≤ 30   API 31+ (bulut + cihaz transferi)',
          ...rows.map((r) => `${r.file.padEnd(38)} ${String(r.backup).padEnd(10)} ${r.extraction}`),
          '',
          `$ run-as ${env.APP_ID} ls shared_prefs | grep ssl_cert_config → ${legacy.length ? legacy.join(', ') : '(yok)'}`,
          '',
          'Önceki bulgu giderildi: saklı pin config\'i her Config API için ayrı bir dosyada',
          '(ssl_cert_config_<id>.xml) tutuluyordu ve Android yedekleme kuralları joker',
          'karakter desteklemediği için kütüphane yalnızca kendi kimliklerini listeleyebiliyordu;',
          'kendi kimliğini kullanan bir uygulamanın pin config\'i yedeğe girerdi (M-07).',
          'Şimdi bütün bloklar tek dosyada (pinvault_secure_config.xml), her biri kendi ad',
          'alanında; kurallar bu dosyayı adıyla dışarıda bırakıyor. Bu uygulamanın blokları',
          '(sample-host, sample-mtls) da kapsamda.',
        ].join('\n'),
      );
      for (const r of rows) {
        expect(r.backup, `${r.file} API ≤ 30 kuralında`).toBe(1);
        expect(r.extraction, `${r.file} bulut + cihaz transferi kurallarında`).toBe(2);
      }
      expect(legacy).toHaveLength(0);
    });

    await test.step('Kaynak: örnek uygulamanın kuralları kütüphaneninkileri aynen içeriyor ve elle yüklenen sertifikayı da dışarıda tutuyor', async () => {
      const appBackup = fs.readFileSync(path.join(APP_RULES_DIR, 'sample_backup_rules.xml'), 'utf8');
      const appExtraction = fs.readFileSync(path.join(APP_RULES_DIR, 'sample_data_extraction_rules.xml'), 'utf8');
      const libBackup = fs.readFileSync(path.join(RULES_DIR, 'pinvault_backup_rules.xml'), 'utf8');
      const excludes = (xml) => xml.match(/<exclude [^>]*\/>/g) || [];
      const missingFromApp = [...new Set(excludes(libBackup))].filter((rule) => !appBackup.includes(rule) || !appExtraction.includes(rule));
      const countFile = (xml, file) => xml.split(`<exclude domain="file" path="${file}" />`).length - 1;
      const appRows = APP_FILES.map((file) => ({ file, backup: countFile(appBackup, file), extraction: countFile(appExtraction, file) }));
      await attachText(testInfo, 'sample_data_extraction_rules.xml (API 31+, örnek uygulama)', appExtraction.trim());
      await attachText(
        testInfo,
        'Örnek uygulamanın kuralları',
        [
          `kütüphanenin kurallarından örnekte eksik olan: ${missingFromApp.length ? missingFromApp.join(', ') : '(yok) ✓'}`,
          '',
          'dosya (files/)              API ≤ 30   API 31+ (bulut + cihaz transferi)',
          ...appRows.map((r) => `${r.file.padEnd(27)} ${String(r.backup).padEnd(10)} ${r.extraction}`),
          '',
          'allowBackup="false" Android 12+\'da cihazdan cihaza taşımayı kapatmıyor; elle',
          'yüklenen sertifikanın şifreli kopyası ve içe aktarılmayı bekleyen düz P12 bu',
          'yüzden kurallarla dışarıda tutuluyor.',
        ].join('\n'),
      );
      expect(missingFromApp).toHaveLength(0);
      for (const r of appRows) {
        expect(r.backup, `${r.file} API ≤ 30 kuralında`).toBe(1);
        expect(r.extraction, `${r.file} bulut + cihaz transferi kurallarında`).toBe(2);
      }
    });

    await test.step('Not: bu test neden daha ileri gidemiyor', async () => {
      await attachText(
        testInfo,
        'Dışarıdan test etmenin sınırı',
        [
          'Kuralların ayrı ayrı etkisi (hangi dosyanın yedeğe girip girmediği) bu',
          'uygulamayla gösterilemiyor: allowBackup="false" olduğu için sistem hiç',
          'yedek üretmiyor — yukarıdaki "Backup is not allowed" satırı bunun kanıtı.',
          '',
          'Göstermek için allowBackup="true" ile derlenmiş ikinci bir APK gerekir;',
          'o zaman `bmgr backupnow` sonrası /data/backup altındaki tar dökümünde',
          'hangi shared_prefs dosyalarının bulunduğu sayılabilirdi. Bu, test uğruna',
          'örnek uygulamanın güvenlik ayarını zayıflatmak olurdu; bu yüzden',
          'yapılmadı ve sınır burada not edildi.',
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
