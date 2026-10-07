// I02 — iOS: PinVault'un telefonda sakladıkları.
//
// Şifreli tercih depoları Library/Application Support/pinvault/*.plist: her
// kaydın adı HMAC (ad alanı etiketi + anahtar etiketi, Base64url), değeri
// AES-256-GCM. İki anahtar (pinvault_prefs_aes, pinvault_prefs_mac) Keychain'de,
// ThisDeviceOnly erişimle: yedekle ya da başka bir cihaza taşınamazlar. Dosyalar
// ve dizin `isExcludedFromBackup` ile işaretli; macOS/iOS bunu dosyada
// `com.apple.metadata:com_apple_backup_excludeItem` genişletilmiş özniteliği
// olarak tutar (Mac'ten `xattr` ile okunur). Vault dosya deposu da aynı kurallarla.
//
// Android karşılığı D01 (şifreli depo) ve D05 (yedeğe girmiyor).
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const STORE_DIR = 'Library/Application Support/pinvault';
const BACKUP_XATTR = 'com.apple.metadata:com_apple_backup_excludeItem';
/** SecurePreferences: 12 karakter ad alanı etiketi + "." + 32 karakter anahtar etiketi (Base64url HMAC). */
const HMAC_NAME = /^[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]{32}$/;
/** Kütüphanenin kayıt adları; dosyada hiçbiri düz görünmemeli. */
const PLAIN_NAMES = ['config_', 'client_p12_', 'vault_data_', 'vault_ver_', 'keyset_'];
const KEY = env.VAULT_KEYS.flags;
/** Dosya deposu stratejisindeki dosya: vault_files/*.enc */
const MODEL = env.VAULT_KEYS.model;

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: plist depoları, Keychain ve isExcludedFromBackup iOS\'a özgü (Android karşılığı D01, D05)');

/** `xattr -p` çıktısı; öznitelik yoksa null. */
function xattrOf(file) {
  try {
    return require('child_process').execFileSync('xattr', ['-p', BACKUP_XATTR, file], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

test('iOS: şifreli depolar Application Support/pinvault altında plist, kayıt adları HMAC, düz metin yok, yedekten hariç; iki Keychain anahtarı ThisDeviceOnly', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const root = device.appContainer(env.APP_ID);
  const storeDir = path.join(root, STORE_DIR);
  const content = `i02-${Date.now()}`;

  try {
    await test.step('Mobil: saklanacak veri üretilir (config + iki vault dosyası)', async () => {
      await dashboard.uploadVaultText(env.VAULT_API, KEY, content, { policy: 'public', encryption: 'plain' });
      await dashboard.uploadVaultText(env.VAULT_API, MODEL, `${content}-model`, { policy: 'public', encryption: 'plain' });
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('vault dosyası indirildi');
      expect(status).toContain(`${KEY} v`);
      expect(await app.fetchVault(MODEL)).toContain(`${MODEL} v`);
      await app.snap('dosya deposundaki vault dosyası indirildi');
      await app.backToMain();
    });

    await test.step('Cihaz: depo dosyaları Library/Application Support/pinvault altında .plist', async () => {
      const listing = await attachCommand(
        testInfo,
        `simctl get_app_container ${device.udid} ${env.APP_ID} data → ls -laR "${STORE_DIR}"`,
        'ls',
        ['-laR', STORE_DIR],
        { cwd: root },
      );
      const plists = fs.readdirSync(storeDir).filter((f) => f.endsWith('.plist'));
      expect(plists).toContain('pinvault_secure_config.plist');
      expect(plists.every((f) => f.startsWith('pinvault_'))).toBe(true);
      expect(listing).toContain('vault_files');
      // Android'in shared_prefs/*.xml dosyaları iOS'ta yok.
      expect(fs.existsSync(path.join(root, 'shared_prefs'))).toBe(false);
    });

    await test.step('Cihaz: kayıt adları HMAC, değerler okunmuyor; host adı, IP ve pin dosyalarda geçmiyor', async () => {
      const plists = fs.readdirSync(storeDir).filter((f) => f.startsWith('pinvault_secure_') && f.endsWith('.plist'));
      const needles = [
        env.TARGET_HOST, env.LAN_IP, env.MOCK_TLS_HOST, env.MOCK_MTLS_HOST,
        ...run.goodPins, ...run.hostPins, 'BEGIN', 'sha256/', content,
      ].filter(Boolean);
      const rows = [];
      let sample = '';
      for (const file of plists) {
        const abs = path.join(storeDir, file);
        const raw = fs.readFileSync(abs);
        const xml = device.appFileText(env.APP_ID, `shared_prefs/${file.replace(/\.plist$/, '.xml')}`);
        const entries = device.parsePrefs(xml);
        const badNames = entries.filter((e) => !HMAC_NAME.test(e.name) || PLAIN_NAMES.some((p) => e.name.includes(p)));
        const leaks = needles.filter((n) => raw.includes(Buffer.from(n, 'utf8')) || xml.includes(n));
        rows.push({ file, size: raw.length, entries: entries.length, badNames, leaks });
        if (!sample && entries.length) sample = `${file}:\n  ${entries.slice(0, 2).map((e) => `${e.name} → ${e.value.slice(0, 40)}…`).join('\n  ')}`;
      }
      const vaultDir = path.join(storeDir, 'vault_files');
      const vaultFiles = fs.existsSync(vaultDir) ? fs.readdirSync(vaultDir) : [];
      const vaultLeaks = vaultFiles.filter((f) => fs.readFileSync(path.join(vaultDir, f)).includes(Buffer.from(content, 'utf8')));
      await attachText(
        testInfo,
        'Depo dosyalarının içi (plutil -convert xml1)',
        [
          'dosya                                    boyut   kayıt  HMAC olmayan ad  düz metin',
          ...rows.map((r) => `${r.file.padEnd(40)} ${String(r.size).padEnd(7)} ${String(r.entries).padEnd(6)} ${String(r.badNames.length).padEnd(16)} ${r.leaks.length ? r.leaks.join(', ') : 'yok ✓'}`),
          '',
          'Örnek kayıtlar (ad = ad alanı etiketi.anahtar etiketi, değer = Base64 AES-256-GCM):',
          sample || '(kayıt yok)',
          '',
          `vault_files: ${vaultFiles.join(', ') || '(boş)'}`,
          `  içerikte düz metin (dosya adı vault anahtarıdır, Android'deki gibi): ${vaultLeaks.length ? vaultLeaks.join(', ') : 'yok ✓'}`,
          '',
          `Aranan düz metinler: ${needles.map((n) => (n.length > 24 ? `${n.slice(0, 12)}…` : n)).join(', ')}`,
        ].join('\n'),
      );
      expect(rows.find((r) => r.file === 'pinvault_secure_config.plist').entries).toBeGreaterThan(0);
      for (const r of rows) {
        expect(r.badNames, `${r.file} HMAC olmayan kayıt adı`).toEqual([]);
        expect(r.leaks, `${r.file} düz metin`).toEqual([]);
      }
      expect(vaultFiles.length).toBeGreaterThan(0);
      expect(vaultLeaks).toEqual([]);
    });

    await test.step('Cihaz: dosyalar ve dizin yedekten hariç (com_apple_backup_excludeItem)', async () => {
      const targets = [
        STORE_DIR,
        ...fs.readdirSync(storeDir).filter((f) => f.endsWith('.plist')).map((f) => `${STORE_DIR}/${f}`),
        `${STORE_DIR}/vault_files`,
        ...(fs.existsSync(path.join(storeDir, 'vault_files')) ? fs.readdirSync(path.join(storeDir, 'vault_files')).map((f) => `${STORE_DIR}/vault_files/${f}`) : []),
      ];
      const rows = targets.map((rel) => ({ rel, value: xattrOf(path.join(root, rel)) }));
      const listing = await attachCommand(testInfo, `xattr -l (veri kabında, ${STORE_DIR})`, 'xattr', ['-l', ...targets], { cwd: root });
      await attachText(
        testInfo,
        `isExcludedFromBackup → ${BACKUP_XATTR}`,
        [
          ...rows.map((r) => `${r.value ? '✓' : '✗'} ${r.rel}${r.value ? `  (${r.value})` : '  — öznitelik YOK'}`),
          '',
          'URLResourceValues.isExcludedFromBackup = true, dosya sisteminde bu genişletilmiş',
          'öznitelik olarak duruyor; iCloud ve bilgisayar yedeği bu dosyaları almıyor.',
          'Kütüphane her yazmada (PreferenceStore, EncryptedFileStorageProvider) işareti koyuyor.',
        ].join('\n'),
      );
      expect(listing).toContain(BACKUP_XATTR);
      for (const r of rows) expect(r.value, `${r.rel} yedekten hariç değil`).toBe('com.apple.MobileBackup');
    });

    await test.step('Mobil: Depolama ekranı — iki Keychain anahtarı ThisDeviceOnly, dosyalarda HMAC adlar', async () => {
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — şifreli dosyalar ve Keychain');
      const keychain = (text.split('== Keychain ==')[1] || '').split('\n\n==')[0];
      const aes = keychain.split('\n').find((l) => l.includes('pinvault_prefs_aes')) || '';
      const mac = keychain.split('\n').find((l) => l.includes('pinvault_prefs_mac')) || '';
      const filesPart = (text.split('== Şifreli tercih dosyaları')[1] || '').split('\n\n==')[0];
      await attachText(
        testInfo,
        'Depolama ekranı — tercih dosyaları ve Keychain',
        [
          `== Şifreli tercih dosyaları${filesPart}`,
          '',
          `== Keychain ==${keychain}`,
          '',
          'pinvault_prefs_aes: dosyalardaki değerleri şifreleyen AES-256 anahtarı;',
          'pinvault_prefs_mac: kayıt adlarını üreten HMAC anahtarı. "ThisDeviceOnly" erişim',
          'sınıfı anahtarın şifreli yedeğe ve yeni cihaza taşınmasını engeller: dosyalar bir',
          'yedeğe girse bile başka bir cihazda açılamaz.',
        ].join('\n'),
      );
      expect(aes).toContain('genel parola (Keychain)');
      expect(mac).toContain('genel parola (Keychain)');
      expect(aes).toMatch(/erişim: \w*ThisDeviceOnly/);
      expect(mac).toMatch(/erişim: \w*ThisDeviceOnly/);
      expect(filesPart).toContain('pinvault_secure_config.plist');
      expect(filesPart).toContain('kayıt adları okunabilir mi: hayır ✓ (HMAC)');
      expect(filesPart).not.toContain('VAR ✗');
      expect(filesPart).not.toContain('EVET ✗');
      await app.backToMain();
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, MODEL).catch(() => {});
  }
});
