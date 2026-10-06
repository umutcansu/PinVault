// D01 — Saklı pin config'i cihazda şifreli.
//
// CertificateConfigStore config'i `shared_prefs/pinvault_secure_config.xml`
// dosyasına yazıyor (her Config API kendi ad alanında): değerler AES-256-GCM,
// kayıt adları HMAC-SHA256; ikisinin anahtarı da Android Keystore'da üretiliyor
// ve oradan hiç çıkmıyor. Uygulama pin'leri ekranda gösterebiliyor ama dosyada
// ne host adı, ne IP, ne de tek bir pin düz metin olarak geçiyor.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');

/** SecurePreferences kayıt adı: <ad alanı HMAC'i 12>.<anahtar HMAC'i 32>, base64url. */
const HMAC_NAME = /^[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]{32}$/;

const PREFS = 'shared_prefs/pinvault_secure_config.xml';
/** PinVault 2.0.x'in bu blok için kullandığı dosya; ilk açılışta taşınıp silinir. */
const LEGACY = 'ssl_cert_config_sample-host.xml';

test('Depolama: saklı pin config\'i şifreli; host adı, IP ve pin\'ler düz metin olarak yok', async ({
  app,
  device,
  run,
}, testInfo) => {
  let status;

  await test.step('Mobil: uygulama config\'i almış, pin\'leri gösteriyor', async () => {
    status = await app.waitReady();
    await app.snap('ana ekran — config ve host sürümleri');
    expect(status).toContain(`${TARGET_HOST} → pin v`);
    await attachText(
      testInfo,
      'Telefon durum kutusu',
      [status, '', 'Kütüphane pin\'leri biliyor; aşağıdaki dosyada hiçbiri düz metin değil.'].join('\n'),
    );
  });

  await test.step('Cihaz: config dosyası şifreli ve düz metin içermiyor', async () => {
    const listing = device.appFiles(env.APP_ID, 'shared_prefs');
    const xml = device.appFileText(env.APP_ID, PREFS);
    const names = device.parsePrefs(xml).filter((e) => e.type === 'string' && e.name).map((e) => e.name);
    const secrets = {
      'hedef host adı': TARGET_HOST,
      'host IP\'si': env.LAN_IP,
      'test sunucusu adı (mock host)': env.MOCK_TLS_HOST,
      'hedefin birinci pin\'i': run.goodPins[0],
      'hedefin ikinci pin\'i': run.goodPins[1],
      'gömülü ilk pin (bootstrap)': run.hostPins[0],
      'config kayıt adı (config_pins)': 'config_pins',
      'sürüm kayıt adı (config_version)': 'config_version',
    };
    const leaks = Object.entries(secrets).filter(([, value]) => value && xml.includes(value));
    await attachText(
      testInfo,
      device.appLabel(`adb shell run-as ${env.APP_ID} ls -la shared_prefs`),
      listing,
    );
    await attachText(
      testInfo,
      device.appLabel(`adb shell run-as ${env.APP_ID} cat ${PREFS}`),
      [
        xml.length > 1600 ? `${xml.slice(0, 1600)}\n… (${xml.length - 1600} karakter daha)` : xml,
        '',
        `kayıt sayısı: ${names.length}`,
        ...names.map((n) => `  ${n.length > 64 ? n.slice(0, 64) + '…' : n}`),
        '',
        'Düz metin taraması:',
        ...Object.entries(secrets).map(([label, value]) =>
          `  ${label.padEnd(34)} ${value ? (xml.includes(value) ? 'GEÇİYOR ✗' : 'geçmiyor ✓') : '(değer yok)'}`),
        '',
        `kayıt adları HMAC biçiminde (ad alanı.anahtar): ${names.every((n) => HMAC_NAME.test(n)) ? 'evet ✓' : 'HAYIR ✗'}`,
        `PinVault 2.0.x dosyası (${LEGACY}): ${listing.includes(LEGACY) ? 'VAR ✗' : 'yok ✓'}`,
        'Kayıt adları da gizli (Keystore anahtarıyla HMAC): dosyaya bakan biri hangi',
        'alanların saklandığını bile göremiyor.',
      ].join('\n'),
    );
    expect(leaks).toHaveLength(0);
    expect(names.length).toBeGreaterThan(0);
    expect(names.every((n) => HMAC_NAME.test(n))).toBe(true);
    expect(listing).not.toContain(LEGACY);
  });

  await test.step('Mobil: Depolama ekranı "düz metin sızıntısı: yok" diyor', async () => {
    await app.openStorage();
    const text = await app.refreshStorage();
    await app.snap('Depolama ekranı — şifreli tercih dosyaları');
    await attachText(testInfo, 'Depolama ekranı dökümü', text);
    expect(text).toContain(device.prefsFileName('pinvault_secure_config'));
    expect(text).toContain('kayıt adları okunabilir mi: hayır ✓');
    expect(text).toContain('düz metin sızıntısı (host adı, IP, pin): yok');
    expect(text).not.toContain('VAR ✗');
    expect(text).not.toContain('EVET ✗');
    // Ekran şifrelemenin iki Keystore anahtarını da listeliyor (iOS: Keychain'deki
    // iki 32 baytlık anahtar; adları aynı, tür ve boy satırı platforma özgü).
    if (device.platform === 'ios') {
      expect(text).toContain('pinvault_prefs_aes');
      expect(text).toContain('pinvault_prefs_mac');
    } else {
      expect(text).toMatch(/pinvault_prefs_aes: AES 256 bit/);
      expect(text).toMatch(/pinvault_prefs_mac: HmacSHA256 \d+ bit/);
    }
    await app.backToMain();
  });
});
