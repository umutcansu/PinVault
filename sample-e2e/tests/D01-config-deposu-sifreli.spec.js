// D01 — Saklı pin config'i cihazda şifreli.
//
// CertificateConfigStore config'i EncryptedSharedPreferences ile
// `shared_prefs/ssl_cert_config_<configApiId>.xml` dosyasına yazıyor: anahtar
// adları AES256-SIV, değerler AES256-GCM, keyset Android Keystore'daki master
// key'le sarılı. Uygulama pin'leri ekranda gösterebiliyor ama dosyada ne host
// adı, ne IP, ne de tek bir pin düz metin olarak geçiyor.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');

const PREFS = 'shared_prefs/ssl_cert_config_sample-host.xml';

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
    const names = [...xml.matchAll(/<string name="([^"]+)"/g)].map((m) => m[1]);
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
      `adb shell run-as ${env.APP_ID} ls -la shared_prefs`,
      listing,
    );
    await attachText(
      testInfo,
      `adb shell run-as ${env.APP_ID} cat ${PREFS}`,
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
        `Tink keyset kaydı: ${xml.includes('__androidx_security_crypto_encrypted_prefs_key_keyset__') ? 'var ✓' : 'yok ✗'}`,
        'Kayıt adları da şifreli (AES256-SIV): dosyaya bakan biri hangi alanların',
        'saklandığını bile göremiyor.',
      ].join('\n'),
    );
    expect(leaks).toHaveLength(0);
    expect(xml).toContain('__androidx_security_crypto_encrypted_prefs_key_keyset__');
    expect(xml).toContain('__androidx_security_crypto_encrypted_prefs_value_keyset__');
    // Keyset'ler dışında en az bir şifreli config kaydı olmalı.
    expect(names.filter((n) => !n.startsWith('__androidx_security_crypto')).length).toBeGreaterThan(0);
  });

  await test.step('Mobil: Depolama ekranı "düz metin sızıntısı: yok" diyor', async () => {
    await app.openStorage();
    const text = await app.refreshStorage();
    await app.snap('Depolama ekranı — şifreli SharedPreferences dosyaları');
    await attachText(testInfo, 'Depolama ekranı dökümü', text);
    expect(text).toContain('ssl_cert_config_sample-host.xml');
    expect(text).toContain('Tink keyset: var');
    expect(text).toContain('düz metin sızıntısı (host adı, IP, pin): yok');
    expect(text).not.toContain('VAR ✗');
    // Ekran master key'i de listeliyor: keyset bu anahtarla sarılı.
    expect(text).toMatch(/_androidx_security_master_key_: AES \d+ bit/);
    await app.backToMain();
  });
});
