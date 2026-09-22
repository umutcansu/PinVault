// D03 — Cihazın uçtan uca şifreleme anahtarı (Android Keystore RSA).
//
// DeviceKeyProvider init sırasında `pinvault_vault_e2e_rsa` alias'ında RSA-2048
// üretiyor (mümkünse StrongBox), public yarısını her Config API'ye kaydediyor,
// private yarısı Keystore'dan hiç çıkmıyor. Depolama ekranındaki anahtar bilgisi
// ile sunucudaki kayıtlı PEM'in SHA-256'sı karşılaştırılıyor.
const crypto = require('crypto');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const ALIAS = 'pinvault_vault_e2e_rsa';
const KEY = env.VAULT_KEYS.e2e;

/** PEM gövdesini DER'e çevirip SHA-256 alır (SPKI). */
function spkiSha256(pem) {
  const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  return { der, hex: crypto.createHash('sha256').update(der).digest('hex') };
}

test('Depolama: cihaz RSA anahtarı Keystore\'da ve sunucudaki public key ile eşleşiyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  let deviceId;
  let deviceKeyLine;
  let onDeviceHash;

  try {
    await test.step('Mobil: cihaz kimliği ve Keystore anahtar bilgisi', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.backToMain();
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — Android Keystore anahtarları');
      deviceKeyLine = text.split('\n').find((l) => l.includes(ALIAS)) || '';
      onDeviceHash = (deviceKeyLine.match(/public key SHA-256: ([0-9a-f]{64})/) || [])[1];
      await attachText(
        testInfo,
        'Depolama ekranı — Android Keystore bölümü',
        [
          text.split('== Android Keystore ==')[1] || text,
          '',
          `cihaz kimliği (ANDROID_ID): ${deviceId}`,
        ].join('\n'),
      );
      expect(deviceKeyLine).toContain('RSA 2048 bit');
      expect(deviceKeyLine).toMatch(/güvenli donanım: (evet|hayır)/);
      expect(onDeviceHash).toMatch(/^[0-9a-f]{64}$/);
      await app.backToMain();
    });

    await test.step('Sunucu: kayıtlı public key cihazdakiyle aynı', async () => {
      await attachCommand(
        testInfo,
        'sqlite3 — device_public_keys (bu cihaz)',
        'sqlite3',
        ['-readonly', '-line', env.DB_FILE,
          `SELECT device_id, config_api_id, algorithm, registered_at FROM device_public_keys WHERE device_id='${deviceId}';`],
      );
      const pem = hostApi.devicePublicKeyPem(deviceId, env.VAULT_API);
      expect(pem).toContain('BEGIN PUBLIC KEY');
      const { der, hex } = spkiSha256(pem);
      await attachText(
        testInfo,
        'Cihazdaki anahtar ↔ sunucudaki kayıt',
        [
          `Depolama ekranı satırı:`,
          `  ${deviceKeyLine.trim()}`,
          '',
          `Sunucudaki PEM: ${pem.length} karakter, SPKI DER ${der.length} bayt`,
          `  cihazda   SHA-256: ${onDeviceHash}`,
          `  sunucuda  SHA-256: ${hex}`,
          `  eşleşiyor mu: ${hex === onDeviceHash ? 'EVET ✓' : 'hayır ✗'}`,
          '',
          `${pem.split('\n')[0]}`,
          `${pem.split('\n')[1]}…`,
          `${pem.split('\n').slice(-1)[0]}`,
          '',
          'Sunucuda yalnızca PUBLIC yarısı var. Private anahtar Android Keystore\'da,',
          'PURPOSE_DECRYPT ile ve yalnızca OAEP-SHA256 için kullanılabilir; ham materyali',
          'uygulamaya bile verilmiyor (Cipher üzerinden kullanılıyor).',
        ].join('\n'),
      );
      expect(hex).toBe(onDeviceHash);
    });

    await test.step('Mobil: anahtar gerçekten çalışıyor — uçtan uca dosya çözülüyor', async () => {
      const secret = `anahtar-calisiyor-${Date.now()}`;
      const version = await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, {
        policy: 'public',
        encryption: 'end_to_end',
      });
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('cihaz anahtarıyla çözülen dosya');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain('cihaz anahtarıyla çözüldü');
      expect(status).toContain(secret);
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      await attachText(
        testInfo,
        'Aynı dosyanın kablodaki hâli',
        [
          `X-Vault-Encryption: ${res.headers['x-vault-encryption']}`,
          `gövde: ${res.body.length} bayt, sarılı anahtar ${res.body.readUInt32BE(0)} bayt`,
          `düz metin gövdede geçiyor mu: ${res.body.includes(Buffer.from(secret, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Zarf yukarıdaki public key ile sarıldı; yalnızca Keystore\'daki private',
          'yarısı açabilir.',
        ].join('\n'),
      );
      expect(res.body.readUInt32BE(0)).toBe(256);
      await app.backToMain();
    });

    await test.step('Cihaz: anahtar uygulama dosyalarında değil', async () => {
      const files = device.runAs(env.APP_ID, 'ls -la shared_prefs files');
      const grep = device.runAs(
        env.APP_ID,
        'grep -rl "PRIVATE KEY" shared_prefs files 2>/dev/null || echo "(eşleşme yok)"',
      );
      await attachText(
        testInfo,
        `adb shell run-as ${env.APP_ID} — anahtar materyali araması`,
        [
          files.trim(),
          '',
          '$ grep -rl "PRIVATE KEY" shared_prefs files',
          grep.trim(),
          '',
          'Keystore anahtarları uygulamanın veri dizininde değil; sistem tarafında',
          '(keystore2 / TEE) tutuluyor ve yalnızca alias ile kullanılabiliyor.',
        ].join('\n'),
      );
      expect(grep).toContain('(eşleşme yok)');
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
