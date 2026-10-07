// I03 — iOS: cihaz RSA anahtarı RSA-OAEP-SHA256-MGF1-SHA256 ile kaydediliyor.
//
// iOS'un `.rsaEncryptionOAEPSHA256`'sı OAEP'in maske fonksiyonunda da SHA-256
// kullanıyor (MGF1-SHA256); Android Keystore'un OAEP-SHA256'sı MGF1-SHA1. Sunucu
// cihaz anahtarını algoritmasıyla saklıyor ve uçtan uca (end_to_end) dosyanın AES
// anahtarını o algoritmayla sarıyor; yanlış MGF1 ile sarılmış anahtarı telefon
// açamazdı. Kanıt: device_public_keys / device_user_auth_keys tablolarının
// `algorithm` sütunu, yönetim API'sindeki cihaz anahtarları ve telefonda açılan
// end_to_end dosyası.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const secureVault = require('../lib/secureVault');
const env = require('../lib/env');

const ALGORITHM = 'RSA-OAEP-SHA256-MGF1-SHA256';
const KEY = env.VAULT_KEYS.flags;

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: MGF1-SHA256 iOS anahtarlarına özgü (Android anahtarları RSA-OAEP-SHA256 olarak kalıyor; D03, C10)');

test('iOS: cihaz anahtarı RSA-OAEP-SHA256-MGF1-SHA256 algoritmasıyla kayıtlı; end_to_end dosya bu algoritmayla sarılıp telefonda açılıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const sv = { clientId: `i03-cihaz-${Date.now()}` };
  const secret = `mgf1-sha256-${Date.now()}`;
  let deviceId;

  try {
    await test.step('Hazırlık: cihaz mTLS\'e kayıt olur (cihaz RSA anahtarları üretilip kaydedilir)', async () => {
      await secureVault.prepare({ app, device, dashboard }, sv);
      await app.openVault();
      deviceId = app.deviceId();
      await app.backToMain();
    });

    await test.step('Sunucu: device_public_keys ve device_user_auth_keys — algoritma MGF1-SHA256', async () => {
      const sql = (table) => `SELECT device_id, config_api_id, algorithm, registered_at FROM ${table} WHERE device_id='${deviceId}' ORDER BY config_api_id;`;
      const e2e = await attachCommand(testInfo, 'sqlite3 — device_public_keys (bu cihaz)', 'sqlite3', ['-readonly', '-line', env.DB_FILE, sql('device_public_keys')]);
      const userAuth = await attachCommand(testInfo, 'sqlite3 — device_user_auth_keys (bu cihaz)', 'sqlite3', ['-readonly', '-line', env.DB_FILE, sql('device_user_auth_keys')]);
      const algorithms = (text) => [...text.matchAll(/algorithm = (\S+)/g)].map((m) => m[1]);
      expect(algorithms(e2e).length, 'cihaz anahtarı kayıtlı değil').toBeGreaterThan(0);
      expect(new Set(algorithms(e2e))).toEqual(new Set([ALGORITHM]));
      expect(e2e).toContain(`config_api_id = ${env.VAULT_API}`);
      expect(algorithms(userAuth).length, 'ekran kilidi anahtarı kayıtlı değil').toBeGreaterThan(0);
      expect(new Set(algorithms(userAuth))).toEqual(new Set([ALGORITHM]));
    });

    await test.step('Yönetim API\'si: cihazın anahtarları algoritmalarıyla', async () => {
      const lines = [];
      for (const apiId of [env.VAULT_API, env.MTLS_API]) {
        const res = await hostApi.api(`/api/v1/config-apis/${apiId}/vault/devices/${encodeURIComponent(deviceId)}/keys`);
        expect(res.status, res.text).toBe(200);
        const brief = (k) => (k ? { algorithm: k.algorithm, registeredAt: k.registeredAt || k.registered_at, publicKeyPem: `${String(k.publicKeyPem || '').split('\n')[1] || ''}…` } : null);
        lines.push(`GET /api/v1/config-apis/${apiId}/vault/devices/${deviceId}/keys → HTTP ${res.status}`,
          JSON.stringify({ e2e: brief(res.json.e2e), userAuth: brief(res.json.userAuth) }, null, 2), '');
        if (apiId === env.VAULT_API) expect(res.json.e2e.algorithm).toBe(ALGORITHM);
        if (res.json.userAuth) expect(res.json.userAuth.algorithm).toBe(ALGORITHM);
      }
      await attachText(testInfo, 'Yönetim API\'si — cihaz anahtarları', [
        ...lines,
        'Android\'in kaydettiği anahtarlar "RSA-OAEP-SHA256" (MGF1-SHA1, varsayılan) olarak duruyor;',
        'sunucu dosyayı her cihazın kendi algoritmasıyla sarıyor (VaultEncryptionService).',
      ].join('\n'));
    });

    await test.step('Web → Mobil: end_to_end dosya iner ve cihaz anahtarıyla açılır', async () => {
      const version = await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, { policy: 'public', encryption: 'end_to_end' });
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('end_to_end dosya cihaz anahtarıyla açıldı');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain(secret);
      await app.backToMain();
    });

    await test.step('Ağ trafiği: AES anahtarı 2048 bit RSA-OAEP ile sarılı, düz metin yok', async () => {
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      const wrappedLength = res.body.readUInt32BE(0);
      await attachText(
        testInfo,
        'Aynı dosyanın ağdaki hâli (Mac\'ten, bu cihazın kimliğiyle)',
        [
          `HTTP ${res.status}, X-Vault-Encryption: ${res.headers['x-vault-encryption']}`,
          `gövde: ${res.body.length} bayt = [4 B uzunluk=${wrappedLength}][RSA-OAEP ile sarılmış AES anahtarı][12 B IV][AES-GCM]`,
          `düz metin gövdede geçiyor mu: ${res.body.includes(Buffer.from(secret, 'utf8')) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          `Sarma: RSA/ECB/OAEPPadding, OAEPParameterSpec(SHA-256, MGF1, MGF1ParameterSpec.SHA256) — ${ALGORITHM}.`,
          'Telefon sarılı anahtarı SecKeyCreateDecryptedData(.rsaEncryptionOAEPSHA256) ile açtı;',
          'MGF1-SHA1 ile sarılmış olsaydı çözme "decode error" ile düşerdi.',
        ].join('\n'),
      );
      expect(res.headers['x-vault-encryption']).toBe('end_to_end');
      expect(wrappedLength).toBe(256);
      expect(res.body.includes(Buffer.from(secret, 'utf8'))).toBe(false);
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
    await secureVault.cleanup({ device }, sv);
  }
});
