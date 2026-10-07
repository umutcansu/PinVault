// I01 — iOS: cihaz kimlik anahtarı (mTLS kaydı) Secure Enclave'de.
//
// Kütüphane kimlik anahtarını Keychain'de `kSecAttrTokenIDSecureEnclave` ile
// (P-256, `.privateKeyUsage`, ThisDeviceOnly, kSecAttrIsExtractable=false)
// üretiyor; CSR'ı bu anahtarla imzalıyor, sunucu sertifikayı bu anahtarın
// public yarısına kesiyor. Atestasyon raporu da aynı anahtarla imzalanıyor ve
// `device.keySecurityLevel` alanında anahtarın yerini söylüyor.
//
// Kanıt: kayıt başarılı; Depolama ekranında anahtarın yeri secure_enclave, Keychain
// satırında "güvenli donanım: evet (Secure Enclave)" ve özel yarıyı dışarı alma
// denemesinin reddi; sunucudaki kimlik kaydının anahtarı (spki_sha256) telefondakiyle
// aynı, atestasyon kaydında aynı anahtar ve keySecurityLevel=secure_enclave.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const IDENTITY_ALIAS_PREFIX = 'pinvault_client_identity_ec_';

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: Secure Enclave Apple cihazlarına özgü (Android karşılığı D02/B04: Keystore)');

/** Bu cihazın atestasyon kaydı (panel API'si), yoksa null. */
async function attestationRecord(deviceId) {
  const res = await hostApi.api(`/api/v1/config-apis/${env.VAULT_API}/attestation/devices/${encodeURIComponent(deviceId)}`);
  return res.status === 200 ? res.json : null;
}

test('iOS: kimlik anahtarı Secure Enclave\'de üretiliyor, dışarı alınamıyor; sunucudaki kayıt aynı anahtarı ve düzeyi gösteriyor', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const clientId = `i01-se-${Date.now()}`;
  let deviceId;
  let keyLine;
  let onDeviceSpki;

  try {
    await test.step('Mobil: kayıtlı değil, cihaz kimliği okunur', async () => {
      await app.openMtls();
      deviceId = app.mtlsDeviceId();
      // Önceki senaryoların iptal ettiği kimlikler kaydı "cihaz iptal edilmiş" diye kesmesin.
      await hostApi.forgetRevokedIdentitiesOf(deviceId);
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('mTLS ekranı — kayıtlı değil');
    });

    await test.step('Web → Mobil: telefona bağlı token\'la kayıt olunur', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId, { deviceUid: deviceId });
      const status = await app.enroll(token);
      await app.snap('kayıt başarılı');
      expect(status).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
      await app.backToMain();
    });

    await test.step('Mobil: Depolama ekranı — anahtarın yeri secure_enclave, özel yarı dışarı alınamıyor', async () => {
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — Keychain ve istemci sertifikası');
      const levelLine = text.split('\n').find((l) => l.includes('kimlik anahtarının yeri')) || '';
      keyLine = text.split('\n').find((l) => l.includes(IDENTITY_ALIAS_PREFIX)) || '';
      onDeviceSpki = (keyLine.match(/public key SHA-256: ([0-9a-f]{64})/) || [])[1];
      await attachText(
        testInfo,
        'Depolama ekranı — Keychain ve istemci sertifikası bölümleri',
        [
          `== Keychain ==${(text.split('== Keychain ==')[1] || '').trim() ? `\n${text.split('== Keychain ==')[1].trim()}` : ' (yok)'}`,
          '',
          `kimlik anahtarı satırı: ${keyLine.trim() || '(yok)'}`,
          `düzey satırı:          ${levelLine.trim() || '(yok)'}`,
          '',
          'Satır uygulamanın kendi Keychain sorgusundan (SecItemCopyMatching, kSecClassKey):',
          'kSecAttrTokenID = kSecAttrTokenIDSecureEnclave → "güvenli donanım: evet". Özel',
          'yarıyı SecKeyCopyExternalRepresentation ile istemek Secure Enclave anahtarında',
          'hata döndürüyor: anahtarın baytları Secure Enclave\'den hiç çıkmıyor, uygulama',
          'yalnızca imzalatabiliyor.',
        ].join('\n'),
      );
      expect(levelLine).toContain('secure_enclave');
      expect(keyLine).toContain('EC 256 bit');
      expect(keyLine).toContain('güvenli donanım: evet (Secure Enclave)');
      expect(keyLine).toMatch(/dışa aktarılabilir: hayır \(SecKeyCopyExternalRepresentation → -?\d+\)/);
      expect(keyLine).toMatch(/erişim: \w+ThisDeviceOnly/);
      expect(onDeviceSpki).toMatch(/^[0-9a-f]{64}$/);
      await app.backToMain();
    });

    await test.step('Sunucu: kimlik kaydı aynı anahtara kesilmiş; atestasyon kaydında düzey secure_enclave', async () => {
      // Atestasyon açılışta ve "Atestasyon" düğmesiyle aynı kimlik anahtarıyla imzalanır.
      await app.attest();
      await app.snap('atestasyon raporu gönderildi');
      const identity = hostApi.dbQuery(
        `SELECT client_id, config_api_id, device_uid, spki_sha256, attested, attestation_security_level, attestation_reason FROM client_identities WHERE client_id='${clientId}';`,
        { mode: 'line' },
      );
      await attachCommand(
        testInfo,
        'sqlite3 — client_identities (bu kayıt)',
        'sqlite3',
        ['-readonly', '-line', env.DB_FILE,
          `SELECT client_id, config_api_id, device_uid, spki_sha256, attested, attestation_security_level, attestation_reason FROM client_identities WHERE client_id='${clientId}';`],
      );
      // client_identities SPKI özetini Base64, attested_devices hex yazar.
      const serverSpkiB64 = (identity.match(/spki_sha256 = (\S+)/) || [])[1];
      const serverSpki = serverSpkiB64 ? Buffer.from(serverSpkiB64, 'base64').toString('hex') : undefined;
      const record = await attestationRecord(deviceId);
      const row = hostApi.dbQuery(
        `SELECT spki_sha256, key_security_level, json_extract(last_report, '$.device.keySecurityLevel') FROM attested_devices WHERE config_api_id='${env.VAULT_API}' AND device_id='${deviceId}';`,
      );
      const [attSpki, attLevelCol, reportLevel] = row.split('|');
      await attachText(
        testInfo,
        'Telefondaki anahtar ↔ sunucudaki kayıtlar',
        [
          `Depolama ekranı (Keychain)        public key SHA-256: ${onDeviceSpki}`,
          `client_identities.spki_sha256     (sertifikanın anahtarı): ${serverSpki || '(yok)'}  (Base64: ${serverSpkiB64})`,
          `attested_devices.spki_sha256      (atestasyon anahtarı):  ${attSpki || '(yok)'}`,
          `  eşleşiyor mu: ${serverSpki === onDeviceSpki && attSpki === onDeviceSpki ? 'EVET ✓' : 'hayır ✗'}`,
          '',
          `attested_devices.key_security_level: ${attLevelCol || '(boş: yalnızca Android anahtar atestasyonu doldurur)'}`,
          `son raporun device.keySecurityLevel'ı: ${reportLevel || '(yok)'}`,
          '',
          'client_identities.attestation_security_level boş, attestation_reason "chain_missing":',
          'iOS anahtarları Android\'deki gibi bir atestasyon zinciri taşımıyor (App Attest',
          'simülatörde yok). Sunucunun bu anahtar için kaydettiği düzey, aynı anahtarla',
          'imzalanan atestasyon raporundaki keySecurityLevel\'dır.',
          '',
          'Panel API\'sinin cihaz kaydı:',
          JSON.stringify(record, null, 2),
        ].join('\n'),
      );
      expect(identity).toContain(`device_uid = ${deviceId}`);
      expect(identity).toContain('attestation_reason = chain_missing');
      expect(serverSpki).toBe(onDeviceSpki);
      expect(attSpki).toBe(onDeviceSpki);
      expect(reportLevel).toBe('secure_enclave');
      expect(record, 'atestasyon kaydı yok').toBeTruthy();
    });

    await test.step('Web: istemci sertifikası panelde etkin', async () => {
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: false });
      await dashboard.snap(`istemci sertifikası etkin: ${clientId}`);
    });
  } finally {
    await hostApi.retireClientIdentity(clientId);
  }
});
