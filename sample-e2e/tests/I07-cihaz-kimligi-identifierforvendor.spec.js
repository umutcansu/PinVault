// I07 — iOS: cihaz kimliği identifierForVendor.
//
// Android'deki ANDROID_ID'nin karşılığı UIDevice.identifierForVendor: aynı
// geliştiricinin uygulamaları için cihaz başına bir UUID; kütüphane küçük harfle
// kullanıyor (kayıt isteğinde deviceUid, vault ve atestasyonda X-Device-Id).
// Uygulama verisi ve Keychain silinince değişmiyor; yalnızca geliştiricinin bütün
// uygulamaları cihazdan kaldırılınca değişiyor (harness uygulamayı bu yüzden hiç silmiyor).
//
// Kanıt: Vault ve mTLS ekranlarındaki kimlik, report.json'daki deviceId; veri +
// Keychain silinip açıldıktan sonra aynı değer; başka bir kimliğe bağlı token
// reddediliyor, bu kimliğe bağlı token'la kayıt sunucuda bu kimliği yazıyor.
const crypto = require('crypto');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: identifierForVendor (Android karşılığı ANDROID_ID; B04, B06)');

test('iOS: cihaz kimliği küçük harf identifierForVendor; veri ve Keychain silinince değişmiyor, sunucu kaydı bu kimliği taşıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const clientId = `i07-cihaz-${Date.now()}`;
  const ids = {};

  const readIds = async (label) => {
    await app.openVault();
    const vault = app.deviceId();
    await app.backToMain();
    await app.openMtls();
    const mtls = app.mtlsDeviceId();
    await app.snap(`${label}: mTLS ekranında cihaz kimliği`);
    await app.backToMain();
    const report = (device.report(env.APP_ID) || {}).deviceId;
    return { vault, mtls, report };
  };

  try {
    await test.step('Mobil: Vault, mTLS ekranı ve report.json aynı küçük harf UUID\'yi gösteriyor', async () => {
      ids.before = await readIds('ilk açılış');
      await attachText(testInfo, 'Cihaz kimliği — ilk açılış', [
        `Vault ekranı ("Cihaz ID")      : ${ids.before.vault}`,
        `mTLS ekranı ("Cihaz kimliği")  : ${ids.before.mtls}`,
        `report.json deviceId           : ${ids.before.report}`,
        '',
        'UIDevice.current.identifierForVendor?.uuidString.lowercased()',
      ].join('\n'));
      expect(ids.before.vault).toMatch(LOWER_UUID);
      expect(ids.before.mtls).toBe(ids.before.vault);
      expect(ids.before.report).toBe(ids.before.vault);
      await hostApi.forgetRevokedIdentitiesOf(ids.before.vault);
    });

    await test.step('Cihaz: uygulama verisi ve Keychain silinip açılınca kimlik aynı', async () => {
      const container = device.appContainer(env.APP_ID);
      app.launchFresh();
      await app.waitReady();
      ids.after = await readIds('veri + Keychain silindikten sonra');
      await app.openStorage();
      const storage = await app.refreshStorage();
      await app.snap('Depolama ekranı — Keychain boşaltılmış, yeni anahtarlar');
      await app.backToMain();
      await attachText(testInfo, 'Cihaz kimliği — veri ve Keychain silindikten sonra', [
        `$ xcrun simctl terminate ${device.udid} ${env.APP_ID}`,
        `$ rm -rf <veri kabı>/{Documents,Library,tmp}/*   (${container})`,
        `$ xcrun simctl keychain ${device.udid} reset`,
        `$ xcrun simctl launch ${device.udid} ${env.APP_ID}`,
        '',
        `önce  : ${ids.before.vault}`,
        `sonra : ${ids.after.vault}  (mTLS ekranı ${ids.after.mtls}, report.json ${ids.after.report})`,
        `aynı mı: ${ids.after.vault === ids.before.vault ? 'EVET ✓' : 'hayır ✗'}`,
        '',
        'Keychain sıfırlandı (yeni anahtarlar üretildi):',
        (storage.split('== Keychain ==')[1] || '').split('\n\n==')[0].trim(),
      ].join('\n'));
      expect(ids.after.vault).toBe(ids.before.vault);
      expect(ids.after.mtls).toBe(ids.before.vault);
      expect(ids.after.report).toBe(ids.before.vault);
    });

    await test.step('Web → Mobil: başka bir kimliğe bağlı token reddediliyor', async () => {
      const otherUid = crypto.randomUUID();
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, `${clientId}-baska`, { deviceUid: otherUid });
      await app.openMtls();
      const status = await app.enroll(token);
      await app.snap('başka telefona bağlı token reddedildi');
      await attachText(testInfo, 'Başka bir kimliğe bağlı token', [`token şu kimliğe bağlı: ${otherUid}`, '', status].join('\n'));
      expect(status).toContain('Kayıt başarısız');
      expect(status).toContain('device_uid_mismatch');
      expect(status).toContain(ids.before.vault);
    });

    await test.step('Web → Mobil: bu kimliğe bağlı token\'la kayıt; sunucu kaydı aynı kimliği taşıyor', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId, { deviceUid: ids.before.vault });
      const status = await app.enroll(token);
      await app.snap('bu telefona bağlı token\'la kayıt başarılı');
      expect(status).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
      await app.backToMain();
      const sql = [
        `SELECT 'client_certs' AS tablo, id, device_uid, device_uid_proven FROM client_certs WHERE id='${clientId}';`,
        `SELECT 'client_identities' AS tablo, client_id, device_uid, config_api_id FROM client_identities WHERE client_id='${clientId}';`,
        `SELECT 'identity_devices' AS tablo, client_id, device_id, proof FROM identity_devices WHERE client_id='${clientId}';`,
        `SELECT 'enrollment_tokens' AS tablo, client_id, device_uid, used FROM enrollment_tokens WHERE client_id='${clientId}';`,
      ];
      const out = [];
      for (const q of sql) {
        try {
          out.push(hostApi.dbQuery(q, { mode: 'line' }));
        } catch (e) {
          out.push(`(${q.split(' FROM ')[1].split(' ')[0]}: ${String(e.message).split('\n')[0]})`);
        }
      }
      const certs = await hostApi.clientCerts();
      const cert = certs.find((c) => c.id === clientId) || {};
      await attachText(testInfo, 'Sunucu kayıtları — bu kayıt', [
        ...out, '',
        'GET /api/v1/client-certs (bu kayıt):',
        JSON.stringify(cert, null, 2),
      ].join('\n'));
      expect(cert.deviceUid).toBe(ids.before.vault);
      expect(out[0]).toContain(`device_uid = ${ids.before.vault}`);
      expect(out[0]).toContain('device_uid_proven = 1');
      expect(out[1]).toContain(`device_uid = ${ids.before.vault}`);
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: false });
      await dashboard.snap(`panelde kayıt: ${clientId}`);
    });
  } finally {
    await hostApi.retireClientIdentity(clientId);
  }
});
