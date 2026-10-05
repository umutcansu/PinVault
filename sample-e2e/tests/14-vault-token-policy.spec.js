// Web ↔ Mobil (gizli vault dosyası): sample-secret uygulamada mTLS bloğunda,
// token_mtls politikasıyla ve ekran kilidi arkasında (userAuth REQUIRED +
// encryption USER_AUTH) tanımlı. Sunucu dosyayı telefonun ekran kilidi
// anahtarına kilitleyip gönderir.
//
// Kanıt: kayıtlı cihaz token olmadan alamıyor; bu cihaz için üretilen token'la
// iniyor ama içerik ekranda görünmüyor ("Kilitli"); "Aç" telefonun ekran
// kilidini soruyor, PIN girilince içerik görünüyor; sorusu kapatılınca
// açılmıyor; token iptal edilince yine reddediliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const secureVault = require('../lib/secureVault');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.secret;
const API = env.SECURE_VAULT_API;

test('Gizli vault dosyası: mTLS + token + ekran kilidi; indirilen dosya kilitli, içerik yalnızca ekran kilidi açılınca görünüyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const secret = `gizli-${Date.now()}`;
  const sv = { clientId: `t14-cihaz-${Date.now()}` };
  let deviceId;
  let token;

  try {
    await test.step('Hazırlık: telefona ekran kilidi, cihaz mTLS\'e kayıt olur', async () => {
      await secureVault.prepare({ app, device, dashboard }, sv);
      await app.snap('kayıtlı, gizli dosyalar tanımlı');
    });

    await test.step('Web: dosya sample-mtls\'e token_mtls + user_auth ile yüklenir', async () => {
      await dashboard.uploadVaultText(API, KEY, secret, { policy: 'token_mtls', encryption: 'user_auth' });
      const cells = await dashboard.vaultRowCells(KEY);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${KEY} token_mtls + user_auth ile yüklendi`);
      expect(cells.policy).toContain('token_mtls');
      expect(cells.encryption).toContain('user_auth');
    });

    await test.step('Mobil: token olmadan indirme reddedilir', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
      await app.snap('token yok, reddedildi');
    });

    await test.step('Sunucu: telefonun ekran kilidi anahtarı kayıtlı', async () => {
      const pem = hostApi.deviceUserAuthKeyPem(deviceId, API);
      await attachText(
        testInfo,
        `device_user_auth_keys — ${deviceId} / ${API}`,
        [
          pem ? `${pem.split('\n')[0]}\n${pem.split('\n')[1]}…` : '(yok)',
          '',
          'Kütüphane açılışta (ekran kilidi varsa) Keystore\'da bir RSA anahtarı üretir;',
          'özel yarısını donanım yalnızca kullanıcı ekran kilidini açınca kullanır.',
          'Public yarısı user_auth dosyası olan her Config API\'ye kaydedilir.',
        ].join('\n'),
      );
      expect(pem).toContain('BEGIN PUBLIC KEY');
    });

    await test.step('Web: bu cihaz için token üretilir', async () => {
      token = await dashboard.generateVaultToken(API, KEY, deviceId);
      expect(token).toMatch(/^[A-Za-z0-9_-]{32,}$/);
      await dashboard.snap('cihaz için token üretildi');
    });

    await test.step('Mobil: token girilir, dosya iner ama içerik gösterilmez', async () => {
      await app.saveVaultToken(token, KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('token ile indirildi — kilitli');
      expect(status).toContain(`${KEY} v`);
      expect(status).toContain('indirildi');
      expect(status).toContain('ekran kilidi anahtarına kilitleyip');
      expect(status).toContain('Kilitli');
      expect(status).not.toContain(secret);
    });

    await test.step('Mobil: "Bilgi" kilitli dosyanın içeriğini göstermiyor', async () => {
      const info = await app.vaultInfo(KEY);
      await app.snap('bilgi — kilitli');
      expect(info).toContain('saklı: var');
      expect(info).toContain('kilitli');
      expect(info).not.toContain(secret);
    });

    await test.step('Mobil: "Aç" ekran kilidini soruyor; vazgeçilince açılmıyor', async () => {
      const status = await app.unlockVault(KEY, { cancel: true });
      await app.snap('ekran kilidi sorusu kapatıldı');
      expect(status).toContain('açılmadı');
      expect(status).not.toContain(secret);
    });

    await test.step('Mobil: "Aç" + PIN → içerik görünüyor', async () => {
      const status = await app.unlockVault(KEY);
      await app.snap('ekran kilidi açıldı — içerik');
      expect(status).toContain(`${KEY} v`);
      expect(status).toContain('açıldı');
      expect(status).toContain(secret);
    });

    await test.step('Web: dağıtım geçmişinde token_mtls ile başarılı indirme', async () => {
      await dashboard.expectDistribution(API, { key: KEY, deviceModel: run.model, status: 'downloaded' });
      await dashboard.snap('dağıtım geçmişi: token_mtls ile indirildi');
    });

    await test.step('Web: token iptal edilir', async () => {
      await dashboard.revokeVaultTokens(API, KEY);
      await dashboard.snap('token iptal edildi');
    });

    await test.step('Mobil: iptal edilen token ile indirme reddedilir', async () => {
      await app.openVault();
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
      await app.snap('iptal sonrası reddedildi');
    });
  } finally {
    await hostApi.deleteVaultFile(API, KEY).catch(() => {});
    await secureVault.cleanup({ device }, sv);
  }
});
