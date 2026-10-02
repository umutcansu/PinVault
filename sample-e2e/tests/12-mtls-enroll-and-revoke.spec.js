// Web ↔ Mobil (mTLS): dashboard'da tek kullanımlık token üretilir, cihaz onunla
// kayıt olur ve sertifika dashboard'da görünür. mTLS bağlantısı sertifikayla
// geçer; dashboard'da sertifika iptal edilince aynı bağlantı reddedilir.
const { test, expect } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test('mTLS: web\'de üretilen token\'la telefon kayıt olur ve bağlanır; sertifika web\'de iptal edilince bağlantı reddedilir', async ({
  app,
  dashboard,
}) => {
  const clientId = `e2e-${Date.now()}`;
  // Sunucu istemci sertifikasının CN'ini "PinVault Client: <istemci kimliği>" diye üretir.
  const cn = `CN=PinVault Client: ${clientId}`;
  let token;

  try {
    await test.step('Mobil: kayıtlı değil, mTLS bağlantısı reddedilir', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const status = await app.mtlsTest();
      expect(status).toContain('mTLS bağlantısı reddedildi');
      await app.snap('sertifikasız mTLS reddedildi');
    });

    await test.step('Web: kayıt token\'ı üretilir', async () => {
      token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      expect(token).toMatch(/^[A-Za-z0-9_-]{32,}$/);
      await dashboard.snapTokenList(env.MTLS_API, `kayıt token'ı üretildi: ${clientId} bekliyor`, [{ clientId, status: 'Bekliyor' }]);
    });

    await test.step('Mobil: token ile kayıt olunur', async () => {
      const status = await app.enroll(token);
      expect(status).toContain(`Kayıt başarılı — ${cn}`);
      expect(app.enrollState()).toContain(cn);
      await app.snap('kayıt başarılı');
    });

    await test.step('Web: sertifika etkin olarak listelenir', async () => {
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: false });
      await dashboard.snap('istemci sertifikası etkin');
    });

    await test.step('Mobil: sertifikayla mTLS bağlantısı geçer', async () => {
      const status = await app.expectMtls(true);
      expect(status).toContain('HTTP 200');
      await app.snap('mTLS bağlantısı başarılı');
    });

    await test.step('Web: sertifika iptal edilir', async () => {
      await dashboard.revokeClientCert(env.MTLS_API, clientId);
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: true });
      await dashboard.snap('sertifika iptal edildi');
    });

    await test.step('Mobil: iptal edilen sertifikayla mTLS bağlantısı reddedilir', async () => {
      const status = await app.expectMtls(false);
      await app.snap('iptal sonrası reddedildi');
      // El sıkışma geçer (sertifika istemci CA\'sından ve süresi dolmamış); sunucu
      // iptali her istekte uygular: 403 reenroll_required. Uygulama bunu ret gösteriyor.
      expect(status).toContain('kimlik iptal edilmiş');
    });

    await test.step('Mobil: kayıt silinir', async () => {
      expect(await app.unenroll()).toContain('Kayıt silindi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('kayıt silindi');
    });
  } finally {
    // Yarıda kalan koşu sunucuda etkin bir test sertifikası bırakmasın.
    await hostApi.revokeClientCertIfActive(clientId);
  }
});
