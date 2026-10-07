// B04 — Otomatik kayıt (PinVault.autoEnroll): token yerine cihaz kimliği.
//
// Sunucu varsayılan olarak `ENROLLMENT_MODE=token` ile çalışıyor ve cihaz
// kimliğiyle yapılan kayıt isteğini 403 ile reddediyor. `ENROLLMENT_MODE=open`
// ile aynı istek kabul ediliyor ve sertifika CN'i
// "PinVault Client: <ANDROID_ID>" oluyor — dashboard'da da bu isimle görünüyor.
// Kimlik iptal edilince aynı telefon bir daha kayıt olamıyor (kimliği kendi
// cihaz kimliği); panelde "Kimliği unut"a basılınca yeni bir anahtarla yeniden
// kayıt oluyor. Sonunda token moduna dönülüp aynı akışın yeniden reddedildiği
// gösteriliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

test('mTLS: otomatik kayıt yalnızca ENROLLMENT_MODE=open iken kabul ediliyor', async ({
  app,
  dashboard,
  device,
}, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  let deviceId;

  try {
    await test.step('Mobil: cihaz kimliği okunuyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.snap(`cihaz kimliği: ${deviceId}`);
      await app.backToMain();
      expect(deviceId).toMatch(device.deviceIdPattern);
    });

    await test.step('Sunucu: kayıt modu "token" iken otomatik kayıt reddediliyor', async () => {
      const mode = await hostApi.api('/api/v1/enrollment-mode');
      await app.openMtls();
      const result = await app.autoEnroll();
      await app.snap('token modunda otomatik kayıt reddedildi');
      await attachText(
        testInfo,
        'GET /api/v1/enrollment-mode + telefonun yanıtı',
        [
          `HTTP ${mode.status} ${mode.text}`,
          '',
          'Telefon:',
          result,
          '',
          'Sunucu CertificateConfigRoute: deviceId gönderildi ama ENROLLMENT_MODE != open →',
          'HTTP 403 "Token required for enrollment…".',
        ].join('\n'),
      );
      expect(mode.json.mode).toBe('token');
      expect(result).toContain('Otomatik kayıt reddedildi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
    });

    await test.step('Sunucu: container ENROLLMENT_MODE=open ile yeniden oluşturuluyor', async () => {
      await hostControl.setEnv({ ENROLLMENT_MODE: 'open' });
      const mode = await hostApi.api('/api/v1/enrollment-mode');
      await attachText(
        testInfo,
        'scripts/env-override.sh set ENROLLMENT_MODE=open',
        [
          'Container aynı veri diziniyle yeniden oluşturuldu (sertifikalar, pin\'ler ve',
          'vault dosyaları korunur; yalnızca ortam değişkeni değişti).',
          '',
          `GET /api/v1/enrollment-mode → HTTP ${mode.status} ${mode.text}`,
        ].join('\n'),
      );
      expect(mode.json.mode).toBe('open');
      // Yarıda kalmış bir önceki koşu bu cihazın kimliğini iptal edilmiş
      // bırakmış olabilir: unutulmazsa telefon bir daha kayıt olamaz.
      if (await hostApi.forgetClientIdentityIfRevoked(deviceId)) {
        await attachText(testInfo, 'Hazırlık', `Önceki koşudan iptal edilmiş kalan ${deviceId} kimliği unutuldu.`);
      }
    });

    await test.step('Mobil: cihaz kimliğiyle kayıt oluyor', async () => {
      await app.openMtls();
      const result = await app.autoEnroll();
      await app.snap('otomatik kayıt başarılı');
      expect(result).toContain(`Otomatik kayıt başarılı — CN=PinVault Client: ${deviceId}`);
      expect(app.enrollState()).toContain(`PinVault Client: ${deviceId}`);
      await attachText(
        testInfo,
        'Otomatik kayıt sonucu',
        [result, '', 'Token yok: kütüphane ANDROID_ID\'yi deviceId olarak gönderiyor.'].join('\n'),
      );
    });

    await test.step('Web: sertifika dashboard\'da ANDROID_ID ile listeleniyor', async () => {
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.expectClientCert(env.MTLS_API, deviceId, { revoked: false });
      await dashboard.snap('otomatik kayıtla üretilen sertifika');
      const cert = (await hostApi.clientCerts()).find((c) => c.id === deviceId);
      await attachText(
        testInfo,
        'GET /api/v1/client-certs',
        [
          `id: ${cert.id}`,
          `commonName: ${cert.commonName}`,
          `fingerprint: ${String(cert.fingerprint).slice(0, 16)}…`,
          `revoked: ${cert.revoked}`,
        ].join('\n'),
      );
      expect(cert.commonName).toBe(`PinVault Client: ${deviceId}`);
    });

    await test.step('Mobil: otomatik kayıt sertifikasıyla mTLS bağlantısı geçiyor', async () => {
      const status = await app.expectMtls(true);
      await app.snap('otomatik kayıt sertifikasıyla mTLS bağlantısı');
      expect(status).toContain('HTTP 200');
    });

    await test.step('Mobil+Web: kayıt siliniyor, sertifika iptal ediliyor', async () => {
      expect(await app.unenroll()).toContain('Kayıt silindi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('kayıt silindi');
      await app.backToMain();
      await dashboard.revokeClientCert(env.MTLS_API, deviceId);
      await dashboard.expectClientCert(env.MTLS_API, deviceId, { revoked: true });
      await dashboard.snap('otomatik kayıt sertifikası iptal edildi');
    });

    await test.step('Mobil: kimliği iptal edilen telefon yeniden kayıt olamıyor', async () => {
      await app.openMtls();
      const result = await app.autoEnroll();
      await app.snap('iptal edilen kimlikle otomatik kayıt reddedildi');
      await attachText(
        testInfo,
        'Telefonun yanıtı',
        [
          result,
          '',
          'Açık modda telefonun kimliği kendi cihaz kimliği (ANDROID_ID): iptal edilen kimlik',
          'iptal edilmiş kalır, bu telefon başka bir kimlikle de gelemez (403 revoked).',
        ].join('\n'),
      );
      expect(result).toContain('Otomatik kayıt reddedildi');
      expect(result).toContain('iptal edilmiş');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
    });

    await test.step('Web: iptal edilen satırda "Kimliği unut"', async () => {
      await dashboard.forgetClientIdentity(env.MTLS_API, deviceId);
      await dashboard.snap('kimlik unutuldu: satır listeden kalktı');
      const certs = await hostApi.clientCerts();
      const entry = ((await hostApi.auditLog({ action: 'client_identity_forgotten', limit: 5 })).entries || [])
        .find((e) => e.target === deviceId);
      await attachText(
        testInfo,
        'GET /api/v1/client-certs + denetim kaydı',
        [
          `${deviceId} listede: ${certs.some((c) => c.id === deviceId) ? 'evet' : 'hayır'}`,
          `Denetim kaydı: ${entry ? `${entry.action} — ${entry.summary}` : 'yok'}`,
          '',
          'Eski sertifikası ve anahtarı reddedilmeye devam eder; telefon yeni bir anahtarla kayıt olur.',
        ].join('\n'),
      );
      expect(certs.some((c) => c.id === deviceId)).toBe(false);
      expect(entry).toBeTruthy();
    });

    await test.step('Mobil: aynı telefon yeni bir anahtarla yeniden kayıt oluyor', async () => {
      await app.openMtls();
      const result = await app.autoEnroll();
      await app.snap('kimlik unutulduktan sonra otomatik kayıt başarılı');
      expect(result).toContain(`Otomatik kayıt başarılı — CN=PinVault Client: ${deviceId}`);
      const status = await app.expectMtls(true);
      expect(status).toContain('HTTP 200');
      expect(await app.unenroll()).toContain('Kayıt silindi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
      // Temizlik: bir sonraki koşu da baştan kayıt olabilsin.
      await hostApi.revokeClientCertIfActive(deviceId);
      await hostApi.forgetClientIdentityIfRevoked(deviceId);
    });

    await test.step('Sunucu: token moduna dönülüyor — otomatik kayıt yine reddediliyor', async () => {
      await hostControl.resetEnv();
      const mode = await hostApi.api('/api/v1/enrollment-mode');
      expect(mode.json.mode).toBe('token');
      await app.openMtls();
      const result = await app.autoEnroll();
      await app.snap('token moduna dönüldü: otomatik kayıt reddedildi');
      await attachText(
        testInfo,
        'scripts/env-override.sh reset',
        [`GET /api/v1/enrollment-mode → HTTP ${mode.status} ${mode.text}`, '', 'Telefon:', result].join('\n'),
      );
      expect(result).toContain('Otomatik kayıt reddedildi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
    });
  } finally {
    await hostControl.resetEnv().catch(() => {});
    if (deviceId) {
      await hostApi.revokeClientCertIfActive(deviceId).catch(() => {});
      await hostApi.forgetClientIdentityIfRevoked(deviceId).catch(() => {});
    }
  }
});
