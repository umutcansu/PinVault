// B04 — Otomatik kayıt (PinVault.autoEnroll): token yerine cihaz kimliği.
//
// Sunucu varsayılan olarak `ENROLLMENT_MODE=token` ile çalışıyor ve cihaz
// kimliğiyle yapılan kayıt isteğini 403 ile reddediyor. `ENROLLMENT_MODE=open`
// ile aynı istek kabul ediliyor ve sertifika CN'i
// "PinVault Client: <ANDROID_ID>" oluyor — dashboard'da da bu isimle görünüyor.
// Sonunda token moduna dönülüp aynı akışın yeniden reddedildiği gösteriliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

test('mTLS: otomatik kayıt yalnızca ENROLLMENT_MODE=open iken kabul ediliyor', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  let deviceId;

  try {
    await test.step('Mobil: cihaz kimliği okunuyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.snap(`cihaz kimliği: ${deviceId}`);
      await app.backToMain();
      expect(deviceId).toMatch(/^[0-9a-f]{8,}$/);
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
    if (deviceId) await hostApi.revokeClientCertIfActive(deviceId).catch(() => {});
  }
});
