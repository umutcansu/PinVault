// B07 — "Kaydı sil" gerçekten kesiyor mu?
//
// Eski davranışta `unenroll` yalnızca şifreli depoyu temizliyor, bellekteki
// KeyManager'ı bırakıyordu: cihaz "kayıtlı değil" görünürken mTLS hedeflerine
// sertifikasını sunmaya devam ediyordu ve ancak uygulama yeniden açılınca
// kesiliyordu. Bu senaryo hem aynı süreçte hem yeniden açılışta bağlantının
// reddedildiğini, hem de cihazdaki kaydın kalmadığını gösteriyor.
//
// Sunucudaki sertifika bilerek iptal EDİLMİYOR: reddin kaynağı cihazın artık
// sertifika sunmaması.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test('mTLS: kayıt silinince bağlantı, uygulama yeniden açılmadan hemen kesiliyor', async ({ app, device, dashboard }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const clientId = `b07-${Date.now()}`;
  const cn = `PinVault Client: ${clientId}`;

  try {
    await test.step('Web+Mobil: cihaz kayıt oluyor ve mTLS bağlantısı geçiyor', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=${cn}`);
      const status = await app.expectMtls(true);
      await app.snap('kayıtlı cihaz: mTLS bağlantısı geçiyor');
      expect(status).toContain('HTTP 200');
    });

    await test.step('Mobil: Depolama ekranında sertifika kaydı görünüyor', async () => {
      await app.backToMain();
      await app.openStorage();
      const text = await app.storageText();
      await app.snap('Depolama: istemci sertifikası kayıtlı');
      const lines = text.split('\n').filter((l) => /İstemci sertifikası|kayıtlı|PKCS12/i.test(l));
      await attachText(testInfo, 'Depolama ekranı — kayıt varken', lines.join('\n'));
      expect(text).toContain(`kayıtlı — CN=${cn}`);
      expect(text).toContain('hayır ✓ (şifreli)');
      await app.backToMain();
    });

    await test.step('Mobil: "Kaydı sil" — uygulama yeniden açılmadan mTLS reddediliyor', async () => {
      device.clearLogcat();
      await app.openMtls();
      expect(await app.unenroll()).toContain('Kayıt silindi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('kayıt silindi');
      const refused = await app.expectMtls(false);
      await app.snap('uygulama yeniden açılmadan mTLS reddedildi');
      const log = device.logcat({ tags: ['PinVault', 'DynamicSSLManager'] });
      await attachText(
        testInfo,
        'logcat — kayıt silme',
        [
          log
            .split('\n')
            .filter((l) => /Client certificate removed|Client keystore cleared|Applied dynamic pinning/.test(l))
            .join('\n') || '(ilgili satır yok)',
          '',
          'PinVault.unenroll hem ClientCertSecureStore kaydını siliyor hem de her Config',
          'API bloğunun DynamicSSLManager\'ındaki KeyManager\'ı boşaltıp istemciyi yeniden',
          'kuruyor (clearClientKeystore + clientProvider.swap). Örnek uygulama ayrıca',
          'PinVault\'u yeniden başlatıyor.',
        ].join('\n'),
      );
      expect(refused).toContain('mTLS bağlantısı reddedildi');
      expect(log).toMatch(/Client certificate removed/);
    });

    await test.step('Mobil: cihazda sertifika kaydı kalmadı', async () => {
      await app.backToMain();
      await app.openStorage();
      const text = await app.storageText();
      await app.snap('Depolama: istemci sertifikası yok');
      const prefs = device.runAs(env.APP_ID, 'cat shared_prefs/pinvault_client_cert.xml 2>/dev/null || echo "(dosya yok)"');
      await attachText(
        testInfo,
        `run-as ${env.APP_ID} — shared_prefs/pinvault_client_cert.xml`,
        [
          prefs.trim().slice(0, 1200),
          '',
          'Kayıt silindikten sonra dosyada P12 kaydı yok (yalnızca Tink keyset\'i kalabilir).',
        ].join('\n'),
      );
      await attachText(
        testInfo,
        'Depolama ekranı — kayıt silindikten sonra',
        text.split('\n').filter((l) => /İstemci sertifikası|kayıtlı|elle yüklenen/i.test(l)).join('\n'),
      );
      expect(text).toContain('kayıtlı değil');
      expect(prefs).not.toContain('pinvault_client_cert_default');
      await app.backToMain();
    });

    await test.step('Mobil: uygulama yeniden açılınca da reddediliyor', async () => {
      app.relaunch();
      await app.waitReady();
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const refused = await app.expectMtls(false);
      await app.snap('yeniden açılışta da reddediliyor');
      expect(refused).toContain('mTLS bağlantısı reddedildi');
      await app.backToMain();
    });

    await test.step('Web: sunucudaki sertifika hâlâ etkin — red cihaz tarafında', async () => {
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: false });
      await dashboard.snap('sunucuda sertifika hâlâ etkin');
      const cert = (await hostApi.clientCerts()).find((c) => c.id === clientId);
      await attachText(
        testInfo,
        'GET /api/v1/client-certs',
        [
          `id: ${cert.id}`,
          `commonName: ${cert.commonName}`,
          `revoked: ${cert.revoked}`,
          '',
          'Sertifika sunucuda iptal edilmedi ve truststore\'da duruyor; bağlantının',
          'reddedilmesinin tek nedeni cihazın artık istemci sertifikası sunmaması.',
        ].join('\n'),
      );
      expect(cert.revoked).toBe(false);
    });
  } finally {
    await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
