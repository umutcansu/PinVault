// B03 — mTLS config + mTLS hedef birlikte: composite KeyManager host'a göre
// doğru istemci sertifikasını seçiyor mu?
//
// Cihazda iki ayrı istemci kimliği var:
//   • kayıt sertifikası  → mTLS Config API'ye (https://<ip>:6652) sunuluyor
//   • host'a özel sertifika → mock mTLS hedefine (mock-mtls.sample:6654)
//
// Seçimin gerçekten host'a göre yapıldığı, kayıt sertifikası dashboard'dan
// iptal edilerek kanıtlanıyor: aynı süreçte Config API bağlantısı reddediliyor
// ama mock mTLS hedefine bağlantı sürüyor. Tek bir sertifika kullanılsaydı iki
// bağlantı da aynı anda düşerdi.
const path = require('path');
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const WORK_DIR = path.join(env.LOCAL_DIR, 'b03');
const P12 = path.join(WORK_DIR, 'host-client.p12');

test('mTLS: composite KeyManager Config API\'ye kayıt sertifikasını, mock host\'a ise ona özel sertifikayı sunuyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  let p12Password; // panelin bir kez gösterdiği tek kullanımlık P12 parolası (2.4.2)
  test.setTimeout(14 * 60 * 1000);
  const stamp = Date.now();
  const hostCertId = `b03-host-${stamp}`;
  const deviceCertId = `b03-device-${stamp}`;
  fs.mkdirSync(WORK_DIR, { recursive: true });

  try {
    await test.step('Web: host\'a özel sertifika üretilir, cihaz ayrıca kayıt olur', async () => {
      await dashboard.generateClientCert(env.MTLS_API, hostCertId, { saveTo: P12 });
      p12Password = dashboard.lastP12Password;
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, deviceCertId);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=PinVault Client: ${deviceCertId}`);
      await app.snap('cihaz kayıt sertifikası');
      await app.backToMain();
      const certs = await hostApi.clientCerts();
      const active = certs.filter((c) => !c.revoked).map((c) => c.id);
      await attachText(
        testInfo,
        'Sunucudaki etkin istemci sertifikaları',
        [
          ...active.map((id) => `• ${id}`),
          '',
          `kayıt sertifikası : ${deviceCertId}  → mTLS Config API için`,
          `host sertifikası  : ${hostCertId}  → ${env.MOCK_MTLS_HOST} için`,
        ].join('\n'),
      );
      expect(active).toEqual(expect.arrayContaining([hostCertId, deviceCertId]));
    });

    await test.step('Web: mTLS Config API\'nin host\'ları ve host\'a özel sertifika hazırlanır', async () => {
      await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await dashboard.setHostMtls(env.MTLS_API, env.MOCK_MTLS_HOST, true);
      const response = await dashboard.uploadHostClientCert(env.MTLS_API, env.MOCK_MTLS_HOST, P12, p12Password);
      await dashboard.snapCard('#host-client-cert-card', `${env.MOCK_MTLS_HOST} → ${hostCertId}`);
      const scope = await hostApi.scopedConfig(env.MTLS_API);
      await attachText(
        testInfo,
        `${env.MTLS_API} içindeki host'lar`,
        [
          response,
          '',
          ...scope.pins.map(
            (p) => `${p.hostname} v${p.version} mtls=${p.mtls} clientCertVersion=${p.clientCertVersion ?? '—'}`,
          ),
        ].join('\n'),
      );
      expect(scope.pins.find((p) => p.hostname === env.LAN_IP).mtls).toBe(false);
      expect(scope.pins.find((p) => p.hostname === env.MOCK_MTLS_HOST).mtls).toBe(true);
    });

    await test.step('Mobil: mTLS config modunda iki sertifika da yükleniyor', async () => {
      device.clearLogcat();
      await app.openSettings();
      expect(await app.applyMode('MTLS_CONFIG')).toContain('Hazır — config v');
      await app.backToMain();
      await app.snap('mTLS config modu hazır');
      const log = device.logcat({ tags: ['SSLCertificateUpdater', 'DynamicSSLManager'] });
      await attachText(
        testInfo,
        'logcat — yüklenen istemci sertifikaları',
        [
          log,
          '',
          `Beklenen: "Host client key loaded: ${env.MOCK_MTLS_HOST}" (anahtar Android Keystore\'a dışarı çıkarılamaz`,
          'olarak alındı: "key in Keystore: true") ve pinleme uygulanırken defaultCert=true, hostCerts=1.',
          'Sertifikanın adı (CN = cihaz kimliği) gizlilik için artık günlüğe yazılmıyor.',
        ].join('\n'),
      );
      expect(log).toMatch(new RegExp(`Host client (key|cert) loaded: ${env.MOCK_MTLS_HOST.replace(/\./g, '\\.')}`));
      expect(log).toContain('key in Keystore: true');
      expect(log).not.toContain(hostCertId);
      expect(log).toMatch(/defaultCert=true, hostCerts=1/);
    });

    await test.step('Mobil: iki mTLS bağlantısı da geçiyor', async () => {
      await app.openMtls();
      const api = await app.expectMtls(true);
      await app.snap('Config API bağlantısı (kayıt sertifikası)');
      const mock = await app.expectMockMtls(true);
      await app.snap('mock mTLS host bağlantısı (host sertifikası)');
      await app.backToMain();
      await attachText(
        testInfo,
        'İki mTLS hedefi',
        [`https://${env.LAN_IP}:${env.MTLS_API_PORT}/health`, api, '', `${env.MOCK_MTLS_HOST}:${env.MOCK_MTLS_PORT}`, mock].join('\n'),
      );
      expect(api).toContain('HTTP 200');
      expect(mock).toContain('HTTP 200');
    });

    await test.step('Web: yalnızca kayıt sertifikası iptal ediliyor', async () => {
      await dashboard.revokeClientCert(env.MTLS_API, deviceCertId);
      await dashboard.expectClientCert(env.MTLS_API, deviceCertId, { revoked: true });
      await dashboard.expectClientCert(env.MTLS_API, hostCertId, { revoked: false });
      await dashboard.snap('kayıt sertifikası iptal, host sertifikası etkin');
      const logs = hostControl.logs(40);
      await attachText(
        testInfo,
        'Sunucu logu — iptal sonrası mTLS sunucuları yeniden başlıyor',
        logs
          .split('\n')
          .filter((l) => /Restarting|Auto-restarting|Mock server/.test(l))
          .slice(-8)
          .join('\n'),
      );
    });

    await test.step('Mobil: Config API reddediyor, mock mTLS hedefi kabul ediyor', async () => {
      await app.openMtls();
      const api = await app.expectMtls(false);
      await app.snap('iptal sonrası Config API reddediyor');
      const mock = await app.expectMockMtls(true);
      await app.snap('iptal sonrası mock mTLS host hâlâ kabul ediyor');
      await app.backToMain();
      await attachText(
        testInfo,
        'Composite KeyManager kanıtı: sertifika host\'a göre seçiliyor',
        [
          `Config API (${env.LAN_IP}) — kayıt sertifikası iptal edildi:`,
          api,
          '',
          `${env.MOCK_MTLS_HOST} — host'a özel sertifika hâlâ geçerli:`,
          mock,
          '',
          'Uygulama yeniden açılmadan, aynı PinVault örneği ve aynı pinli istemciyle iki',
          'farklı sonuç: DynamicSSLManager.buildCompositeKeyManagers el sıkışmadaki',
          'peerHost\'a bakarak host\'a özel KeyManager\'ı seçiyor, bulamazsa varsayılan',
          '(kayıt) sertifikasını kullanıyor. Tek bir sertifika sunulsaydı iki bağlantı',
          'da reddedilirdi.',
        ].join('\n'),
      );
      expect(api).toContain('reddedildi');
      expect(mock).toContain('HTTP 200');
    });

    await test.step('Web: mock mTLS hedefinin bağlantı geçmişinde cihaz görünüyor', async () => {
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.openHostIn(env.VAULT_API, env.MOCK_MTLS_HOST);
      await dashboard.expectLatestConnection(run.model, { status: 'healthy' });
      await dashboard.snapCard('#conn-history-card', `${env.MOCK_MTLS_HOST} bağlantı geçmişi`);
      const history = (await hostApi.connectionHistory(env.MOCK_MTLS_HOST))
        .filter((e) => e.deviceModel === run.model)
        .slice(0, 3);
      await attachText(
        testInfo,
        `GET /api/v1/connection-history/${env.MOCK_MTLS_HOST}`,
        history.map((e) => `${e.timestamp} ${e.status} pinVersion=${e.pinVersion} ${e.deviceModel}`).join('\n'),
      );
      expect(history.length).toBeGreaterThan(0);
    });

    await test.step('Mobil: TLS moduna dönülüyor', async () => {
      await app.openSettings();
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
      expect(await app.waitReady()).toContain('Mod: TLS config');
      await app.snap('TLS moduna dönüldü');
    });
  } finally {
    await mtlsScope.reset().catch(() => {});
    await hostApi.revokeClientCertIfActive(hostCertId).catch(() => {});
    // İptal + unut: token telefona bağlı, kimlik cihazı kanıtlıyor (bkz. retireClientIdentity).
    await hostApi.retireClientIdentity(deviceCertId);
  }
});
