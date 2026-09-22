// B02 — Host'a özel istemci sertifikası (HostPin.mtls + clientCertVersion).
//
// Dashboard'da mock mTLS hedefi mTLS olarak işaretlenir ve o host için ayrı bir
// istemci P12'si yüklenir. Kütüphane bu sertifikayı `clientCertVersion`
// değiştiğinde Config API'den indirir (SSLCertificateUpdater.syncHostClientCerts).
//
// Bilinen kısıt burada kanıtlanıyor: `GET /api/v1/client-certs/{host}/download`
// yalnızca mTLS modundaki dinleyicide servis ediliyor; TLS Config API 403
// döndürüyor. Yani TLS modundaki bir cihaz host'a özel sertifikayı hiç
// alamıyor, mTLS config modundaki cihaz alıyor. İki davranış da telefondan ve
// kablodan gösteriliyor.
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const WORK_DIR = path.join(env.LOCAL_DIR, 'b02');
const P12 = path.join(WORK_DIR, 'host-client.p12');
const CERT_PEM = path.join(WORK_DIR, 'host-client-cert.pem');
const KEY_PEM = path.join(WORK_DIR, 'host-client-key.pem');
const DL = path.join(WORK_DIR, 'downloaded.p12');

/** P12'yi curl'ün kullanabileceği sertifika + anahtar dosyalarına ayırır. */
function splitP12(p12, password = 'changeit') {
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nokeys', '-out', CERT_PEM]);
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nocerts', '-nodes', '-out', KEY_PEM]);
  return execFileSync('openssl', ['x509', '-in', CERT_PEM, '-noout', '-subject'], { encoding: 'utf8' }).trim();
}

test('mTLS: host\'a özel istemci sertifikası yalnızca mTLS dinleyiciden iniyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  const stamp = Date.now();
  const hostCertId = `b02-host-${stamp}`;
  const deviceCertId = `b02-device-${stamp}`;
  fs.mkdirSync(WORK_DIR, { recursive: true });
  let pinVersionBefore;

  try {
    await test.step('Web: host için ayrı bir istemci sertifikası üretilir', async () => {
      await dashboard.generateClientCert(env.MTLS_API, hostCertId, { saveTo: P12 });
      const subject = splitP12(P12);
      await dashboard.snapClientCertTable(`host istemci sertifikası üretildi: ${hostCertId}`);
      await attachText(
        testInfo,
        'Dashboard → Client Cert Üret (P12 indirildi)',
        [`dosya: ${path.basename(P12)} — ${fs.statSync(P12).size} bayt`, `subject: ${subject}`].join('\n'),
      );
      expect(subject).toContain(hostCertId);
    });

    await test.step('Mobil: cihaz kendi kayıt sertifikasını alır', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, deviceCertId);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=PinVault Client: ${deviceCertId}`);
      await app.snap('cihaz kayıt sertifikası alındı');
      await app.backToMain();
      // Kayıt sunucudaki mTLS dinleyicileri yeni truststore ile yeniden
      // başlatıyor; yukarıda üretilen host sertifikası da artık güvenilir.
    });

    await test.step('Web: mock mTLS host\'u mTLS olarak işaretlenir ve host P12\'si yüklenir', async () => {
      pinVersionBefore = (await hostApi.getConfig()).pins.find((p) => p.hostname === env.MOCK_MTLS_HOST).version;
      await dashboard.setHostMtls(env.VAULT_API, env.MOCK_MTLS_HOST, true);
      const afterToggle = (await hostApi.getConfig()).pins.find((p) => p.hostname === env.MOCK_MTLS_HOST).version;
      const response = await dashboard.uploadHostClientCert(env.VAULT_API, env.MOCK_MTLS_HOST, P12);
      await dashboard.snapCard('#host-client-cert-card', `${env.MOCK_MTLS_HOST} host istemci sertifikası`);
      const after = (await hostApi.getConfig()).pins.find((p) => p.hostname === env.MOCK_MTLS_HOST);
      const info = await hostApi.hostClientCertInfo(env.VAULT_API, env.MOCK_MTLS_HOST);
      await attachText(
        testInfo,
        `POST /api/v1/hosts/${env.MOCK_MTLS_HOST}/upload-client-cert?configApiId=${env.VAULT_API}`,
        [
          response,
          '',
          `pin kaydı: mtls=${after.mtls}, clientCertVersion=${after.clientCertVersion}, version=${after.version}`,
          `sunucudaki kayıt: CN=${info.commonName}, v${info.version}`,
          '',
          `Host pin sürümü her iki işlemde de artıyor: v${pinVersionBefore} → v${afterToggle} (mTLS bayrağı)`,
          `→ v${after.version} (host istemci sertifikası). Kütüphanenin değişiklik algılaması host`,
          'pin sürümüne bakıyor; sürüm artmasaydı config\'i daha önce almış bir cihaz',
          'SSLCertificateUpdater.updateNow\'da "AlreadyCurrent" alır ve syncHostClientCerts hiç',
          'çalışmazdı — sertifika yalnızca verisi silinmiş cihaza ulaşırdı.',
        ].join('\n'),
      );
      expect(after.mtls).toBe(true);
      expect(after.clientCertVersion).toBeGreaterThan(0);
      expect(afterToggle).toBe(pinVersionBefore + 1);
      expect(after.version).toBe(afterToggle + 1);
    });

    await test.step('Terminal: TLS Config API host sertifikasını vermiyor (403)', async () => {
      const out = await attachCommand(
        testInfo,
        `TLS Config API :${env.CONFIG_API_PORT} — host sertifikası indirme`,
        'curl',
        ['-sS', '-k', '-w', '\n[HTTP %{http_code}]', '--max-time', '15',
          `https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/client-certs/${env.MOCK_MTLS_HOST}/download`],
      );
      expect(out).toContain('[HTTP 403]');
      expect(out).toContain('only available via mTLS Config API');
    });

    await test.step('Mobil: TLS modunda kütüphane sertifikayı indiremiyor', async () => {
      device.clearLogcat();
      await app.openSettings();
      // "Sıfırla ve yeniden başlat": saklı config silinir, config sıfırdan
      // çekilir — böylece mTLS bayraklı yeni kayıt da görülür.
      expect(await app.restart()).toContain('Hazır — config v');
      await app.backToMain();
      await app.snap('TLS modunda yeniden başlatıldı');
      const log = device.logcat({ tags: ['SSLCertificateUpdater', 'DynamicSSLManager'] });
      await attachText(
        testInfo,
        'logcat — TLS modunda host sertifikası eşitlemesi',
        [log || '(ilgili satır yok)', '', 'Beklenen: 403 yüzünden host sertifikası yüklenmiyor (hostCerts=0).'].join('\n'),
      );
      expect(log).toMatch(/Host client cert unavailable for mock-mtls\.sample|HTTP 403/);
      await app.openMtls();
      const mock = await app.expectMockMtls(true);
      await app.snap('TLS modunda mock mTLS: kayıt sertifikasıyla bağlanıyor');
      await app.backToMain();
      await attachText(
        testInfo,
        'TLS modunda mock mTLS bağlantısı',
        [
          mock,
          '',
          'Bağlantı yine de geçiyor: composite KeyManager host\'a özel sertifika yokken',
          'varsayılan (kayıt) sertifikasına düşüyor ve mock host\'un truststore\'u bütün',
          'istemci sertifikalarını tanıyor. Yani TLS modunda host\'a özel sertifika hiç',
          'devreye girmiyor.',
        ].join('\n'),
      );
    });

    await test.step('Web: aynı sertifika mTLS Config API kapsamına da yüklenir', async () => {
      await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await dashboard.setHostMtls(env.MTLS_API, env.MOCK_MTLS_HOST, true);
      const response = await dashboard.uploadHostClientCert(env.MTLS_API, env.MOCK_MTLS_HOST, P12);
      await dashboard.snapCard('#host-client-cert-card', `${env.MTLS_API} kapsamında host istemci sertifikası`);
      const scope = await hostApi.scopedConfig(env.MTLS_API);
      const pin = scope.pins.find((p) => p.hostname === env.MOCK_MTLS_HOST);
      await attachText(
        testInfo,
        `POST /api/v1/hosts/${env.MOCK_MTLS_HOST}/upload-client-cert?configApiId=${env.MTLS_API}`,
        [
          response,
          '',
          `${env.MTLS_API} kapsamı: mtls=${pin.mtls}, clientCertVersion=${pin.clientCertVersion}`,
          '',
          'Host\'a özel sertifika deposu (host_client_certs) hostname + configApiId ile',
          'anahtarlanıyor: aynı P12 her kapsama ayrı yükleniyor.',
        ].join('\n'),
      );
      expect(pin.clientCertVersion).toBeGreaterThan(0);
    });

    await test.step('Terminal: mTLS Config API sertifikayı istemci sertifikası sunana veriyor (200)', async () => {
      const out = await attachCommand(
        testInfo,
        `mTLS Config API :${env.MTLS_API_PORT} — host sertifikası indirme (curl --cert/--key)`,
        'curl',
        ['-sS', '-k', '--cert', CERT_PEM, '--key', KEY_PEM, '-o', DL,
          '-w', 'HTTP %{http_code} — %{size_download} bayt indirildi\n', '--max-time', '20',
          `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/client-certs/${env.MOCK_MTLS_HOST}/download`],
      );
      expect(out).toContain('HTTP 200');
      const subject = splitP12(DL);
      await attachText(
        testInfo,
        'İnen dosya bir PKCS12 istemci sertifikası',
        [`${fs.statSync(DL).size} bayt`, `subject: ${subject}`, '', 'Yüklenen P12 ile aynı istemci kimliği.'].join('\n'),
      );
      expect(subject).toContain(hostCertId);
    });

    await test.step('Mobil: mTLS config modunda host sertifikası iniyor', async () => {
      device.clearLogcat();
      await app.openSettings();
      expect(await app.applyMode('MTLS_CONFIG')).toContain('Hazır — config v');
      await app.backToMain();
      await app.snap('mTLS config modu — host sertifikası eşitlendi');
      const log = device.logcat({ tags: ['SSLCertificateUpdater', 'DynamicSSLManager'] });
      await attachText(testInfo, 'logcat — mTLS config modunda host sertifikası eşitlemesi', log);
      expect(log).toContain(`Host client cert downloaded: ${env.MOCK_MTLS_HOST}`);
      expect(log).toMatch(/Loaded 1 host-specific client certs/);
      await app.openMtls();
      expect(await app.expectMockMtls(true)).toContain('HTTP 200');
      await app.snap('mTLS config modu: mock mTLS host bağlantısı');
      await app.backToMain();
    });

    await test.step('Sunucu: 403 ürün kararı mı, hata mı — değerlendirme', async () => {
      await attachText(
        testInfo,
        'Host\'a özel sertifika yalnızca mTLS dinleyicide — değerlendirme',
        [
          'Sunucu kodu bunu bilerek yapıyor (CertificateConfigRoute):',
          '  if (configApiMode == "tls") → 403 "Host client certs are only available via',
          '  mTLS Config API. Enroll first ... then use the mTLS endpoint".',
          '',
          'Karar doğru: TLS dinleyicide çağıranın kimliği yok. Uç yalnızca API anahtarı',
          'istemeyen cihaz uçları arasında; TLS üzerinden servis edilse herkes herhangi bir',
          'host\'un özel anahtarını indirebilirdi. mTLS dinleyicide çağıran doğrulanmış bir',
          'istemci sertifikası sunuyor.',
          '',
          'Eksik olan: kütüphane tarafında bu kısıt yok. TLS bloğundaki bir host mtls=true',
          'işaretlenirse SSLCertificateUpdater her config güncellemesinde 403 alan bir istek',
          'atıyor ve sessizce vazgeçiyor; uygulamaya "bu host için özel sertifika alınamadı"',
          'diye bir sinyal gitmiyor. Öneri: (a) dashboard mTLS bayrağını yalnızca mTLS',
          'kapsamındaki host\'larda açtırsın ya da uyarı göstersin, (b) kütüphane 403 durumunu',
          'InitResult/UpdateResult\'a yansıtsın.',
          '',
          'Daha önce burada raporlanan ikinci bulgu düzeltildi: `toggle-mtls` ve',
          '`upload-client-cert` artık host pin sürümünü de artırıyor (yukarıdaki panel),',
          'böylece değişiklik yalnızca sıfırlanmış cihaza değil, config\'i zaten almış',
          'cihazlara da ulaşıyor.',
        ].join('\n'),
      );
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
    await hostApi.clearHostMtlsFlags(env.MOCK_MTLS_HOST).catch(() => {});
    await hostApi.revokeClientCertIfActive(hostCertId).catch(() => {});
    await hostApi.revokeClientCertIfActive(deviceCertId).catch(() => {});
  }
});
