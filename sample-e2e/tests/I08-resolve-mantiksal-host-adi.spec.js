// I08 — iOS: mock host adları resolve(host:to:) ile host IP'sine gidiyor.
//
// mock-tls.sample ve mock-mtls.sample gerçek DNS'te yok; sertifikaları bu
// adlara kesilmiş. Android örneği OkHttp Dns'i (MockDns) kullanıyor; iOS'ta
// URLSession'a özel DNS verilemediği için kütüphane PinVaultConfig.Builder
// .resolve(host:to:) ile adı adrese eşliyor: istek IP'ye gidiyor, ama pin, ad
// doğrulaması ve istemci sertifikası seçimi mantıksal adla yapılıyor. Mac'in ve
// simülatörün /etc/hosts'una dokunulmuyor.
//
// Kanıt: /etc/hosts'ta ve DNS'te ad yok; telefon adla bağlanıyor ve günlükte pin
// "host=mock-tls.sample" için doğrulanıyor; sunucuda o ada yanlış pin yazılınca
// telefon reddediyor; mTLS mock'u istemci sertifikasını yalnızca kayıttan sonra
// alıyor ve sertifika iptal edilince aynı mock reddediyor (sertifikayı gerçekten
// o host'a sunduğunun kanıtı).
const dns = require('dns');
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: resolve(host:to:) (Android karşılığı OkHttp Dns / MockDns)');

test('iOS: mock host\'lar /etc/hosts olmadan resolve ile bulunuyor; pin ve istemci sertifikası mantıksal adla seçiliyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const clientId = `i08-cihaz-${Date.now()}`;
  let wrongPinsSet = false;

  try {
    await test.step('Mac: /etc/hosts\'ta mock-tls.sample yok, DNS adı çözemiyor', async () => {
      const hosts = fs.readFileSync('/etc/hosts', 'utf8');
      const lookups = [];
      for (const name of [env.MOCK_TLS_HOST, env.MOCK_MTLS_HOST]) {
        lookups.push(await dns.promises.lookup(name).then((r) => `${name} → ${r.address} ✗`, (e) => `${name} → ${e.code} ✓`));
      }
      await attachText(testInfo, '/etc/hosts ve DNS', [
        '$ cat /etc/hosts',
        hosts.trim(),
        '',
        `$ grep ${env.MOCK_TLS_HOST} /etc/hosts → ${hosts.includes(env.MOCK_TLS_HOST) ? 'VAR ✗' : '(yok) ✓'}`,
        '',
        'getaddrinfo (Mac; simülatör Mac\'in çözücüsünü kullanır):',
        ...lookups,
      ].join('\n'));
      expect(hosts).not.toContain(env.MOCK_TLS_HOST);
      expect(hosts).not.toContain(env.MOCK_MTLS_HOST);
      expect(lookups.every((l) => l.endsWith('✓'))).toBe(true);
    });

    await test.step('Mobil: Mock TLS host adla bağlanıyor; pin mantıksal adla doğrulanıyor', async () => {
      device.clearLogcat();
      await app.openMtls();
      const status = await app.mockTls();
      await app.snap('mock-tls.sample bağlantısı başarılı');
      expect(status).toContain('host bağlantısı başarılı');
      const log = device.logcat({ tags: ['DynamicSSLManager'], match: /Pin verified/ });
      await attachText(testInfo, 'log show — DynamicSSLManager', [
        log || '(satır yok)',
        '',
        `Uygulamanın config'i: resolve(host: "${env.MOCK_TLS_HOST}", to: "${env.LAN_IP}") — istek ${env.LAN_IP}:${env.MOCK_TLS_PORT}'e`,
        `gidiyor (Host: ${env.MOCK_TLS_HOST}), oturumun pin ve ad denetimi "${env.MOCK_TLS_HOST}" için.`,
      ].join('\n'));
      expect(log).toContain(`host=${env.MOCK_TLS_HOST}`);
    });

    await test.step('Web → Mobil: sunucuda mock-tls.sample\'a yanlış pin yazılınca telefon reddediyor', async () => {
      await dashboard.openHost(env.MOCK_TLS_HOST);
      const v0 = await dashboard.version();
      await dashboard.setPins(env.MOCK_TLS_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
      wrongPinsSet = true;
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      await dashboard.snapHostSummary(`${env.MOCK_TLS_HOST}: yanlış pin'ler, v${v0 + 1}`);
      await app.backToMain();
      expect(await app.refreshConfig()).toMatch(/Yeni config uygulandı|Config güncel/);
      await app.openMtls();
      const status = await app.mockTls();
      await app.snap('yanlış pin — mock-tls.sample reddedildi');
      await attachText(testInfo, 'Sonuç kutusu (yanlış pin)', status);
      expect(status).toContain('host bağlantısı reddedildi');
    });

    await test.step('Web → Mobil: doğru pin geri yazılınca bağlantı geri geliyor', async () => {
      await dashboard.setPins(env.MOCK_TLS_HOST, run.baseline[env.MOCK_TLS_HOST]);
      wrongPinsSet = false;
      await app.backToMain();
      await app.refreshConfig();
      await app.openMtls();
      const status = await app.expectRepeated(() => app.mockTls(), 'host bağlantısı başarılı', 30_000);
      await app.snap('doğru pin — mock-tls.sample yine başarılı');
      expect(status).toContain('host bağlantısı başarılı');
    });

    await test.step('Mobil: kayıt yokken mTLS mock\'u istemci sertifikası alamıyor ve reddediyor', async () => {
      await hostApi.forgetRevokedIdentitiesOf(app.mtlsDeviceId());
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const status = await app.mockMtls();
      await app.snap('kayıt yok — mock-mtls.sample reddetti');
      expect(status).toContain('host bağlantısı reddedildi');
    });

    await test.step('Web → Mobil: kayıttan sonra sertifika mantıksal adla seçilip mTLS mock\'una sunuluyor', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId, { deviceUid: app.mtlsDeviceId() });
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
      device.clearLogcat();
      const status = await app.expectMockMtls(true);
      await app.snap('kayıt sonrası mock-mtls.sample kabul etti');
      const log = device.logcat({ tags: ['DynamicSSLManager'], match: /Pin verified/ });
      await attachText(testInfo, 'log show — mock mTLS bağlantısı', [
        status, '', log || '(satır yok)', '',
        `Uygulama varsayılan kimliği clientCertHosts(${env.MOCK_MTLS_HOST}:${env.MOCK_MTLS_PORT}) ile bu ada bağladı;`,
        `istek ${env.LAN_IP}'ye gitse de oturum kimliği "${env.MOCK_MTLS_HOST}" için seçiyor.`,
      ].join('\n'));
      expect(status).toContain('HTTP 200');
      expect(log).toContain(`host=${env.MOCK_MTLS_HOST}`);
      expect(log).toMatch(new RegExp(`host=${env.MOCK_MTLS_HOST.replace(/\./g, '\\.')}.*clientCert=true`));
    });

    await test.step('Web → Mobil: kimlik iptal edilince aynı mTLS mock\'u reddediyor (sunulan sertifika buydu)', async () => {
      await dashboard.revokeClientCert(env.MTLS_API, clientId);
      const status = await app.expectMockMtls(false, 45_000);
      await app.snap('kimlik iptal edildi — mock-mtls.sample reddetti');
      await attachText(testInfo, 'Sonuç kutusu (iptal sonrası mock mTLS)', [
        status, '',
        'Mock mTLS host\'u iptal listesini (RevocationGate) her istekte uyguluyor: reddettiği,',
        `telefonun ona sunduğu sertifikanın ${clientId} kimliğine ait olduğunu gösteriyor.`,
      ].join('\n'));
      expect(status).toContain('host bağlantısı reddedildi');
    });
  } finally {
    if (wrongPinsSet) await hostApi.restoreBaseline(run.baseline).catch(() => {});
    await hostApi.retireClientIdentity(clientId);
  }
});
