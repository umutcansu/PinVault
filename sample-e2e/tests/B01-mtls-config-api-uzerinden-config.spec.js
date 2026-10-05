// B01 — Config'in mTLS Config API üzerinden çekilmesi.
//
// Cihaz önce TLS bloğundan kayıt olur (tek kullanımlık token), sonra Ayarlar'dan
// MTLS_CONFIG moduna geçer: artık birincil Config API bloğu
// https://<ip>:6652 ve kütüphane her config isteğinde istemci sertifikasını
// sunuyor. Aynı adrese sertifikasız yapılan istek TLS el sıkışmasında
// reddediliyor — kanıt olarak curl paneli.
//
// Yol boyunca şüphede bağlantıya izin vermeyen iki davranış da belgeleniyor:
//   • mTLS config modu istemci sertifikası yokken hiç başlamıyor.
//   • mTLS Config API'nin kendi pin kapsamı boşken kütüphane config'i
//     reddediyor ("at least one pin entry") ve başlatma düşüyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachFailingCommand, redact } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const MTLS_URL = `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/certificate-config?signed=false`;

test('mTLS: cihaz config\'i mTLS Config API\'den istemci sertifikasıyla çeker', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const clientId = `b01-${Date.now()}`;
  const cn = `PinVault Client: ${clientId}`;
  let token;

  try {
    await test.step('Mobil: sertifika yokken mTLS config modu hiç başlamıyor', async () => {
      await app.openSettings();
      const result = await app.applyMode('MTLS_CONFIG');
      expect(result).toContain('istemci sertifikası gerekir');
      await app.snap('sertifikasız mTLS config modu reddedildi');
      // Geri TLS moduna: kayıt varsayılan (TLS) blok üzerinden yapılıyor.
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
    });

    await test.step('Web: kayıt token\'ı üretilir ve cihaz kayıt olur', async () => {
      token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      await dashboard.snapTokenList(env.MTLS_API, `tek kullanımlık kayıt token'ı: ${clientId} bekliyor`, [{ clientId, status: 'Bekliyor' }]);
      await app.openMtls();
      const status = await app.enroll(token);
      expect(status).toContain(`Kayıt başarılı — CN=${cn}`);
      await app.snap('token ile kayıt başarılı');
      await attachText(
        testInfo,
        'Kayıt',
        [
          `istemci kimliği: ${clientId}`,
          `token (kısaltılmış): ${redact(token)}`,
          `sertifika CN: ${cn}`,
          'P12, X-P12-SHA256 başlığındaki hash ile doğrulanıp şifreli depoya yazıldı.',
        ].join('\n'),
      );
      await app.backToMain();
    });

    await test.step('Mobil: mTLS Config API\'de hiç pin yokken başlatma başarısız (şüphede bağlantıya izin yok)', async () => {
      // Temel durumda mTLS Config API'nin kendi kapsamı boş (provision.sh onu
      // yalnızca dinleyici olarak açar); yarıda kalmış bir koşu bırakmışsa sil.
      await mtlsScope.reset();
      const scope = await hostApi.scopedConfig(env.MTLS_API);
      expect(scope.pins || []).toHaveLength(0);
      await app.openSettings();
      const result = await app.applyMode('MTLS_CONFIG');
      expect(result).toContain('başlatılamadı');
      expect(result).toContain('at least one pin');
      await app.backToMain();
      const status = await app.waitInitFailed();
      await app.snap('mTLS Config API\'de pin yok: başlatma reddedildi');
      // Başlatma düştüğü için uygulama pinli istek düğmelerini hiç açmıyor:
      // fail-closed'ın uçtaki görünümü bu.
      await app.openMtls();
      await app.waitFor('mtlsTestButton', (n) => !n.enabled, { what: 'mTLS testi kapalı' });
      await app.snap('pin yok: pinli istek denenemiyor');
      await app.backToMain();
      await attachText(
        testInfo,
        `mTLS Config API'de hiç pin yokken (GET /api/v1/config/${env.MTLS_API} → pins: [])`,
        [
          'Ayarlar sonucu:',
          result,
          '',
          'Ana ekran:',
          status,
          '',
          'mTLS ekranı: "mTLS ile test" düğmesi kapalı (init READY değil).',
          '',
          'Boş config "değişiklik yok" sayılmıyor, hata sayılıyor: SSLCertificateUpdater.updateNow',
          'boş pin listesini her zaman değişiklik kabul edip doğruluyor ve',
          '"Config must contain at least one pin entry" ile reddediyor. Birincil blok',
          '(mTLS) başarısız olunca init de başarısız oluyor. Eskiden bu durumda',
          'AlreadyCurrent dönüyor, InitResult.Ready(v0) veriliyordu; durum kutusu',
          'hiç pin yokken "Hazır" diyordu.',
          '',
          'Not: mesajın başındaki "No stored config and backend unreachable" sunucuya',
          'ulaşılamadığını değil, bu blok için kullanılabilir hiçbir config olmadığını',
          'anlatıyor: sunucu yanıt verdi, yanıtı reddedildi.',
        ].join('\n'),
      );
    });

    await test.step('Web: mTLS Config API\'ye host\'lar eklenir', async () => {
      const report = await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await dashboard.snap('mTLS Config API\'deki host\'lar');
      await attachText(
        testInfo,
        'POST /api/v1/hosts/upload-cert?configApiId=sample-mtls ("+ → Yükle")',
        [
          'Host keystore\'ları container\'dan alınıp dashboard\'ın "Yükle" sekmesinden',
          'mTLS Config API\'ye eklendi; pin\'leri sunucu sertifikadan hesapladı.',
          '',
          report,
        ].join('\n'),
      );
      const scope = await hostApi.scopedConfig(env.MTLS_API);
      expect(scope.pins.map((p) => p.hostname).sort()).toEqual([env.LAN_IP, env.MOCK_MTLS_HOST].sort());
    });

    await test.step('Mobil: mTLS config modu hazır — pin kaynağı mTLS adresi', async () => {
      await app.openSettings();
      const result = await app.applyMode('MTLS_CONFIG');
      expect(result).toContain('Hazır — config v');
      await app.backToMain();
      const status = await app.waitReady();
      await app.snap('mTLS config modu hazır');
      expect(status).toContain('Mod: mTLS config');
      expect(status).toContain(`Pin kaynağı: https://${env.LAN_IP}:${env.MTLS_API_PORT}/ (mTLS)`);
      // Birincil blok artık mTLS kapsamının pin'lerini uyguluyor.
      expect(status).toContain(`${env.MOCK_MTLS_HOST} → pin v`);
      await attachText(testInfo, 'Telefon durum kutusu (mTLS config modu)', status);
    });

    await test.step('Mobil: config API\'ye sertifikalı pinli istek geçiyor', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain(cn);
      const status = await app.expectMtls(true);
      expect(status).toContain('HTTP 200');
      await app.snap('mTLS Config API bağlantısı başarılı');
      await app.backToMain();
    });

    await test.step('Terminal: aynı adrese sertifikasız istek el sıkışmada reddediliyor', async () => {
      const out = await attachFailingCommand(
        testInfo,
        'Sertifikasız istek (curl -k, istemci sertifikası yok)',
        'curl',
        ['-sS', '-k', '--max-time', '15', MTLS_URL],
      );
      expect(out).toMatch(/alert|handshake|SSL|TLS|reset/i);
    });

    await test.step('Web: cihazın mTLS Config API bağlantısı geçmişte görünüyor', async () => {
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.openHostIn(env.VAULT_API, env.LAN_IP);
      await dashboard.expectLatestConnection(run.model, { status: 'healthy' });
      await dashboard.snapCard('#conn-history-card', `${env.LAN_IP} bağlantı geçmişi`);
      const history = await hostApi.connectionHistory(env.LAN_IP);
      const mine = history.filter((e) => e.deviceModel === run.model).slice(0, 3);
      await attachText(
        testInfo,
        `GET /api/v1/connection-history/${env.LAN_IP}`,
        mine.map((e) => `${e.timestamp} ${e.status} pinVersion=${e.pinVersion} ${e.deviceModel}`).join('\n'),
      );
      expect(mine.length).toBeGreaterThan(0);
    });

    await test.step('Mobil: TLS moduna dönülüyor', async () => {
      await app.openSettings();
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
      const status = await app.waitReady();
      expect(status).toContain('Mod: TLS config');
      await app.snap('TLS moduna dönüldü');
    });
  } finally {
    // Ana host temel duruma: mTLS kapsamı boş, test sertifikası iptal.
    await mtlsScope.reset().catch(() => {});
    // İptal + unut: token telefona bağlı, kimlik cihazı kanıtlıyor (bkz. retireClientIdentity).
    await hostApi.retireClientIdentity(clientId);
  }
});
