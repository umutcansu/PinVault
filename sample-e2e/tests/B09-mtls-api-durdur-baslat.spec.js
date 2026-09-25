// B09 — mTLS Config API'nin durdurulup başlatılması.
//
// İki cihaz durumu ayrı ayrı gösteriliyor:
//   • TLS modundaki cihaz: config'i TLS API'den aldığı için "Hazır" kalıyor,
//     yalnızca mTLS hedefine giden istek reddediliyor.
//   • mTLS config modundaki cihaz: dinleyici kapalıyken yeniden açılışta
//     saklı (şifreli) config ile çalışmaya devam ediyor — init düşmüyor —
//     ama "Config yenile" başarısız oluyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

/** Durdurulmuş Config API'yi kayıtlı portuyla geri başlatır (temizlik). */
async function startMtlsApi() {
  const all = (await hostApi.api('/api/v1/all-configs')).json || [];
  const api = all.find((a) => a.id === env.MTLS_API);
  if (!api || api.running) return;
  await hostApi.api('/api/v1/config-apis/start', {
    method: 'POST',
    body: { id: env.MTLS_API, port: api.port, mode: 'mtls' },
  });
}

test('mTLS: mTLS Config API durdurulup yeniden başlatılınca cihazın davranışı', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  const clientId = `b09-${Date.now()}`;

  try {
    await test.step('Web+Mobil: cihaz kayıt oluyor, mTLS bağlantısı geçiyor', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
      expect(await app.expectMtls(true)).toContain('HTTP 200');
      await app.snap('mTLS API çalışıyor: bağlantı geçiyor');
      await app.backToMain();
    });

    await test.step('Web: mTLS Config API durduruluyor', async () => {
      await dashboard.setConfigApiRunning(env.MTLS_API, false);
      await dashboard.snap('mTLS Config API durduruldu');
      const all = (await hostApi.api('/api/v1/all-configs')).json || [];
      await attachText(
        testInfo,
        'GET /api/v1/all-configs',
        all.map((a) => `${a.id} :${a.port} ${a.mode} running=${a.running}`).join('\n'),
      );
      expect(all.find((a) => a.id === env.MTLS_API).running).toBe(false);
    });

    await test.step('Mobil: TLS modunda "Hazır" — yalnızca mTLS isteği reddediliyor', async () => {
      const status = await app.waitReady();
      const refresh = await app.refreshConfig();
      await app.snap('TLS modu: mTLS API kapalıyken hâlâ hazır');
      await app.openMtls();
      const refused = await app.expectMtls(false);
      await app.snap('mTLS API kapalı: bağlantı reddedildi');
      await app.backToMain();
      await attachText(
        testInfo,
        'TLS modundaki cihaz (mTLS API kapalı)',
        [
          'Ana ekran:',
          status,
          '',
          'Config yenileme (TLS Config API üzerinden):',
          refresh,
          '',
          'mTLS testi:',
          refused,
        ].join('\n'),
      );
      expect(status).toContain('Hazır — config v');
      expect(refresh).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(refused).toContain('mTLS bağlantısı reddedildi');
    });

    await test.step('Web: mTLS Config API yeniden başlatılıyor — bağlantı dönüyor', async () => {
      await dashboard.setConfigApiRunning(env.MTLS_API, true);
      await dashboard.snap('mTLS Config API yeniden çalışıyor');
      await app.openMtls();
      expect(await app.expectMtls(true)).toContain('HTTP 200');
      await app.snap('mTLS bağlantısı geri geldi');
      await app.backToMain();
    });

    await test.step('Web: mTLS Config API\'ye host\'lar eklenip cihaz mTLS config moduna geçiyor', async () => {
      await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await app.openSettings();
      expect(await app.applyMode('MTLS_CONFIG')).toContain('Hazır — config v');
      await app.backToMain();
      const status = await app.waitReady();
      await app.snap('mTLS config modu hazır');
      expect(status).toContain('Mod: mTLS config');
    });

    await test.step('Web: API tekrar durduruluyor — cihaz bu kez mTLS config modunda', async () => {
      await dashboard.setConfigApiRunning(env.MTLS_API, false);
      await dashboard.snap('mTLS Config API yeniden durduruldu');
      const refresh = await app.refreshConfig();
      await app.snap('mTLS config modu: config yenilenemedi');
      await attachText(testInfo, 'Config yenileme (birincil blok durdurulmuş API\'ye bağlı)', refresh);
      expect(refresh).toContain('Config yenilenemedi');
    });

    await test.step('Mobil: yeniden açılışta saklı config ile çalışmaya devam ediyor', async () => {
      app.relaunch();
      const status = await app.waitReady();
      await app.snap('kapalı API: saklı config ile hazır');
      await attachText(
        testInfo,
        'mTLS config modunda yeniden açılış (API kapalı)',
        [
          status,
          '',
          'Gerçek davranış: init başarısız olmuyor. SSLCertificateUpdater.initializeAndUpdate',
          'güncelleme başarısız olduğunda saklı (şifreli) config\'i kullanıyor ve',
          'InitResult.Ready(storedConfig.version) dönüyor; forceUpdate açık olsaydı',
          'ForceUpdateFailedException ile başarısız olurdu (bkz. F01). Pin\'ler geçerli',
          'kalıyor, yalnızca yeni config alınamıyor.',
        ].join('\n'),
      );
      expect(status).toContain('Hazır — config v');
      expect(status).toContain('Mod: mTLS config');
    });

    await test.step('Web+Mobil: API geri açılıyor, cihaz TLS moduna dönüyor', async () => {
      await dashboard.setConfigApiRunning(env.MTLS_API, true);
      await dashboard.snap('mTLS Config API tekrar çalışıyor');
      const refresh = await app.refreshConfig();
      expect(refresh).toMatch(/Config güncel|Yeni config uygulandı/);
      await app.snap('API dönünce config yenileme çalışıyor');
      await app.openSettings();
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
      expect(await app.waitReady()).toContain('Mod: TLS config');
      await app.snap('TLS moduna dönüldü');
    });
  } finally {
    await startMtlsApi().catch(() => {});
    await mtlsScope.reset().catch(() => {});
    await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
