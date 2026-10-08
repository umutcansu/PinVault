// R01 — Root tespiti (kütüphanenin KENDİ RootProbe'u + atestasyon zinciri).
//
// Root'lu bir cihazda tipik olarak bir kök yöneticisi (Magisk vb.) kuruludur.
// RootProbe bu paketleri arar (kütüphane manifestindeki <queries> ile Android
// 11+'da görünür) ve `rooted` sinyalini yükseltir. Test, paket adı Magisk'inkiyle
// aynı olan boş bir stub APK kurar: kütüphane cihazı root'lu sayar. Host politikası
// `rooted: reject` iken telefon KALIR, token alamaz ve token isteyen mock host
// isteği 401'le geri çevirir. Stub kaldırılınca (aynı politikayla) aynı telefon
// GEÇER ve token alır; böylece reddi özel olarak `rooted` sinyalinin, o da
// cihazdaki gerçek artifact'ın yaptığı kanıtlanır.
//
// Not: Gerçek telefon root'lanmaz; root senaryoları yalnızca tek kullanımlık
// emülatörde yapılır.
//
// Bulgu (bu emülatör imajı): salt ambient root — `ro.debuggable=1` ve
// `/system/xbin/su` — SELinux enforcing altında untrusted uygulama tarafından
// görülemediğinden tek başına `rooted` yükseltmiyordu; bu yüzden tespit,
// paket görünürlüğü gibi uygulamanın gerçekten okuyabildiği bir sinyalle
// gösteriliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API; // uygulamanın TLS bloğunun Config API kimliği (default-tls)

test('R01 Root: kök yöneticisi kuruluyken rooted yükselir, politika reddedince token yok ve mock host 401; kaldırılınca geçer', async ({ app, device, dashboard }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let original;
  let deviceId;
  let planted = false;

  try {
    await test.step('Önkoşul: yalnızca tek kullanımlık emülatör', async () => {
      expect(device.isEmulator(), 'root senaryosu yalnızca emülatörde koşar; gerçek telefon root\'lanmaz').toBeTruthy();
    });

    await test.step('Hazırlık: kök yöneticisi kur, politika yalnızca rooted\'ı reddeder, mock host token ister', async () => {
      original = await res.getPolicy(SCOPE);
      const pkg = res.plantRootManager(device);
      planted = true;
      expect(device.shell(`pm list packages ${pkg}`), 'kök yöneticisi stub\'ı kurulmalı').toContain(pkg);
      // Her şeyi uyarıya çek (emülatörde zaten yükselen emulator/debuggable vb.
      // tek başına reddetmesin), sonra sadece rooted'ı reject yap.
      await res.setPolicy(SCOPE, { ...res.LENIENT, rooted: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
      attachText(testInfo, 'Kurulu kök yöneticisi', `${pkg}\n${device.shell(`pm list packages ${pkg}`).trim()}`);
    });

    await test.step('Mobil: rooted reddedilir → atestasyon KALDI, token yok, mock host 401', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('rooted');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('root tespit edildi: atestasyon kaldı, mock host 401');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record, 'cihaz kaydı yok').toBeTruthy();
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('rooted');
      attachText(testInfo, 'Cihaz kaydı (rooted reddedildi)', JSON.stringify(record, null, 2));
    });

    await test.step('Web: panelde cihaz reddedilmiş, gerekçe rooted', async () => {
      await dashboard.openConfigApiTab(SCOPE, 'attestation');
      await dashboard.snap('panel: atestasyon sekmesi, rooted reddi');
    });

    await test.step('Kök yöneticisi kaldırılır → Mobil: aynı politikayla rooted düşer, atestasyon GEÇER ve token alır', async () => {
      res.removeRootManager(device);
      planted = false;
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('kök yöneticisi kaldırıldı: atestasyon geçti, mock host 200');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('pass');
      expect(res.reasonsOf(record)).not.toContain('rooted');
      attachText(testInfo, 'Cihaz kaydı (rooted kalktı, geçti)', JSON.stringify(record, null, 2));
    });

    await test.step('Ağ: token olmadan mock host 401 (kök korunur)', async () => {
      const bare = await hostApi.mockTlsRequest('/');
      expect(bare.status).toBe(401);
      expect(bare.headers['www-authenticate'] || '').toContain('PinVault-Token');
      attachText(testInfo, 'Mock host, token yok', `HTTP ${bare.status}\n${JSON.stringify(bare.headers, null, 2)}`);
    });
  } finally {
    if (planted) res.removeRootManager(device);
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
