// R07 — environmentGuard (ele geçirilmiş ortamda hassas işlemleri reddetme).
//
// Kütüphanenin environmentGuard'ı, uygulamanın "bu cihaz güvenli mi?" yanıtını
// her hassas işlemden (kayıt, dosya indirme, kilit açma) önce sorar; INIT'e
// izin verir ki pinli trafik çalışsın. sample-client bu yanıtı DeviceShield'a
// bağlar: root dosyaları, bağlı hata ayıklayıcı ve /proc/self/maps'te hooking
// kütüphaneleri. Test derlemelerinde Ayarlar'daki "Ortam kontrolü" ile açılır
// (varsayılan kapalı; release'te hep açık).
//
// Test ortam kontrolünü açar ve sürece ham bir JDWP hata ayıklayıcısı bağlar
// (R05'teki gibi; DeviceShield bunu her soruda yeniden kontrol eder). Bağlıyken
// public bir vault dosyası İNDİRİLEMEZ (FETCH_FILE reddi, ağ çağrısından önce);
// hata ayıklayıcı ayrılınca aynı istek yeniden ağa ulaşır. Böylece reddi özel
// olarak guard'ın, o da cihazdaki gerçek bir tehdidin yaptığı kanıtlanır.
//
// Not: emülatör imajının /system/xbin/su'su SELinux yüzünden uygulamaya
// görünmez (R01'deki bulgu), bu yüzden tehdit olarak hata ayıklayıcı seçildi.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');
const res = require('../lib/resilience');

const FLAGS = env.VAULT_KEYS.flags; // 'sample-flags' — herkese açık vault dosyası (mTLS gerekmez)

test('R07 environmentGuard: hata ayıklayıcı bağlıyken dosya indirme ağdan önce reddedilir; ayrılınca iner', async ({ app, device }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  // Guard reddi, dosyanın sunucudaki erişim politikasından bağımsız olarak ağ
  // çağrısından ÖNCE olur. Bu yüzden testin dayanağı, dosyanın başarıyla inmesi
  // değil, sonuç NEDENİNİN değişmesidir: tehdit varken sonuç HER ZAMAN guard
  // reddi; yokken istek ağa ulaşır (başarı ya da sunucu hatası) ve ASLA guard
  // mesajı taşımaz.
  const GUARD = /environment guard refused FETCH_FILE/;
  let detach;
  let guardOn = false;
  try {
    await test.step('Önkoşul: tek kullanımlık emülatör, uygulama debuggable', async () => {
      expect(device.isEmulator(), 'bu senaryo yalnızca emülatörde koşar').toBeTruthy();
      const info = device.shell(`dumpsys package ${env.APP_ID}`);
      expect(/\bflags=\[[^\]]*\bDEBUGGABLE\b/.test(info), 'uygulama debuggable olmalı (debug/e2e derlemesi)').toBeTruthy();
    });

    await test.step('Ayarlar: "Ortam kontrolü" açılır, PinVault yeniden kurulur', async () => {
      await app.openSettings();
      const applied = await app.setEnvironmentGuard(true);
      guardOn = true;
      expect(applied).toContain('Hazır — config v');
      await app.snap('Ayarlar: ortam kontrolü açık');
      await app.backToMain();
    });

    await test.step('Temiz cihaz: indirme isteği ağa ulaşır (guard reddetmez)', async () => {
      await app.openVault();
      const clean = await app.fetchVault(FLAGS);
      expect(clean, `temiz cihazda guard devreye girmemeliydi:\n${clean}`).not.toMatch(GUARD);
      attachText(testInfo, 'Temiz cihaz (ağ sonucu)', clean);
      await app.snap('temiz cihaz: istek ağa ulaştı');
      await app.backToMain();
    });

    await test.step('Hata ayıklayıcı bağlanır → environmentGuard FETCH_FILE\'ı ağ çağrısından önce reddeder', async () => {
      detach = await res.attachDebugger(device, env.APP_ID);
      await new Promise((r) => setTimeout(r, 2500));
      await app.openVault();
      const refused = await app.fetchVault(FLAGS);
      expect(refused).toContain('indirilemedi');
      expect(refused).toMatch(GUARD);
      attachText(testInfo, 'Guard reddi (FETCH_FILE, hata ayıklayıcı bağlı)', refused);
      await app.snap('environmentGuard: indirme reddedildi');
      await app.backToMain();
    });

    await test.step('Hata ayıklayıcı ayrılınca: istek yeniden ağa ulaşır (guard mesajı yok)', async () => {
      await detach();
      detach = null;
      await new Promise((r) => setTimeout(r, 2500));
      await app.openVault();
      const clean = await app.fetchVault(FLAGS);
      expect(clean, `hata ayıklayıcı ayrılınca guard devreden çıkmalıydı:\n${clean}`).not.toMatch(GUARD);
      attachText(testInfo, 'Hata ayıklayıcı ayrıldı (ağ sonucu)', clean);
      await app.snap('hata ayıklayıcı ayrıldı: istek ağa ulaştı');
      await app.backToMain();
    });
  } finally {
    if (detach) await detach().catch(() => {});
    // Ortam kontrolünü kapat: sonraki testler etkilenmesin (fixture zaten pm clear yapar).
    if (guardOn) {
      try {
        await app.openSettings();
        await app.setEnvironmentGuard(false);
        await app.backToMain();
      } catch {
        /* no-op */
      }
    }
  }
});
