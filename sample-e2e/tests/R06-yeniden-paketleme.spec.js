// R06 — Yeniden paketleme / imza tespiti (AppIntegrityProbe + atestasyon zinciri).
//
// Uygulama beklenen imzalama sertifikasına bağlanır (expectedSignerSha256,
// host.expectedSignerSha256'dan derlemeye gömülür). Doğru imzalı APK atestasyonda
// `app_integrity`'yi temiz geçer. APK atılabilir BAŞKA bir anahtarla yeniden
// imzalanıp (yeniden paketleme) kurulunca istemci imzayı beklenenle uyuşmaz bulur
// ve raporda `app_integrity`'yi yükseltir; sunucu bu sinyali onurlandırır
// (AttestationService.raisedFlags raporun signals'ını okur), politika
// `app_integrity: reject` iken telefon KALIR, token alamaz, mock host 401 döner.
//
// Not: Yeniden imzalama cihazda yeni bir ANDROID_ID (dolayısıyla yeni deviceId)
// doğurur; yeniden paketlenmiş kopyanın kaydı ayrı okunur. Test sonunda doğru
// imzalı APK geri kurulur.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

test('R06 Yeniden paketleme: doğru imza app_integrity\'yi geçer; farklı anahtarla imzalı APK yükseltir, reddedilir ve mock host 401', async ({ app, device }, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  let original;
  let tampered = false;
  let deviceId;

  try {
    await test.step('Önkoşul: istemciye beklenen imza gömülü (host.expectedSignerSha256)', async () => {
      // Bu değer boşsa istemci app_integrity'yi yargılamaz; test anlamlı olmaz.
      // Derlemeye gömülüdür; cihazdaki değeri doğrudan okuyamayız, bu yüzden
      // doğru imzalı uygulamanın app_integrity'yi TEMİZ geçmesiyle dolaylı
      // doğrularız (ilk adım). Açık uyarı için global-setup'ın yazdığını da anarız.
      expect(env.APK, 'APK yolu bilinmiyor').toBeTruthy();
    });

    await test.step('Hazırlık: politika yalnızca app_integrity\'yi reddeder, mock host token ister', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT, app_integrity: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Doğru imza: atestasyon app_integrity\'yi temiz geçer, token gelir, mock host 200', async () => {
      const text = await app.attest();
      expect(text, `doğru imzalı uygulama geçmeliydi:\n${text}`).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('doğru imza: atestasyon geçti');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(res.reasonsOf(record)).not.toContain('app_integrity');
    });

    await test.step('Yeniden paketle: APK\'yı başka anahtarla imzala ve kur', async () => {
      const tamperedApk = res.repackageApk(env.APK);
      device.adb(['uninstall', env.APP_ID]); // imza değişimi temiz kurulum ister
      device.adb(['install', '-r', '-t', tamperedApk]);
      tampered = true;
      app.launchFresh();
      await app.waitReady();
      attachText(testInfo, 'Yeniden paketlenmiş APK kuruldu', tamperedApk);
    });

    await test.step('Yeniden paketlenmiş uygulama: app_integrity yükselir, KALDI, token yok, mock host 401', async () => {
      await app.openVault();
      const tamperedId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(tamperedId).catch(() => {});
      // Yeni imza = yeni ANDROID_ID ve yeni anahtar; daha önceki bir koşu bu kimliği
      // eski anahtarla kaydetmişse host key_mismatch der. Kayıt unutulur, cihaz yeniden kaydolur.
      await hostApi.api(res.devicePath(SCOPE, tamperedId), { method: 'DELETE' }).catch(() => {});
      await app.backToMain();

      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('app_integrity');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('yeniden paketleme tespit edildi: atestasyon kaldı, mock host 401');

      const record = await res.deviceRecord(SCOPE, tamperedId);
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('app_integrity');
      attachText(testInfo, 'Cihaz kaydı (app_integrity reddedildi)', JSON.stringify(record, null, 2));
    });
  } finally {
    if (tampered) {
      try {
        device.adb(['uninstall', env.APP_ID]);
        device.adb(['install', '-r', '-t', env.APK]); // doğru imzalı uygulamayı geri kur
      } catch {
        /* sonraki testin global-setup'ı da -r ile kurar */
      }
    }
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
