// I04 — iOS: ekran kilitli vault dosyası Face ID ile açılıyor.
//
// sample-secret mTLS bloğunda, token_mtls politikasıyla ve ekran kilidi
// arkasında (userAuth REQUIRED, encryption USER_AUTH): sunucu dosyayı telefonun
// ekran kilidi anahtarına kilitleyip gönderir. "Aç" LocalAuthentication
// (.deviceOwnerAuthentication) sorusunu açar; simülatörde Face ID kaydedilir,
// tarama "eşleşti" / "eşleşmedi" bildirimleriyle yanıtlanır (lib/ios.js).
//
// Kanıt: soru ekrandayken ve eşleşmeyen taramadan sonra içerik ne sonuç kutusunda
// ne de ekrandaki herhangi bir öğede var; Vazgeç dosyayı kilitli bırakır;
// eşleşen tarama içeriği gösterir.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const { sleep } = require('../lib/device');
const hostApi = require('../lib/hostApi');
const secureVault = require('../lib/secureVault');
const iosDriver = require('../lib/iosDriver');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.secret;
const API = env.SECURE_VAULT_API;
const FACE_ID_NOMATCH = 'com.apple.BiometricKit_Sim.pearl.nomatch';

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: Face ID / LocalAuthentication (Android karşılığı 14: ekran kilidi PIN\'i)');

test('iOS: kilitli vault dosyası yalnızca eşleşen Face ID taramasıyla açılıyor; eşleşmeyince ve Vazgeç\'te kilitli kalıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const secret = `face-id-${Date.now()}`;
  const sv = { clientId: `i04-cihaz-${Date.now()}` };

  /** Ekrandaki bütün öğelerin (uygulama + sistem penceresi) metinleri: içerik hiçbirinde olmamalı. */
  const screenTexts = () => {
    const app_ = device.uiNodes().map((n) => `${n.label} ${n.value}`);
    let alerts = {};
    try {
      alerts = iosDriver.request('GET', '/alerts');
    } catch {
      /* pencere yok */
    }
    return { app: app_.join('\n'), alerts };
  };

  /** "Aç"a basar ve sistem penceresi (Face ID) görünene kadar bekler; önceki sıra numarasını döndürür. */
  const tapUnlockAndWaitPrompt = async () => {
    await app.setVaultKey(KEY);
    const before = SampleApp.seqOf(app.status());
    await app.tapButton('unlockButton');
    await expect.poll(() => device.credentialPromptShown(env.UNLOCK_PROMPT_TITLE), {
      timeout: 30_000, intervals: [500, 1000],
    }).toBe(true);
    // Açılış animasyonu.
    await sleep(1500);
    return before;
  };

  const waitResult = async (before, pattern, what) => (await app.waitFor('statusView',
    (n) => SampleApp.seqOf(n.text) > before && pattern.test(n.text), { timeout: 45_000, what })).text;

  try {
    await test.step('Hazırlık: simülatörde Face ID kayıtlı, cihaz mTLS\'e kayıt olur', async () => {
      await secureVault.prepare({ app, device, dashboard }, sv);
      await attachText(testInfo, 'Face ID (simülatör)', [
        `com.apple.BiometricKit.enrollmentChanged = ${device.faceIdEnrolled() ? '1 (kayıtlı)' : '0'}`,
        '',
        'Simülatörde cihaz parolası her zaman var; Face ID kaydı "Features → Face ID → Enrolled"',
        'ile aynı bildirimle açılıyor. Tarama sonucu: com.apple.BiometricKit_Sim.pearl.match / .nomatch.',
      ].join('\n'));
      expect(device.faceIdEnrolled()).toBe(true);
    });

    await test.step('Web → Mobil: dosya token_mtls + user_auth ile yüklenir; iner ama kilitli', async () => {
      await dashboard.uploadVaultText(API, KEY, secret, { policy: 'token_mtls', encryption: 'user_auth' });
      await app.openVault();
      const token = await dashboard.generateVaultToken(API, KEY, app.deviceId());
      await app.saveVaultToken(token, KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('dosya indi — kilitli, içerik yok');
      expect(status).toContain('indirildi');
      expect(status).toContain('Kilitli');
      expect(status).not.toContain(secret);
      expect(screenTexts().app).not.toContain(secret);
    });

    await test.step('Mobil: "Aç" → Face ID sorusu; soru ekrandayken içerik yok', async () => {
      const before = await tapUnlockAndWaitPrompt();
      await app.snap('Face ID sorusu açık');
      const shown = screenTexts();
      await attachText(testInfo, 'Sistem penceresi (SpringBoard, ios-driver /alerts)', JSON.stringify(shown.alerts, null, 2));
      expect(shown.app).not.toContain(secret);
      expect(JSON.stringify(shown.alerts)).not.toContain(secret);

      // Eşleşmeyen tarama: pencere "tekrar dene / Vazgeç" durumuna geçer, dosya açılmaz.
      device.notify(FACE_ID_NOMATCH);
      await sleep(2500);
      await app.snap('Face ID eşleşmedi');
      const afterNoMatch = screenTexts();
      await attachText(testInfo, 'Eşleşmeyen taramadan sonra pencere', JSON.stringify(afterNoMatch.alerts, null, 2));
      expect(afterNoMatch.app).not.toContain(secret);
      expect(app.status()).not.toContain(secret);

      // Vazgeç: eşleşmeyen tarama + sistem penceresinin Vazgeç düğmesi.
      expect(await device.cancelCredentialPrompt(env.UNLOCK_PROMPT_TITLE)).toBe(true);
      const status = await waitResult(before, /açılmadı|açılamadı/, 'Vazgeç sonrası sonuç');
      await app.snap('Vazgeç — dosya açılmadı');
      expect(status).toContain(`${KEY} açılmadı`);
      expect(status).not.toContain(secret);
      expect(screenTexts().app).not.toContain(secret);
    });

    await test.step('Mobil: "Bilgi" dosyanın hâlâ kilitli durduğunu söylüyor', async () => {
      const info = await app.vaultInfo(KEY);
      await app.snap('bilgi — hâlâ kilitli');
      expect(info).toContain('saklı: var');
      expect(info).toContain('kilitli');
      expect(info).not.toContain(secret);
    });

    await test.step('Mobil: "Aç" → eşleşen Face ID taraması → içerik görünüyor', async () => {
      const before = await tapUnlockAndWaitPrompt();
      expect(screenTexts().app).not.toContain(secret);
      device.enterCredential();
      const status = await waitResult(before, / açıldı\n| açılmadı| açılamadı/, 'eşleşen tarama sonrası sonuç');
      await app.snap('Face ID eşleşti — içerik açıldı');
      await attachText(testInfo, 'Sonuç kutusu (eşleşen tarama)', status);
      expect(status).toContain(`${KEY} v`);
      expect(status).toContain('açıldı');
      expect(status).toContain(secret);
    });

    await test.step('Kaynak: kütüphane LocalAuthentication ile soruyor (.deviceOwnerAuthentication)', async () => {
      const file = path.resolve(env.ROOT, '../pinvault-ios/Sources/PinVault/Internal/UserAuthPrompt.swift');
      const lines = fs.readFileSync(file, 'utf8').split('\n')
        .map((l, i) => `${String(i + 1).padStart(4)}  ${l}`)
        .filter((l) => /deviceOwnerAuthentication|evaluatePolicy|LAContext/.test(l));
      await attachText(testInfo, 'pinvault-ios/Sources/PinVault/Internal/UserAuthPrompt.swift', [
        ...lines,
        '',
        '.deviceOwnerAuthentication: Face ID (kayıtlıysa) ve onun yerine cihaz parolası. Eşleşmeyen',
        'tarama soruyu kapatmaz; Vazgeç LAError.userCancel döndürür, kütüphane bunu "kullanıcı',
        'vazgeçti" sayar ve şifreli kopyaya dokunmaz.',
      ].join('\n'));
      expect(lines.join('\n')).toContain('evaluatePolicy(.deviceOwnerAuthentication');
    });
  } finally {
    await hostApi.deleteVaultFile(API, KEY).catch(() => {});
    await secureVault.cleanup({ device }, sv);
  }
});
