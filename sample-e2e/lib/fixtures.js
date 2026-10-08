// Playwright fixture'ları: her test ayakta bir host'tan, temel pin durumundan,
// verisi silinmiş bir uygulamadan ve API anahtarıyla açılmış bir dashboard'dan
// başlar. Cihaz platforma göre Android (adb) ya da iOS simülatörüdür
// (lib/device.js, E2E_PLATFORM); yalnızca Android'de anlamlı senaryolar
// (env.ANDROID_ONLY_TESTS) iOS koşusunda buradan atlanır.
const path = require('path');
const base = require('@playwright/test');
const env = require('./env');
const hostApi = require('./hostApi');
const hostControl = require('./hostControl');
const state = require('./state');
const { createDevice } = require('./device');
const { SampleApp } = require('./sampleApp');
const { Dashboard } = require('./dashboard');

/** Senaryonun dosya adı öneki: "D05-yedeklemeye-girmiyor.spec.js" → "D05", "11-…" → "11". */
function scenarioId(file) {
  const m = path.basename(file || '').match(/^([A-Z]?\d+)-/);
  return m ? m[1] : '';
}

/** Bu platformda atlanacaksa nedeni, yoksa null. */
function platformSkipReason(file) {
  if (env.PLATFORM !== 'ios') return null;
  const reason = env.ANDROID_ONLY_TESTS[scenarioId(file)];
  return reason ? `Yalnızca Android: ${reason}` : null;
}

const test = base.test.extend({
  // Her senaryodan önce (otomatik): platformda karşılığı olmayan senaryo atlanır,
  // uygulama ve dashboard hiç kurulmaz.
  platformGuard: [
    async ({}, use, testInfo) => {
      const reason = platformSkipReason(testInfo.file);
      testInfo.skip(!!reason, reason || '');
      await use(env.PLATFORM);
    },
    { auto: true },
  ],

  run: [
    async ({}, use) => {
      const value = state.read();
      if (!value) throw new Error('.e2e-state.json yok: testleri "npm test" ile çalıştır (global setup gerekli).');
      await use(value);
    },
    { scope: 'worker' },
  ],

  device: [async ({ run }, use) => use(createDevice(run.serial)), { scope: 'worker' }],

  app: async ({ device, run, platformGuard }, use, testInfo) => {
    await device.ensureOnline();
    // Emülatörün saati koşu boyunca geri kalıyor; o anda üretilen sunucu
    // sertifikaları cihazda "not valid until …" ile reddedilmesin diye her
    // senaryodan önce Mac'in saatine hizalanır (fark küçükse dokunulmaz).
    // iOS: simülatör Mac'in saatini kullanır; kalmış bir kaydırma sıfırlanır.
    device.syncClockToHost();
    await hostControl.ensureUp();
    await hostApi.restoreBaseline(run.baseline);
    // Atestasyon cihazı ilk anahtarıyla tanır; launchFresh uygulama verisini
    // sildiği için telefon yeni anahtar üretir. Eski kayıt silinmezse her
    // atestasyon key_mismatch olur.
    try {
      await hostApi.forgetAttestationDevice(device.appAndroidId(env.APP_ID), [env.VAULT_API, env.MTLS_API]);
    } catch {
      /* uygulama henüz hiç açılmadıysa ANDROID_ID yok; kayıt da yok */
    }
    const app = new SampleApp(device, testInfo);
    app.launchFresh();
    await app.waitReady();
    await use(app);
    // Başarısız testte telefonun son hali de rapora girsin; Playwright yalnızca
    // tarayıcının ekran görüntüsünü alır.
    if (testInfo.status !== testInfo.expectedStatus) {
      try {
        await app.snap('hata anında telefon');
      } catch {
        /* cihaz yanıt vermiyorsa asıl hatayı gölgelemesin */
      }
    }
    // Test cihazda ağ kuralı (iptables; iOS'ta denetim dosyasındaki yönlendirme) ya da kapalı host bırakmış olabilir.
    try {
      device.clearNetRules();
    } catch {
      /* emülatör değil ya da kural yok */
    }
    await hostControl.ensureUp();
    await hostApi.restoreBaseline(run.baseline);
  },

  dashboard: async ({ page, platformGuard }, use, testInfo) => {
    const dashboard = new Dashboard(page, testInfo);
    // Onay ve bilgi pencereleri (force update, silme, iptal, token) kabul edilir;
    // metinleri test okuyabilsin diye saklanır. prompt'lara test önceden
    // [answerPrompt] ile yanıt bırakabilir (cihaz ACL'i düzenleme).
    Dashboard.attachDialogs(page, dashboard);
    await Dashboard.seedApiKey(page, env.API_KEY);
    await dashboard.open();
    await use(dashboard);
  },
});

module.exports = { test, expect: base.expect, TARGET_HOST: env.TARGET_HOST, platformSkipReason, scenarioId };
