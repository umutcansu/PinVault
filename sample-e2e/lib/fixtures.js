// Playwright fixture'ları: her test ayakta bir host'tan, temel pin durumundan,
// verisi silinmiş bir uygulamadan ve API anahtarıyla açılmış bir dashboard'dan
// başlar.
const base = require('@playwright/test');
const env = require('./env');
const hostApi = require('./hostApi');
const hostControl = require('./hostControl');
const state = require('./state');
const { Device } = require('./android');
const { SampleApp } = require('./sampleApp');
const { Dashboard } = require('./dashboard');

const test = base.test.extend({
  run: [
    async ({}, use) => {
      const value = state.read();
      if (!value) throw new Error('.e2e-state.json yok: testleri "npm test" ile çalıştır (global setup gerekli).');
      await use(value);
    },
    { scope: 'worker' },
  ],

  device: [async ({ run }, use) => use(new Device(run.serial)), { scope: 'worker' }],

  app: async ({ device, run }, use, testInfo) => {
    await device.ensureOnline();
    // Emülatörün saati koşu boyunca geri kalıyor; o anda üretilen sunucu
    // sertifikaları cihazda "not valid until …" ile reddedilmesin diye her
    // senaryodan önce Mac'in saatine hizalanır (fark küçükse dokunulmaz).
    device.syncClockToHost();
    await hostControl.ensureUp();
    await hostApi.restoreBaseline(run.baseline);
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
    // Test cihazda ağ kuralı (iptables) ya da kapalı host bırakmış olabilir.
    try {
      device.clearNetRules();
    } catch {
      /* emülatör değil ya da kural yok */
    }
    await hostControl.ensureUp();
    await hostApi.restoreBaseline(run.baseline);
  },

  dashboard: async ({ page }, use, testInfo) => {
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

module.exports = { test, expect: base.expect, TARGET_HOST: env.TARGET_HOST };
