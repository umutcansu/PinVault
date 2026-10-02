// @ts-check
const { defineConfig } = require('@playwright/test');
const { WEB_URL } = require('./lib/env');

module.exports = defineConfig({
  testDir: './tests',
  // Tek telefon ve tek paylaşılan sunucu durumu: senaryolar sırayla, tek tek koşar.
  workers: 1,
  fullyParallel: false,
  // Durum değiştiren uçtan uca adımlar körlemesine tekrarlanmaz.
  retries: 0,
  timeout: 4 * 60 * 1000,
  expect: { timeout: 20_000 },
  globalSetup: require.resolve('./global-setup'),
  globalTeardown: require.resolve('./global-teardown'),
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
    // Tek dosyalık kanıt sayfası: evidence/index.html
    ['./lib/evidence-reporter.js', { outputFolder: 'evidence' }],
  ],
  use: {
    baseURL: WEB_URL,
    // Bulunamayan bir öğe senaryonun tamamını (25 dk'ya varan) beklemek yerine
    // bir dakikada hata versin.
    actionTimeout: 60_000,
    navigationTimeout: 60_000,
    headless: true,
    viewport: { width: 1440, height: 900 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
