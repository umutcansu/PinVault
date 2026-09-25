// Kurulum yolculuğu K13: Swagger UI (/docs) ve OpenAPI dosyası, dashboard'un
// TR/EN dil geçişi ve tablo sayfalaması. Geçici test sunucusunda çalışır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');

test('Kurulum: Swagger UI açılır, OpenAPI uçları belgelenir, dashboard TR/EN ve sayfalama çalışır', async ({
  browser,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();

  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;

  try {
    await test.step('Web: /docs Swagger UI\'ı açar (K13)', async () => {
      const errors = [];
      page.on('pageerror', (e) => errors.push(e.message));
      page.on('console', (m) => {
        if (m.type() === 'error') errors.push(`console: ${m.text()}`);
      });
      await page.goto(`${fresh.WEB_URL}/docs`);
      // docExpansion: 'none' — önce etiket grupları gelir, işlemler açılınca.
      await expect(page.locator('#swagger-ui .opblock-tag').first()).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('.information-container')).toContainText('PinVault Demo Server API');
      await dashboard.snap('Swagger UI (/docs) — etiket grupları');
      const tagCount = await page.locator('#swagger-ui .opblock-tag').count();
      await page.locator('#swagger-ui .opblock-tag').first().click();
      await expect(page.locator('#swagger-ui .opblock').first()).toBeVisible({ timeout: 20_000 });
      await dashboard.snap('Swagger UI — ilk etiket açıldı, işlemler görünüyor');
      const opCount = await page.locator('#swagger-ui .opblock').count();
      await attachText(
        testInfo,
        'Swagger UI',
        [
          `GET ${fresh.WEB_URL}/docs → /static/docs.html`,
          `Etiket grubu: ${tagCount} · ilk grupta işlem bloğu: ${opCount}`,
          'Swagger\'ın JS/CSS dosyaları dashboard ile aynı adresten (/static/vendor/…) geliyor; tarayıcının güvenlik kuralı (CSP script-src \'self\') bunları engellemiyor.',
          `Sayfa hatası: ${errors.length === 0 ? 'yok' : errors.join('; ')}`,
        ].join('\n'),
      );
      expect(tagCount).toBeGreaterThan(5);
      expect(opCount).toBeGreaterThan(0);
    });

    await test.step('Sunucu: openapi.yaml\'da belgelenen API uçları (K13)', async () => {
      const res = await fetch(`${fresh.WEB_URL}/static/openapi.yaml`);
      const text = await res.text();
      const paths = text.match(/^ {2}\/[^\s:]+:/gm) || [];
      await attachText(
        testInfo,
        'GET /static/openapi.yaml',
        [
          `HTTP ${res.status} · ${text.length} bayt`,
          `Belgelenen yol sayısı: ${paths.length}`,
          '',
          paths.map((p) => p.trim().replace(/:$/, '')).join('\n'),
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(paths.length).toBeGreaterThan(50);
    });

    await test.step('Web: dashboard TR → EN → TR (K13)', async () => {
      await page.goto(`${fresh.WEB_URL}/`);
      await expect(page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.setLang('en');
      await expect(page.locator('#sidebar-hosts-label')).toContainText('Config API');
      await expect(page.locator('#btn-add-api')).toContainText('Config API');
      await dashboard.snap('dashboard: EN');
      await dashboard.setLang('tr');
      await dashboard.snap('dashboard: TR');
    });

    await test.step('Web: bağlantı geçmişi sayfalaması (K13)', async () => {
      // Sayfalamanın görünmesi için yeterli kayıt üret.
      for (let i = 0; i < 14; i++) {
        await fresh.api('/api/v1/connection-history/web', {
          method: 'POST',
          body: { hostname: 'k07-sayfalama.sample', status: 'healthy', responseTimeMs: 10 + i },
        });
      }
      await page.reload();
      await dashboard.openHealth();
      const counter = page.locator('text=/\\d+-\\d+ \\/ \\d+/').first();
      await expect(counter).toBeVisible();
      const firstPage = (await counter.innerText()).trim();
      await dashboard.snap(`sayfalama: birinci sayfa (${firstPage})`);

      await dashboard.nextPage();
      const secondPage = (await page.locator('text=/\\d+-\\d+ \\/ \\d+/').first().innerText()).trim();
      await dashboard.snap(`sayfalama: ikinci sayfa (${secondPage})`);

      await dashboard.setPageSize(25);
      const bigPage = (await page.locator('text=/\\d+-\\d+ \\/ \\d+/').first().innerText()).trim();
      await dashboard.snap(`sayfalama: sayfa boyutu 25 (${bigPage})`);

      await attachText(
        testInfo,
        'Sayfalama sayaçları',
        [`birinci sayfa : ${firstPage}`, `ikinci sayfa  : ${secondPage}`, `boyut 25      : ${bigPage}`].join('\n'),
      );
      expect(firstPage).not.toBe(secondPage);
      expect(firstPage.startsWith('1-')).toBe(true);
    });
  } finally {
    await page.close();
  }
});
