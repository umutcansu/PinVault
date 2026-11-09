// Kurulum yolculuğu: sihirbazın içindeki yönergeler. Üretime hazırlanan
// yönetici her kontrol satırının yanında "Nasıl yapılır" düğmesini bulur;
// düğme o satırı HAZIR yapan numaralı adımları açar: hangi komut, hangi .env
// satırı, paneldeki hangi kart ve düğme, en sonda "Doğrula". Kanıtlanan:
//
//   • 1 · Sunucu adımının başında "Kurulum sırası" kartı (beş adım),
//   • HAZIR olmayan her satırda "Nasıl yapılır"; HAZIR satırda yok,
//   • .env'den değişen bir satırın yönergesi adımları, .env satırlarını ve
//     yeniden başlatma notunu gösterir; "Kapat" kapatır,
//   • Ayarlar kartından değişen bir satırın yönergesindeki "Ayarlar kartında aç"
//     düğmesi ilgili ayara kaydırır ve onu vurgular,
//   • 2 · Sertifikalar: UYARI'lı host satırının yönergesi her eksik kontrol için
//     bir bölüm açar (yedek pin → openssl komutu),
//   • 4 · Kod: "Sonraki adımlar" kartı; mTLS Config API seçilince kayıt token'ı
//     adımı eklenir, TLS'te yoktur,
//   • İngilizce arayüzde aynı yönergeler İngilizce ("How to", "Verify").
//
// Geçici test sunucusunda koşar (yalnızca panel; telefon gerekmez).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');

const API = 'default-tls';
const MANUAL_HOST = 'k10-manual.sample';

test('Kurulum: sihirbazın her satırında "Nasıl yapılır" yönergeleri, Kod adımında "Sonraki adımlar"', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  await fresh.ensure();
  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;
  const step = (s) => page.locator(`[data-action="setSetupStep"][data-arg0="${s}"]`).first();
  const check = (id) => page.locator(`tr[data-setup-check="${id}"]`).first();
  const howtoRow = (key) => page.locator(`tr.setup-howto[data-setup-howto="${key}"]`);

  try {
    await test.step('Web: elle girilen bir host eklenir (yedek pin UYARI verecek)', async () => {
      await dashboard.addHostManual(API, MANUAL_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    });

    await test.step('Web: Kurulum Sihirbazı → 1 · Sunucu: "Kurulum sırası" kartı ve kontrol tablosu', async () => {
      await page.click('#nav-setup');
      await expect(page.locator('#setup-order')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('#setup-order ol li')).toHaveCount(5);
      await expect(page.locator('#setup-order')).toContainText('setup.sh');
      await dashboard.snapCard('#setup-order', 'Kurulum sırası: beş adım, komutlarla');
      const checks = (await fresh.api('/api/v1/setup')).json.checks;
      await attachText(
        testInfo,
        'GET /api/v1/setup — kontrol listesi',
        checks.map((c) => `${String(c.level).toUpperCase().padEnd(5)} ${c.id.padEnd(24)} ${c.current}`).join('\n'),
      );
    });

    await test.step('Web: HAZIR olmayan satırlarda "Nasıl yapılır" var, HAZIR satırlarda yok', async () => {
      const rows = page.locator('tr[data-setup-check]');
      const n = await rows.count();
      expect(n).toBeGreaterThan(5);
      let withButton = 0;
      for (let i = 0; i < n; i++) {
        const row = rows.nth(i);
        const level = await row.getAttribute('data-setup-level');
        const buttons = await row.locator('[data-action="toggleSetupHowto"]').count();
        if (level === 'ok') expect(buttons, `HAZIR satırda düğme olmamalı (${await row.getAttribute('data-setup-check')})`).toBe(0);
        else { expect(buttons, `${await row.getAttribute('data-setup-check')} satırında "Nasıl yapılır" yok`).toBe(1); withButton++; }
      }
      expect(withButton).toBeGreaterThan(0);
      await attachText(testInfo, '"Nasıl yapılır" düğmesi olan satır sayısı', String(withButton));
    });

    await test.step('Web: .env\'den değişen satır ("Config imzalayıcıları"): adımlar, .env satırları, yeniden başlatma notu; "Kapat"', async () => {
      await expect(check('signers')).toHaveAttribute('data-setup-level', 'warn');
      await check('signers').locator('[data-action="toggleSetupHowto"]').click();
      const row = howtoRow('server:signers');
      await expect(row).toBeVisible();
      await expect(row.locator('ol.howto-steps li')).toHaveCount(4);
      await expect(row.locator('li.howto-verify')).toContainText('Doğrula');
      await expect(row.locator('code').first()).toBeVisible();
      await expect(row.locator('pre.json-box')).toContainText('CONFIG_SIGNERS=');
      await expect(row.locator('.howto-restart')).toContainText('docker compose up -d');
      await dashboard.snapElement('"Config imzalayıcıları" yönergesi: dört adım, .env satırları, yeniden başlatma', 'tr.setup-howto[data-setup-howto="server:signers"]');
      await check('signers').locator('[data-action="toggleSetupHowto"]').click();
      await expect(row).toHaveCount(0);
    });

    await test.step('Web: Ayarlar kartından değişen satır ("Canlı sertifika kontrolü"): "Ayarlar kartında aç" ilgili ayara götürür ve vurgular', async () => {
      await expect(check('live_check')).toHaveAttribute('data-setup-level', 'warn');
      await check('live_check').locator('[data-action="toggleSetupHowto"]').click();
      const row = howtoRow('server:live_check');
      await expect(row).toBeVisible();
      await expect(row.locator('pre.json-box')).toHaveCount(0);   // panelden değişiyor: .env kutusu yok
      const go = row.locator('[data-action="setupGoSetting"][data-arg0="PIN_LIVE_CHECK"]');
      await expect(go).toBeVisible();
      await go.click();
      const setting = page.locator('#setting-PIN_LIVE_CHECK');
      await expect(setting).toHaveClass(/setting-flash/);
      await expect(setting).toBeInViewport();
      await dashboard.snapElement('"Ayarlar kartında aç": Canlı sertifika kontrolü ayarı vurgulu', '#setting-PIN_LIVE_CHECK');
    });

    await test.step('Web: 2 · Sertifikalar: UYARI\'lı host satırının yönergesi, yedek pin için openssl komutu', async () => {
      await step('certs').click();
      await expect(page.locator('#setup-certs-hosts')).toBeVisible({ timeout: 30_000 });
      const hostRow = page.locator(`tr[data-setup-host="${MANUAL_HOST}"]`);
      await expect(hostRow).toHaveAttribute('data-setup-level', 'warn');
      await hostRow.locator('[data-action="toggleSetupHowto"]').click();
      const row = howtoRow(`host:${MANUAL_HOST}:${API}`);
      await expect(row).toBeVisible();
      await expect(row.locator('.howto-title').first()).toBeVisible();
      await expect(row).toContainText('openssl x509');
      await dashboard.snapElement(`${MANUAL_HOST} yönergesi: yedek pin kimin, nasıl hesaplanır`, `tr.setup-howto[data-setup-howto="host:${MANUAL_HOST}:${API}"]`);
    });

    await test.step('Web: 4 · Kod: "Sonraki adımlar"; mTLS seçilince kayıt token\'ı adımı eklenir', async () => {
      await step('app').click();
      await expect(page.locator('select[data-arg0="apiId"]')).toBeVisible({ timeout: 30_000 });
      await page.selectOption('select[data-arg0="apiId"]', API);
      await step('code').click();
      await expect(page.locator('#setup-next-steps')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('#setup-next-steps li[data-setup-next="dependency"]')).toContainText('io.github.umutcansu:pinvault');
      await expect(page.locator('#setup-next-steps li[data-setup-next="token"]')).toHaveCount(0);
      await dashboard.snapCard('#setup-next-steps', 'Sonraki adımlar (TLS Config API): token adımı yok');

      await step('app').click();
      const options = await page.locator('select[data-arg0="apiId"] option').allTextContents();
      const mtls = options.find((o) => /MTLS/.test(o));
      if (!mtls) {
        await attachText(testInfo, 'mTLS Config API yok', options.join('\n'));
        return;
      }
      await page.selectOption('select[data-arg0="apiId"]', { label: mtls });
      await step('code').click();
      await expect(page.locator('#setup-next-steps li[data-setup-next="token"]')).toContainText('Token Üret');
      await dashboard.snapCard('#setup-next-steps', 'Sonraki adımlar (mTLS Config API): kayıt token\'ı adımı var');
    });

    await test.step('Web: İngilizce arayüz: "How to", adımlar İngilizce, "Verify"', async () => {
      await dashboard.setLang('en');
      await step('server').click();
      await expect(check('signers')).toBeVisible({ timeout: 30_000 });
      await expect(check('signers').locator('[data-action="toggleSetupHowto"]')).toHaveText('How to');
      await check('signers').locator('[data-action="toggleSetupHowto"]').click();
      const row = howtoRow('server:signers');
      await expect(row.locator('li.howto-verify')).toContainText('Verify');
      await expect(row).toContainText('at least two signers');
      await expect(page.locator('#setup-order')).toContainText('Order of work');
      await dashboard.snapElement('English: the "Config signers" how-to', 'tr.setup-howto[data-setup-howto="server:signers"]');
      await dashboard.setLang('tr');
    });
  } finally {
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json?.pins || []).filter((p) => p.hostname !== MANUAL_HOST);
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } }).catch(() => {});
    await page.close().catch(() => {});
  }
});
