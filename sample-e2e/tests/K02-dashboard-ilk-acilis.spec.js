// Kurulum yolculuğu K4–K5: dashboard'un ilk açılışı (API anahtarı istemi,
// yanlış anahtar reddi, doğru anahtarla giriş) ve varsayılan Config API'nin
// Genel / Bootstrap / İmzalama sekmeleri (pin'ler, SAN'daki LAN IP, istemci
// kod parçası, imzalama public key'i). Geçici test sunucusunda çalışır.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

test('Kurulum: dashboard ilk açılışta API anahtarı ister; Config API sekmeleri pin\'leri ve imzalama public key\'ini gösterir', async ({
  browser,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();

  const dashboard = await fresh.openDashboard(browser, testInfo, { withKey: false });
  const page = dashboard.page;

  try {
    await test.step('Web: anahtarsız açılış — dashboard API anahtarı ister (K4)', async () => {
      dashboard.answerPrompt('yanlis-anahtar');
      await page.goto(`${fresh.WEB_URL}/`);
      await expect.poll(() => dashboard.dialogs.length, { timeout: 20_000 }).toBeGreaterThan(0);
      await attachText(
        testInfo,
        'Dashboard\'un açtığı anahtar sorusu pencereleri',
        dashboard.dialogs.map((d, i) => `#${i + 1} ${d}`).join('\n'),
      );
      expect(dashboard.lastDialog()).toContain('X-API-Key');
      await dashboard.snap('yanlış anahtardan sonra dashboard: host listesi boş (anahtar sorusunun metni ayrı panelde)');
    });

    await test.step('Sunucu: anahtarsız istek 401, yanlış anahtarlı istek 403 alır (K4)', async () => {
      const none = await fresh.api('/api/v1/all-configs', { withKey: false });
      const wrong = await fresh.api('/api/v1/all-configs', { key: 'yanlis-anahtar' });
      await attachText(
        testInfo,
        'GET /api/v1/all-configs — anahtarsız / yanlış anahtar',
        [
          `anahtarsız      → HTTP ${none.status} ${none.text.trim()}`,
          `yanlış anahtar  → HTTP ${wrong.status} ${wrong.text.trim()}`,
          '',
          'Dashboard her iki durumda da anahtarı yeniden sorar (app-core.js: apiFetch).',
        ].join('\n'),
      );
      expect(none.status).toBe(401);
      expect([401, 403]).toContain(wrong.status);
      // Yanlış anahtarla veri gelmediği için host ağacı boş kalır.
      await expect(page.locator('#host-list .api-header')).toHaveCount(0);
    });

    await test.step('Web: doğru anahtarla giriş (K4)', async () => {
      dashboard.promptAnswers.length = 0;
      dashboard.answerPrompt(fresh.apiKey());
      await page.goto(`${fresh.WEB_URL}/`);
      await expect(page.locator('#host-list .api-header').first()).toBeVisible({ timeout: 20_000 });
      await dashboard.snap('doğru anahtarla giriş yapıldı');
      const hosts = await dashboard.hostNames();
      expect(hosts).toContain(env.LAN_IP);
    });

    await test.step('Web: Config API → Genel sekmesi (port, mod, host sayısı, sürüm) (K5)', async () => {
      await dashboard.openConfigApiTab('default-tls', 'general');
      await expect(page.locator('#config-api-tab-content')).toContainText('TLS');
      await dashboard.snap('default-tls Genel sekmesi');
    });

    await test.step('Web: "Bootstrap Pin" sekmesi — uygulamaya gömülecek sunucu pin\'leri ve örnek istemci kodu (K5)', async () => {
      const pins = await dashboard.bootstrapPins('default-tls');
      await dashboard.snap('Bootstrap Pin sekmesi: uygulamaya gömülecek sunucu pin\'leri');
      expect(pins.slice(0, 2)).toEqual(fresh.hostPins().slice(0, 2));
      await expect(page.locator('.key-box')).toContainText('BOOTSTRAP_PINS');
      await attachText(
        testInfo,
        'data/certs/demo-server.pins ile karşılaştırma',
        [
          `dashboard : ${pins.join('\n            ')}`,
          `dosya     : ${fresh.hostPins().join('\n            ')}`,
        ].join('\n'),
      );
    });

    await test.step('Sunucu: sertifikanın geçerli olduğu adresler (SAN) arasında LAN IP var (K5)', async () => {
      const out = await attachCommand(testInfo, `openssl s_client :${fresh.PORTS.https} → SAN`, 'bash', [
        '-c',
        `echo | openssl s_client -connect localhost:${fresh.PORTS.https} -servername localhost 2>/dev/null | openssl x509 -noout -text | grep -A 2 "Subject Alternative Name"`,
      ]);
      expect(out).toContain(env.LAN_IP);
    });

    await test.step('Web: İmzalama sekmesindeki public key, sunucudaki anahtar dosyasıyla aynı (K5)', async () => {
      const shown = await dashboard.signingPublicKey('default-tls');
      await dashboard.snap('İmzalama sekmesi: ECDSA public key');
      expect(shown).toBe(fresh.signingKeyRaw().split('\n')[1].trim());
    });
  } finally {
    await page.close();
  }
});
