// Kurulum yolculuğu: sunucu ayarları panelden. Kurulum Sihirbazının Ayarlar
// kartında bir ayar değiştirilir ve kaydedilir; panel "yeniden başlayınca
// geçerli olacak" der. "Şimdi yeniden başlat" ile sunucu kapanıp açılır ve
// ayar geçerli olur. Sunucuyu açmayacak bir ayar kaydedilemez; dosyaya elle
// yazılsa bile sunucu onsuz açılır ve panel nedenini gösterir. Yeniden
// başlatma yıkıcı olduğu için geçici test sunucusunda çalışır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const fs = require('fs');

async function setting(key) {
  const res = await fresh.api('/api/v1/server-settings');
  expect(res.status, `ayarlar okunamadı: ${res.text}`).toBe(200);
  return res.json.settings.find((s) => s.key === key);
}

/** Sunucu yeniden açılıp ayarları okuyana kadar bekler (panel kendi de bekler). */
async function waitRestarted(page) {
  await page.waitForFunction(
    () => !document.getElementById('settings-pending') && document.getElementById('settings-card'),
    null,
    { timeout: 180_000 },
  );
}

test('Kurulum: sunucu ayarları panelden seçilir, kaydedilir ve yeniden başlatınca geçerli olur', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  await fresh.ensure();
  // Önceki bir koşudan kalan kopyada yeni compose ayarı (PINVAULT_RESTART_ON_EXIT) olmayabilir;
  // .env'de yazılı bir değer de ayarı panelde kilitlerdi.
  fresh.copyTree();
  const envText = fs.readFileSync(fresh.envFile(), 'utf8').replace(/^(PIN_LIVE_CHECK|CONFIG_TTL_SECONDS)=.*$/gm, '$1=');
  fs.writeFileSync(fresh.envFile(), envText, { mode: 0o600 });
  fresh.compose(['up', '-d', '--build']);
  await fresh.waitHealthy();

  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;

  try {
    await test.step('Web: Kurulum Sihirbazında Ayarlar kartı açılır', async () => {
      await page.click('#nav-setup');
      await expect(page.locator('#settings-card')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('#setting-PIN_LIVE_CHECK select')).toBeEnabled();
      // Compose'un doldurduğu adres ayarları .env (ortam) ile sabit: değiştirilemez.
      await expect(page.locator('#setting-SETUP_PUBLIC_HOST input')).toBeDisabled();
      await dashboard.snapElement('Ayarlar kartı: ayarlar gruplu, açıklamalı; ortamda sabit olanlar kilitli', '#settings-card');
    });

    await test.step('Web: iki ayar değiştirilip kaydedilir; panel "yeniden başlayınca" der', async () => {
      await page.selectOption('#setting-PIN_LIVE_CHECK select', 'warn');
      await page.fill('#setting-CONFIG_TTL_SECONDS input', '43200');
      await page.locator('#setting-CONFIG_TTL_SECONDS input').dispatchEvent('change');
      await page.click('[data-action="saveServerSettings"]');
      await expect(page.locator('#settings-pending')).toBeVisible({ timeout: 20_000 });
      await expect(page.locator('#setting-PIN_LIVE_CHECK')).toContainText('Yeniden başlayınca: Uyarı ver');
      const live = await setting('PIN_LIVE_CHECK');
      expect(live.saved).toBe('warn');
      expect(live.running).toBeNull();
      await dashboard.snap('kaydedildi: "Kaydedilen değişiklikler sunucu yeniden başlayınca geçerli olacak"');
    });

    await test.step('Web: "Şimdi yeniden başlat" → sunucu kapanıp açılır, ayarlar geçerli', async () => {
      const started = Date.now();
      await page.click('[data-action="restartServer"]');
      await waitRestarted(page);
      const live = await setting('PIN_LIVE_CHECK');
      const ttl = await setting('CONFIG_TTL_SECONDS');
      expect(live.running).toBe('warn');
      expect(ttl.running).toBe('43200');
      expect(live.pending || ttl.pending).toBe(false);
      await dashboard.snapElement('yeniden başladı: "Şu an: Uyarı ver", config ömrü 43200', '#settings-card');
      await attachText(testInfo, 'Yeniden başlatma', [
        `Süre: ${Math.round((Date.now() - started) / 1000)} sn`,
        `PIN_LIVE_CHECK: ${live.running} · CONFIG_TTL_SECONDS: ${ttl.running}`,
        'Ayarlar data/db/server-settings.json dosyasında; .env\'e dokunulmadı.',
      ].join('\n'));
    });

    await test.step('Web: sunucuyu açmayacak ayar kaydedilmez (paket adı olmadan "Engelle")', async () => {
      const res = await fresh.api('/api/v1/server-settings', {
        method: 'PUT', body: { values: { ATTESTATION_KEY_POLICY: 'enforce' } },
      });
      expect(res.status).toBe(400);
      expect(res.json.error).toBe('would_not_start');
      expect((await setting('ATTESTATION_KEY_POLICY')).saved).toBeNull();
      await attachText(testInfo, 'Reddedilen kayıt', JSON.stringify(res.json, null, 2));
    });

    await test.step('Sunucu: dosyaya elle yazılan bozuk ayar sunucuyu kilitlemez; panel nedenini gösterir', async () => {
      fresh.run('docker', ['exec', fresh.CONTAINER, 'sh', '-c',
        'printf \'{"values":{"ATTESTATION_KEY_POLICY":"enforce"}}\' > /data/db/server-settings.json']);
      fresh.run('docker', ['restart', fresh.CONTAINER]);
      await fresh.waitHealthy();
      const view = (await fresh.api('/api/v1/server-settings')).json;
      expect(view.rejected && view.rejected.reason).toContain('ATTESTATION_KEY_POLICY=enforce');
      expect((await setting('ATTESTATION_KEY_POLICY')).running).toBeNull();
      await page.reload();
      await page.click('#nav-setup');
      await expect(page.locator('[data-action="dismissSettingsRejected"]')).toBeVisible({ timeout: 30_000 });
      await dashboard.snap('panel: "Panelden kaydedilen ayarlar sunucuyu başlatmadı, bu yüzden uygulanmadı"');
      await page.click('[data-action="dismissSettingsRejected"]');
      await expect(page.locator('[data-action="dismissSettingsRejected"]')).toHaveCount(0);
    });
  } finally {
    // Geçici sunucuyu varsayılan ayarlara döndür.
    await fresh.api('/api/v1/server-settings', {
      method: 'PUT', body: { values: { PIN_LIVE_CHECK: '', CONFIG_TTL_SECONDS: '' } },
    }).catch(() => {});
    try {
      fresh.run('docker', ['restart', fresh.CONTAINER]);
      await fresh.waitHealthy();
    } catch {
      /* geçici sunucu zaten kapalı */
    }
    await page.close().catch(() => {});
  }
});
