// E12 — Config API'nin pin seti geçmişi ve bütün seti geri alma.
//
// Host sayfasındaki geri alma tek host içindir; Config API sayfasındaki "Pin
// Seti Geçmişi" kartı kapsamın tamamını bir önceki duruma döndürür: sonradan
// eklenen host'lar listeden çıkar, silinenler geri gelir (sürümleri v1'e
// dönmez, kaldığı yerden devam eder). Kanıtlanan:
//
//   • kart her değişiklikten sonra bir satır alıyor ("kim", "ne değişti"),
//   • host A eklenip B eklenip A silindikten sonra "A var, B yok" satırına
//     "Bu duruma dön": A geri geliyor (sürümü artarak), B çıkıyor,
//   • en üst satır "yayında", kart yeniden çiziliyor,
//   • arayüz İngilizce'ye alınınca kart ve düğmeler İngilizce.
//
// Geçici test sunucusunda koşar (ana host'un pin'lerine dokunulmaz).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');

const API = 'default-tls';
const HOST_A = 'e12-a.sample';
const HOST_B = 'e12-b.sample';

async function scopedHosts() {
  const res = await fresh.api(`/api/v1/config/${API}`);
  return Object.fromEntries((res.json.pins || []).map((p) => [p.hostname, p.version]));
}

async function snapshots() {
  const res = await fresh.api(`/api/v1/pin-snapshots?configApiId=${API}`);
  expect(res.status, res.text).toBe(200);
  return res.json;
}

test('Web: Config API sayfasındaki pin seti geçmişi her değişikliği listeliyor; "Bu duruma dön" bütün seti geri getiriyor (eklenen çıkar, silinen döner, sürüm devam eder)', async ({
  browser,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();
  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;
  const card = page.locator('#snapshots-card');
  const pinsA = [hostApi.randomPin(), hostApi.randomPin()];
  const pinsB = [hostApi.randomPin(), hostApi.randomPin()];
  let wanted;
  let versionA;
  let hostsWithA;

  try {
    await test.step('Web: host A eklenir; Config API sayfasındaki "Pin Seti Geçmişi" kartının en üstünde "A v1" satırı, rozeti "yayında"', async () => {
      await dashboard.addHostManual(API, HOST_A, pinsA);
      versionA = (await scopedHosts())[HOST_A];
      hostsWithA = Object.keys(await scopedHosts()).sort();   // the provisioned hosts + A
      await dashboard.openConfigApiTab(API, 'general');
      await expect(card.locator('tbody tr').first()).toContainText(`${HOST_A} v${versionA}`, { timeout: 30_000 });
      await expect(card.locator('tbody tr').first()).toContainText('yayında');
      await dashboard.snapCard('#snapshots-card', `pin seti geçmişi: ${HOST_A} eklendi`);
      wanted = (await snapshots())[0];
      expect(wanted.changed).toContain(`${HOST_A} v${versionA}`);
    });

    await test.step('Web: host B eklenir, A silinir; kartta iki yeni satır ("B v1", "A removed")', async () => {
      await dashboard.addHostManual(API, HOST_B, pinsB);
      await dashboard.deleteHost(HOST_A);
      await dashboard.openConfigApiTab(API, 'general');
      await expect(card.locator('tbody tr').first()).toContainText(`${HOST_A} removed`, { timeout: 30_000 });
      const list = await snapshots();
      await attachText(
        testInfo,
        `GET /api/v1/pin-snapshots?configApiId=${API}`,
        list.slice(0, 5).map((s) => `#${s.id}  ${s.takenAt}  ${s.actor}  ${s.hostCount} host  değişen: ${s.changed.join(', ') || '—'}`).join('\n'),
      );
      expect(list[0].changed).toContain(`${HOST_A} removed`);
      expect(list[1].changed).toContain(`${HOST_B} v1`);
      expect(list[2].id).toBe(wanted.id);
      await dashboard.snapCard('#snapshots-card', 'B eklendi, A silindi: üç satır');
    });

    await test.step('Web: "A var, B yok" satırında "Bu duruma dön" → A geri gelir (sürümü artar), B çıkar; en üst satır yayında', async () => {
      const dialogsBefore = dashboard.dialogs.length;
      const response = page.waitForResponse(
        (r) => r.url().includes(`/api/v1/pin-snapshots/${wanted.id}/restore`) && r.request().method() === 'POST',
        { timeout: 30_000 },
      );
      await card.locator(`[data-action="restoreSnapshot"][data-arg1="${wanted.id}"]`).click();
      const res = await response;
      const body = JSON.parse(await res.text());
      const confirmText = dashboard.dialogs[dialogsBefore] || '';
      await expect.poll(async () => Object.keys(await scopedHosts()).sort(), { timeout: 30_000 }).toEqual(hostsWithA);
      await dashboard.ensureApiExpanded(API);
      await expect(dashboard.hostItem(HOST_A)).toBeVisible({ timeout: 30_000 });
      await expect(dashboard.hostItem(HOST_B)).toHaveCount(0);
      const hosts = await scopedHosts();
      await dashboard.snap(`geri alındı: ${HOST_A} listede (v${hosts[HOST_A]}), ${HOST_B} yok`);
      await attachText(
        testInfo,
        `"Bu duruma dön" (POST /api/v1/pin-snapshots/${wanted.id}/restore)`,
        [
          `Onay penceresi: ${confirmText}`,
          '',
          `HTTP ${res.status()} ${JSON.stringify(body)}`,
          '',
          `${HOST_A}: eklendiğinde v${versionA}, geri gelince v${hosts[HOST_A]} (v1'e dönmedi, kaldığı yerden devam etti)`,
          `${HOST_B}: listeden çıktı`,
        ].join('\n'),
      );
      expect(confirmText).toContain('yeni sürümlerle');
      expect(body.restored).toBe(true);
      expect(hosts[HOST_A]).toBeGreaterThan(versionA);
      expect(hosts[HOST_B]).toBeUndefined();
      await dashboard.openConfigApiTab(API, 'general');
      await expect(card.locator('tbody tr').first()).toContainText('yayında', { timeout: 30_000 });
      await dashboard.snapCard('#snapshots-card', 'geri alma sonrası: en üst satır yayında');
    });

    await test.step('Web: İngilizce arayüzde kart ve düğmeler İngilizce', async () => {
      await dashboard.setLang('en');
      await dashboard.openConfigApiTab(API, 'general');
      await expect(card).toContainText('Pin Set History', { timeout: 30_000 });
      await expect(card.locator('[data-action="restoreSnapshot"]').first()).toContainText('Restore this state');
      await dashboard.snapCard('#snapshots-card', 'English: Pin Set History / Restore this state');
      await dashboard.setLang('tr');
    });
  } finally {
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json?.pins || []).filter((p) => ![HOST_A, HOST_B].includes(p.hostname));
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } }).catch(() => {});
    await page.close().catch(() => {});
  }
});
