// E5–E6: Config API yaşam döngüsü (oluştur / durdur / başlat / sil — silinince
// kapsamdaki host'lar da gider), port çakışması ve host doğrulama uçları
// (ping-remote geçerli host + komut enjeksiyonu reddi, test-connection).
// Geçici test sunucusunda çalışır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const API_ID = 'e05-tls';
const API_PORT = 8096;
const CONFLICT_ID = 'e05-cakisma';
const SCOPED_HOST = 'e05-scoped.sample';
const MOCK_HOST = env.MOCK_TLS_HOST;

/** Container içinden Config API'nin kendi portuna istek (port dışarı açılmamış). */
function probeInside(port) {
  try {
    return fresh
      .compose(['exec', '-T', 'pinvault-host', 'curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}',
        '--max-time', '5', `https://localhost:${port}/api/v1/certificate-config?signed=false`])
      .trim();
  } catch (e) {
    return `bağlanamadı (${(e.stdout || '').trim() || 'curl hata'})`;
  }
}

test('Sunucu: Config API oluşturulur, durdurulur, başlatılır ve silinince host\'ları da gider', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  await fresh.ensure();

  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;

  try {
    await test.step('Web: yeni Config API oluşturulur ve kendi host\'u eklenir', async () => {
      const toast = await dashboard.createConfigApi(API_ID, API_PORT, 'tls');
      await expect(page.locator(`#host-list .api-header[data-arg0="${API_ID}"]`)).toBeVisible({ timeout: 20_000 });
      await dashboard.addHostGenerate(API_ID, SCOPED_HOST);
      await dashboard.snap(`yeni Config API ve kapsamındaki host: ${API_ID}`);
      const inside = probeInside(API_PORT);
      await attachText(
        testInfo,
        `Config API :${API_PORT}`,
        [
          `toast: ${toast}`,
          `container içinden GET https://localhost:${API_PORT}/api/v1/certificate-config → ${inside}`,
          `kapsamdaki host: ${SCOPED_HOST}`,
        ].join('\n'),
      );
      expect(inside).toBe('200');
    });

    await test.step('Web: aynı porta ikinci bir Config API açılınca önceki durduruluyor', async () => {
      // ConfigApiManager aynı portu kullanan örneği önce durduruyor: port
      // çakışmasında hata dönmüyor, "son gelen kazanır" davranışı var.
      const toast = await dashboard.createConfigApi(CONFLICT_ID, API_PORT, 'tls');
      const all = await fresh.api('/api/v1/all-configs');
      const rows = (all.json || []).filter((a) => a.port === API_PORT);
      await attachText(
        testInfo,
        `Aynı port (${API_PORT}) iki Config API`,
        [
          `dashboard → sunucu yanıtı: ${toast}`,
          '',
          ...rows.map((a) => `${a.id} :${a.port} running=${a.running}`),
          '',
          'ConfigApiManager.start: aynı porttaki örneği durdurup yeni dinleyiciyi açıyor;',
          'istek hata döndürmüyor, eski Config API "durduruldu" durumuna geçiyor.',
        ].join('\n'),
      );
      await dashboard.snap('aynı porta ikinci Config API: önceki durduruldu');
      expect(rows.find((a) => a.id === API_ID).running).toBe(false);
      expect(rows.find((a) => a.id === CONFLICT_ID).running).toBe(true);

      // Senaryonun devamı için çakışan örneği sil, ilkini geri başlat.
      await fresh.api('/api/v1/config-apis/delete', { method: 'POST', body: { id: CONFLICT_ID } });
      await fresh.api('/api/v1/config-apis/start', { method: 'POST', body: { id: API_ID, port: API_PORT, mode: 'tls' } });
      await page.reload();
      await expect(page.locator('#host-list .api-header').first()).toBeVisible();
    });

    await test.step('Web: Config API durdurulur → dinleyici kapanır', async () => {
      await dashboard.setConfigApiRunning(API_ID, false);
      await dashboard.snap(`${API_ID} durduruldu`);
      const inside = probeInside(API_PORT);
      await attachText(
        testInfo,
        'Durdurulmuş Config API',
        [
          `all-configs → running=${await dashboard.apiRunning(API_ID)}`,
          `container içinden GET https://localhost:${API_PORT}/… → ${inside}`,
        ].join('\n'),
      );
      expect(inside).not.toBe('200');
    });

    await test.step('Web: Config API tekrar başlatılır → dinleyici döner', async () => {
      await dashboard.setConfigApiRunning(API_ID, true);
      await dashboard.snap(`${API_ID} tekrar çalışıyor`);
      const inside = probeInside(API_PORT);
      await attachText(testInfo, 'Yeniden başlatılan Config API', `container içinden → ${inside}`);
      expect(inside).toBe('200');
    });

    await test.step('Sunucu: ping-remote gerçek bir host\'u doğruluyor, komut enjeksiyonu denemesini reddediyor', async () => {
      await dashboard.addHostFromUrl('default-tls', `https://${env.TARGET_HOST}`);
      await expect(dashboard.hostItem(env.TARGET_HOST)).toBeVisible({ timeout: 30_000 });
      const ok = await fresh.api(`/api/v1/hosts/${env.TARGET_HOST}/ping-remote?configApiId=default-tls`);
      const bad = await fresh.api('/api/v1/hosts/%24(id)/ping-remote?configApiId=default-tls');
      const unknown = await fresh.api(`/api/v1/hosts/${MOCK_HOST}/ping-remote?configApiId=default-tls`);
      await attachText(
        testInfo,
        'GET /api/v1/hosts/{hostname}/ping-remote',
        [
          `${env.TARGET_HOST} → HTTP ${ok.status}`,
          ok.text,
          '',
          `"$(id)" (komut enjeksiyonu denemesi) → HTTP ${bad.status}`,
          bad.text,
          '',
          `${MOCK_HOST} (container DNS'inde yok) → HTTP ${unknown.status}`,
          unknown.text,
        ].join('\n'),
      );
      expect(ok.json.reachable).toBe(true);
      expect(ok.json.pinMatch).toBe(true);
      expect(bad.status).toBe(400);
    });

    await test.step('Sunucu: fetch-cert-url — kayıtlı host\'un pin\'leri, host\'un şu an sunduğu sertifikadan yenilenir', async () => {
      // Arayüzde düğmesi olmayan uç: host zaten kayıtlıyken pin'leri URL'den
      // yeniden çeker, sürümü artırır, geçmişe "cert_fetched" yazar.
      const readEntry = async () =>
        (await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false })).json.pins
          .find((p) => p.hostname === env.TARGET_HOST);
      const before = await readEntry();
      const res = await fresh.api(`/api/v1/hosts/${env.TARGET_HOST}/fetch-cert-url?configApiId=default-tls`, {
        method: 'POST',
        body: { url: `https://${env.TARGET_HOST}` },
      });
      const after = await readEntry();
      const live = await hostApi.livePins(env.TARGET_HOST);
      // Sayfanın bellekteki config kopyası eski: yeniden yüklenip host ağaçtan açılır.
      await page.reload();
      await expect(page.locator('#host-list .api-header').first()).toBeVisible();
      await dashboard.openHostIn('default-tls', env.TARGET_HOST);
      await dashboard.snapHostSummary(`${env.TARGET_HOST}: URL'den yenilenen pin'ler, v${after.version}`);
      await expect(page.locator('#pin-history-card tbody tr').first()).toContainText('cert_fetched', { timeout: 20_000 });
      await dashboard.snapCard('#pin-history-card', 'pin geçmişi: cert_fetched');
      await attachText(
        testInfo,
        `POST /api/v1/hosts/${env.TARGET_HOST}/fetch-cert-url {"url":"https://${env.TARGET_HOST}"}`,
        [
          `HTTP ${res.status} ${res.text.trim()}`,
          '',
          `önce : v${before.version}  ${before.sha256.join(' | ')}`,
          `sonra: v${after.version}  ${after.sha256.join(' | ')}`,
          `canlı zincir: ${live.join(' | ')}`,
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(after.version).toBe(before.version + 1);
      expect(after.sha256).toEqual(live);
    });

    await test.step('Web: test için kurulan hedef sunucuda (mock host) "Bağlantıyı Test Et"', async () => {
      const toast = await dashboard.testConnection(MOCK_HOST);
      const res = await fresh.api(`/api/v1/hosts/${MOCK_HOST}/test-connection?configApiId=default-tls`, { method: 'POST' });
      await dashboard.snap('mock host bağlantı testi');
      await attachText(
        testInfo,
        `POST /api/v1/hosts/${MOCK_HOST}/test-connection`,
        `dashboard toast: ${toast}\n\nHTTP ${res.status}\n${res.text}`,
      );
      expect(res.json.success).toBe(true);
    });

    await test.step('Web: Config API silinince kapsamındaki host\'lar da silinir', async () => {
      await dashboard.deleteConfigApi(API_ID);
      await dashboard.snap(`${API_ID} silindi`);
      const all = await fresh.api('/api/v1/all-configs');
      const ids = (all.json || []).map((a) => a.id);
      const scoped = (all.json || []).flatMap((a) => (a.pins || []).map((p) => `${a.id}/${p.hostname}`));
      await attachText(
        testInfo,
        'GET /api/v1/all-configs (silmeden sonra)',
        [`Config API'ler: ${ids.join(', ')}`, '', 'Host kapsamları:', ...scoped].join('\n'),
      );
      expect(ids).not.toContain(API_ID);
      expect(scoped.join(',')).not.toContain(SCOPED_HOST);
      expect(probeInside(API_PORT)).not.toBe('200');
    });
  } finally {
    await fresh.api('/api/v1/config-apis/delete', { method: 'POST', body: { id: API_ID } }).catch(() => {});
    await fresh.api('/api/v1/config-apis/delete', { method: 'POST', body: { id: CONFLICT_ID } }).catch(() => {});
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json.pins || []).filter((p) => p.hostname !== env.TARGET_HOST);
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } });
    await page.close();
  }
});
