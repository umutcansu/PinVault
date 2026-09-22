// Kurulum yolculuğu K7–K8: mTLS Config API oluşturma (istemci sertifikası
// yokken truststore olmadığı için 400, sertifika üretilince başarı) ve mock
// hedef host'ların başlatılıp "Bağlantıyı test et" ile doğrulanması.
// Taze host örneği üzerinde.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');

const MTLS_API = 'k04-mtls';
const MTLS_API_PORT = 8095;
const MOCK_HOST = 'k04-mock.sample';
const MOCK_PORT = 8446;
const CLIENT_ID = 'k04-client';

test('Kurulum: mTLS Config API truststore olmadan reddedilir, sertifikayla açılır; mock host test edilir', async ({
  browser,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();

  const trustStore = path.join(fresh.DIR, 'data/certs/client-truststore.jks');
  const stash = `${trustStore}.k04-stash`;
  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;

  try {
    await test.step('Sunucu: truststore yok (kurulumun ilk anı) (K7)', async () => {
      if (fs.existsSync(trustStore)) fs.renameSync(trustStore, stash);
      await attachText(
        testInfo,
        'data/certs içeriği (truststore yok)',
        fs.readdirSync(path.join(fresh.DIR, 'data/certs')).join('\n'),
      );
      expect(fs.existsSync(trustStore)).toBe(false);
    });

    await test.step('Web: istemci sertifikası yokken mTLS Config API reddedilir (K7)', async () => {
      const toast = await dashboard.createConfigApi(MTLS_API, MTLS_API_PORT, 'mtls');
      await dashboard.snap('mTLS Config API reddedildi (truststore yok)');
      const direct = await fresh.api('/api/v1/config-apis/start', {
        method: 'POST',
        body: { id: MTLS_API, port: MTLS_API_PORT, mode: 'mtls' },
      });
      await attachText(
        testInfo,
        'POST /api/v1/config-apis/start (mode=mtls, truststore yok)',
        `dashboard toast: ${toast}\n\nHTTP ${direct.status}\n${direct.text}`,
      );
      expect(direct.status).toBe(400);
      expect(direct.text).toContain('client sertifika');
    });

    await test.step('Web: istemci sertifikası üretilir → truststore oluşur (K7)', async () => {
      await dashboard.generateClientCert('sample-mtls', CLIENT_ID);
      await dashboard.snap(`istemci sertifikası üretildi: ${CLIENT_ID}`);
      expect(fs.existsSync(trustStore)).toBe(true);
      await attachText(
        testInfo,
        'data/certs içeriği (truststore üretildi)',
        fs.readdirSync(path.join(fresh.DIR, 'data/certs')).join('\n'),
      );
    });

    await test.step('Web: mTLS Config API açılır (K7)', async () => {
      const toast = await dashboard.createConfigApi(MTLS_API, MTLS_API_PORT, 'mtls');
      await expect(page.locator(`#host-list .api-header[data-arg0="${MTLS_API}"]`)).toBeVisible({ timeout: 20_000 });
      await dashboard.snap(`mTLS Config API çalışıyor: ${MTLS_API}`);
      await attachText(testInfo, 'Dashboard → sunucu yanıtı', toast);
      expect(await dashboard.apiRunning(MTLS_API)).toBe(true);
    });

    await test.step('Web: mock hedef host eklenir ve başlatılır (K8)', async () => {
      await dashboard.addHostGenerate('default-tls', MOCK_HOST);
      const toast = await dashboard.startMock(MOCK_HOST, { port: MOCK_PORT });
      await dashboard.snap(`mock host başlatıldı: ${MOCK_HOST}`);
      const status = await fresh.api(`/api/v1/hosts/${MOCK_HOST}/status?configApiId=default-tls`);
      await attachText(testInfo, `GET /api/v1/hosts/${MOCK_HOST}/status`, `toast: ${toast}\n\nHTTP ${status.status}\n${status.text}`);
      expect(status.json.mockServerRunning).toBe(true);
    });

    await test.step('Web: "Bağlantıyı test et" mock host\'a pinli bağlanır (K8)', async () => {
      const toast = await dashboard.testConnection(MOCK_HOST);
      await dashboard.snap('bağlantı testi sonucu');
      await attachText(testInfo, 'Bağlantı testi toast\'ı', toast);
      expect(toast.toLowerCase()).not.toContain('hata');

      const test1 = await fresh.api(`/api/v1/hosts/${MOCK_HOST}/test-connection?configApiId=default-tls`, { method: 'POST' });
      await attachText(testInfo, `POST /api/v1/hosts/${MOCK_HOST}/test-connection`, `HTTP ${test1.status}\n${test1.text}`);
      expect(test1.json.success).toBe(true);
    });

    await test.step('Web: provision.sh\'ın açtığı mock host\'lar ağaçta çalışıyor (K8)', async () => {
      await page.reload();
      await expect(page.locator('#host-list .api-header').first()).toBeVisible();
      // Durum noktaları arka planda yenileniyor; "local mock ayakta" beklenir.
      await expect(page.locator('#host-list .host-dot-running').first()).toBeVisible({ timeout: 30_000 });
      await dashboard.snapCard('#host-list', 'host ağacı: mock host durumları');
    });
  } finally {
    try {
      await fresh.api('/api/v1/config-apis/delete', { method: 'POST', body: { id: MTLS_API } });
      await fresh.api(`/api/v1/hosts/${MOCK_HOST}/stop-mock?configApiId=default-tls`, { method: 'POST' });
      const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
      const keep = (cfg.json.pins || []).filter((p) => p.hostname !== MOCK_HOST);
      await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } });
      if (!fs.existsSync(trustStore) && fs.existsSync(stash)) fs.renameSync(stash, trustStore);
      if (fs.existsSync(stash)) fs.unlinkSync(stash);
    } catch {
      /* temizlik en iyi çaba */
    }
    await page.close();
  }
});
