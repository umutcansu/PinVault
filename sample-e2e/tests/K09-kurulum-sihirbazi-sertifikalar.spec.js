// Kurulum yolculuğu: sihirbazın "Sertifikalar" adımı. Üretime geçmeden karar
// verilecek sertifikalar tek sayfada: Config API'nin kendi sertifikası
// (uygulamadaki ilk pin'ler), mTLS (client CA, kurtarma kapısı), pinlenen
// host'lar ve vault dosyalarının süreleri. Her satırda tamam / uyarı / eksik
// rozeti ve değişikliğin yapıldığı sayfaya giden düğme. Kanıtlanan:
//
//   • dört kart; Config API sertifikası "self-signed, pinned" ile HAZIR, yedek
//     anahtar var, telefonların bağlandığı ad (LAN IP) sertifikada,
//   • mTLS kartındaki client CA pin'i Kod adımındaki clientCaPins ile aynı,
//   • süresi geçmiş sertifikayla yüklenen host "EKSİK", elle girilen host yedek
//     pin'i için "UYARI"; "Host sayfası" düğmesi host'u açıyor,
//   • "Bootstrap sekmesi" düğmesi Config API'nin Bootstrap sekmesini açıyor,
//   • adımlar arasında ileri / geri; İngilizce arayüz.
//
// Geçici test sunucusunda koşar.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');

const API = 'default-tls';
const EXPIRED_HOST = 'k09-expired.sample';
const MANUAL_HOST = 'k09-manual.sample';

function makeExpiredKeystore(name) {
  fs.rmSync(path.join(fresh.DIR, `data/certs/${name}.jks`), { force: true });
  return fresh.compose([
    'exec', '-T', 'pinvault-host', 'keytool', '-genkeypair',
    '-alias', name, '-keyalg', 'RSA', '-keysize', '2048',
    '-dname', `CN=${name}, O=PinVault E2E`,
    '-validity', '1', '-startdate', '-400d',
    '-keystore', `/data/certs/${name}.jks`,
    '-storepass', 'changeit', '-keypass', 'changeit',
  ]);
}

test('Kurulum: sihirbazın "Sertifikalar" adımı her sertifikayı rozetle listeliyor ve ilgili sayfaya götürüyor', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  await fresh.ensure();
  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;
  const certsTab = () => page.locator('[data-action="setSetupStep"][data-arg0="certs"]').first();
  const check = (id) => page.locator(`tr[data-setup-check="${id}"]`).first();

  try {
    await test.step('Web: süresi geçmiş sertifikalı bir host (Dosya Yükle) ve elle girilen bir host eklenir', async () => {
      makeExpiredKeystore(EXPIRED_HOST);
      await dashboard.addHostUpload(API, EXPIRED_HOST, path.join(fresh.DIR, `data/certs/${EXPIRED_HOST}.jks`), 'changeit');
      await dashboard.addHostManual(API, MANUAL_HOST, [hostApi.randomPin(), hostApi.randomPin()]);
    });

    await test.step('Web: Kurulum Sihirbazı → "2 · Sertifikalar": dört kart, rozetler', async () => {
      await page.click('#nav-setup');
      await expect(certsTab()).toBeVisible({ timeout: 30_000 });
      await certsTab().click();
      await expect(page.locator('#setup-certs-config-api table')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('#setup-certs-mtls')).toBeVisible();
      await expect(page.locator('#setup-certs-hosts')).toBeVisible();
      await expect(page.locator('#setup-certs-vault')).toBeVisible();
      await dashboard.snap('Sertifikalar adımı: dört kart');
      const facts = (await fresh.api('/api/v1/setup/certificates')).json;
      await attachText(
        testInfo,
        'GET /api/v1/setup/certificates — kontrol listesi',
        facts.checks.map((c) => `${String(c.level).toUpperCase().padEnd(5)} ${c.id.padEnd(26)} ${(c.hostname || c.key || c.configApiId || '').padEnd(24)} ${c.current}`).join('\n'),
      );
    });

    await test.step('Web: Config API sertifikası — self-signed ama pinli (HAZIR), yedek anahtar var, LAN IP sertifikanın adlarında', async () => {
      await expect(check('config_api_cert_source')).toHaveAttribute('data-setup-level', 'ok');
      await expect(check('config_api_cert_source')).toContainText('self-signed, pinned');
      await expect(check('config_api_backup_key')).toHaveAttribute('data-setup-level', 'ok');
      await expect(check('config_api_cert_name')).toHaveAttribute('data-setup-level', 'ok');
      await dashboard.snapCard('#setup-certs-config-api', 'Config API sertifikası kartı');
    });

    await test.step('Web: mTLS kartındaki client CA pin\'i Kod adımındaki clientCaPins ile aynı', async () => {
      const pin = (await page.locator('#setup-certs-client-ca-pin').innerText()).trim();
      expect(pin).toMatch(/^[A-Za-z0-9+/]{43}=$/);
      await dashboard.snapCard('#setup-certs-mtls', 'mTLS kartı: client CA, cihaz sertifikası ömrü, kurtarma kapısı');
      await page.locator('[data-action="setSetupStep"][data-arg0="code"]').first().click();
      const code = await page.locator('pre.json-box').first().innerText();
      await attachText(testInfo, 'Kod adımındaki clientCaPins satırı', code.split('\n').filter((l) => l.includes('clientCaPins')).join('\n') || '(satır yok)');
      expect(code).toContain(`clientCaPins("${pin}")`);
      await page.locator('[data-action="setSetupStep"][data-arg0="certs"]').first().click();
      await expect(page.locator('#setup-certs-hosts')).toBeVisible({ timeout: 30_000 });
    });

    await test.step('Web: host\'lar kartı — süresi geçmiş host EKSİK, elle girilen host yedek pin için UYARI; "Host sayfası" host\'u açıyor', async () => {
      const expiredRow = page.locator(`tr[data-setup-host="${EXPIRED_HOST}"]`);
      const manualRow = page.locator(`tr[data-setup-host="${MANUAL_HOST}"]`);
      await expect(expiredRow).toHaveAttribute('data-setup-level', 'fail');
      await expect(expiredRow).toContainText('expired');
      await expect(manualRow).toHaveAttribute('data-setup-level', 'warn');
      await expect(manualRow).toContainText('elle girildi');
      await dashboard.snapCard('#setup-certs-hosts', 'host\'lar kartı: süresi geçmiş host EKSİK, elle girilen host UYARI');
      await expiredRow.locator('[data-action="setupOpenHost"]').click();
      await expect(page.locator('.section-title-main')).toContainText(EXPIRED_HOST, { timeout: 30_000 });
      await dashboard.snap(`"Host sayfası": ${EXPIRED_HOST} açıldı`);
    });

    await test.step('Web: "Bootstrap sekmesi" düğmesi Config API\'nin Bootstrap sekmesini açıyor', async () => {
      await page.click('#nav-setup');
      await certsTab().click();
      await expect(check('config_api_cert')).toBeVisible({ timeout: 30_000 });
      await check('config_api_cert').locator('[data-action="setupOpenBootstrap"]').click();
      await expect(page.locator('button.tab-btn.tab-active[data-arg0="bootstrap"]')).toBeVisible({ timeout: 30_000 });
      await dashboard.snap('"Bootstrap sekmesi": Config API\'nin sertifika sekmesi');
    });

    await test.step('Web: adımlar arasında geri / ileri ve İngilizce arayüz', async () => {
      await page.click('#nav-setup');
      await certsTab().click();
      await expect(page.locator('#setup-certs')).toBeVisible({ timeout: 30_000 });
      await page.locator('#setup-certs [data-action="setSetupStep"][data-arg0="server"]').click();
      await expect(page.locator('#settings-card')).toBeVisible({ timeout: 30_000 });
      await page.locator('[data-action="setSetupStep"][data-arg0="certs"]').last().click();
      await expect(page.locator('#setup-certs-hosts')).toBeVisible({ timeout: 30_000 });
      await dashboard.setLang('en');
      await expect(page.locator('#setup-certs-config-api')).toContainText('first pins', { timeout: 30_000 });
      await expect(certsTab()).toContainText('Certificates');
      await dashboard.snap('English: Certificates step');
      await dashboard.setLang('tr');
    });
  } finally {
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json?.pins || []).filter((p) => ![EXPIRED_HOST, MANUAL_HOST].includes(p.hostname));
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } }).catch(() => {});
    fs.rmSync(path.join(fresh.DIR, `data/certs/${EXPIRED_HOST}.jks`), { force: true });
    await page.close().catch(() => {});
  }
});
