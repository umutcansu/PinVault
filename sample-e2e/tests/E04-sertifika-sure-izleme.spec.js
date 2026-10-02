// E4: sertifika süre izleme. Süresi geçmiş ve yakında dolacak sertifikalar
// geçici test sunucusunun dashboard'undan yüklenir; GET /api/v1/cert-expiry "expired" /
// "warning" döndürür, dashboard'un sertifika süre kartı bunları gösterir ve
// sunucu açılışta CRITICAL / WARNING loglar.
//
// İkinci yarı ANA host'ta ve telefonla: mock TLS host'a süresi geçmiş bir
// sertifika yüklenir; telefon el sıkışmayı "expired or not yet valid" ile
// reddeder ve kurtarma (config yenileme) TETİKLENMEZ — süre hatası pin
// uyuşmazlığı değildir, config tazelemek onu düzeltmez. Sonunda mock host'un
// sertifikası dashboard'dan yenilenir ve taban durumu yeni pin'lere göre
// güncellenir (A20 deseni).
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');
const state = require('../lib/state');
const env = require('../lib/env');

const EXPIRED_HOST = 'e04-expired.sample';
const WARNING_HOST = 'e04-warning.sample';
const MOCK = env.MOCK_TLS_HOST;
const EXPIRED_MOCK_JKS = 'e04-expired-mock.jks';

/**
 * Taze container'daki keytool ile geçmiş tarihli (ya da yakında dolacak) bir
 * keystore üretir. `openssl req -x509` geçmiş bitiş tarihi kabul etmiyor;
 * keytool'un `-startdate` göreli ofseti (ör. -400d) bunu yapabiliyor.
 */
function makeKeystore(name, { startdate, validity }) {
  fs.rmSync(path.join(fresh.DIR, `data/certs/${name}.jks`), { force: true });
  return fresh.compose([
    'exec', '-T', 'pinvault-host', 'keytool', '-genkeypair',
    '-alias', name,
    '-keyalg', 'RSA', '-keysize', '2048',
    '-dname', `CN=${name}, O=PinVault E2E`,
    '-validity', String(validity),
    '-startdate', startdate,
    '-keystore', `/data/certs/${name}.jks`,
    '-storepass', 'changeit', '-keypass', 'changeit',
  ]);
}

/** Ana host container'ında mock TLS host için süresi 399 gün önce dolmuş keystore. */
function makeExpiredMockKeystore() {
  fs.rmSync(path.join(env.HOST_DIR, 'data/certs', EXPIRED_MOCK_JKS), { force: true });
  return execFileSync(
    'docker',
    [
      'exec', env.CONTAINER, 'keytool', '-genkeypair',
      '-alias', 'server', '-keyalg', 'RSA', '-keysize', '2048',
      '-dname', `CN=${MOCK}, O=PinVault E2E`,
      '-ext', `SAN=dns:${MOCK}`,
      '-validity', '1', '-startdate', '-400d',
      '-keystore', `/data/certs/${EXPIRED_MOCK_JKS}`,
      '-storepass', 'changeit', '-keypass', 'changeit',
    ],
    { encoding: 'utf8', timeout: 120_000 },
  );
}

test('Sunucu: süresi geçmiş sertifika cert-expiry\'de "expired", dashboard kartında ve logda görünür; telefon süresi dolmuş host\'u reddeder', async ({
  app,
  device,
  dashboard,
  run,
  browser,
}, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  await fresh.ensure();

  const freshDash = await fresh.openDashboard(browser, testInfo);
  const page = freshDash.page;
  let mockV0;
  let uploaded = false;
  let renewed = false;

  try {
    await test.step('Terminal: süresi geçmiş ve yakında dolacak sertifikalar üretilir', async () => {
      const expiredOut = makeKeystore(EXPIRED_HOST, { startdate: '-400d', validity: 1 });
      const warningOut = makeKeystore(WARNING_HOST, { startdate: '-1d', validity: 6 });
      const list = fresh.compose([
        'exec', '-T', 'pinvault-host', 'keytool', '-list', '-v',
        '-keystore', `/data/certs/${EXPIRED_HOST}.jks`, '-storepass', 'changeit',
      ]);
      await attachText(
        testInfo,
        'keytool ile geçmiş tarihli sertifika',
        [
          `$ keytool -genkeypair -validity 1 -startdate -400d -alias ${EXPIRED_HOST}`,
          expiredOut.trim(),
          `$ keytool -genkeypair -validity 6 -startdate -1d -alias ${WARNING_HOST}`,
          warningOut.trim(),
          '',
          list.split('\n').filter((l) => /Owner|Valid from/.test(l)).join('\n'),
        ].join('\n'),
      );
      expect(list).toMatch(/Valid from/);
    });

    await test.step('Web: sertifikalar "Yükle" sekmesinden host olarak eklenir', async () => {
      for (const host of [EXPIRED_HOST, WARNING_HOST]) {
        await page.locator('#host-list [data-action="showAddHostScoped"][data-arg0="default-tls"]').click();
        await page.locator('[data-action="switchAddTab"][data-arg0="upload"]').click();
        await page.fill('#upload-hostname', host);
        await page.setInputFiles('#upload-file', path.join(fresh.DIR, `data/certs/${host}.jks`));
        await page.fill('#upload-password', 'changeit');
        await page.locator('[data-action="createHostUpload"]').click();
        await expect(freshDash.hostItem(host)).toBeVisible({ timeout: 30_000 });
      }
      await freshDash.snap('süresi geçmiş ve yakında dolacak sertifikalar yüklendi');
    });

    await test.step('Sunucu: GET /api/v1/cert-expiry expired ve warning döndürüyor', async () => {
      const res = await fresh.api('/api/v1/cert-expiry');
      const byHost = Object.fromEntries((res.json || []).map((c) => [c.hostname, c]));
      await attachText(
        testInfo,
        'GET /api/v1/cert-expiry',
        [
          `HTTP ${res.status}`,
          ...(res.json || []).map(
            (c) => `${c.hostname.padEnd(30)} ${String(c.level).padEnd(8)} ${c.daysRemaining} gün · ${c.validUntil}`,
          ),
          '',
          'Uyarı eşiği: CERT_EXPIRY_WARN_DAYS (varsayılan 30 gün).',
        ].join('\n'),
      );
      expect(byHost[EXPIRED_HOST].level).toBe('expired');
      expect(byHost[EXPIRED_HOST].daysRemaining).toBeLessThan(0);
      expect(byHost[WARNING_HOST].level).toBe('warning');

      const health = await fresh.api('/api/v1/health');
      await attachText(testInfo, 'GET /api/v1/health (özet)', `HTTP ${health.status}\n${health.text}`);
      expect(health.json.status).toBe('critical');
    });

    await test.step('Web: dashboard sertifika süre kartı', async () => {
      await page.reload();
      await freshDash.openHealth();
      // Aynı başlık hem özet kutusunda hem tablolu kartta var; tablolu olanı seç.
      const card = page.locator('.card', { hasText: 'Sertifika Süreleri' }).filter({ has: page.locator('table') }).first();
      await expect(card).toContainText(EXPIRED_HOST);
      await expect(card).toContainText(WARNING_HOST);
      await freshDash.snapCard('.stats', 'sağlık özeti: süresi dolan sertifika sayısı');
      await card.scrollIntoViewIfNeeded();
      await testInfo.attach('🌐 sertifika süre kartı', {
        body: await card.screenshot(),
        contentType: 'image/png',
      });
    });

    await test.step('Sunucu: açılış logunda CRITICAL ve WARNING satırları', async () => {
      fresh.compose(['restart']);
      await fresh.waitHealthy();
      const logs = fresh.compose(['logs', '--tail', '400']);
      const lines = logs
        .split('\n')
        .filter((l) => /CRITICAL: Certificate EXPIRED|WARNING: Certificate expires/.test(l))
        .join('\n');
      await attachText(testInfo, 'docker compose logs | CertExpiryMonitor', lines);
      expect(lines).toContain(`CRITICAL: Certificate EXPIRED for ${EXPIRED_HOST}`);
      expect(lines).toContain(`WARNING: Certificate expires in`);
    });

    // ── Ana host + telefon: süresi dolmuş sertifikalı hedef ──────────────

    await test.step('Terminal+Web: ana host\'ta test için kurulan hedef sunucuya (mock TLS host) süresi geçmiş sertifika yüklenir', async () => {
      const out = makeExpiredMockKeystore();
      await dashboard.openHost(MOCK);
      mockV0 = await dashboard.version();
      const res = await dashboard.uploadHostCert(MOCK, path.join(env.HOST_DIR, 'data/certs', EXPIRED_MOCK_JKS), 'changeit');
      uploaded = true;
      await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(mockV0 + 1);
      await dashboard.snapCard('#cert-info-card', `${MOCK} sertifikası: süresi geçmiş JKS yüklendi (v${mockV0 + 1})`);
      const status = (await hostApi.api(`/api/v1/hosts/${MOCK}/status?configApiId=${env.VAULT_API}`)).json || {};
      await attachText(
        testInfo,
        `keytool (ana host container'ı) + Sertifika kartı → "JKS Yükle" (POST /api/v1/hosts/${MOCK}/upload-cert)`,
        [
          `$ keytool -genkeypair -validity 1 -startdate -400d -ext SAN=dns:${MOCK} -keystore /data/certs/${EXPIRED_MOCK_JKS}`,
          out.trim() || '(çıktı yok)',
          '',
          `HTTP ${res.status} ${res.body}`,
          '',
          `host durumu: mock çalışıyor=${status.mockServerRunning}, keystore=${status.keystorePath || '-'}`,
          '',
          'Yükleme host\'un pin\'lerini yeni sertifikaya geçirir (sürüm +1) ve çalışan',
          'mock dinleyiciyi yeni keystore ile yeniden başlatır: hedef artık süresi',
          'dolmuş bir sertifika sunuyor.',
        ].join('\n'),
      );
      expect(res.json.sha256Pins.length).toBeGreaterThan(0);
      expect(Date.parse(res.json.certValidUntil)).toBeLessThan(Date.now());
    });

    await test.step('Mobil: telefon süresi dolmuş sertifikayı reddediyor; otomatik config yenileme (kurtarma) devreye girmiyor', async () => {
      // Mock dinleyici yeni (süresi geçmiş) sertifikayla gerçekten ayağa kalksın.
      const expiredPin = (await hostApi.getConfig()).pins.find((p) => p.hostname === MOCK).sha256[0];
      await expect
        .poll(() => hostApi.servedPin(env.MOCK_TLS_PORT, MOCK).catch(() => null), { timeout: 60_000, intervals: [500, 1000, 2000] })
        .toBe(expiredPin);
      const status = await app.refreshConfig();
      expect(SampleApp.hostVersion(status, MOCK)).toBe(mockV0 + 1);
      // Ölçüm penceresi: olay listesi ve günlük temiz; kurtarma olsaydı bir
      // [config] satırı ve config isteği görünürdü.
      await app.tapButton('clearLogButton');
      await app.waitFor('eventLogView', (n) => n.text.includes('henüz olay yok'), { what: 'olay listesi boş' });
      device.clearLogcat();
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap('süresi dolmuş sertifika: mock TLS host reddedildi');
      await app.backToMain();
      await new Promise((r) => setTimeout(r, 3000));
      const eventLog = app.eventLog();
      const configLines = eventLog.split('\n').filter((l) => l.includes('[config]'));
      const log = device
        .logcat({ match: /expired or not yet valid|CertificateValidity|PinRecoveryInterceptor|recovery/i })
        .split('\n')
        .slice(-12)
        .join('\n');
      await attachText(
        testInfo,
        `Telefonun cevabı (${MOCK}, pin v${mockV0 + 1}) ve cihaz günlüğü`,
        [
          result,
          '',
          `Olay listesi ([config] satırı: ${configLines.length}):`,
          eventLog,
          '',
          'logcat:',
          log || '(ilgili satır yok)',
          '',
          'DynamicSSLManager.verifyPin: leaf.checkValidity() hatası CertificateValidityException',
          'olarak fırlatılıyor; PinRecoveryInterceptor bu türü pin uyuşmazlığı saymıyor',
          '(config\'i yenilemek sertifikanın süresini uzatmaz), bu yüzden config yenileme',
          'denemesi yok ve hata çağırana olduğu gibi dönüyor.',
        ].join('\n'),
      );
      expect(result).toContain('host bağlantısı reddedildi');
      expect(result).toMatch(/expired or not yet valid/);
      expect(configLines, 'kurtarma tetiklenmemeli (config satırı yok)').toHaveLength(0);
    });

    await test.step('Web+Mobil: mock host sertifikası yenilenir → telefon yeni pin\'lerle bağlanıyor', async () => {
      const toast = await dashboard.renewHostCert(MOCK);
      await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(mockV0 + 2);
      const newPins = await dashboard.viewedPins(MOCK);
      // Bundan sonraki senaryolar (ve teardown) yeni pin'leri temel almalı.
      run.baseline[MOCK] = newPins;
      state.write(run);
      renewed = true;
      await dashboard.snapCard('#cert-info-card', `${MOCK} sertifikası yenilendi, geçerli (v${mockV0 + 2})`);

      // Dinleyici yeni keystore ile ayağa kalksın ve cihaz saati notBefore'u geçsin (A20).
      let validFromMs = 0;
      await expect
        .poll(
          async () => {
            const cert = await hostApi.servedCert(env.MOCK_TLS_PORT, MOCK).catch(() => null);
            validFromMs = cert ? cert.validFromMs : 0;
            return cert && cert.pin;
          },
          { timeout: 60_000, intervals: [500, 1000, 2000] },
        )
        .toBe(newPins[0]);
      await expect.poll(() => device.epochMs(), { timeout: 30_000, intervals: [1000] }).toBeGreaterThan(validFromMs + 1000);

      const status = await app.refreshConfig();
      await app.openMtls();
      const result = await app.expectRepeated(() => app.mockTls(), 'host bağlantısı başarılı', 30_000);
      await app.snap(`yeni sertifika: mock TLS host bağlantısı başarılı (pin v${mockV0 + 2})`);
      await attachText(
        testInfo,
        'Sertifika yenilendikten sonra',
        [`toast: ${toast}`, `telefondaki ${MOCK} sürümü: v${SampleApp.hostVersion(status, MOCK)}`, '', result].join('\n'),
      );
      expect(SampleApp.hostVersion(status, MOCK)).toBe(mockV0 + 2);
      expect(result).toContain('host bağlantısı başarılı');
      await app.backToMain();
    });
  } finally {
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json.pins || []).filter((p) => ![EXPIRED_HOST, WARNING_HOST].includes(p.hostname));
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } });
    for (const host of [EXPIRED_HOST, WARNING_HOST]) {
      fs.rmSync(path.join(fresh.DIR, `data/certs/${host}.jks`), { force: true });
    }
    fs.rmSync(path.join(env.HOST_DIR, 'data/certs', EXPIRED_MOCK_JKS), { force: true });
    if (uploaded && !renewed) {
      // Yarıda kaldıysa mock host süresi geçmiş sertifikayla kalmasın.
      const pins = await hostApi.regenerateHostCert(MOCK, env.VAULT_API).catch(() => null);
      if (pins) {
        run.baseline[MOCK] = pins;
        state.write(run);
      }
    }
    await page.close();
  }
});
