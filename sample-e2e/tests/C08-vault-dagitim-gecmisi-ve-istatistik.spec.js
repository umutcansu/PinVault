// C08 — Dağıtım geçmişi, istatistikler, durum süzgeci ve cihaz detayı.
//
// Kütüphane her vault denemesini raporluyor: başarılı indirme (downloaded),
// 304 ile yereldeki kopyanın kullanılması (cached) ve başarısızlık (failed +
// neden + hangi yetkilendirmeyle denendiği). Dashboard bunları sayıyor,
// süzüyor ve cihaz bazında topluyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const FLAGS = env.VAULT_KEYS.flags;
const ADMIN = env.VAULT_KEYS.admin;
// Token'lı dosya örneği olarak herkese açık sample-atrest sunucuda token
// politikasına alınır: uygulama onu public tanımladığı için token göndermez,
// sunucu reddeder. (Gizli sample-secret mTLS'te; kayıt gerektirir.)
const SECRET = env.VAULT_KEYS.atrest;

test('Vault dağıtım geçmişi: durum, sürüm ve cihaz kaydı; filtre, istatistik ve cihaz detayı', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const stamp = Date.now();
  let flagsVersion;
  let deviceId;

  try {
    await test.step('Web: üç farklı politikada dosya yüklenir', async () => {
      flagsVersion = await dashboard.uploadVaultText(env.VAULT_API, FLAGS, `bayraklar-${stamp}`, { policy: 'public' });
      await dashboard.uploadVaultText(env.VAULT_API, ADMIN, `yonetim-${stamp}`, { policy: 'api_key' });
      await dashboard.uploadVaultText(env.VAULT_API, SECRET, `tokenli-${stamp}`, { policy: 'token' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'üç vault dosyası');
    });

    await test.step('Mobil: bir başarılı indirme, bir "değişmedi" (304) ve iki başarısız deneme yapılır', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      expect(await app.fetchVault(FLAGS)).toContain(`${FLAGS} v${flagsVersion} indirildi`);
      expect(await app.fetchVault(FLAGS)).toContain(`${FLAGS} güncel (v${flagsVersion})`);
      await app.snap('public dosya: indirildi ve güncel');
      expect(await app.fetchVault(ADMIN)).toContain('401');
      expect(await app.fetchVault(SECRET)).toContain('401');
      await app.snap('api_key ve token dosyaları reddedildi');
    });

    await test.step('Sunucu: dağıtım kayıtlarında durum, sürüm ve cihaz bilgisi var', async () => {
      const dists = (await hostApi.vaultDistributions(env.VAULT_API)).filter((d) => d.deviceId === deviceId);
      const byStatus = (s) => dists.filter((d) => d.status === s);
      await attachText(
        testInfo,
        `GET /api/v1/config-apis/${env.VAULT_API}/vault/distributions (bu cihaz)`,
        dists
          .slice(0, 10)
          .map((d) =>
            `${d.timestamp} ${d.vaultKey.padEnd(14)} v${String(d.version).padEnd(3)} ${d.status.padEnd(10)} ` +
            `auth=${String(d.authMethod).padEnd(9)} ${(d.failureReason || '—').replace(/\s+/g, ' ').slice(0, 50)}`)
          .join('\n'),
      );
      expect(byStatus('downloaded').some((d) => d.vaultKey === FLAGS && d.version === flagsVersion)).toBe(true);
      expect(byStatus('cached').some((d) => d.vaultKey === FLAGS && d.version === flagsVersion)).toBe(true);
      const adminFail = byStatus('failed').find((d) => d.vaultKey === ADMIN);
      const secretFail = byStatus('failed').find((d) => d.vaultKey === SECRET);
      expect(adminFail.authMethod).toBe('api_key');
      // Kütüphane hata nedenini sabit bir kodla raporlar (VaultFileResult.Failed.code),
      // sunucunun mesajını ya da istisna metnini değil.
      expect(adminFail.failureReason).toBe('http_401');
      // authMethod uygulamanın raporu: dosyayı public tanımladığı için 'public'.
      // Sunucu yine de kendi politikasını (token) uyguladı.
      expect(secretFail.authMethod).toBe('public');
      // Token gönderilmedi (public tanımlı dosyada kütüphane X-Vault-Token
      // başlığını hiç eklemez); sunucu 401 "X-Vault-Token header required" verdi.
      // Rapor yalnızca sabit kodu taşır, sunucunun mesajını değil.
      expect(secretFail.failureReason).toBe('http_401');
      // Başarısız denemede sürüm 0: cihazda o dosyanın bir kopyası yok.
      expect(adminFail.version).toBe(0);
    });

    await test.step('Web: istatistik kartları sunucunun sayılarıyla aynı', async () => {
      const cards = await dashboard.vaultStatCards(env.VAULT_API);
      const stats = await hostApi.vaultStats(env.VAULT_API);
      const files = await hostApi.vaultFiles(env.VAULT_API);
      await dashboard.snapCard('.stats', 'vault istatistik kartları');
      await attachText(
        testInfo,
        `GET /api/v1/config-apis/${env.VAULT_API}/vault/stats`,
        [
          JSON.stringify(stats, null, 2),
          '',
          'Dashboard kartları:',
          `  ${cards.keys.label} = ${cards.keys.value}   (dosya listesi uzunluğu = ${files.length})`,
          `  ${cards.devices.label} = ${cards.devices.value}   (stats.uniqueDevices)`,
          `  ${cards.ok.label} = ${cards.ok.value}   (totalDistributions − failed; "cached" de burada)`,
          `  ${cards.failed.label} = ${cards.failed.value}   (stats.failed)`,
        ].join('\n'),
      );
      expect(Number(cards.keys.value)).toBe(files.length);
      expect(Number(cards.devices.value)).toBe(stats.uniqueDevices);
      expect(Number(cards.failed.value)).toBe(stats.failed);
      expect(Number(cards.ok.value)).toBe(stats.totalDistributions - stats.failed);
      expect(stats.failed).toBeGreaterThanOrEqual(2);
    });

    await test.step('Web: "Başarısız" filtresi yalnızca hatalı satırları gösteriyor', async () => {
      await dashboard.setVaultStatusFilter(env.VAULT_API, 'failed');
      const rows = await dashboard.vaultDistributionRows();
      await dashboard.snap('dağıtım geçmişi — "Başarısız" filtresi');
      await attachText(
        testInfo,
        'Filtre: başarısız',
        rows.slice(0, 8).map((r) => `${r.key} ${r.version} ${r.status} ${r.auth} ${r.reason.slice(0, 50)}`).join('\n'),
      );
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.status.includes('failed'))).toBe(true);
      expect(rows.some((r) => r.key === ADMIN && r.auth.includes('api_key'))).toBe(true);
    });

    await test.step('Web: "Başarılı" filtresi indirilenleri ve önbellekten (cached) gelenleri gösteriyor', async () => {
      await dashboard.setVaultStatusFilter(env.VAULT_API, 'downloaded');
      const rows = await dashboard.vaultDistributionRows();
      await dashboard.snap('dağıtım geçmişi — "Başarılı" filtresi');
      await attachText(
        testInfo,
        'Filtre: başarılı',
        rows.slice(0, 8).map((r) => `${r.key} ${r.version} ${r.status} ${r.auth}`).join('\n'),
      );
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => /downloaded|cached/.test(r.status))).toBe(true);
      expect(rows.some((r) => r.status.includes('cached'))).toBe(true);
      // Süzgeç aynı karta ikinci tıklamada kalkıyor.
      await dashboard.setVaultStatusFilter(env.VAULT_API, 'downloaded');
      const all = await dashboard.vaultDistributionRows();
      expect(all.some((r) => r.status.includes('failed'))).toBe(true);
    });

    await test.step('Web: cihaz detayı dosya bazında özeti ve tüm geçmişi gösteriyor', async () => {
      const subtitle = await dashboard.openVaultDeviceDetail(env.VAULT_API, deviceId);
      await dashboard.snap('cihaz detayı');
      const byDevice = await hostApi.vaultDistributionsByDevice(env.VAULT_API, deviceId);
      await attachText(
        testInfo,
        `GET …/vault/distributions/device/${deviceId}`,
        [
          `alt başlık: ${subtitle}`,
          '',
          `${byDevice.length} kayıt, ${new Set(byDevice.map((d) => d.vaultKey)).size} farklı dosya`,
          ...byDevice.slice(0, 6).map((d) => `  ${d.vaultKey} v${d.version} ${d.status}`),
        ].join('\n'),
      );
      expect(subtitle).toContain(deviceId);
      expect(byDevice.length).toBeGreaterThanOrEqual(4);
      await expect(dashboard.page.locator('table.data-table', { hasText: ADMIN }).first()).toBeVisible();
    });

    await test.step('Web: dosya detayında sürüm zaman çizelgesi ve cihaz özeti', async () => {
      await dashboard.openVaultFileDetail(env.VAULT_API, FLAGS);
      await dashboard.snap(`${FLAGS} dosya detayı`);
      const sub = (await dashboard.page.locator('.section-sub').first().innerText()).trim();
      await attachText(
        testInfo,
        `${FLAGS} dosya detayı başlığı`,
        [sub, '', 'Sürüm zaman çizelgesi, cihaz özeti, token yönetimi ve tüm geçmiş aynı sayfada.'].join('\n'),
      );
      expect(sub).toMatch(/versiyon/);
      expect(sub).toMatch(/cihaz/);
    });
  } finally {
    for (const key of [FLAGS, ADMIN, SECRET]) await hostApi.deleteVaultFile(env.VAULT_API, key).catch(() => {});
  }
});
