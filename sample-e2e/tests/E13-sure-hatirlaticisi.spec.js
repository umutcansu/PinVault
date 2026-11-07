// E13 — Süre hatırlatıcısı: her sertifika türü ve vault dosyaları.
//
// Sağlık sekmesindeki "Sertifika Süreleri" kartı artık yalnızca host
// sertifikalarını değil, Config API'nin kendi sertifikasını, client ve sunucu
// CA'larını ve süre girilen vault dosyalarını da tür etiketiyle listeler.
// Süresi dolan ya da dolmak üzere olan her şey günde bir denetim kaydına ve
// webhook'a düşer. Kanıtlanan:
//
//   • kartta Config API sertifikası, client CA ve sunucu CA satırları "geçerli",
//   • yarın dolan ve dün dolmuş süreyle yüklenen iki vault dosyası listede sarı /
//     kırmızı rozetle; kartta "yakında doluyor" ve "süresi doldu"; özet "critical",
//   • GET /api/v1/cert-expiry iki satırı vault_file türüyle döndürüyor; yeniden
//     başlatınca denetimde vault_file_expiring ve webhook'a imzalı bildirim,
//   • dosya detayında süre ileri alınınca "geçerli", silinince karttan düşüyor;
//     sürüm numarası değişmiyor (telefonlar yeniden indirmez),
//   • geçersiz tarih (31 Şubat) 400 ile reddediliyor, dosya yüklenmiyor.
//
// Geçici test sunucusunda koşar (webhook alıcısı Mac'te dinler).
const crypto = require('crypto');
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const webhookSink = require('../lib/webhookSink');

const API = 'default-tls';
const SOON = 'e13-yarin-dolan';
const GONE = 'e13-dun-dolmus';
const BAD = 'e13-gecersiz';
const day = (offset) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);

async function expiryRows() {
  const res = await fresh.api('/api/v1/cert-expiry');
  expect(res.status, res.text).toBe(200);
  return res.json;
}

test('Web+Sunucu: süre kartı her sertifika türünü ve süre girilen vault dosyalarını gösteriyor; dolan dosya denetim kaydına ve webhook\'a düşüyor; süre detaydan değişip kaldırılıyor', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  await fresh.ensure();
  const secret = crypto.randomBytes(24).toString('hex');
  const sink = await webhookSink.start({ secret });
  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;
  const envBackup = fs.readFileSync(fresh.envFile(), 'utf8');
  const CARD = '.card:has(table):has-text("Sertifika Süreleri")';
  const card = () => page.locator(CARD).first();

  try {
    await test.step('Web: Sağlık sekmesi — Config API sertifikası, client CA ve sunucu CA satırları "geçerli"', async () => {
      await dashboard.openHealth();
      await expect(card().locator('tr[data-expiry-kind="config_api"]')).toHaveCount(1, { timeout: 30_000 });
      await expect(card().locator('tr[data-expiry-kind="client_ca"]')).toHaveCount(1);
      await expect(card().locator('tr[data-expiry-kind="server_ca"]')).toHaveCount(1);
      await expect(card().locator('tr[data-expiry-kind="config_api"]')).toContainText('geçerli');
      await dashboard.snapCard(CARD, 'süre kartı: sunucunun kendi sertifikaları tür etiketiyle');
      const rows = await expiryRows();
      await attachText(
        testInfo,
        'GET /api/v1/cert-expiry (tür sütunu yeni)',
        rows.map((r) => `${String(r.kind).padEnd(18)} ${r.hostname.padEnd(36)} ${String(r.level).padEnd(8)} ${r.daysRemaining} gün`).join('\n'),
      );
      expect(rows.map((r) => r.kind)).toEqual(expect.arrayContaining(['config_api', 'client_ca', 'server_ca']));
    });

    await test.step('Web: yarın dolan ve dün dolmuş süreyle iki vault dosyası yüklenir; listede sarı ve kırmızı rozet', async () => {
      await dashboard.uploadVaultText(API, SOON, '{"licence":"soon"}', { expiresAt: day(1) });
      await dashboard.uploadVaultText(API, GONE, '{"licence":"gone"}', { expiresAt: day(-1) });
      await expect(dashboard.vaultFileRow(SOON).locator('[data-expiry-level="warning"]')).toBeVisible();
      await expect(dashboard.vaultFileRow(GONE).locator('[data-expiry-level="expired"]')).toBeVisible();
      await dashboard.snapCard('.card:has(form[data-action-submit="uploadVaultFile"]) ~ .card', 'vault listesi: "Geçerlilik sonu" sütunu, sarı ve kırmızı rozet');
    });

    await test.step('Web: süre kartında iki vault satırı ("yakında doluyor", "süresi doldu"); özet critical', async () => {
      await dashboard.openHealth();
      await expect(card().locator(`tr[data-expiry-kind="vault_file"]`)).toHaveCount(2, { timeout: 30_000 });
      await expect(card()).toContainText(SOON);
      await expect(card()).toContainText(GONE);
      await dashboard.snapCard(CARD, 'süre kartı: vault dosyaları yakında doluyor / süresi doldu');
      const health = await fresh.api('/api/v1/health');
      await attachText(testInfo, 'GET /api/v1/health', `HTTP ${health.status}\n${health.text}`);
      expect(health.json.status).toBe('critical');
      const vault = (await expiryRows()).filter((r) => r.kind === 'vault_file');
      expect(Object.fromEntries(vault.map((r) => [r.hostname, r.level]))).toEqual({ [SOON]: 'warning', [GONE]: 'expired' });
    });

    await test.step('Sunucu: webhook açılıp yeniden başlatılınca günlük kontrol koşuyor — denetimde vault_file_expiring, alıcıda imzalı bildirim', async () => {
      fs.writeFileSync(
        fresh.envFile(),
        `${envBackup.replace(/^(NOTIFY_WEBHOOK_URL|NOTIFY_WEBHOOK_SECRET)=.*$/gm, '').trimEnd()}\nNOTIFY_WEBHOOK_URL=${sink.url}\nNOTIFY_WEBHOOK_SECRET=${secret}\n`,
        { mode: 0o600 },
      );
      fresh.compose(['up', '-d']);
      await fresh.waitHealthy();
      const hit = await sink.waitFor((r) => r.json && r.json.event === 'vault_file_expiring' && String(r.json.target) === GONE);
      const log = await fresh.api('/api/v1/audit-log?action=vault_file_expiring&limit=10');
      const entries = (log.json && log.json.entries) || [];
      await attachText(
        testInfo,
        'Denetim kaydı ve webhook (vault_file_expiring)',
        [
          ...entries.map((e) => `#${e.id} ${e.actor} — ${e.summary}`),
          '',
          `Webhook alıcısı: ${hit.path}  X-PinVault-Event=${hit.event}  imza doğru=${hit.signatureValid}`,
          (hit.body || '').slice(0, 400),
        ].join('\n'),
      );
      expect(entries.some((e) => e.summary.includes(GONE) && e.summary.includes('EXPIRED'))).toBe(true);
      expect(entries.some((e) => e.summary.includes(SOON))).toBe(true);
      expect(hit.signatureValid).toBe(true);
      await page.reload();
      await dashboard.openHealth();
    });

    await test.step('Web: dosya detayında süre ileri alınınca "geçerli"; kaldırılınca karttan düşüyor; sürüm değişmiyor', async () => {
      await dashboard.openVaultFileDetail(API, GONE);
      const versionBefore = (await fresh.api(`/api/v1/config-apis/${API}/vault`)).json.find((f) => f.key === GONE).version;
      await page.fill(`#expires-edit-${GONE}`, day(400));
      await page.locator(`[data-action="saveVaultFilePolicy"][data-arg1="${GONE}"]`).click();
      await expect(page.locator('.toast.success').last()).toContainText('Politika güncellendi', { timeout: 20_000 });
      await expect.poll(async () => (await expiryRows()).find((r) => r.hostname === GONE)?.level, { timeout: 20_000 }).toBe('ok');
      await dashboard.snapVaultPolicy(`${GONE}: süre ileri alındı, rozet "geçerli"`);
      await page.fill(`#expires-edit-${GONE}`, '');
      await page.locator(`[data-action="saveVaultFilePolicy"][data-arg1="${GONE}"]`).click();
      await expect(page.locator('.toast.success').last()).toContainText('Politika güncellendi', { timeout: 20_000 });
      await expect.poll(async () => (await expiryRows()).some((r) => r.hostname === GONE), { timeout: 20_000 }).toBe(false);
      const after = (await fresh.api(`/api/v1/config-apis/${API}/vault`)).json.find((f) => f.key === GONE);
      await attachText(testInfo, 'Süre değişikliği sürümü artırmaz', `önce v${versionBefore}, sonra v${after.version}; expires_at="${after.expires_at}"`);
      expect(after.version).toBe(versionBefore);
      expect(after.expires_at).toBe('');
    });

    await test.step('Sunucu: geçersiz tarih (31 Şubat) reddediliyor, dosya yüklenmiyor', async () => {
      const res = await fresh.api(`/api/v1/config-apis/${API}/vault/${BAD}?expiresAt=2027-02-31`, {
        method: 'PUT', rawBody: 'x', headers: { 'Content-Type': 'application/octet-stream' },
      });
      const list = (await fresh.api(`/api/v1/config-apis/${API}/vault`)).json;
      await attachText(testInfo, `PUT …/vault/${BAD}?expiresAt=2027-02-31`, `HTTP ${res.status} ${res.text}`);
      expect(res.status).toBe(400);
      expect(list.some((f) => f.key === BAD)).toBe(false);
    });
  } finally {
    for (const key of [SOON, GONE, BAD]) await fresh.api(`/api/v1/config-apis/${API}/vault/${key}`, { method: 'DELETE' }).catch(() => {});
    fs.writeFileSync(fresh.envFile(), envBackup, { mode: 0o600 });
    try {
      fresh.compose(['up', '-d']);
      await fresh.waitHealthy();
    } catch {
      /* geçici sunucu kapalı */
    }
    await sink.stop();
    await page.close().catch(() => {});
  }
});
