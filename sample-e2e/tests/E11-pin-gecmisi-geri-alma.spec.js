// E11 — Host pin geçmişi ve tek tıkla geri alma.
//
// Yanlış ya da erken yayımlanan bir pin seti her cihazı o anda kilitler.
// Sunucu her değişiklikten sonra kapsamın bütün pin setini saklar; host
// sayfasındaki "Önceki Pin Setleri" kartı bu host'un daha önce yayımlanmış
// setlerini gösterir ve "Bu pinlere dön" eski pinleri YENİ bir sürüm
// numarasıyla yayımlar: telefonlar sürüm düşürmeyi reddettiği için eski sürüm
// değil eski pinler geri gelir. Kanıtlanan:
//
//   • ilk setin kartta "yayında" rozeti var; pinler değişince (v2) v1 satırında
//     "Bu pinlere dön" düğmesi çıkıyor,
//   • düğmeye basınca onay penceresi "yeni sürüm olarak yayımlanacak" diyor;
//     bildirim "Pinler geri getirildi (v3)", host v3 ve v1'in pinlerini taşıyor,
//   • "Değişiklik Geçmişi" kartında "Pinler geri getirildi", denetim kaydında
//     pins_restored (hangi anlık görüntüden),
//   • kartta artık üç satır: v3 yayında, v2 geri alınabilir (ileri-geri gidilebilir),
//   • telefon config'i yenileyince host'u v3 olarak alıyor (sürüm düşmedi, cihaz
//     reddetmedi) ve pinleri eski set,
//   • zaten yayında olan sete "dön" denemesi sürümü artırmıyor.
//
// Ana host üzerinde, kendi geçici host'uyla koşar; sonunda host silinir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const HOST = 'e11-geri-al.sample';
const short = (pin) => `${String(pin).slice(0, 12)}…`;

async function entryOf(host) {
  const cfg = await hostApi.getConfig();
  return cfg.pins.find((p) => p.hostname === host) || null;
}

async function pinVersions(host) {
  const res = await hostApi.api(`/api/v1/hosts/${encodeURIComponent(host)}/pin-versions?configApiId=${env.VAULT_API}`);
  expect(res.status, res.text).toBe(200);
  return res.json;
}

test('Web+Mobil: host\'un önceki pin setleri listeleniyor; "Bu pinlere dön" eski pinleri yeni sürümle yayımlıyor, telefon yeni sürümü alıyor, geçmiş ve denetim kaydı değişikliği gösteriyor', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  const first = [hostApi.randomPin(), hostApi.randomPin()];
  const second = [hostApi.randomPin(), hostApi.randomPin()];
  const page = dashboard.page;
  const versionsCard = page.locator('#pin-versions-card');
  const restoreButton = (version) => versionsCard.locator(`[data-action="restoreHostPins"][data-arg2="${version}"]`);
  const versions = {};

  try {
    await test.step('Web: geçici host elle iki pinle eklenir; "Önceki Pin Setleri" kartında tek satır, rozeti "yayında"', async () => {
      await dashboard.addHostManual(env.VAULT_API, HOST, first);
      await dashboard.openHost(HOST);
      versions.v1 = await dashboard.version();
      await expect(versionsCard.locator('tbody tr').first()).toContainText(`v${versions.v1}`, { timeout: 30_000 });
      await expect(versionsCard.locator('tbody tr').first()).toContainText('yayında');
      await expect(restoreButton(versions.v1)).toHaveCount(0);
      await dashboard.snapCard('#pin-versions-card', `host eklendi: tek pin seti, v${versions.v1} yayında`);
    });

    await test.step('Web: pinler değiştirilir (v2); kartta iki satır — v2 yayında, v1 "Bu pinlere dön"', async () => {
      await dashboard.setPins(HOST, second);
      await expect.poll(async () => (await entryOf(HOST))?.version, { timeout: 20_000 }).toBeGreaterThan(versions.v1);
      versions.v2 = (await entryOf(HOST)).version;
      await dashboard.openHost(HOST);
      await expect(versionsCard.locator('tbody tr').first()).toContainText(`v${versions.v2}`, { timeout: 30_000 });
      await expect(restoreButton(versions.v1)).toBeVisible();
      await expect(restoreButton(versions.v2)).toHaveCount(0);
      await dashboard.snapCard('#pin-versions-card', `pinler değişti: v${versions.v2} yayında, v${versions.v1} geri alınabilir`);
      const list = await pinVersions(HOST);
      await attachText(
        testInfo,
        `GET /api/v1/hosts/${HOST}/pin-versions`,
        list.map((v) => `v${v.version}  ${v.sha256.map(short).join(' ')}  ${v.takenAt}  ${v.actor}`).join('\n'),
      );
      expect(list.slice(0, 2).map((v) => v.version)).toEqual([versions.v2, versions.v1]);
    });

    await test.step('Web: v1 satırında "Bu pinlere dön" → onay penceresi; bildirim "Pinler geri getirildi (v3)"; host v3 ve eski pinleri taşıyor', async () => {
      const dialogsBefore = dashboard.dialogs.length;
      const response = page.waitForResponse(
        (r) => r.url().includes('/api/v1/pin-snapshots/') && r.url().includes('/restore') && r.request().method() === 'POST',
        { timeout: 30_000 },
      );
      await restoreButton(versions.v1).click();
      const res = await response;
      const body = JSON.parse(await res.text());
      const confirmText = dashboard.dialogs[dialogsBefore] || '';
      await expect.poll(async () => (await entryOf(HOST))?.version, { timeout: 20_000 }).toBeGreaterThan(versions.v2);
      const entry = await entryOf(HOST);
      versions.v3 = entry.version;
      await dashboard.openHost(HOST);
      await dashboard.snapHostSummary(`geri alındı: v${versions.v3}, v${versions.v1}'in pinleri`);
      await attachText(
        testInfo,
        `"Bu pinlere dön" (POST /api/v1/pin-snapshots/{id}/restore {"hostname":"${HOST}"})`,
        [
          `Onay penceresi: ${confirmText}`,
          '',
          `HTTP ${res.status()} ${JSON.stringify(body)}`,
          '',
          `sürüm çizgisi: v${versions.v1} (${first.map(short).join(' ')}) → v${versions.v2} (${second.map(short).join(' ')}) → v${versions.v3} (${entry.sha256.map(short).join(' ')})`,
          'Eski sürüm geri gelmedi; eski pinler yeni sürümle yayımlandı. Telefonlar sürüm düşürmeyi reddeder.',
        ].join('\n'),
      );
      expect(confirmText).toContain('yeni bir sürüm olarak');
      expect(res.status()).toBe(200);
      expect(body.restored).toBe(true);
      expect(entry.sha256).toEqual(first);
      expect(versions.v3).toBeGreaterThan(versions.v2);
    });

    await test.step('Web: "Değişiklik Geçmişi" kartında "Pinler geri getirildi"; kartta üç satır, v2 tekrar geri alınabilir; denetim kaydında pins_restored', async () => {
      await expect(page.locator('#pin-history-card')).toContainText('Pinler geri getirildi', { timeout: 30_000 });
      await dashboard.snapCard('#pin-history-card', 'değişiklik geçmişi: "Pinler geri getirildi" satırı');
      await expect(versionsCard.locator('tbody tr').first()).toContainText(`v${versions.v3}`);
      await expect(restoreButton(versions.v3)).toHaveCount(0);
      await expect(restoreButton(versions.v2)).toBeVisible();
      await dashboard.snapCard('#pin-versions-card', `üç set: v${versions.v3} yayında, v${versions.v2} geri alınabilir`);
      const log = await hostApi.auditLog({ action: 'pins_restored', limit: 5 });
      const entry = log.entries.find((e) => (e.target || '').includes(HOST));
      await attachText(
        testInfo,
        'Denetim kaydı: pins_restored',
        entry ? `#${entry.id} ${entry.actor} — ${entry.summary}` : '(kayıt yok)',
      );
      expect(entry, 'pins_restored kaydı').toBeTruthy();
      expect(entry.summary).toContain('snapshot');
    });

    await test.step('Mobil: telefon config\'i yeniliyor; host v3 (sürüm düştü sanılmadı, reddedilmedi)', async () => {
      const status = await app.refreshConfig();
      await app.snap(`config yenilendi: ${HOST} → pin v${versions.v3}`);
      await attachText(testInfo, 'Telefonun durum metni', status);
      expect(SampleApp.hostVersion(status, HOST)).toBe(versions.v3);
    });

    await test.step('Web: zaten yayında olan sete dönme denemesi hiçbir şeyi değiştirmiyor', async () => {
      const list = await pinVersions(HOST);
      const current = list[0];
      const res = await hostApi.api(`/api/v1/pin-snapshots/${current.snapshotId}/restore?configApiId=${env.VAULT_API}`, {
        method: 'POST',
        body: { hostname: HOST },
      });
      await attachText(testInfo, 'Yayındaki sete geri dönme denemesi', `HTTP ${res.status} ${res.text}`);
      expect(res.json.unchanged).toBe(true);
      expect((await entryOf(HOST)).version).toBe(versions.v3);
    });
  } finally {
    const cfg = await hostApi.getConfig();
    if (cfg.pins.some((p) => p.hostname === HOST)) {
      await hostApi.api('/api/v1/certificate-config', {
        method: 'PUT',
        body: { version: 0, forceUpdate: false, pins: cfg.pins.filter((p) => p.hostname !== HOST) },
      });
    }
  }
});
