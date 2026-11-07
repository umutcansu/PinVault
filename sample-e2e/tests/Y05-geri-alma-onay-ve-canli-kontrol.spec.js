// Y05 — Pin geri alma da onay ve canlı sertifika kontrolünden geçer.
//
// "Bu pinlere dön" bir pin değişikliğidir: iki kişi onayı açıkken (Y03) tek
// başına uygulanmaz, canlı sertifika kontrolü açıkken (Y04) host'un şu an
// sunmadığı pinlere dönülemez. Kanıtlanan:
//
//   • alice'in "Bu pinlere dön" isteği 202 ile beklemeye alınıyor; pinler
//     değişmiyor; Onaylar sekmesinde "Pin geri alma" kartı hangi anlık
//     görüntüden, hangi host'a, hangi pinlerin geldiğini gösteriyor; alice'in
//     kendi onay düğmesi kapalı,
//   • bob onaylayınca pinler geri geliyor; denetimde pins_restored
//     "alice (approved by bob)",
//   • PIN_LIVE_CHECK=enforce iken bu sunucunun kendisinin sunduğu mock host'un
//     eski pinlerine dönüş 422 ile reddediliyor (host sertifikasını
//     değiştirmedi); panel nedeni gösteriyor, pinler değişmiyor.
//
// Ana host üzerinde koşar; ortam sonunda .env değerlerine döner. Mock host'un
// sertifikası yenilendiği için taban durumu yeni pin'lere göre güncellenir (A20).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { Dashboard } = require('../lib/dashboard');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const state = require('../lib/state');
const { keys, adminKeysEnv } = require('../lib/admins');
const env = require('../lib/env');

const HOST = 'y05-geri-al.sample';
const MOCK = env.MOCK_TLS_HOST;
const HOST_MAP = 'mock-tls.sample=127.0.0.1:8443;mock-mtls.sample=127.0.0.1:8444';
const short = (pin) => `${String(pin).slice(0, 12)}…`;

async function entryOf(host) {
  const cfg = await hostApi.getConfig();
  return cfg.pins.find((p) => p.hostname === host) || null;
}

async function pinVersions(host, key) {
  const res = await hostApi.api(`/api/v1/hosts/${encodeURIComponent(host)}/pin-versions?configApiId=${env.VAULT_API}`, { key });
  expect(res.status, res.text).toBe(200);
  return res.json;
}

test('Web+Terminal: geri alma iki kişi onayı bekliyor (alice ister, bob onaylar) ve canlı sertifika kontrolü host\'un sunmadığı pinlere dönüşü reddediyor', async ({
  dashboard,
  browser,
  run,
}, testInfo) => {
  test.setTimeout(25 * 60 * 1000);
  const first = [hostApi.randomPin(), hostApi.randomPin()];
  const second = [hostApi.randomPin(), hostApi.randomPin()];
  let overridden = false;
  let alice;
  let bob;
  let crId;
  let renewedPins = null;

  try {
    await test.step('Web: geçici host eklenir ve pinleri bir kez değiştirilir (onay kapalıyken)', async () => {
      await dashboard.addHostManual(env.VAULT_API, HOST, first);
      await dashboard.openHost(HOST);
      await dashboard.setPins(HOST, second);
      await expect.poll(async () => (await entryOf(HOST))?.sha256?.[0], { timeout: 20_000 }).toBe(second[0]);
    });

    await test.step('Web: mock host\'un sertifikası yenilenir (eski pinler anlık görüntüde kalır); taban durumu yeni pinlere göre güncellenir', async () => {
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      const v0 = await dashboard.version();
      const toast = await dashboard.renewHostCert(MOCK);
      // The page redraws after the server answers; read the pins only once the version moved (A20 pattern).
      await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(v0 + 1);
      renewedPins = await dashboard.viewedPins(MOCK);
      run.baseline[MOCK] = renewedPins;
      state.write(run);
      await expect
        .poll(() => hostApi.servedPin(env.MOCK_TLS_PORT, MOCK).catch(() => null), { timeout: 60_000, intervals: [500, 1000, 2000] })
        .toBe(renewedPins[0]);
      await attachText(testInfo, 'Mock host sertifikası yenilendi', [`toast: ${toast}`, `yeni pinler: ${renewedPins.map(short).join(' ')}`].join('\n'));
      expect(toast).not.toContain('Live certificate check failed');
    });

    await test.step('Sunucu: ADMIN_KEYS (alice, bob) + PIN_CHANGE_APPROVALS=2; Web: alice ve bob ayrı oturumlarda', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), PIN_CHANGE_APPROVALS: '2' });
      overridden = true;
      const leftovers = await hostApi.changeRequests('pending', keys.bob);
      for (const cr of leftovers) await hostApi.rejectChange(cr.id, 'E2E: önceki koşudan kalan istek', keys.bob);
      alice = await Dashboard.openAs(browser, testInfo, keys.alice);
      bob = await Dashboard.openAs(browser, testInfo, keys.bob);
      await attachText(testInfo, 'Ortam', 'ADMIN_KEYS=alice:<sha256>,bob:<sha256>  PIN_CHANGE_APPROVALS=2');
    });

    await test.step('Web (alice): "Bu pinlere dön" → 202, "onay bekliyor"; pinler değişmedi', async () => {
      await alice.openHostIn(env.VAULT_API, HOST);
      const versions = await pinVersions(HOST, keys.alice);
      const older = versions.find((v) => v.sha256[0] === first[0]);
      expect(older, 'ilk pin seti listede').toBeTruthy();
      const response = alice.page.waitForResponse(
        (r) => r.url().includes('/api/v1/pin-snapshots/') && r.url().includes('/restore') && r.request().method() === 'POST',
        { timeout: 30_000 },
      );
      await alice.page.locator(`#pin-versions-card [data-action="restoreHostPins"][data-arg1="${older.snapshotId}"]`).click();
      const res = await response;
      const body = JSON.parse(await res.text());
      expect(res.status()).toBe(202);
      expect(body.pendingApproval).toBe(true);
      crId = body.changeRequestId;
      await expect(alice.page.locator('.toast.info').last()).toContainText(`#${crId} onay bekliyor`);
      await alice.snap(`alice: geri alma isteği #${crId} onay bekliyor`);
      expect((await entryOf(HOST)).sha256).toEqual(second);
    });

    await test.step('Web (alice): Onaylar sekmesinde "Pin geri alma" kartı — anlık görüntü, host ve pin farkı; alice kendi isteğini onaylayamıyor', async () => {
      await alice.openApprovals('pending');
      const card = alice.changeCard(crId);
      await expect(card).toBeVisible({ timeout: 20_000 });
      await expect(card).toContainText('Pin geri alma');
      await alice.expandChange(crId);
      const text = await card.innerText();
      const button = await alice.approveButtonState(crId);
      await alice.snapApprovals(`bekleyen istek #${crId}: Pin geri alma (${HOST})`, { ids: [crId] });
      await attachText(testInfo, `Değişiklik kartı #${crId}`, text);
      expect(text).toContain(HOST);
      expect(text).toMatch(/snapshot|anlık görüntü/i);
      expect(text).toContain(short(first[0]).slice(0, 8));
      expect(button.disabled).toBe(true);
    });

    await test.step('Web (bob): onaylar → pinler geri gelir; denetimde pins_restored "alice (approved by bob)"', async () => {
      await bob.openApprovals('pending');
      const res = await bob.approveChange(crId);
      await attachText(testInfo, `bob onaylıyor (POST /api/v1/change-requests/${crId}/approve)`, `HTTP ${res.status} ${res.body}`);
      expect(res.status).toBe(200);
      await expect.poll(async () => (await entryOf(HOST))?.sha256?.[0], { timeout: 20_000 }).toBe(first[0]);
      const entry = await entryOf(HOST);
      const log = await hostApi.auditLog({ action: 'pins_restored', limit: 5, key: keys.bob });
      const audit = log.entries.find((e) => (e.target || '').includes(HOST));
      await bob.snapApprovals('bob onayladı: istek geçmişte', { ids: [crId] });
      await attachText(testInfo, 'Denetim kaydı', audit ? `#${audit.id} ${audit.actor} — ${audit.summary}` : '(kayıt yok)');
      expect(entry.sha256).toEqual(first);
      expect(audit && audit.actor).toContain('alice (approved by bob)');
    });

    await test.step('Sunucu: onay kapalı, canlı sertifika kontrolü açık (PIN_LIVE_CHECK=enforce, LIVE_CHECK_HOST_MAP)', async () => {
      await alice.page.close();
      await bob.page.close();
      await hostControl.setEnv({ ADMIN_KEYS: '', PIN_CHANGE_APPROVALS: '1', PIN_LIVE_CHECK: 'enforce', LIVE_CHECK_HOST_MAP: HOST_MAP });
      await dashboard.reload();
      await attachText(testInfo, 'Ortam', `PIN_LIVE_CHECK=enforce LIVE_CHECK_HOST_MAP='${HOST_MAP}' (onay kapalı)`);
    });

    await test.step('Web: mock host\'un eski pinlerine "Bu pinlere dön" → 422, canlı kontrol reddediyor; panel nedeni gösteriyor, pinler değişmiyor', async () => {
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      // The set served now is the first row. The list may hold more than one
      // renewal (an earlier attempt of this scenario renews too; the server
      // itself writes no pins on a restart — checked against the audit log on
      // 2026-11-07), so "older" is any earlier row with other pins.
      const versions = await pinVersions(MOCK);
      const current = versions[0];
      const currentPins = (await entryOf(MOCK)).sha256;
      const older = versions.find((v) => v.snapshotId !== current.snapshotId && !v.sha256.every((p) => currentPins.includes(p)));
      expect(older, 'yenilemeden önceki pin seti listede').toBeTruthy();
      const response = dashboard.page.waitForResponse(
        (r) => r.url().includes(`/api/v1/pin-snapshots/${older.snapshotId}/restore`) && r.request().method() === 'POST',
        { timeout: 60_000 },
      );
      await dashboard.page.locator(`#pin-versions-card [data-action="restoreHostPins"][data-arg1="${older.snapshotId}"]`).click();
      const res = await response;
      const body = JSON.parse(await res.text());
      await expect(dashboard.page.locator('.toast.error').last()).toContainText('Live certificate check failed', { timeout: 20_000 });
      await dashboard.snap(`canlı kontrol: ${MOCK} için eski pinlere dönüş reddedildi (422)`);
      await attachText(
        testInfo,
        'Canlı sertifika kontrolü (PIN_LIVE_CHECK=enforce) geri almayı reddediyor',
        [`HTTP ${res.status()}`, JSON.stringify(body, null, 2).slice(0, 1500)].join('\n'),
      );
      expect(res.status()).toBe(422);
      expect((await entryOf(MOCK)).sha256).toEqual(currentPins);
    });
  } finally {
    // Later scenarios restore the baseline: keep it at what the mock host serves now.
    const served = (await entryOf(MOCK).catch(() => null))?.sha256;
    if (served) { run.baseline[MOCK] = served; state.write(run); }
    if (alice) await alice.page.close().catch(() => {});
    if (bob) await bob.page.close().catch(() => {});
    if (overridden) await hostControl.resetEnv();
    const cfg = await hostApi.getConfig();
    if (cfg.pins.some((p) => p.hostname === HOST)) {
      await hostApi.api('/api/v1/certificate-config', {
        method: 'PUT',
        body: { version: 0, forceUpdate: false, pins: cfg.pins.filter((p) => p.hostname !== HOST) },
      });
    }
  }
});
