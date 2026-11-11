// K11 — Panelde betik enjeksiyonu (XSS): serbest metin gerçek tarayıcıda metin olarak kalıyor.
//
// Panel sunucudan gelen her değeri HTML'e yazar. Bir değer olduğu gibi
// yazılırsa ("innerHTML"), değeri seçebilen biri — telefonun gönderdiği bir
// rapor, bir yöneticinin yazdığı gerekçe — paneli açan yöneticinin tarayıcısında
// betik çalıştırır ve onun API anahtarıyla her şeyi yapar. İki savunma:
//
//   1. Girişte: cihazdan gelen ve kimlik gibi kullanılan alanlar (rapordaki
//      host adı, model, üretici; kayıt politikası adı) yalnızca dar bir karakter
//      kümesini kabul eder; HTML 400 ile reddedilir.
//   2. Çizimde: serbest metin kalan alanlar (ret gerekçesi; onay kartı ve
//      denetim kaydı ayrıntısı) kaçışla (escape) yazılır. Kaynak koddaki her
//      interpolasyonu DashboardEscapingTest denetliyor; bu senaryo aynı şeyi
//      gerçek tarayıcıda gösterir: yük metin olarak görünür, hiçbir betik
//      çalışmaz, DOM'a onerror/onload taşıyan öğe eklenmez.
//
// Yükler zararsızdır: yalnızca sayfada bir sayaç (window.__pvXss) artırırlar.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { Dashboard } = require('../lib/dashboard');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const { keys, adminKeysEnv } = require('../lib/admins');
const env = require('../lib/env');

const PAYLOADS = [
  '<img src=x onerror="window.__pvXss=(window.__pvXss||0)+1">',
  '"><svg onload="window.__pvXss=(window.__pvXss||0)+1">',
  "'><script>window.__pvXss=(window.__pvXss||0)+1</script>",
];
const REASON = `E2E XSS denemesi ${PAYLOADS.join(' ')}`;

/** Sayfada betik çalıştı mı, DOM'a olay özniteliği taşıyan öğe girdi mi? */
async function domVerdict(page) {
  return page.evaluate(() => ({
    ran: window.__pvXss || 0,
    injected: document.querySelectorAll('img[onerror], svg[onload], [onload], [onerror]').length,
    scripts: [...document.querySelectorAll('script')].filter((s) => (s.textContent || '').includes('__pvXss')).length,
  }));
}

async function clientReport(body) {
  const res = await fetch(`${env.WEB_URL}/api/v1/connection-history/client-report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, text: (await res.text()).trim() };
}

test('Web: panel serbest metni metin olarak gösteriyor (ret gerekçesindeki <img onerror>, <svg onload>, <script> Onaylar ve Denetim Kaydı sayfalarında çalışmıyor); cihaz raporu ve politika adı HTML\'i girişte reddediyor', async ({
  browser,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let overridden = false;
  let bob;
  let crId;
  const dialogs = [];

  try {
    await test.step('Sunucu (giriş): cihaz raporundaki host adı / model / üretici ve kayıt politikası adı HTML\'i 400 ile reddediyor', async () => {
      const base = { hostname: TARGET_HOST, status: 'success', pinVersion: 1, deviceManufacturer: 'Google', deviceModel: 'Pixel' };
      const tries = [
        ['deviceModel', await clientReport({ ...base, deviceModel: PAYLOADS[0] })],
        ['deviceManufacturer', await clientReport({ ...base, deviceManufacturer: PAYLOADS[1] })],
        ['hostname', await clientReport({ ...base, hostname: PAYLOADS[2] })],
      ];
      const policy = await hostApi.api('/api/v1/enrollment-policies', {
        method: 'POST',
        body: { name: PAYLOADS[0], maxDevices: 1, validDays: 1, requireApproval: true },
      });
      await attachText(
        testInfo,
        'Girişte reddedilen HTML',
        [
          ...tries.map(([field, r]) => `POST /api/v1/connection-history/client-report  ${field}=${JSON.stringify(PAYLOADS[0]).slice(0, 40)}…\n  → HTTP ${r.status} ${r.text.slice(0, 140)}`),
          `POST /api/v1/enrollment-policies  name=<img …>\n  → HTTP ${policy.status} ${policy.text.trim().slice(0, 140)}`,
        ].join('\n\n'),
      );
      for (const [field, r] of tries) expect(r.status, field).toBe(400);
      expect(policy.status).toBe(400);
    });

    await test.step('Sunucu: ADMIN_KEYS (alice, bob) + PIN_CHANGE_APPROVALS=2; alice bir pin değişikliği ister, bob gerekçesine üç yük yazarak reddeder', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), PIN_CHANGE_APPROVALS: '2' });
      overridden = true;
      const leftovers = await hostApi.changeRequests('pending', keys.bob);
      for (const cr of leftovers) await hostApi.rejectChange(cr.id, 'E2E: önceki koşudan kalan istek', keys.bob);
      const cfg = await hostApi.getConfig();
      const req = await hostApi.api('/api/v1/certificate-config', {
        method: 'PUT',
        key: keys.alice,
        body: { version: 0, forceUpdate: false, pins: cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: [...run.goodPins, hostApi.randomPin()] } : p)) },
      });
      crId = req.json && req.json.changeRequestId;
      const rej = await hostApi.rejectChange(crId, REASON, keys.bob);
      await attachText(
        testInfo,
        'Ret gerekçesi (serbest metin, saklanıyor)',
        [`PUT /api/v1/certificate-config (alice) → HTTP ${req.status} #${crId}`, `POST /api/v1/change-requests/${crId}/reject (bob)`, `  reason: ${REASON}`, `  → HTTP ${rej.status}`].join('\n'),
      );
      expect(req.status).toBe(202);
      expect(rej.status).toBe(200);
    });

    await test.step('Web (bob): "Onaylar → Geçmiş" ve satır ayrıntısı → gerekçe metin olarak görünüyor, hiçbir betik çalışmıyor', async () => {
      bob = await Dashboard.openAs(browser, testInfo, keys.bob);
      bob.page.on('dialog', (d) => dialogs.push(d.message()));
      await bob.openApprovals('history');
      await expect(bob.decidedRow(crId)).toBeVisible({ timeout: 20_000 });
      await bob.expandChange(crId);
      await expect(bob.page.locator('#approvals-view')).toContainText('<img src=x onerror=');
      await bob.snapApprovals(`Onaylar → Geçmiş: #${crId}, gerekçe düz metin`, { ids: [crId] });
      const verdict = await domVerdict(bob.page);
      await attachText(testInfo, 'Onaylar sayfası: tarayıcıdaki sonuç', JSON.stringify({ ...verdict, dialogs }, null, 2));
      expect(verdict).toEqual({ ran: 0, injected: 0, scripts: 0 });
      expect(dialogs).toEqual([]);
    });

    await test.step('Web (bob): "Denetim Kaydı" → change_rejected satırı ve ayrıntısı → metin olarak görünüyor, hiçbir betik çalışmıyor', async () => {
      const log = await hostApi.auditLog({ action: 'change_rejected', limit: 5, key: keys.bob });
      const entry = log.entries.find((e) => (e.summary || '').includes(`#${crId}`));
      await bob.openAudit();
      await bob.setAuditFilter('change_rejected');
      const detail = entry ? await bob.expandAuditEntry(entry.id) : '';
      await bob.snapCard('#audit-view', 'Denetim Kaydı: change_rejected, ayrıntı açık');
      const verdict = await domVerdict(bob.page);
      await attachText(
        testInfo,
        'Denetim Kaydı: tarayıcıdaki sonuç',
        [`kayıt: ${entry ? `#${entry.id} ${entry.actor} — ${entry.summary}` : '(yok)'}`, '', 'ayrıntı (innerText):', detail.slice(0, 800), '', JSON.stringify({ ...verdict, dialogs })].join('\n'),
      );
      expect(entry).toBeTruthy();
      expect(verdict).toEqual({ ran: 0, injected: 0, scripts: 0 });
      expect(dialogs).toEqual([]);
    });
  } finally {
    if (bob) await bob.context.close().catch(() => {});
    if (overridden) await hostControl.resetEnv();
    await hostApi.restoreBaseline(run.baseline);
  }
});
