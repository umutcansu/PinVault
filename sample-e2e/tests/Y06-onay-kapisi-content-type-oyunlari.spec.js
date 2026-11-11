// Y06 — Onay kapısında Content-Type oyunları (N7, 2026-11-09).
//
// Onay açıkken (PIN_CHANGE_APPROVALS=2) bir değişiklik iki kez okunur: kapı
// gövdeyi onay kartını yazmak için okur, onaylanınca aynı gövde işleyiciye
// (handler) yeniden verilir. İkisi gövdeyi farklı okursa onaylayan bir şey
// görür, sunucu başka bir şey yapar. Bulgu: kapı yalnızca küçük harfle
// "application/json" ile başlayan başlıkta charset'e bakıyordu;
// `text/plain; charset=UTF-16` ile gönderilen bir geri alma isteği kartta
// "tek host" görünüyor, onaylanınca BÜTÜN pin setini geri alıyordu.
//
// Düzeltmeden sonra kapı başlığı Ktor'un okuduğu gibi okur: UTF-8 dışında
// charset adlandıran her istek, medya türü ve yazımı
// ne olursa olsun 415 ile reddedilir (ayrıştırılamayan başlık daha önce 400 alır);
// ne değişiklik isteği oluşur ne de bir şey
// uygulanır. Geri alma gövdesi kart ve işleyici için aynı kodla okunur
// (PinRestore.requestedHost); okunamayan gövde 400'dür, asla "bütün set" değil.
//
// Senaryo yalnızca sunucuya konuşur (telefon gerekmez). Ortam sonunda sıfırlanır.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const { keys, adminKeysEnv } = require('../lib/admins');
const env = require('../lib/env');

const short = (pin) => `${pin.slice(0, 12)}…`;

/** Yönetim API'sine ham istek: başlık ve gövde baytları olduğu gibi gider. */
async function raw(pathname, { method = 'POST', key, contentType, body }) {
  const res = await fetch(env.WEB_URL + pathname, {
    method,
    headers: { 'X-API-Key': key, ...(contentType ? { 'Content-Type': contentType } : {}) },
    body,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, text, json };
}

const utf16 = (obj) => Buffer.from(JSON.stringify(obj), 'utf16le');

async function hostState() {
  const cfg = await hostApi.getConfig();
  return Object.fromEntries(cfg.pins.map((p) => [p.hostname, { version: p.version, sha256: p.sha256 }]));
}

test('Terminal: onay kapısı UTF-8 dışı charset\'i (415) ve okunamayan başlığı (400) medya türü ne olursa olsun reddediyor, istek oluşmuyor; tek host\'luk geri alma onaylanınca yalnızca o host geri geliyor', async ({
  run,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  const created = [];
  const extraPin = hostApi.randomPin();
  let overridden = false;
  let snapshotWithExtra;

  try {
    await test.step('Sunucu (onay kapalı): hedef host\'a fazladan bir pin eklenip geri alınır → geri dönülebilecek bir pin seti oluşur', async () => {
      const cfg = await hostApi.getConfig();
      const write = (sha) =>
        hostApi.api('/api/v1/certificate-config', {
          method: 'PUT',
          body: { version: 0, forceUpdate: false, pins: cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: sha, forceUpdate: false } : p)) },
        });
      const a = await write([...run.goodPins, extraPin]);
      const b = await write(run.goodPins);
      const versions = (await hostApi.api(`/api/v1/hosts/${encodeURIComponent(TARGET_HOST)}/pin-versions`)).json || [];
      snapshotWithExtra = versions.find((v) => v.sha256.includes(extraPin));
      await attachText(
        testInfo,
        'Hazırlık: pin seti geçmişi',
        [
          `PUT (fazladan pin ${short(extraPin)}) → HTTP ${a.status}`,
          `PUT (temel pin'ler)                   → HTTP ${b.status}`,
          '',
          `GET /api/v1/hosts/${TARGET_HOST}/pin-versions → ${versions.length} kayıt`,
          `geri dönülecek: anlık görüntü #${snapshotWithExtra && snapshotWithExtra.snapshotId}, v${snapshotWithExtra && snapshotWithExtra.version}`,
        ].join('\n'),
      );
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect(snapshotWithExtra).toBeTruthy();
    });

    await test.step('Sunucu: ADMIN_KEYS (alice, bob) + PIN_CHANGE_APPROVALS=2', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), PIN_CHANGE_APPROVALS: '2' });
      overridden = true;
      const leftovers = await hostApi.changeRequests('pending', keys.bob);
      for (const cr of leftovers) await hostApi.rejectChange(cr.id, 'E2E: önceki koşudan kalan istek', keys.bob);
      const me = await hostApi.adminMe(keys.alice);
      expect(me.approvalsRequired).toBe(2);
    });

    const before = {};
    await test.step('alice: aynı isteği beş farklı Content-Type ile gönderir → hepsi reddediliyor (UTF-8 dışı charset 415, ayrıştırılamayan başlık 400), hiçbiri onay kuyruğuna girmiyor, hiçbir pin değişmiyor', async () => {
      Object.assign(before, await hostState());
      const restorePath = `/api/v1/pin-snapshots/${snapshotWithExtra.snapshotId}/restore`;
      const cfg = await hostApi.getConfig();
      const fullPut = { version: 0, forceUpdate: false, pins: cfg.pins.map((p) => ({ ...p, sha256: [hostApi.randomPin(), hostApi.randomPin()] })) };
      const tries = [
        { what: 'geri alma, text/plain; charset=UTF-16 (bulgudaki istek)', path: restorePath, contentType: 'text/plain; charset=UTF-16', body: utf16({ hostname: TARGET_HOST }) },
        { what: 'geri alma, Application/JSON; charset=UTF-16 (büyük harf)', path: restorePath, contentType: 'Application/JSON; charset=UTF-16', body: utf16({ hostname: TARGET_HOST }) },
        { what: 'geri alma, application/json; charset=UTF-16LE', path: restorePath, contentType: 'application/json; charset=UTF-16LE', body: utf16({ hostname: TARGET_HOST }) },
        // Ktor böyle bir başlığı kapıya gelmeden "okunamayan istek" sayıp 400 ile
        // kesiyor; kapı da (ayrıştıramadığı başlığa) 415 derdi. İkisi de ret.
        { what: 'geri alma, ayrıştırılamayan başlık', path: restorePath, contentType: 'application/json; charset="UTF-16', body: utf16({ hostname: TARGET_HOST }), refusedWith: [400, 415] },
        { what: 'bütün pin\'ler (PUT), APPLICATION/JSON; CHARSET=UTF-16', path: '/api/v1/certificate-config', method: 'PUT', contentType: 'APPLICATION/JSON; CHARSET=UTF-16', body: utf16(fullPut) },
      ];
      const lines = [];
      for (const t of tries) {
        const r = await raw(t.path, { method: t.method || 'POST', key: keys.alice, contentType: t.contentType, body: t.body });
        t.status = r.status;
        lines.push(`${(t.method || 'POST').padEnd(4)} ${t.path}`, `  Content-Type: ${t.contentType}`, `  → HTTP ${r.status} ${r.text.trim().slice(0, 140)}`, `  (${t.what})`, '');
      }
      const pending = await hostApi.changeRequests('pending', keys.bob);
      const after = await hostState();
      lines.push(`bekleyen değişiklik isteği: ${pending.length}`);
      lines.push(`${TARGET_HOST}: v${before[TARGET_HOST].version} → v${after[TARGET_HOST].version}`);
      await attachText(testInfo, 'Onay kapısı: Content-Type denemeleri (alice)', lines.join('\n'));
      for (const t of tries) expect(t.refusedWith || [415], t.what).toContain(t.status);
      expect(pending).toEqual([]);
      expect(after).toEqual(before);
    });

    let crId;
    await test.step(`alice: aynı geri almayı UTF-8 ile ister ({"hostname": "${TARGET_HOST}"}) → 202, kart yalnızca bu host'u gösteriyor`, async () => {
      const r = await raw(`/api/v1/pin-snapshots/${snapshotWithExtra.snapshotId}/restore`, {
        key: keys.alice,
        contentType: 'application/json',
        body: JSON.stringify({ hostname: TARGET_HOST }),
      });
      const pending = await hostApi.changeRequests('pending', keys.bob);
      const card = pending.find((c) => r.json && c.id === r.json.changeRequestId);
      if (r.json && r.json.changeRequestId) {
        crId = r.json.changeRequestId;
        created.push(crId);
      }
      await attachText(
        testInfo,
        'UTF-8 geri alma isteği ve onay kartı',
        [
          `POST /api/v1/pin-snapshots/${snapshotWithExtra.snapshotId}/restore  Content-Type: application/json`,
          `→ HTTP ${r.status} ${r.text.trim()}`,
          '',
          `kart #${crId}: ${card ? card.summary : '(yok)'}`,
          card && card.detail ? `ayrıntı: ${JSON.stringify(card.detail).slice(0, 600)}` : '',
        ].join('\n'),
      );
      expect(r.status).toBe(202);
      expect(card, 'onay kartı oluşmalı').toBeTruthy();
      expect(card.summary).toContain(TARGET_HOST);
    });

    await test.step('bob onaylar → yalnızca hedef host geri geliyor (fazladan pin, yeni sürüm); diğer host\'lar değişmiyor; denetimde pins_restored', async () => {
      const r = await hostApi.approveChange(crId, keys.bob);
      const after = await hostState();
      const log = await hostApi.auditLog({ action: 'pins_restored', limit: 5, key: keys.bob });
      const audit = log.entries.find((e) => (e.target || '').includes(TARGET_HOST));
      const others = Object.keys(before).filter((h) => h !== TARGET_HOST);
      await attachText(
        testInfo,
        'Onay sonrası',
        [
          `POST /api/v1/change-requests/${crId}/approve (bob) → HTTP ${r.status}`,
          '',
          `${TARGET_HOST}: v${before[TARGET_HOST].version} → v${after[TARGET_HOST].version}, pin'ler ${after[TARGET_HOST].sha256.map(short).join(', ')}`,
          ...others.map((h) => `${h}: v${before[h].version} → v${after[h] ? after[h].version : '-'}`),
          '',
          'Denetim (pins_restored):',
          audit ? `  #${audit.id} ${audit.actor} — ${audit.summary}` : '  (kayıt yok)',
        ].join('\n'),
      );
      expect(r.status).toBe(200);
      expect(audit && audit.actor).toContain('alice (approved by bob)');
      expect(after[TARGET_HOST].sha256).toContain(extraPin);
      expect(after[TARGET_HOST].version).toBeGreaterThan(before[TARGET_HOST].version);
      for (const h of others) expect(after[h], h).toEqual(before[h]);
      created.splice(created.indexOf(crId), 1);
    });
  } finally {
    for (const id of created) {
      try {
        await hostApi.rejectChange(id, 'E2E temizliği: senaryo yarıda kaldı', keys.bob);
      } catch {
        /* ortam aşağıda sıfırlanır */
      }
    }
    if (overridden) await hostControl.resetEnv();
    await hostApi.restoreBaseline(run.baseline);
  }
});
