// Y07 — Ayar ve atestasyon kartının eskimesi (N8, 2026-11-09).
//
// Onay kartı onaylayana "bu değişiklik şunu şundan şuna çevirir" der. Kart
// yazıldıktan sonra aynı şey başka bir istekle değişirse kart artık doğruyu
// söylemez: onaylayan "7200 → 3600" görür, sunucu başka bir değerin üstüne
// yazar. Pin'ler için kart pin setinin parmak izini taşıyor (Y03'te kanıtlı);
// sunucu ayarları ve atestasyon politikası kartları taşımıyordu.
//
// Düzeltmeden sonra bu kartlar da dayandıkları durumun anahtarını taşıyor
// (`stateKey`): onay anında kart yeniden hesaplanır, anahtar değiştiyse istek
// "stale" olur ve 409 ile reddedilir; denetimde change_stale.
//
// Senaryo: alice aynı ayar için iki istek açar; bob ikincisini onaylar, ilki
// eskir. Aynısı atestasyon politikasında. Sonunda değerler eski haline döner
// (ayar: sunucunun varsayılanına; politika: başlangıçtaki değere). Telefon gerekmez.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const { keys, adminKeysEnv } = require('../lib/admins');
const env = require('../lib/env');

const SETTING = 'CONFIG_TTL_SECONDS';
const POLICY_PATH = `/api/v1/config-apis/${env.VAULT_API}/attestation/policy`;

/** alice'in isteği: 202 beklenir, değişiklik isteğinin kimliği döner. */
async function aliceAsks(pathname, body) {
  const r = await hostApi.api(pathname, { method: 'PUT', body, key: keys.alice });
  return { status: r.status, id: r.json && r.json.changeRequestId, text: r.text };
}

async function savedSetting() {
  const r = await hostApi.api('/api/v1/server-settings', { key: keys.bob });
  return (r.json.settings.find((s) => s.key === SETTING) || {}).saved ?? null;
}

async function policyTtl() {
  const r = await hostApi.api(POLICY_PATH, { key: keys.bob });
  return r.json.tokenTtlSeconds;
}

test('Web+Terminal: ayar ve atestasyon kartı eskiyor — aynı şeye iki istek açılıp biri onaylanınca diğeri 409 "stale" ile reddediliyor', async ({}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const created = [];
  let overridden = false;
  let settingTouched = false;
  let originalTtl;

  /** İkinci isteği onaylar, ilkini onaylamayı dener; kanıt satırlarını döndürür. */
  async function raceTwo(label, first, second, readValue) {
    const a = await aliceAsks(first.path, first.body);
    const b = await aliceAsks(second.path, second.body);
    for (const x of [a, b]) if (x.id) created.push(x.id);
    const pending = await hostApi.changeRequests('pending', keys.bob);
    const cardOf = (id) => (pending.find((c) => c.id === id) || {}).summary || '(yok)';
    const okSecond = await hostApi.approveChange(b.id, keys.bob);
    const value = await readValue();
    const staleFirst = await hostApi.approveChange(a.id, keys.bob);
    const valueAfter = await readValue();
    const history = await hostApi.changeRequests('stale', keys.bob);
    const audit = await hostApi.auditLog({ action: 'change_stale', limit: 5, key: keys.bob });
    const staleEntry = audit.entries.find((e) => (e.summary || '').includes(`#${a.id}`));
    for (const id of [a.id, b.id]) created.splice(created.indexOf(id), 1);
    await attachText(
      testInfo,
      `${label}: iki istek, biri onaylanıyor, diğeri eskiyor`,
      [
        `alice PUT ${first.path} ${JSON.stringify(first.body)} → HTTP ${a.status} (#${a.id})`,
        `  kart: ${cardOf(a.id)}`,
        `alice PUT ${second.path} ${JSON.stringify(second.body)} → HTTP ${b.status} (#${b.id})`,
        `  kart: ${cardOf(b.id)}`,
        '',
        `bob onaylar #${b.id} → HTTP ${okSecond.status}; değer şimdi ${value}`,
        `bob onaylar #${a.id} → HTTP ${staleFirst.status} ${staleFirst.text.trim().slice(0, 200)}`,
        `değer sonra: ${valueAfter}`,
        '',
        `GET /api/v1/change-requests?status=stale → ${history.some((c) => c.id === a.id) ? `#${a.id} stale` : `#${a.id} listede yok`}`,
        `denetim change_stale: ${staleEntry ? `#${staleEntry.id} ${staleEntry.actor} — ${staleEntry.summary}` : '(kayıt yok)'}`,
      ].join('\n'),
    );
    return { a, b, okSecond, staleFirst, value, valueAfter, history, staleEntry };
  }

  try {
    await test.step('Sunucu: ADMIN_KEYS (alice, bob) + PIN_CHANGE_APPROVALS=2', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), PIN_CHANGE_APPROVALS: '2' });
      overridden = true;
      const leftovers = await hostApi.changeRequests('pending', keys.bob);
      for (const cr of leftovers) await hostApi.rejectChange(cr.id, 'E2E: önceki koşudan kalan istek', keys.bob);
      expect((await hostApi.adminMe(keys.alice)).approvalsRequired).toBe(2);
      expect(await savedSetting()).toBeNull();
      originalTtl = await policyTtl();
    });

    await test.step(`Sunucu ayarı: alice ${SETTING}=7200 ve sonra =3600 ister; bob 3600'ü onaylar → 7200 isteği eskiyor (409), değer 3600'de kalıyor`, async () => {
      settingTouched = true;
      const r = await raceTwo(
        'Sunucu ayarı',
        { path: '/api/v1/server-settings', body: { values: { [SETTING]: '7200' } } },
        { path: '/api/v1/server-settings', body: { values: { [SETTING]: '3600' } } },
        savedSetting,
      );
      expect(r.a.status).toBe(202);
      expect(r.b.status).toBe(202);
      expect(r.okSecond.status).toBe(200);
      expect(r.value).toBe('3600');
      expect(r.staleFirst.status).toBe(409);
      expect(r.valueAfter).toBe('3600');
      expect(r.history.some((c) => c.id === r.a.id)).toBe(true);
      expect(r.staleEntry).toBeTruthy();
    });

    await test.step('Atestasyon politikası: alice token ömrünü (eski + 1) ve (eski + 2) saniye ister; bob ikinciyi onaylar → ilki eskiyor (409)', async () => {
      const r = await raceTwo(
        'Atestasyon politikası',
        { path: POLICY_PATH, body: { tokenTtlSeconds: originalTtl + 1 } },
        { path: POLICY_PATH, body: { tokenTtlSeconds: originalTtl + 2 } },
        policyTtl,
      );
      expect(r.a.status).toBe(202);
      expect(r.b.status).toBe(202);
      expect(r.okSecond.status).toBe(200);
      expect(r.value).toBe(originalTtl + 2);
      expect(r.staleFirst.status).toBe(409);
      expect(r.valueAfter).toBe(originalTtl + 2);
      expect(r.staleEntry).toBeTruthy();
    });

    await test.step('Geri alma: ayar varsayılana, politika eski değerine döner (alice ister, bob onaylar)', async () => {
      const s = await aliceAsks('/api/v1/server-settings', { values: { [SETTING]: null } });
      if (s.id) created.push(s.id);
      const sOk = await hostApi.approveChange(s.id, keys.bob);
      const p = await aliceAsks(POLICY_PATH, { tokenTtlSeconds: originalTtl });
      if (p.id) created.push(p.id);
      const pOk = await hostApi.approveChange(p.id, keys.bob);
      for (const id of [s.id, p.id]) created.splice(created.indexOf(id), 1);
      settingTouched = false;
      const saved = await savedSetting();
      const ttl = await policyTtl();
      await attachText(testInfo, 'Geri alma', `ayar → HTTP ${sOk.status}, kayıtlı ${SETTING}: ${saved ?? '(varsayılan)'}\npolitika → HTTP ${pOk.status}, tokenTtlSeconds: ${ttl}`);
      expect(saved).toBeNull();
      expect(ttl).toBe(originalTtl);
    });
  } finally {
    for (const id of created) {
      try {
        await hostApi.rejectChange(id, 'E2E temizliği: senaryo yarıda kaldı', keys.bob);
      } catch {
        /* ortam aşağıda sıfırlanır */
      }
    }
    if (overridden) {
      // Yarıda kaldıysa kaydedilmiş ayar ve politika, onay kapandıktan sonra paylaşılan anahtarla geri alınır
      // (kayıtlı ayar bir sonraki açılışta uygulanırdı).
      await hostControl.resetEnv();
      if (settingTouched) {
        await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { [SETTING]: null } } });
        // Bu açılış kayıtlı değerle başladı: varsayılanla bir kez daha başlatılır.
        await hostControl.resetEnv();
      }
      if (originalTtl !== undefined && (await hostApi.api(POLICY_PATH)).json.tokenTtlSeconds !== originalTtl) {
        await hostApi.api(POLICY_PATH, { method: 'PUT', body: { tokenTtlSeconds: originalTtl } });
      }
    }
  }
});
