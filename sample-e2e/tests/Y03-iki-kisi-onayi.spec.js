// Y03 — İki kişi onayı (PIN_CHANGE_APPROVALS=2).
//
// Cihazların neye güveneceğini değiştiren her yönetici yazımı (pin'ler, force,
// host sertifikası, bootstrap pin'leri, imzalama anahtarı / anahtar seti,
// Config API başlat/durdur) uygulanmaz: "değişiklik isteği" olarak saklanır ve
// 202 {pendingApproval, changeRequestId} döner. İsteyen DIŞINDA bir yönetici
// onaylayınca sunucu saklanan isteği birebir, isteyenin adına kendi yönetim
// portuna yeniden gönderir (tek kullanımlık X-PinVault-Replay token'ı). Kanıtlanan:
//
//   • alice'in pin değişikliği beklemede; telefon eski sürümde kalıyor,
//   • alice kendi isteğini onaylayamıyor (düğme kapalı, API 409); paylaşılan
//     API_KEY ne onaylayabiliyor ne de değişiklik İSTEYEBİLİYOR (409: kimseyi
//     adlandırmayan bir anahtarla istenen değişikliği isteyen kendisi onaylayabilirdi),
//   • bob onaylayınca uygulanıyor, telefon yeni sürümü alıyor; denetimde
//     pins_changed "alice (approved by bob)" ve change_applied,
//   • ret: reddedilen istek uygulanmıyor; Config API'yi durdurmak da onaya
//     tabi (bir portun hangi kapsamın pin'lerini sunduğunu belirler) — bob
//     reddediyor, dinleyici çalışmaya devam ediyor,
//   • karara bağlanan isteğin saklı gövdesi siliniyor (yüklemeler özel anahtar
//     taşıyabilir),
//   • eskimiş istek (pin'ler bu arada değişti): aynı pin'ler üzerinde iki
//     istekten biri onaylanınca diğeri 409 "changed after … was requested" (eskidi),
//   • vault dosyası yükleme ve kayıt token'ı üretme de onaya tabi (202; dosya ve
//     token onaylanmadan oluşmuyor),
//   • onay açıkken Config API portları pin yazımını hiç kabul etmiyor (409).
//
// Ana host üzerinde koşar. Onay açıkken fixture'ın temel duruma dönüşü
// (paylaşılan API_KEY ile pin yazımı) 409 alırdı: ortam finally'de, fixture'dan
// ÖNCE sıfırlanır. Config API durdurma isteği hiçbir koşulda onaylanmaz.
const crypto = require('crypto');
const https = require('https');
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const { Dashboard } = require('../lib/dashboard');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const { keys, adminKeysEnv } = require('../lib/admins');
const env = require('../lib/env');
const { testDeviceUid } = require('../lib/android');

const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const keyLabel = (name) => `<${name}'in kişisel anahtarı; sha256 ${sha256Hex(keys[name]).slice(0, 12)}…>`;
const adminKeysDisplay = () =>
  adminKeysEnv()
    .split(',')
    .map((pair) => `${pair.split(':')[0]}:${pair.split(':')[1].slice(0, 12)}…`)
    .join(',');
const short = (pin) => `${pin.slice(0, 12)}…`;

/**
 * Config API portuna (TLS, 6651) istek: sunucu sertifikası sistem güvenine
 * değil host'un pin'ine göre doğrulanır (telefonun yaptığı gibi).
 */
function configPortRequest({ method = 'GET', pathname, key, body }) {
  const expectedPins = hostApi.hostPins();
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: 'localhost',
        port: env.CONFIG_API_PORT,
        path: pathname,
        method,
        rejectUnauthorized: false,
        agent: false,
        headers: {
          ...(key ? { 'X-API-Key': key } : {}),
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        },
      },
      (res) => {
        const pin = hostApi.spkiPin(res.socket.getPeerCertificate().raw);
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode, pin, pinOk: expectedPins.includes(pin), text, json });
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Pin kaydı: hedef host'un sürümü ve pin'leri (herkese açık imzasız görünüm). */
async function targetPins() {
  const cfg = await hostApi.getConfig();
  return cfg.pins.find((p) => p.hostname === TARGET_HOST);
}

test('Web+Mobil+Terminal: iki kişi onayı — alice\'in pin değişikliği bob onaylayana kadar bekliyor; ne alice kendi isteğini ne de paylaşılan anahtar onaylayabiliyor; ret, Config API\'yi durdurmak da onaya tabi, kararla saklanan istek siliniyor, eskimiş istek uygulanmıyor, Config API portu pin yazımını reddediyor', async ({
  app,
  browser,
  run,
}, testInfo) => {
  test.setTimeout(25 * 60 * 1000);
  const created = [];
  const pins = { a: hostApi.randomPin(), b: hostApi.randomPin(), c: hostApi.randomPin(), d: hostApi.randomPin() };
  let overridden = false;
  let alice;
  let bob;
  let v0;
  let crApplied;
  let crRejected;
  let crStop;
  let crFirst;
  let crStale;
  let stopBodyLen;

  /**
   * alice pin düzenleyicisinden kaydeder; 202 yanıtını ve toast'ı bekler,
   * isteğin kimliğini döndürür.
   */
  async function aliceRequestsPins(pinList) {
    await alice.openHostIn(env.VAULT_API, TARGET_HOST);
    const response = alice.page.waitForResponse(
      (r) => r.url().includes('/api/v1/certificate-config') && r.request().method() === 'PUT',
      { timeout: 30_000 },
    );
    await alice.setPins(TARGET_HOST, pinList, { expectSaved: false });
    const res = await response;
    const body = JSON.parse(await res.text());
    expect(res.status()).toBe(202);
    expect(body.pendingApproval).toBe(true);
    created.push(body.changeRequestId);
    await expect(alice.page.locator('.toast.info').last()).toContainText(`#${body.changeRequestId} onay bekliyor`);
    return { id: body.changeRequestId, body };
  }

  try {
    await test.step('Sunucu: ADMIN_KEYS (alice, bob) + PIN_CHANGE_APPROVALS=2; Web: alice ve bob iki ayrı tarayıcı oturumunda — kimlik rozetleri, "2 kişi onayı"', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), PIN_CHANGE_APPROVALS: '2' });
      overridden = true;
      // Yarıda kalmış eski bir koşunun beklemede bıraktığı istek varsa (finally
      // onu reddeder, ama süreç öldürüldüyse kalabilir) bob reddeder: sayımlar
      // ve "bekleyen" listesi yalnızca bu koşunun isteklerini göstersin.
      const leftovers = await hostApi.changeRequests('pending', keys.bob);
      for (const cr of leftovers) await hostApi.rejectChange(cr.id, 'E2E: önceki koşudan kalan istek', keys.bob);
      alice = await Dashboard.openAs(browser, testInfo, keys.alice);
      bob = await Dashboard.openAs(browser, testInfo, keys.bob);
      const names = { alice: await alice.adminName(), bob: await bob.adminName() };
      const badges = await alice.adminBadges();
      await alice.snap('alice\'in dashboard\'u: kimlik rozeti "alice", "2 kişi onayı"');
      const meAlice = await hostApi.adminMe(keys.alice);
      const meBob = await hostApi.adminMe(keys.bob);
      await attachText(
        testInfo,
        'env-override.sh + GET /api/v1/admin/me (alice, bob)',
        [
          `$ ./scripts/env-override.sh set ADMIN_KEYS=${adminKeysDisplay()} PIN_CHANGE_APPROVALS=2`,
          'Host hazır: http://localhost:6650 (set)',
          '',
          `GET /api/v1/admin/me   X-API-Key: ${keyLabel('alice')}`,
          JSON.stringify(meAlice),
          `GET /api/v1/admin/me   X-API-Key: ${keyLabel('bob')}`,
          JSON.stringify(meBob),
          '',
          `dashboard (oturum 1): ${names.alice}  rozetler: ${badges.join(', ')}`,
          `dashboard (oturum 2): ${names.bob}`,
          ...(leftovers.length ? ['', `önceki koşudan kalan bekleyen istek(ler) reddedildi: ${leftovers.map((c) => `#${c.id}`).join(', ')}`] : []),
        ].join('\n'),
      );
      expect(names).toEqual({ alice: 'alice', bob: 'bob' });
      expect(badges).toContain('2 kişi onayı');
      expect(meAlice.approvalsRequired).toBe(2);
      expect(meBob.name).toBe('bob');
    });

    await test.step('Web (alice): hedef host\'un pin\'leri değiştirilir → "onay bekliyor", "Onaylar" rozeti 1; Mobil: config yenile → sürüm değişmedi', async () => {
      await alice.openHostIn(env.VAULT_API, TARGET_HOST);
      v0 = await alice.version();
      const req = await aliceRequestsPins([...run.goodPins, pins.a]);
      crApplied = req.id;
      await expect(alice.page.locator('#approvals-badge')).toHaveText('1', { timeout: 20_000 });
      await alice.snapWithToast(`alice: "Değişiklik #${crApplied} onay bekliyor"; "Onaylar" rozeti 1; host hâlâ v${v0}`);
      const stored = await targetPins();
      const pending = await hostApi.changeRequests('pending', keys.alice);
      const status = await app.refreshConfig();
      await app.snap(`onay beklerken telefon: ${TARGET_HOST} hâlâ v${v0}`);
      await attachText(
        testInfo,
        'PUT /api/v1/certificate-config (alice) → 202 ve bekleyen istek',
        [
          `HTTP 202 ${JSON.stringify(req.body)}`,
          '',
          `GET /api/v1/change-requests?status=pending → ${pending.map((c) => `#${c.id} ${c.status}, isteyen ${c.requestedBy}: ${c.summary}`).join('\n  ')}`,
          '',
          `sunucudaki ${TARGET_HOST}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')}  (değişmedi)`,
          `telefon: ${status.split('\n')[0]} → ${TARGET_HOST} v${SampleApp.hostVersion(status, TARGET_HOST)}`,
        ].join('\n'),
      );
      expect(await alice.version()).toBe(v0);
      expect(stored.version).toBe(v0);
      expect(stored.sha256).not.toContain(pins.a);
      expect(pending.map((c) => c.id)).toEqual([crApplied]);
      expect(pending[0].requestedBy).toBe('alice');
      expect(status).toContain('Config güncel');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0);
    });

    await test.step('Web (alice): "Onaylar"da kendi isteğinin "Onayla" düğmesi kapalı; Terminal: API\'den onay alice ile 409, paylaşılan API_KEY ile 409; paylaşılan anahtar değişiklik İSTEYEMİYOR da (409)', async () => {
      await alice.openApprovals();
      await alice.expandChange(crApplied);
      const button = await alice.approveButtonState(crApplied);
      await alice.snapApprovals(`alice: kendi isteği #${crApplied} — "Onayla" kapalı, pin farkı açık`, { ids: [crApplied] });
      const selfApprove = await hostApi.approveChange(crApplied, keys.alice);
      const sharedApprove = await hostApi.approveChange(crApplied);
      const cfg = await hostApi.getConfig();
      const sharedWrite = await hostApi.api(`/api/v1/certificate-config?configApiId=${env.VAULT_API}`, {
        method: 'PUT',
        body: {
          version: 0,
          pins: cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: [...run.goodPins, pins.b] } : p)),
          forceUpdate: false,
        },
      });
      const pending = await hostApi.changeRequests('pending', keys.alice);
      const refused = (await hostApi.auditLog({ action: 'change_approval_refused', limit: 5, key: keys.alice })).entries.filter((e) =>
        e.summary.startsWith(`#${crApplied}:`),
      );
      await attachText(
        testInfo,
        'Kendi isteğini onaylama, paylaşılan anahtarla onaylama ve istekte bulunma',
        [
          `dashboard (alice): "Onayla" disabled=${button.disabled}, title="${button.title}"`,
          '',
          `$ curl -X POST -H 'X-API-Key: ${keyLabel('alice')}' …/api/v1/change-requests/${crApplied}/approve`,
          `HTTP ${selfApprove.status} ${selfApprove.text.trim()}`,
          '',
          `$ curl -X POST -H 'X-API-Key: <paylaşılan API_KEY>' …/api/v1/change-requests/${crApplied}/approve`,
          `HTTP ${sharedApprove.status} ${sharedApprove.text.trim()}`,
          '',
          `$ curl -X PUT -H 'X-API-Key: <paylaşılan API_KEY>' …/api/v1/certificate-config  (${TARGET_HOST} + ${short(pins.b)})`,
          `HTTP ${sharedWrite.status} ${sharedWrite.text.trim()}`,
          '',
          `bekleyen istekler: ${pending.map((c) => `#${c.id}`).join(', ')} (paylaşılan anahtarın yazımı istek bile olmadı)`,
          '',
          'denetim kaydı (reddedilen onay girişimleri):',
          ...refused.map((e) => `  #${e.id} ${e.actor.padEnd(6)} ${e.action}: ${e.summary}`),
        ].join('\n'),
      );
      expect(button.disabled).toBe(true);
      expect(button.title).toContain('Kendi isteğinizi onaylayamazsınız');
      expect(selfApprove.status).toBe(409);
      expect(selfApprove.json.error).toContain('cannot approve it');
      expect(sharedApprove.status).toBe(409);
      expect(sharedApprove.json.error).toContain('shared key (API_KEY) cannot approve');
      expect(sharedWrite.status).toBe(409);
      expect(sharedWrite.json.error).toContain('personal admin key');
      expect(pending.map((c) => c.id)).toEqual([crApplied]);
      expect(refused.map((e) => e.actor).sort()).toEqual(['admin', 'alice']);
      expect((await targetPins()).version).toBe(v0);
    });

    await test.step('Web (bob, ikinci oturum): "Onayla" → uygulandı; Mobil: config yenile → yeni sürüm', async () => {
      await bob.openApprovals();
      await bob.expandChange(crApplied);
      const button = await bob.approveButtonState(crApplied);
      expect(button.disabled).toBe(false);
      const res = await bob.approveChange(crApplied);
      const decided = JSON.parse(res.body);
      await expect(bob.page.locator('.toast.success').last()).toContainText(`#${crApplied} onaylandı ve uygulandı`);
      await bob.snapWithToast(`bob onayladı: "Değişiklik #${crApplied} onaylandı ve uygulandı"`);
      const stored = await targetPins();
      const status = await app.refreshConfig();
      await app.snap(`bob'un onayından sonra telefon: ${TARGET_HOST} v${v0 + 1}`);
      await attachText(
        testInfo,
        `POST /api/v1/change-requests/${crApplied}/approve (bob)`,
        [
          `HTTP ${res.status}`,
          JSON.stringify({ ...decided, detail: '(pin farkı)', resultBody: decided.resultBody ? '(sunucunun yeniden çalıştırdığı PUT\'un yanıtı)' : null }, null, 2),
          '',
          `sunucudaki ${TARGET_HOST}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')}`,
          `telefon: ${status.split('\n')[0]} → ${TARGET_HOST} v${SampleApp.hostVersion(status, TARGET_HOST)}`,
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(decided.status).toBe('applied');
      expect(decided.approvedBy).toEqual(['bob']);
      expect(decided.decidedBy).toBe('bob');
      expect(decided.resultStatus).toBe(200);
      expect(stored.version).toBe(v0 + 1);
      expect(stored.sha256).toContain(pins.a);
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Web: denetim kaydında isteğin bütün adımları — change_requested (alice), reddedilen onay denemeleri, pins_changed "alice (approved by bob)", change_applied (bob)', async () => {
      const log = (await hostApi.auditLog({ limit: 40, key: keys.bob })).entries;
      const mine = (e) => e.summary.startsWith(`#${crApplied} `) || e.summary.startsWith(`#${crApplied}:`);
      const requested = log.find((e) => e.action === 'change_requested' && mine(e));
      expect(requested, `#${crApplied} için change_requested kaydı`).toBeTruthy();
      const journey = log.filter(
        (e) =>
          mine(e) ||
          (e.id > requested.id && e.action === 'pins_changed' && e.actor === 'alice (approved by bob)' && e.target.split(',').includes(TARGET_HOST)),
      );
      const byAction = (a) => journey.filter((e) => e.action === a);
      const pinsChanged = byAction('pins_changed')[0];
      expect(pinsChanged, 'onaylanan değişikliğin pins_changed kaydı').toBeTruthy();
      await bob.openAudit();
      await bob.expandAuditEntry(pinsChanged.id);
      await bob.snapAudit(`bob: Denetim Kaydı — #${crApplied} isteğinin kayıtları; pins_changed kim: "alice (approved by bob)"`, {
        ids: journey.map((e) => e.id),
      });
      const cells = await bob.auditRowCells(pinsChanged.id);
      const refusedCells = await Promise.all(byAction('change_approval_refused').map((e) => bob.auditRowCells(e.id)));
      const filterHasRefused = await bob.page.locator('#audit-action-filter option[value="change_approval_refused"]').count();
      await attachText(
        testInfo,
        `GET /api/v1/audit-log — değişiklik isteği #${crApplied}`,
        [
          ...[...journey]
            .sort((a, b) => a.id - b.id)
            .map((e) => `#${e.id}  ${e.actor.padEnd(24)} ${e.action.padEnd(24)} [${e.configApiId || '—'} · ${e.target || '—'}]  ${e.summary}`),
          '',
          `dashboard: reddedilen onay satırları kapsam/hedef → ${refusedCells.map((c) => `${c.configApiId} · ${c.target}`).join(' | ')}`,
          `dashboard: işlem süzgecinde "change_approval_refused" seçeneği: ${filterHasRefused ? 'var' : 'YOK'}`,
        ].join('\n'),
      );
      expect(byAction('change_requested').map((e) => e.actor)).toEqual(['alice']);
      expect(byAction('change_approval_refused').map((e) => e.actor).sort()).toEqual(['admin', 'alice']);
      for (const e of byAction('change_approval_refused')) {
        expect(e.configApiId).toBe(env.VAULT_API);
        expect(e.target).toBe('PUT /api/v1/certificate-config');
      }
      expect(refusedCells.map((c) => c.configApiId)).toEqual([env.VAULT_API, env.VAULT_API]);
      expect(filterHasRefused).toBe(1);
      expect(byAction('pins_changed')).toHaveLength(1);
      expect(pinsChanged.summary).toContain(`${TARGET_HOST}: pins v${v0}→v${v0 + 1}`);
      expect(cells.actor).toBe('alice (approved by bob)');
      expect(byAction('change_applied').map((e) => e.actor)).toEqual(['bob']);
    });

    await test.step('Web: alice ikinci bir pin değişikliği ister, bob gerekçeyle reddeder → "reddedildi", hiçbir şey uygulanmadı', async () => {
      crRejected = (await aliceRequestsPins([...run.goodPins, pins.b])).id;
      const reason = 'Yedek pin kayıtlı bir anahtara ait değil (E2E)';
      await bob.openApprovals();
      await expect(bob.changeCard(crRejected)).toBeVisible({ timeout: 20_000 });
      const res = await bob.rejectChange(crRejected, reason);
      await expect(bob.page.locator('.toast.success').last()).toContainText(`#${crRejected} reddedildi`);
      await bob.setApprovalsTab('history');
      await expect(bob.decidedRow(crRejected)).toContainText('reddedildi');
      await bob.snapApprovals(`bob: Geçmiş — #${crRejected} reddedildi (gerekçeyle), #${crApplied} uygulandı`, { ids: [crApplied, crRejected] });
      const cr = JSON.parse(res.body);
      const stored = await targetPins();
      await attachText(
        testInfo,
        `POST /api/v1/change-requests/${crRejected}/reject (bob)`,
        [
          `prompt yanıtı (gerekçe): "${reason}"`,
          `HTTP ${res.status}: #${cr.id} status=${cr.status}, decidedBy=${cr.decidedBy}, reason="${cr.reason}"`,
          '',
          `sunucudaki ${TARGET_HOST}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')}`,
          `(reddedilen istekteki ${short(pins.b)} yok)`,
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(cr.status).toBe('rejected');
      expect(cr.decidedBy).toBe('bob');
      expect(cr.reason).toBe(reason);
      expect(stored.version).toBe(v0 + 1);
      expect(stored.sha256).not.toContain(pins.b);
    });

    await test.step('Web (alice): varsayılan TLS Config API\'yi durdurmak da onaya tabi → 202, istek beklemede; Config API çalışmaya devam ediyor', async () => {
      await alice.openConfigApi(env.VAULT_API);
      const toggle = alice.page.locator(`[data-action="toggleConfigApi"][data-arg0="${env.VAULT_API}"]`).first();
      await expect(toggle).toContainText('Çalışıyor');
      const response = alice.page.waitForResponse((r) => r.url().includes('/api/v1/config-apis/stop'), { timeout: 30_000 });
      await toggle.click();
      const res = await response;
      const body = JSON.parse(await res.text());
      expect(res.status()).toBe(202);
      crStop = body.changeRequestId;
      created.push(crStop);
      await expect(alice.page.locator('.toast.info').last()).toContainText(`#${crStop} onay bekliyor`);
      await expect(alice.page.locator(`[data-action="toggleConfigApi"][data-arg0="${env.VAULT_API}"]`).first()).toContainText('Çalışıyor');
      await alice.snapWithToast(`alice: Config API "durdur" → "Değişiklik #${crStop} onay bekliyor"; ${env.VAULT_API} hâlâ çalışıyor`);
      const cr = (await hostApi.changeRequests('pending', keys.alice)).find((c) => c.id === crStop);
      stopBodyLen = Number(hostApi.dbQuery(`SELECT length(body) FROM change_requests WHERE id=${crStop};`));
      const running = (await hostApi.api('/api/v1/all-configs', { key: keys.alice })).json.find((a) => a.id === env.VAULT_API);
      await attachText(
        testInfo,
        'POST /api/v1/config-apis/stop (alice, dashboard\'daki anahtar)',
        [
          `istek gövdesi: {"id":"${env.VAULT_API}"}`,
          `HTTP 202 ${JSON.stringify(body)}`,
          '',
          `bekleyen #${cr.id}: ${cr.summary}`,
          `$ sqlite3 -readonly data/db/pinvault.db "SELECT length(body) FROM change_requests WHERE id=${crStop}"`,
          `${stopBodyLen}   ← karar verilene kadar saklanan istek gövdesi (bayt)`,
          '',
          `GET /api/v1/all-configs → ${env.VAULT_API}: running=${running.running}`,
          '',
          'Bir portun hangi Config API\'nin pin\'lerini sunduğuna, o Config API\'yi başlatan/durduran karar verir;',
          'imzalı config hangi Config API\'ye ait olduğunu yazmadığı için başlatma/durdurma da iki kişi onayına tabi.',
        ].join('\n'),
      );
      expect(cr.summary).toContain(`Stop Config API ${env.VAULT_API}`);
      expect(cr.requestedBy).toBe('alice');
      expect(stopBodyLen).toBeGreaterThan(0);
      expect(running.running).not.toBe(false);
    });

    await test.step('Web (bob): Config API\'yi durdurma isteğini reddeder → Config API çalışmaya devam ediyor; Mobil: config yenileme hâlâ çalışıyor', async () => {
      await bob.openApprovals();
      await bob.expandChange(crStop);
      const opBadge = (await bob.changeCard(crStop).locator('.op-badge').innerText()).trim();
      await bob.snapApprovals(`bob: bekleyen #${crStop} "${opBadge}" — Stop Config API ${env.VAULT_API}, reddedilecek`, { ids: [crStop] });
      const res = await bob.rejectChange(crStop, 'Üretim dinleyicisi durdurulmaz (E2E)');
      await expect(bob.page.locator('.toast.success').last()).toContainText(`#${crStop} reddedildi`);
      const cr = JSON.parse(res.body);
      const running = (await hostApi.api('/api/v1/all-configs', { key: keys.bob })).json.find((a) => a.id === env.VAULT_API);
      const envelope = await hostApi.signedConfig();
      const status = await app.refreshConfig();
      await app.snap(`durdurma reddedildi: Config API yanıt veriyor, ${TARGET_HOST} v${v0 + 1}`);
      await attachText(
        testInfo,
        `POST /api/v1/change-requests/${crStop}/reject (bob) ve Config API'nin durumu`,
        [
          `onay kartı: işlem rozeti "${opBadge}", özet "${cr.summary}"`,
          `HTTP ${res.status}: #${cr.id} status=${cr.status}, decidedBy=${cr.decidedBy}, reason="${cr.reason}"`,
          `GET /api/v1/all-configs → ${env.VAULT_API}: running=${running.running}`,
          `GET https://localhost:${env.CONFIG_API_PORT}/api/v1/certificate-config → imzalı yanıt, ${envelope.config.pins.length} host`,
          `telefon: ${status.split('\n')[0]} → ${TARGET_HOST} v${SampleApp.hostVersion(status, TARGET_HOST)}`,
        ].join('\n'),
      );
      expect(opBadge).toBe('Config API başlat/durdur');
      expect(cr.status).toBe('rejected');
      expect(running.running).not.toBe(false);
      expect(envelope.config.pins.some((p) => p.hostname === TARGET_HOST)).toBe(true);
      expect(status).toContain('Config güncel');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Terminal: karar verilen isteklerin saklanan gövdesi silinmiş (sqlite3 -readonly)', async () => {
      const ids = [crApplied, crRejected, crStop];
      const rows = hostApi
        .dbQuery(`SELECT id, status, requested_by, decided_by, length(body), body IS NULL FROM change_requests WHERE id IN (${ids.join(',')}) ORDER BY id;`)
        .split('\n')
        .map((line) => {
          const [id, status, requestedBy, decidedBy, bodyLen, bodyNull] = line.split('|');
          return { id: Number(id), status, requestedBy, decidedBy, bodyLen, bodyNull: bodyNull === '1' };
        });
      await attachText(
        testInfo,
        'change_requests tablosu (ana host, salt okunur)',
        [
          `$ sqlite3 -readonly -header data/db/pinvault.db "SELECT id, status, requested_by, decided_by, length(body), body IS NULL FROM change_requests WHERE id IN (${ids.join(',')})"`,
          'id|status|requested_by|decided_by|length(body)|body IS NULL',
          ...rows.map((r) => `${r.id}|${r.status}|${r.requestedBy}|${r.decidedBy}|${r.bodyLen}|${r.bodyNull ? 1 : 0}`),
          '',
          `#${crStop} beklerken gövde ${stopBodyLen} bayttı; kararla birlikte silindi. Yüklemeler (sertifika, anahtar seti)`,
          'özel anahtar ya da parola taşıyabilir: karar verildikten sonra hiçbir şeyin onlara ihtiyacı yok.',
        ].join('\n'),
      );
      expect(rows.map((r) => r.id)).toEqual(ids);
      expect(rows.map((r) => r.status)).toEqual(['applied', 'rejected', 'rejected']);
      expect(rows.every((r) => r.bodyNull)).toBe(true);
    });

    await test.step('Web: eskimiş istek — aynı pin\'ler için iki istek; bob birincisini onaylayınca pin\'ler değiştiği için ikincisi 409 "changed after … was requested" alıyor ("eskidi")', async () => {
      crFirst = (await aliceRequestsPins([...run.goodPins, pins.c])).id;
      crStale = (await aliceRequestsPins([...run.goodPins, pins.d])).id;
      await bob.openApprovals();
      await expect(bob.changeCard(crFirst)).toBeVisible({ timeout: 20_000 });
      await expect(bob.changeCard(crStale)).toBeVisible({ timeout: 20_000 });
      const first = await bob.approveChange(crFirst);
      await expect(bob.page.locator('.toast.success').last()).toContainText(`#${crFirst} onaylandı ve uygulandı`);
      await expect(bob.changeCard(crStale)).toBeVisible({ timeout: 20_000 });
      const second = await bob.approveChange(crStale);
      await expect(bob.page.locator('.toast.error').last()).toContainText(`changed after #${crStale} was requested`);
      await bob.snapWithToast(`bob: #${crFirst} uygulandı; #${crStale} → 409 "changed after #${crStale} was requested"`);
      await bob.setApprovalsTab('history');
      await expect(bob.decidedRow(crStale)).toContainText('eskidi');
      await bob.snapApprovals(`bob: Geçmiş — #${crFirst} uygulandı, #${crStale} eskidi`, { ids: [crFirst, crStale] });
      const staleCr = (await hostApi.changeRequests('all', keys.bob)).find((c) => c.id === crStale);
      const stored = await targetPins();
      await attachText(
        testInfo,
        'İki istek aynı pin\'lerden yola çıktı: birincisi uygulanınca ikincisi eskidi',
        [
          `#${crFirst}: ${TARGET_HOST} → + ${short(pins.c)}   #${crStale}: ${TARGET_HOST} → + ${short(pins.d)}   (ikisi de v${v0 + 1} üzerinden)`,
          '',
          `POST …/${crFirst}/approve (bob) → HTTP ${first.status}, status=${JSON.parse(first.body).status}`,
          `POST …/${crStale}/approve (bob) → HTTP ${second.status} ${second.body}`,
          `#${crStale}: status=${staleCr.status}, reason="${staleCr.reason}"`,
          '',
          `sunucudaki ${TARGET_HOST}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')}`,
          'İstek, istendiği andaki pin\'lerin özetini (baseHash) saklar; onayda özet tutmazsa uygulanmaz —',
          'geç onaylanan tam config yazımı arada onaylanmış bir değişikliği geri alamaz.',
        ].join('\n'),
      );
      expect(first.status).toBe(200);
      expect(JSON.parse(first.body).status).toBe('applied');
      expect(second.status).toBe(409);
      expect(JSON.parse(second.body).error).toContain(`changed after #${crStale} was requested`);
      expect(staleCr.status).toBe('stale');
      expect(stored.version).toBe(v0 + 2);
      expect(stored.sha256).toContain(pins.c);
      expect(stored.sha256).not.toContain(pins.d);
    });

    await test.step('Terminal: onay açıkken vault dosyası yükleme ve kayıt token\'ı üretme de beklemeye alınıyor (alice → 202, dosya ve token oluşmadı); bob ikisini de reddediyor', async () => {
      const vaultKey = `y03-onayli-${Date.now()}`;
      const upload = await hostApi.api(
        `/api/v1/config-apis/${env.VAULT_API}/vault/${vaultKey}?policy=public&encryption=plain`,
        { method: 'PUT', rawBody: JSON.stringify({ not: 'iki kişi onayı denemesi' }), key: keys.alice },
      );
      const token = await hostApi.api('/api/v1/enrollment-tokens/generate', {
        method: 'POST',
        body: { clientId: `y03-onayli-${Date.now()}`, deviceUid: testDeviceUid() },
        key: keys.alice,
      });
      for (const r of [upload, token]) if (r.status === 202 && r.json) created.push(r.json.changeRequestId);
      const pending = await hostApi.changeRequests('pending', keys.alice);
      const filePresent = (await hostApi.vaultFiles(env.VAULT_API)).some((f) => f.key === vaultKey);
      const decisions = [];
      for (const r of [upload, token]) {
        if (r.status !== 202 || !r.json) continue;
        const res = await hostApi.rejectChange(r.json.changeRequestId, 'Yalnızca onay kapısının denemesi (E2E)', keys.bob);
        decisions.push(`#${r.json.changeRequestId} → bob reddetti: HTTP ${res.status} status=${res.json && res.json.status}`);
      }
      await attachText(
        testInfo,
        'Onaya tabi yeni işlemler: vault yükleme ve kayıt token\'ı',
        [
          `$ curl -X PUT -H 'X-API-Key: ${keyLabel('alice')}' …/api/v1/config-apis/${env.VAULT_API}/vault/${vaultKey}?policy=public&encryption=plain`,
          `HTTP ${upload.status} ${upload.text.trim()}`,
          '',
          `$ curl -X POST -H 'X-API-Key: ${keyLabel('alice')}' …/api/v1/enrollment-tokens/generate`,
          `HTTP ${token.status} ${token.text.trim()}`,
          '',
          `bekleyen istekler: ${pending.map((c) => `#${c.id} ${c.summary}`).join(' | ')}`,
          `vault'ta ${vaultKey}: ${filePresent ? 'VAR' : 'yok'} (onaylanmadıkça yüklenmez)`,
          ...decisions,
          '',
          'Bir vault dosyası onu çekebilen her cihaza gider; bir kayıt token\'ı yeni bir cihaz kimliği açar.',
          'Onay açıkken ikisi de pin değişikliği gibi ikinci bir yöneticiyi bekler.',
        ].join('\n'),
      );
      expect(upload.status).toBe(202);
      expect(upload.json.pendingApproval).toBe(true);
      expect(token.status).toBe(202);
      expect(token.json.pendingApproval).toBe(true);
      expect(token.json.token).toBeUndefined();
      expect(filePresent).toBe(false);
      expect(decisions).toHaveLength(2);
    });

    await test.step('Terminal: Config API portunda (6651) pin yazımı alice\'in anahtarıyla → 409 (onay açıkken Config API portları pin yazımını reddediyor)', async () => {
      const cfg = await hostApi.getConfig();
      const body = {
        version: 0,
        pins: cfg.pins.map((p) => (p.hostname === TARGET_HOST ? { ...p, sha256: [...run.goodPins, pins.d] } : p)),
        forceUpdate: false,
      };
      const put = await configPortRequest({ method: 'PUT', pathname: '/api/v1/certificate-config', key: keys.alice, body });
      const get = await configPortRequest({ pathname: '/api/v1/certificate-config?currentVersion=0' });
      const pending = await hostApi.changeRequests('pending', keys.alice);
      const stored = await targetPins();
      await attachText(
        testInfo,
        `Config API portu https://localhost:${env.CONFIG_API_PORT} (sunucu pin'i ${put.pinOk ? 'host pin\'iyle eşleşti ✓' : 'EŞLEŞMEDİ'})`,
        [
          `$ curl -X PUT -H 'X-API-Key: ${keyLabel('alice')}' https://localhost:${env.CONFIG_API_PORT}/api/v1/certificate-config  (${TARGET_HOST} + ${short(pins.d)})`,
          `HTTP ${put.status} ${put.text.trim()}`,
          '',
          `$ curl https://localhost:${env.CONFIG_API_PORT}/api/v1/certificate-config   (cihaz yolu, anahtarsız)`,
          `HTTP ${get.status} (imzalı yanıt, ${get.text.length} bayt) — cihazlara config verilmeye devam ediyor`,
          '',
          `bekleyen istek: ${pending.length ? pending.map((c) => `#${c.id}`).join(', ') : 'yok'}; ${TARGET_HOST} v${stored.version} (değişmedi)`,
          'Onay açıkken pin değişikliği yalnızca yönetim API\'sinden, ikinci bir yöneticiyi bekleyerek girer;',
          'cihazların bağlandığı portlar yazımı istek olarak bile almaz.',
        ].join('\n'),
      );
      expect(put.pinOk).toBe(true);
      expect(put.status).toBe(409);
      expect(put.json.error).toContain('accepted only through the management API');
      expect(get.status).toBe(200);
      expect(pending).toEqual([]);
      expect(stored.version).toBe(v0 + 2);
    });
  } finally {
    // Yarıda kalırsa bu senaryonun açık bıraktığı istek (özellikle Config API
    // durdurma isteği) beklemede kalmasın: bob reddeder.
    for (const id of created) {
      try {
        const cr = (await hostApi.changeRequests('pending', keys.bob)).find((c) => c.id === id);
        if (cr) await hostApi.rejectChange(id, 'E2E temizliği: senaryo yarıda kaldı', keys.bob);
      } catch {
        /* sunucu kapalı olabilir; ortam aşağıda sıfırlanır */
      }
    }
    if (alice) await alice.context.close().catch(() => {});
    if (bob) await bob.context.close().catch(() => {});
    if (overridden) {
      await test.step('Sunucu: ortam .env değerlerine döner (onay kapalı); böylece test sonunda temel pin\'ler paylaşılan anahtarla geri yüklenebiliyor', async () => {
        await hostControl.resetEnv();
        const me = await hostApi.adminMe();
        const pending = await hostApi.changeRequests('pending');
        await attachText(
          testInfo,
          'env-override.sh reset → GET /api/v1/admin/me',
          [
            '$ ./scripts/env-override.sh reset',
            'Host hazır: http://localhost:6650 (reset)',
            '',
            JSON.stringify(me),
            `bekleyen değişiklik isteği: ${pending.length}`,
          ].join('\n'),
        );
        expect(me.approvalsRequired).toBe(1);
        expect(pending.filter((c) => created.includes(c.id))).toEqual([]);
      });
    }
  }
});
