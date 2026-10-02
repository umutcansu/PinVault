// Y01 — Kişisel yönetici anahtarları, denetim kaydı ve anında bildirim.
//
// Varsayılan kurulumda yönetim API'sinin tek bir paylaşılan anahtarı (API_KEY)
// var; denetim kaydı her yazımı "admin" adına tutar ve "bu pin'i kim
// değiştirdi?" sorusunun yanıtı olmaz. ADMIN_KEYS ile her yöneticinin kendi
// anahtarı olur — sunucunun ortamında yalnızca SHA-256'sı durur:
//
//   • dashboard anahtarın sahibini gösterir (kimlik rozeti),
//   • pin değişikliği denetim kaydına kişinin adıyla ve host bazlı farkla
//     (sürüm, eklenen / çıkan pin) düşer; kayıtlar, kayıtları birbirine
//     bağlayan bir hash zinciriyle tutulur,
//   • NOTIFY_WEBHOOK_URL ile olay anında dışarı gönderilir: gövde paylaşılan
//     gizli anahtarla imzalı (HMAC, X-PinVault-Signature) ve kaydın hash
//     zincirindeki değerini taşır, yani veritabanında sonradan yeniden yazılan
//     bir kayıt dışarıdaki kopyayla çelişir,
//   • yanlış anahtar denemesi "auth_failed" olarak (kim: unknown, kaynak IP)
//     kaydedilir. Kayıt dakikada bir toplanır: pencerenin İLK denemesi hemen
//     yazılır, aynı dakikadaki diğerleri pencere kapanınca tek bir özet
//     satırı olur (AuthFailureRecorder) — Config API portlarından günlüğü ya
//     da webhook'u doldurmak mümkün olmasın diye.
//
// Ana host üzerinde koşar; sonunda ortam .env değerlerine döner (fixture temel
// pin'leri ondan sonra geri yükler).
const crypto = require('crypto');
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const { Dashboard } = require('../lib/dashboard');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const webhookSink = require('../lib/webhookSink');
const { keys, adminKeysEnv } = require('../lib/admins');

const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
/** Anahtarın kendisi asla kanıta girmez; yalnızca sunucunun da bildiği SHA-256'sının öneki. */
const keyLabel = (name) => `<${name}'in kişisel anahtarı; sha256 ${sha256Hex(keys[name]).slice(0, 12)}…>`;
const adminKeysDisplay = () =>
  adminKeysEnv()
    .split(',')
    .map((pair) => `${pair.split(':')[0]}:${pair.split(':')[1].slice(0, 12)}…`)
    .join(',');

test('Web+Mobil+Terminal: kişisel yönetici anahtarları — kimlik rozeti, değişiklik denetim kaydında kişinin adıyla, webhook paylaşılan gizli anahtarla imzalı (HMAC) ve kaydın hash\'ini taşıyor, yanlış anahtar auth_failed', async ({
  app,
  browser,
  run,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  const secret = crypto.randomBytes(24).toString('hex');
  const backupPin = hostApi.randomPin();
  const sink = await webhookSink.start({ secret });
  let overridden = false;
  let alice;
  let v0;
  let pinEntry;
  let authEntries = [];

  try {
    await test.step('Sunucu: ADMIN_KEYS (alice, bob) ve NOTIFY_WEBHOOK_URL/SECRET açılır; Web: dashboard alice\'in anahtarıyla açılır, kimlik rozetinde "alice" yazıyor', async () => {
      await hostControl.setEnv({ ADMIN_KEYS: adminKeysEnv(), NOTIFY_WEBHOOK_URL: sink.url, NOTIFY_WEBHOOK_SECRET: secret });
      overridden = true;
      const me = await hostApi.adminMe(keys.alice);
      const shared = await hostApi.adminMe();
      alice = await Dashboard.openAs(browser, testInfo, keys.alice);
      const name = await alice.adminName();
      await alice.snap('dashboard alice\'in kişisel anahtarıyla: kenar çubuğunda kimlik rozeti "alice"');
      await attachText(
        testInfo,
        'env-override.sh + GET /api/v1/admin/me',
        [
          `$ ./scripts/env-override.sh set ADMIN_KEYS=${adminKeysDisplay()} \\`,
          `      NOTIFY_WEBHOOK_URL=${sink.url} NOTIFY_WEBHOOK_SECRET=<rastgele, gizli>`,
          'Host hazır: http://localhost:6650 (set)',
          '',
          'ADMIN_KEYS yalnızca ad:SHA-256(anahtar) taşır (scripts/add-admin.sh biçimi); anahtarların',
          'kendisi test düzeneğinde .local/admins.json (0600) içinde durur; sunucuya ve bu sayfaya girmez.',
          '',
          `GET /api/v1/admin/me   X-API-Key: ${keyLabel('alice')}`,
          JSON.stringify(me, null, 2),
          '',
          `GET /api/v1/admin/me   X-API-Key: <paylaşılan API_KEY>  →  name: "${shared.name}"`,
          '',
          `dashboard kimlik rozeti: ${name}`,
        ].join('\n'),
      );
      expect(name).toBe('alice');
      expect(me.name).toBe('alice');
      expect(me.admins).toEqual(['admin', 'alice', 'bob']);
      expect(me.notificationsConfigured).toBe(true);
      expect(shared.name).toBe('admin');
    });

    await test.step('Web: alice hedef host\'a yedek pin ekler (yayın); Mobil: config yenile → yeni sürüm uygulandı', async () => {
      await alice.openHost(TARGET_HOST);
      v0 = await alice.version();
      await alice.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
      await expect.poll(() => alice.version(), { timeout: 20_000 }).toBe(v0 + 1);
      await alice.snapHostSummary(`alice yayımladı: ${TARGET_HOST} v${v0 + 1} (yedek pin eklendi)`);
      const status = await app.refreshConfig();
      await app.snap(`alice'in yayını telefonda: ${TARGET_HOST} v${v0 + 1}`);
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(v0 + 1);
    });

    await test.step('Web: "Denetim Kaydı" — pins_changed, kim: alice; ayrıntıda host bazlı fark (sürüm ve eklenen yedek pin)', async () => {
      const log = await hostApi.auditLog({ action: 'pins_changed', limit: 10, key: keys.alice });
      pinEntry = log.entries.find((e) => e.actor === 'alice' && e.target.split(',').includes(TARGET_HOST));
      expect(pinEntry, 'alice adına pins_changed kaydı').toBeTruthy();
      await alice.openAudit();
      const cells = await alice.auditRowCells(pinEntry.id);
      const detailText = await alice.expandAuditEntry(pinEntry.id);
      await alice.snapAudit(`Denetim Kaydı: #${pinEntry.id} pins_changed — kim: alice, ayrıntı açık`, { ids: [pinEntry.id] });
      const diff = JSON.parse(pinEntry.detail);
      const changed = diff.changed.find((c) => c.hostname === TARGET_HOST);
      await attachText(
        testInfo,
        `GET /api/v1/audit-log?action=pins_changed → #${pinEntry.id}`,
        [
          `#${pinEntry.id}  ${pinEntry.at}`,
          `kim     : ${pinEntry.actor}          (dashboard satırı: "${cells.actor}")`,
          `işlem   : ${pinEntry.action}`,
          `kapsam  : ${pinEntry.configApiId}`,
          `hedef   : ${pinEntry.target}`,
          `özet    : ${pinEntry.summary}`,
          `kaynak  : ${pinEntry.sourceIp}`,
          '',
          `fark (${TARGET_HOST}):`,
          `  önce  v${changed.from.version}: ${changed.from.sha256.map((p) => `${p.slice(0, 12)}…`).join(', ')}`,
          `  sonra v${changed.to.version}: ${changed.to.sha256.map((p) => `${p.slice(0, 12)}…`).join(', ')}`,
          `  eklenen: ${backupPin.slice(0, 12)}… (yedek pin)`,
          '',
          `hash zinciri: prevHash ${pinEntry.prevHash.slice(0, 16)}…  hash ${pinEntry.hash.slice(0, 16)}…`,
        ].join('\n'),
      );
      expect(cells.actor).toBe('alice');
      expect(cells.action).toBe('pins_changed');
      expect(pinEntry.summary).toContain(`${TARGET_HOST}: pins v${v0}→v${v0 + 1}`);
      expect(changed.from.version).toBe(v0);
      expect(changed.to.version).toBe(v0 + 1);
      expect(changed.from.sha256).not.toContain(backupPin);
      expect(changed.to.sha256).toContain(backupPin);
      expect(detailText).toContain(backupPin);
    });

    await test.step('Terminal: webhook pins_changed bildirimini aldı — X-PinVault-Signature (HMAC) imzası doğru; gövdedeki auditId/auditHash denetim kaydıyla aynı', async () => {
      const hit = await sink.waitFor((r) => r.json && r.json.event === 'pins_changed' && r.json.auditId === pinEntry.id);
      const recomputed = `sha256=${crypto.createHmac('sha256', secret).update(hit.body).digest('hex')}`;
      await expect
        .poll(async () => ((await hostApi.notifications(keys.alice)).recent || []).some((d) => d.auditId === pinEntry.id && d.status === 204), {
          timeout: 20_000,
        })
        .toBe(true);
      await alice.refreshAudit();
      await alice.snapCard('#notif-card', 'Webhook Bildirimleri kartı: yapılandırılmış, HMAC imzası var; son teslimat HTTP 204');
      const body = { ...hit.json, detail: hit.json.detail ? '(pin farkı — denetim kaydının detail alanıyla aynı)' : undefined };
      await attachText(
        testInfo,
        `Webhook alıcısı (${sink.url}) — gelen istek`,
        [
          `POST ${hit.path}   (${hit.at})`,
          `X-PinVault-Event    : ${hit.event}`,
          `X-PinVault-Signature: ${hit.signature.slice(0, 23)}…`,
          `HMAC-SHA256(NOTIFY_WEBHOOK_SECRET, gövde) yeniden hesaplandı: ${recomputed.slice(0, 23)}… → ${hit.signatureValid ? 'EŞİT ✓' : 'FARKLI ✗'}`,
          '',
          JSON.stringify(body, null, 2),
          '',
          `denetim kaydı #${pinEntry.id}.hash = ${pinEntry.hash}`,
          `webhook auditHash      = ${hit.json.auditHash}`,
          `→ ${hit.json.auditHash === pinEntry.hash ? 'aynı ✓' : 'FARKLI ✗'}: dışarıya giden kopya, hash zincirinin o anki son değerini taşıyor;`,
          '  veritabanında sonradan yeniden yazılan bir kayıt bu kopyayla çelişir.',
        ].join('\n'),
      );
      expect(hit.signatureValid).toBe(true);
      expect(hit.signature).toBe(recomputed);
      expect(hit.event).toBe('pins_changed');
      expect(hit.json.actor).toBe('alice');
      expect(hit.json.auditHash).toBe(pinEntry.hash);
      expect(hit.json.summary).toBe(pinEntry.summary);
    });

    await test.step('Terminal+Web: yanlış anahtarla üç istek → 403; denetim kaydında auth_failed (kim: unknown, kaynak IP) — dakikanın ilk denemesi hemen yazılıyor, aynı dakikadaki diğerleri tek özet satırında', async () => {
      const lastId = (await hostApi.auditLog({ limit: 1, key: keys.alice })).entries[0].id;
      const wrongKey = `yanlis-anahtar-${crypto.randomBytes(4).toString('hex')}`;
      const ATTEMPTS = 3;
      const sentAt = new Date().toISOString();
      const statuses = [];
      for (let i = 0; i < ATTEMPTS; i++) {
        statuses.push((await hostApi.api('/api/v1/audit-log?limit=1', { key: wrongKey })).status);
      }
      expect(statuses).toEqual(Array(ATTEMPTS).fill(403));
      // Pencerenin ilk denemesi hemen yazılır; aynı dakikadaki diğerleri pencere
      // kapanınca (≤ 60 sn) tek bir özet satırı olur. Denemelerin hepsi
      // kayda geçene kadar beklenir: satır sayısı deneme sayısından az olmalı.
      const counted = (e) => {
        const m = /^(\d+) more invalid X-API-Key attempt\(s\) in the same minute/.exec(e.summary);
        return m ? Number(m[1]) : 1;
      };
      const started = Date.now();
      await expect
        .poll(
          async () => {
            const log = await hostApi.auditLog({ action: 'auth_failed', limit: 10, key: keys.alice });
            authEntries = log.entries.filter((e) => e.id > lastId).sort((a, b) => a.id - b.id);
            return authEntries.reduce((n, e) => n + counted(e), 0);
          },
          { timeout: 80_000, intervals: [1000, 2000, 5000] },
        )
        .toBe(ATTEMPTS);
      const waitedS = Math.round((Date.now() - started) / 1000);
      const immediate = authEntries.filter((e) => e.summary.startsWith('Invalid X-API-Key from'));
      const summaries = authEntries.filter((e) => !e.summary.startsWith('Invalid X-API-Key from'));
      const hooks = [];
      for (const e of authEntries) hooks.push(await sink.waitFor((r) => r.json && r.json.event === 'auth_failed' && r.json.auditId === e.id));
      await alice.openAudit();
      await alice.setAuditFilter('auth_failed');
      for (const e of authEntries) await alice.expandAuditEntry(e.id);
      await alice.snapAudit(
        `Denetim Kaydı (süzgeç: auth_failed): ${ATTEMPTS} deneme → ${authEntries.length} satır — kim: unknown, kaynak IP`,
        { ids: authEntries.map((e) => e.id) },
      );
      await attachText(
        testInfo,
        'Yanlış anahtar denemeleri ve denetim kaydı',
        [
          `$ for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\\n' -H 'X-API-Key: ${wrongKey}' http://localhost:6650/api/v1/audit-log?limit=1; done   (${sentAt})`,
          ...statuses.map(String),
          '',
          `auth_failed kayıtları (${waitedS} sn içinde; ${ATTEMPTS} deneme → ${authEntries.length} satır):`,
          ...authEntries.map((e) => `  #${e.id}  kim: ${e.actor}  kaynak: ${e.sourceIp || '(özette)'}  hedef: ${e.target || '—'}\n         ${e.summary}`),
          '',
          ...hooks.map((h) => `webhook: event=${h.event}, auditId=${h.json.auditId}, HMAC ${h.signatureValid ? 'doğru ✓' : 'YANLIŞ'}`),
          '',
          'Kayıtlar dakika dakika gruplanır (AuthFailureRecorder): dakikanın ilk denemesi hemen yazılır, aynı',
          'dakikadaki sonrakiler dakika dolunca tek özet satırı olur. Böylece cihazların bağlandığı portlardan',
          'denetim kaydı ve webhook doldurulamaz.',
          `alice'in kendi isteklerinin kaynak adresi (pins_changed #${pinEntry.id}): ${pinEntry.sourceIp}`,
        ].join('\n'),
      );
      expect(authEntries.every((e) => e.actor === 'unknown' && e.action === 'auth_failed')).toBe(true);
      expect(authEntries.length).toBeLessThan(ATTEMPTS);
      expect(summaries.length).toBeGreaterThanOrEqual(1);
      for (const e of immediate) {
        expect(e.sourceIp).toBe(pinEntry.sourceIp);
        expect(e.summary).toBe(`Invalid X-API-Key from ${pinEntry.sourceIp}`);
        expect(e.target).toBe('GET /api/v1/audit-log');
      }
      for (const e of summaries) expect(e.summary).toContain(`address(es): ${pinEntry.sourceIp}`);
      expect(hooks.every((h) => h.signatureValid)).toBe(true);
    });

    await test.step('Web: "Zinciri Doğrula" → hash zinciri sağlam; doğrulanan kayıt sayısı yazıyor', async () => {
      await alice.setAuditFilter('');
      const result = await alice.verifyAuditChain();
      const total = (await hostApi.auditLog({ limit: 1, key: keys.alice })).total;
      await alice.snapAudit(`"Zinciri Doğrula": ${result.text}`, { ids: [pinEntry.id, ...authEntries.map((e) => e.id)] });
      await attachText(
        testInfo,
        'GET /api/v1/audit-log/verify (dashboard düğmesinin çağırdığı uç)',
        [
          `HTTP ${result.status} ${JSON.stringify(result.json)}`,
          `dashboard: ${result.text}`,
          `GET /api/v1/audit-log → total ${total}`,
          '',
          'Doğrulama bütün zinciri baştan yeniden hesaplar: her satırın hash\'i = SHA-256(önceki hash +',
          'alanlar). Tek bir satırın değişmesi o satırdan itibaren zinciri bozar (Y02).',
        ].join('\n'),
      );
      expect(result.status).toBe(200);
      expect(result.json.ok).toBe(true);
      expect(result.text).toContain(`Zincir sağlam — ${result.json.entries} kayıt`);
      expect(result.json.entries).toBeGreaterThanOrEqual(authEntries[authEntries.length - 1].id);
      expect(total).toBeGreaterThanOrEqual(result.json.entries);
    });
  } finally {
    if (alice) await alice.context.close().catch(() => {});
    // Fixture'ın temizliği (temel pin'ler, paylaşılan API_KEY ile) ortam
    // sıfırlandıktan sonra çalışır.
    if (overridden) {
      await test.step('Sunucu: ortam .env değerlerine döner (yalnızca paylaşılan API_KEY, webhook kapalı)', async () => {
        await hostControl.resetEnv();
        const me = await hostApi.adminMe();
        await attachText(
          testInfo,
          'env-override.sh reset → GET /api/v1/admin/me',
          [
            '$ ./scripts/env-override.sh reset',
            'Host hazır: http://localhost:6650 (reset)',
            '',
            JSON.stringify(me, null, 2),
            '',
            `webhook alıcısı durduruluyor: ${sink.received.length} bildirim alındı (${[...new Set(sink.received.map((r) => r.event))].join(', ')})`,
          ].join('\n'),
        );
        expect(me.admins).toEqual(['admin']);
        expect(me.notificationsConfigured).toBe(false);
      });
    }
    await sink.stop();
  }
});
