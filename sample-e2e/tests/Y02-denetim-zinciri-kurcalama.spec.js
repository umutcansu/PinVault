// Y02 — Denetim kaydı sonradan değiştirilirse fark ediliyor: kayıtları
// birbirine bağlayan hash zinciri + veritabanı kuralları (trigger).
//
// Denetim kaydı yalnızca eklenir. Her satırın hash'i = SHA-256(önceki satırın
// hash'i + satırın alanları, aralarında 0x1F); veritabanındaki iki kural
// (trigger: audit_log_no_update / audit_log_no_delete) UPDATE ve DELETE'i
// "audit_log is append-only" diye reddeder. Kuralı silecek kadar veritabanı
// erişimi olan biri bir satırı yeniden yazabilir — ama o satırın saklı hash'i
// artık alanlarını tutmaz ve "Zinciri Doğrula" bozulan ilk satırı gösterir.
// (Bütün zinciri baştan hesaplayıp yazmak da mümkündür; bu yüzden olaylar
// anında webhook'a da gönderilir ve dışarıdaki kopya kaydın hash'ini taşır —
// bkz. Y01.)
//
// Geçici test sunucusunda çalışır: veritabanı kullan-at (koşu sonunda silinir),
// ana host'un kaydına dokunulmaz. Telefon kullanılmaz. Veritabanı dosyası
// container'a bind-mount edildiği için Mac'teki sqlite3 doğrudan açar
// (container'da sqlite3 yok); sunucu her istekte yeni bağlantı açtığı için
// araya giren yazımı bir sonraki istekte görür.
const crypto = require('crypto');
const path = require('path');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachFailingCommand } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

const DB = () => path.join(fresh.DIR, 'data/db/pinvault.db');
const REL_DB = () => path.relative(env.ROOT, DB());
/**
 * Host adı: yalnızca bu senaryonun denetim kayıtları için, taze host'ta. Koşuya
 * özgü: aynı ad daha önce kullanıldıysa sürüm dizisi kaldığı yerden devam eder.
 */
const LAB_HOST = `denetim-lab-${Date.now().toString(36)}.example`;
const GENESIS = '0'.repeat(64);

function randomPin() {
  return crypto.randomBytes(32).toString('base64');
}

/** Sunucunun zincir hash'i (AuditLogStore.chainHash): SHA-256(prev, 0x1F, alan, 0x1F, alan, …). */
function chainHash(prev, fields) {
  const h = crypto.createHash('sha256');
  h.update(prev, 'utf8');
  for (const f of fields) {
    h.update(Buffer.from([0x1f]));
    h.update(String(f), 'utf8');
  }
  return h.digest('hex');
}

function sqlite(args) {
  return execFileSync('sqlite3', args, { encoding: 'utf8', timeout: 30_000 }).trim();
}

/** Satırı olduğu gibi okur (salt okunur). */
function readRow(id) {
  const out = sqlite(['-readonly', '-json', DB(), `SELECT * FROM audit_log WHERE id=${Number(id)};`]);
  return JSON.parse(out || '[]')[0];
}

function triggers() {
  return sqlite(['-readonly', DB(), "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log' ORDER BY name;"]);
}

const RECREATE_TRIGGER =
  "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;";

test('Web+Terminal: denetim kaydı sonradan değiştirilirse fark ediliyor — doğrudan UPDATE/DELETE veritabanı kuralıyla (trigger) reddediliyor; kural silinip satır değiştirilince "Zinciri Doğrula" bozuk satırı gösteriyor', async ({
  browser,
}, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  const pins = [randomPin(), randomPin(), randomPin()];
  let dashboard;
  let entries = [];
  let target;
  let tampered = false;

  try {
    await test.step('Web: geçici test sunucusunda iki yönetici değişikliği (host ekleme, pin düzenleme) Denetim Kaydı\'nda görünüyor; "Zinciri Doğrula" sağlam diyor', async () => {
      await fresh.ensure();
      dashboard = await fresh.openDashboard(browser, testInfo);
      const before = (await fresh.api('/api/v1/audit-log?limit=1')).json;
      await dashboard.addHostManual('default-tls', LAB_HOST, pins.slice(0, 2));
      await dashboard.openHost(LAB_HOST);
      await dashboard.setPins(LAB_HOST, pins);
      await expect.poll(() => dashboard.version(), { timeout: 20_000 }).toBe(2);
      const log = (await fresh.api('/api/v1/audit-log?action=pins_changed&limit=10')).json;
      entries = log.entries.filter((e) => e.target.split(',').includes(LAB_HOST)).sort((a, b) => a.id - b.id);
      expect(entries.length).toBe(2);
      target = entries[0];
      await dashboard.openAudit();
      const result = await dashboard.verifyAuditChain();
      await dashboard.snapAudit(`geçici test sunucusunun Denetim Kaydı: #${entries[0].id} ve #${entries[1].id} (${LAB_HOST}); ${result.text}`, {
        ids: entries.map((e) => e.id),
      });
      await attachText(
        testInfo,
        `Geçici test sunucusu (${fresh.WEB_URL}) — denetim kaydı`,
        [
          `önceki son kayıt: #${before.entries[0] ? before.entries[0].id : 0} (toplam ${before.total})`,
          ...entries.map((e) => `#${e.id}  ${e.actor.padEnd(6)} ${e.action}  ${e.summary}\n      prevHash ${e.prevHash.slice(0, 16)}…  hash ${e.hash.slice(0, 16)}…`),
          '',
          `GET /api/v1/audit-log/verify → ${JSON.stringify(result.json)}`,
          `dashboard: ${result.text}`,
        ].join('\n'),
      );
      expect(entries[0].summary).toBe(`${LAB_HOST} added (2 pins)`);
      expect(entries[1].summary).toBe(`${LAB_HOST}: pins v1→v2`);
      expect(entries[1].prevHash).not.toBe(GENESIS);
      expect(result.json.ok).toBe(true);
      expect(result.text).toContain(`Zincir sağlam — ${result.json.entries} kayıt`);
    });

    await test.step('Terminal: sqlite3 ile doğrudan UPDATE ve DELETE → veritabanı kuralı (trigger) reddediyor ("audit_log is append-only"); satır değişmedi', async () => {
      const row0 = readRow(target.id);
      const upd = await attachFailingCommand(testInfo, `UPDATE audit_log … WHERE id=${target.id} (veritabanı kuralı yerinde)`, 'sqlite3', [
        REL_DB(),
        `UPDATE audit_log SET summary='x' WHERE id=${target.id};`,
      ], { cwd: env.ROOT });
      const del = await attachFailingCommand(testInfo, `DELETE FROM audit_log WHERE id=${target.id} (veritabanı kuralı yerinde)`, 'sqlite3', [
        REL_DB(),
        `DELETE FROM audit_log WHERE id=${target.id};`,
      ], { cwd: env.ROOT });
      const row1 = readRow(target.id);
      const trig = triggers();
      await attachText(
        testInfo,
        `Satır #${target.id} denemelerden sonra (sqlite3 -readonly)`,
        [
          `$ sqlite3 -readonly ${REL_DB()} "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'"`,
          trig,
          '',
          `$ sqlite3 -readonly ${REL_DB()} "SELECT summary, hash FROM audit_log WHERE id=${target.id}"`,
          `${row1.summary}|${row1.hash}`,
          '',
          `özet ve hash değişmedi: ${row1.summary === row0.summary && row1.hash === row0.hash ? 'evet ✓' : 'HAYIR'}`,
        ].join('\n'),
      );
      expect(upd).toContain('audit_log is append-only');
      expect(del).toContain('audit_log is append-only');
      expect(trig.split('\n')).toEqual(['audit_log_no_delete', 'audit_log_no_update']);
      expect(row1.summary).toBe(row0.summary);
      expect(row1.hash).toBe(row0.hash);
    });

    await test.step('Terminal: veritabanı erişimi olan saldırgan veritabanı kuralını (trigger) siler ve satırın özetini yeniden yazar', async () => {
      const forged = `${LAB_HOST}: no pin change`;
      const out = execFileSync(
        'sqlite3',
        [REL_DB(), `DROP TRIGGER audit_log_no_update; UPDATE audit_log SET summary='${forged}' WHERE id=${target.id}; SELECT changes();`],
        { cwd: env.ROOT, encoding: 'utf8', timeout: 30_000 },
      ).trim();
      tampered = true;
      // Sunucu her istekte veritabanını yeniden açar: Mac'teki yazım bind mount
      // üzerinden container'daki sunucuya yansır. Web doğrulamasından önce API'nin
      // yeniden yazılmış satırı döndürdüğü görülür (kısa bir bekleme payıyla).
      const waitStart = Date.now();
      await expect
        .poll(
          async () => {
            const log = (await fresh.api('/api/v1/audit-log?action=pins_changed&limit=10')).json;
            const entry = (log.entries || []).find((e) => e.id === target.id);
            return entry ? entry.summary : null;
          },
          { timeout: 30_000, intervals: [250, 500, 1000] },
        )
        .toBe(forged);
      const visibleAfterMs = Date.now() - waitStart;
      const row = readRow(target.id);
      const stored = row.hash;
      const fields = (summary) => [row.at, row.actor, row.action, row.config_api_id, row.target, summary, row.detail, row.source_ip];
      // Aynı hesap özgün özetle saklı hash'i vermeli (hesabın sunucununkiyle aynı olduğunun kanıtı).
      const original = chainHash(row.prev_hash, fields(target.summary));
      const recomputed = chainHash(row.prev_hash, fields(row.summary));
      await attachText(
        testInfo,
        `DROP TRIGGER + UPDATE #${target.id}`,
        [
          `$ sqlite3 ${REL_DB()} "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET summary='${forged}' WHERE id=${target.id}; SELECT changes();"`,
          out,
          '[exit 0]',
          '',
          `#${target.id} önce : ${target.summary}`,
          `#${target.id} sonra: ${row.summary}`,
          `sunucu (GET /api/v1/audit-log) yeni özeti ${visibleAfterMs} ms içinde görüyor`,
          '',
          `saklı hash                                : ${stored}`,
          `SHA-256(prev_hash, alanlar) — özgün özetle : ${original}  ${original === stored ? '= saklı ✓' : '≠ saklı'}`,
          `SHA-256(prev_hash, alanlar) — yeni özetle  : ${recomputed}  ${recomputed === stored ? '= saklı (?!)' : '≠ saklı'}`,
          '→ saklı hash eski alanlara ait; satır sessizce değiştirilemiyor.',
          '',
          'Saldırgan hash\'i de yeniden hesaplayıp yazsa bu kez bir sonraki satırın prevHash\'i tutmaz;',
          'tutarlı bir zincir için sonraki bütün satırları yeniden yazmak gerekir — dışarıya gönderilmiş',
          'webhook kopyaları (auditHash) o zaman çelişir.',
        ].join('\n'),
      );
      expect(out).toBe('1');
      expect(row.summary).toBe(forged);
      expect(original).toBe(stored);
      expect(recomputed).not.toBe(stored);
    });

    await test.step('Web: "Zinciri Doğrula" → "Zincir #id kaydında bozuk"; değiştirilen satırı gösteriyor', async () => {
      await dashboard.refreshAudit();
      const cells = await dashboard.auditRowCells(target.id);
      const result = await dashboard.verifyAuditChain();
      await dashboard.snapAudit(`"Zinciri Doğrula": ${result.text} (#${target.id} özeti yeniden yazıldı)`, { ids: entries.map((e) => e.id) });
      await attachText(
        testInfo,
        'GET /api/v1/audit-log/verify (dashboard düğmesinin çağırdığı uç)',
        [
          `HTTP ${result.status} ${JSON.stringify(result.json)}`,
          `dashboard: ${result.text}`,
          `dashboard'daki #${target.id} özeti: "${cells.summary}"`,
          '',
          `Doğrulama zinciri baştan hesaplar; ilk tutmayan satır #${result.json.firstBrokenId}: tam olarak yeniden`,
          'yazılan satır. Satırın kendisi ekranda "masum" görünse de zincir değişikliği ele veriyor.',
        ].join('\n'),
      );
      expect(result.json.ok).toBe(false);
      expect(result.json.firstBrokenId).toBe(target.id);
      expect(result.text).toContain(`Zincir #${target.id} kaydında bozuk`);
      expect(cells.summary).toBe(`${LAB_HOST}: no pin change`);
    });
  } finally {
    if (tampered) {
      // Kullan-at veritabanı; yine de koşunun geri kalanında kayıt yalnızca
      // eklenebilir kalsın. Zincir bozuk kalır (geri almak sonraki bütün
      // hash'leri yeniden yazmak demek).
      try {
        execFileSync('sqlite3', [DB(), RECREATE_TRIGGER], { encoding: 'utf8', timeout: 30_000 });
      } catch (e) {
        console.warn(`[Y02] veritabanı kuralı (trigger) geri kurulamadı: ${e.message}`);
      }
    }
    if (dashboard) await dashboard.page.close().catch(() => {});
  }
});
