// Kurulum yolculuğu K9: vault dosyası yükleme — metin ve diskteki dosya,
// politika × şifreleme seçenekleriyle; dosya listesi ve dosya detayı.
// Taze host örneği üzerinde (ana host'un vault dosyalarına dokunulmaz).
const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');

const API = 'default-tls';
// Politika × şifreleme örnekleri; hepsi metinle yüklenir.
const MATRIX = [
  { key: 'k05-public-plain', policy: 'public', encryption: 'plain' },
  { key: 'k05-token-atrest', policy: 'token', encryption: 'at_rest' },
  { key: 'k05-apikey-plain', policy: 'api_key', encryption: 'plain' },
  { key: 'k05-public-e2e', policy: 'public', encryption: 'end_to_end' },
];
const FILE_KEY = 'k05-dosyadan';

test('Kurulum: vault dosyaları metin ve dosya olarak, her politika ve şifrelemeyle yüklenir', async ({
  browser,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();

  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;
  const localFile = path.join(os.tmpdir(), 'k05-model.bin');

  try {
    await test.step('Web: metinden dosya yükleme — politika × şifreleme (K9)', async () => {
      const rows = [];
      for (const item of MATRIX) {
        const version = await dashboard.uploadVaultText(API, item.key, `{"deneme":"${item.key}"}`, item);
        const cells = await dashboard.vaultRowCells(item.key);
        rows.push(`${item.key.padEnd(20)} v${version}  politika=${cells.policy.padEnd(12)} şifreleme=${cells.encryption}`);
        expect(cells.policy.toLowerCase()).toContain(item.policy);
      }
      await attachText(testInfo, 'Yüklenen dosyalar (dashboard tablosundan okundu)', rows.join('\n'));
      await dashboard.snap('vault dosya listesi: politika ve şifreleme sütunları');
    });

    await test.step('Web: diskteki dosyayı yükleme (K9)', async () => {
      fs.writeFileSync(localFile, Buffer.from([0x50, 0x4b, 0x03, 0x04, ...Buffer.from('k05 ikili içerik')]));
      const version = await dashboard.uploadVaultFileFromDisk(API, FILE_KEY, localFile, {
        policy: 'public',
        encryption: 'at_rest',
      });
      const cells = await dashboard.vaultRowCells(FILE_KEY);
      await attachText(
        testInfo,
        'Dosyadan yükleme',
        [
          `yerel dosya : ${localFile} (${fs.statSync(localFile).size} bayt)`,
          `dashboard   : ${cells.key} v${version} · ${cells.size} · ${cells.policy} · ${cells.encryption}`,
        ].join('\n'),
      );
      await dashboard.snap('dosyadan yüklenen vault dosyası');
      expect(version).toBe(1);
    });

    await test.step('Web: dosya detayı (sürümler, cihazlar, token yönetimi) (K9)', async () => {
      await dashboard.openConfigApiTab(API, 'vault');
      await dashboard.vaultFileRow(MATRIX[1].key).click();
      await expect(page.locator('.section-title-main')).toContainText(MATRIX[1].key);
      await dashboard.snap(`vault dosya detayı: ${MATRIX[1].key}`);
    });

    await test.step('Sunucu: at_rest dosya diskte şifreli, plain dosya düz (K9)', async () => {
      // Sunucunun SQLite dosyası host'ta bind mount altında; ham baytlarda
      // aranır (container'da sqlite3 yok).
      const db = fs.readFileSync(path.join(fresh.DIR, 'data/db/pinvault.db'));
      const plainContent = `{"deneme":"${MATRIX[0].key}"}`;
      const atRestContent = `{"deneme":"${MATRIX[1].key}"}`;
      const has = (needle) => db.includes(Buffer.from(needle, 'utf8'));
      const lines = [
        `veritabanı      : data/db/pinvault.db (${db.length} bayt)`,
        `"VLT-ENC1" öneki: ${has('VLT-ENC1') ? 'VAR (at_rest blob\'u şifreli)' : 'YOK'}`,
        `plain içeriği   : ${has(plainContent) ? 'düz metin olarak bulundu' : 'bulunamadı'}  ← ${plainContent}`,
        `at_rest içeriği : ${has(atRestContent) ? 'düz metin olarak bulundu' : 'bulunamadı (şifreli)'}  ← ${atRestContent}`,
      ];
      await attachText(testInfo, 'Sunucu diskindeki vault blob\'ları', lines.join('\n'));
      expect(has('VLT-ENC1')).toBe(true);
      expect(has(plainContent)).toBe(true);
      expect(has(atRestContent)).toBe(false);
    });

    await test.step('Web: dosyalar silinir (K9)', async () => {
      for (const item of [...MATRIX, { key: FILE_KEY }]) {
        await dashboard.deleteVaultFile(API, item.key);
      }
      await dashboard.snap('vault dosyaları silindi');
      const files = await fresh.api(`/api/v1/config-apis/${API}/vault`);
      expect((files.json || []).map((f) => f.key)).not.toContain(FILE_KEY);
    });
  } finally {
    fs.rmSync(localFile, { force: true });
    for (const item of [...MATRIX, { key: FILE_KEY }]) {
      await fresh.api(`/api/v1/config-apis/${API}/vault/${item.key}`, { method: 'DELETE' }).catch(() => {});
    }
    await page.close();
  }
});
