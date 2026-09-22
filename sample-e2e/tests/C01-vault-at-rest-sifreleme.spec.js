// C01 — Vault at_rest şifrelemesi.
//
// `encryption=at_rest` dosyayı YALNIZCA sunucunun diskinde şifreler: SQLite'taki
// blob AES-256-GCM sarmalı ("VLT-ENC1" + salt + IV), kablodaki gövde ise düz
// metin. Cihaz bu katmanı hiç görmez — kütüphane için plain ile aynıdır.
//
// Kanıt zinciri: dashboard yüklemesi → veritabanı dosyasında düz metnin hiç
// geçmemesi → kablodaki ham bayt → telefondaki içerik.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, hexdump, describeResponse } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.atrest;

test('Vault at_rest: sunucu diskinde şifreli, kabloda düz, telefonda doğru', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  const secret = `at-rest-gizli-${Date.now()}-KANIT`;
  let version;
  let deviceId;

  try {
    await test.step('Web: dosya at_rest şifrelemeyle yüklenir', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, {
        policy: 'public',
        encryption: 'at_rest',
      });
      const cells = await dashboard.vaultRowCells(KEY);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları — at_rest');
      expect(cells.encryption).toContain('at_rest');
      expect(cells.policy).toContain('public');
    });

    await test.step('Sunucu: veritabanındaki blob şifreli, düz metin DB dosyasında hiç geçmiyor', async () => {
      const blob = hostApi.vaultBlobFromDb(env.VAULT_API, KEY);
      const marker = blob.subarray(0, 8).toString('latin1');
      await attachCommand(
        testInfo,
        'sqlite3 — vault_files satırı (content HAM blob)',
        'sqlite3',
        ['-readonly', '-line', env.DB_FILE,
          `SELECT config_api_id, key, version, access_policy, encryption, length(content) AS blob_bytes, substr(hex(content),1,64) AS blob_ilk_32_bayt FROM vault_files WHERE key='${KEY}';`],
      );
      await attachText(
        testInfo,
        'Veritabanındaki blob (hex dökümü)',
        [
          `düz metin: ${secret} (${Buffer.byteLength(secret)} bayt)`,
          `blob: ${blob.length} bayt, başlangıç işareti: "${marker}"`,
          '',
          hexdump(blob, 96),
          '',
          'Düzen: [MAGIC "VLT-ENC1" 8B][salt 16B][IV 12B][AES-256-GCM şifreli metin + etiket]',
          'Anahtar VAULT_AT_REST_PASSWORD\'dan PBKDF2-SHA256 (200.000 tur) ile türetiliyor.',
        ].join('\n'),
      );
      expect(marker).toBe('VLT-ENC1');
      expect(blob.includes(Buffer.from(secret, 'utf8'))).toBe(false);

      // Blob satırı şifreli olsa da düz metin veritabanının başka bir yerinde
      // (WAL, serbest sayfa, eski sürüm) durabilir: bütün dosya taranıyor.
      const fs = require('fs');
      const dbBytes = fs.readFileSync(env.DB_FILE);
      const found = dbBytes.includes(Buffer.from(secret, 'utf8'));
      await attachText(
        testInfo,
        'Bütün veritabanı dosyası taraması',
        [
          `$ (dosya) ${env.DB_FILE} — ${dbBytes.length} bayt`,
          `"${secret}" dizisi dosyanın herhangi bir yerinde geçiyor mu: ${found ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Yalnızca vault_files satırı değil, bütün veritabanı dosyası (serbest',
          'sayfalar ve eski kayıtlar dahil) tarandı.',
        ].join('\n'),
      );
      expect(found).toBe(false);
    });

    await test.step('Kablo: gövde DÜZ gidiyor, başlık X-Vault-Encryption: at_rest', async () => {
      const res = await hostApi.rawVaultDownload(KEY, 'c01-kablo-gozlemcisi');
      await attachText(
        testInfo,
        `GET https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/vault/${KEY} — ham yanıt`,
        [
          describeResponse(res, { maxBody: 256 }),
          '',
          'Gövdenin hex dökümü:',
          hexdump(res.body, 96),
          '',
          'at_rest katmanı sunucuda çözülüp gönderiliyor: kabloda plain ile aynı.',
          'Gizliliği sağlayan tek şey TLS + pinleme; disk hırsızlığına karşı koruma',
          'veritabanı tarafında.',
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(res.headers['x-vault-encryption']).toBe('at_rest');
      expect(res.headers['x-vault-version']).toBe(String(version));
      expect(res.body.toString('utf8')).toBe(secret);
      expect(res.headers['x-vault-signature']).toBeTruthy();
    });

    await test.step('Mobil: dosya iner ve içerik doğru', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      await app.snap(`at_rest dosyası v${version} indirildi`);
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain('imza doğrulandı');
      expect(status).toContain('sunucuda şifreli saklanır, kabloda düz');
      expect(status).toContain(secret);
    });

    await test.step('Sunucu: VAULT_AT_REST_PASSWORD ayarı ve demo anahtar uyarısı', async () => {
      const envDump = await attachCommand(
        testInfo,
        'docker exec pinvault-host env (VAULT_*)',
        'docker',
        ['exec', env.CONTAINER, 'sh', '-c', 'env | grep -i vault || echo "(VAULT_* yok)"'],
      );
      const warn = hostControl
        .logs(2000)
        .split('\n')
        .filter((l) => /VaultAtRestCipher|at-rest/i.test(l))
        .join('\n');
      await attachText(
        testInfo,
        'At-rest anahtarının kaynağı — bulgu',
        [
          envDump.trim(),
          '',
          'Sunucu logu:',
          warn || '(ilgili satır yok)',
          '',
          'Bu kurulumda VAULT_AT_REST_PASSWORD BOŞ. VaultAtRestCipher boş değeri',
          '"ayarlanmamış" sayıp sabit demo parolasına düşüyor ve uyarı basıyor;',
          'şifreleme biçimsel kalıyor (anahtar kaynak kodda). Yukarıdaki blob yine',
          'de gerçekten AES-256-GCM: biçim ve akış doğru, eksik olan anahtar yönetimi.',
          'Üretimde VAULT_AT_REST_PASSWORD (ya da KMS) zorunlu.',
        ].join('\n'),
      );
      expect(envDump).toContain('VAULT_AT_REST_PASSWORD');
    });

    await test.step('Web: dağıtım geçmişinde indirme görünüyor', async () => {
      await dashboard.expectDistribution(env.VAULT_API, {
        key: KEY,
        deviceModel: run.model,
        status: 'downloaded',
        version,
      });
      await dashboard.snap('dağıtım geçmişi — at_rest dosyası');
      const dists = await hostApi.vaultDistributions(env.VAULT_API, KEY);
      const mine = dists.find((d) => d.deviceId === deviceId);
      await attachText(
        testInfo,
        'Sunucudaki dağıtım kaydı',
        [
          `key=${mine.vaultKey} v${mine.version} status=${mine.status} authMethod=${mine.authMethod}`,
          `cihaz: ${mine.deviceManufacturer} ${mine.deviceModel} (${mine.deviceId})`,
        ].join('\n'),
      );
      expect(mine.status).toBe('downloaded');
      expect(mine.authMethod).toBe('public');
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY);
  }
});
