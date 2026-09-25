// S03 — Çoklu imza (en az 2 imza şartı): config (ve vault dosyası) iki AYRI
// anahtarla imzalanmadıkça kabul edilmiyor.
//
// Uygulama requiredSignatures(2) ile kurulunca tek bir anahtar — sunucunun
// kendi anahtarı bile — tek başına pin yayımlayamaz: anahtarlar farklı kişi ya
// da sistemlerde tutulursa ikisinin de onayı gerekir. Sunucu birden çok
// imzalayıcıyla (CONFIG_SIGNERS=local,local:second) her config'i her
// anahtarla ayrıca imzalar: imzalı yanıtta `signatures: [{keyId, signature}, …]`,
// vault yanıtında `X-Vault-Signatures: keyId:imza,…`.
//
//   1. sunucu tek anahtarla imzalarken "İki imza iste" → init
//      "1 of 2 required signatures valid" ile başlatılamıyor,
//   2. ikinci imzalayıcı açılınca "Tekrar dene" → Hazır, iki imzalayan,
//   3. vault dosyası da iki imzayla doğrulanıp iniyor.
//
// Geçici test sunucusunda çalışır; sonunda ortam sıfırlanır ve ana APK geri kurulur.
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');
const hostApi = require('../lib/hostApi');
const lab = require('../lib/signingLab');

const VAULT_KEY = env.VAULT_KEYS.flags;
const CONTENT = JSON.stringify({ senaryo: 'S03', imza: '2-of-n', zaman: new Date().toISOString() });

/** Taze host'un Config API'sinden ham vault indirmesi; sunucu sertifikası taze host'un pin'iyle doğrulanır. */
function rawVault(key) {
  const pins = fresh.hostPins();
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: 'localhost', port: fresh.PORTS.https, path: `/api/v1/vault/${encodeURIComponent(key)}`, method: 'GET', rejectUnauthorized: false, agent: false },
      (res) => {
        const pin = hostApi.spkiPin(res.socket.getPeerCertificate().raw);
        if (!pins.includes(pin)) {
          res.destroy();
          reject(new Error(`geçici test sunucusunun pin'i tutmadı: ${pin}`));
          return;
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), pin }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/** Cihazın yaptığı doğrulama: pinvault-vault-file:v1:<key>:<sürüm>:<sha256hex(düz metin)> üzerinde ECDSA. */
function verifyVaultSignature(key, version, body, signatureB64, publicKeyB64) {
  const canonical = `pinvault-vault-file:v1:${key}:${version}:${crypto.createHash('sha256').update(body).digest('hex')}`;
  const pub = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
  return crypto.verify('sha256', Buffer.from(canonical, 'utf8'), pub, Buffer.from(signatureB64, 'base64'));
}

test('Sunucu+Mobil: çoklu imza (en az 2 imza şartı) — iki imza isteyen telefon tek imzalı config\'i reddediyor; sunucu iki anahtarla imzalayınca config ve vault dosyası kabul ediliyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(30 * 60 * 1000);
  const app = new SampleApp(device, testInfo);
  let dashboard;
  let setup;
  let names = {};
  let createdSecond = false;
  let vaultVersion;

  try {
    await test.step('Terminal+Mobil: bu test için derlenen uygulama kurulur; telefon tek imzayla (varsayılan) Hazır', async () => {
      setup = await lab.setup(device, testInfo);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('bu test için derlenen uygulama: 1 imza gerekli, Hazır');
      const sig = SampleApp.signingOf(ready);
      expect(sig.required).toBe(1);
      names = {
        [setup.primary.keyId]: 'sunucunun birincil anahtarı',
        [setup.keys.second.keyId]: lab.KEYS.second,
      };
    });

    await test.step('Sunucu: lab-second ikinci yerel imzalayıcı olarak kurulur; sunucu hâlâ TEK anahtarla imzalıyor', async () => {
      await lab.op(testInfo, 'Operatör: ikinci anahtarı data/signing-key-second.pem olarak kur', {
        display: `./scripts/signing-keys.sh install ${lab.KEYS.second} second`,
        file: './scripts/signing-keys.sh',
        args: ['install', lab.KEYS.second, 'second'],
        note: 'Henüz etkin değil: CONFIG_SIGNERS boş = yalnızca "local" (birincil).',
      });
      createdSecond = true;
      const info = await lab.signingKeyInfo();
      await attachText(
        testInfo,
        'GET /api/v1/signing-key → imzalayıcılar',
        info.signers.map((s) => `${s.keyId}  (${names[s.keyId] || '?'})`).join('\n'),
      );
      expect(info.signers.map((s) => s.keyId)).toEqual([setup.primary.keyId]);
    });

    await test.step('Mobil: Ayarlar → "İki imza iste" → Uygula → PinVault başlatılamıyor ("1 of 2 required signatures valid")', async () => {
      await app.openSettings();
      const result = await app.setTwoSignatures(true);
      await app.snapResult('iki imza isteniyor: tek imzalı config reddedildi');
      await attachText(testInfo, 'Ayarlar → Uygula sonucu', result);
      expect(result).toContain('Gereken imza: 2');
      expect(result).toContain('başlatılamadı');
      expect(result).toContain('1 of 2 required signatures valid');
    });

    await test.step('Sunucu: iki imzalayıcı açılır (CONFIG_SIGNERS=local,local:second); Terminal: imzalı yanıtta iki imza, iki anahtar kimliği', async () => {
      await lab.setEnv(testInfo, 'env-override.sh: iki yerel imzalayıcı', { CONFIG_SIGNERS: 'local,local:second' });
      const jq = '{keyId, signature: (.signature[0:16] + "…"), signatures: [.signatures[] | {keyId, signature: (.signature[0:16] + "…")}]}';
      const cmd = `curl -s ${fresh.WEB_URL}/api/v1/certificate-config | jq '${jq}'`;
      const out = await lab.op(testInfo, 'İmzalı yanıt (GET /api/v1/certificate-config)', {
        display: cmd,
        file: 'sh',
        args: ['-c', cmd],
        note: (o) =>
          JSON.parse(o)
            .signatures.map((s) => `${s.keyId} = ${names[s.keyId] || '?'}`)
            .join('\n'),
      });
      const envelope = JSON.parse(out);
      expect(envelope.signatures.map((s) => s.keyId)).toEqual([setup.primary.keyId, setup.keys.second.keyId]);
      expect(envelope.keyId).toBe(setup.primary.keyId);
    });

    await test.step('Mobil: "Tekrar dene" → Hazır; imza satırı: 2 imza gerekli, config\'i iki anahtar imzalamış', async () => {
      const ready = await app.retryInit();
      await app.snap('iki imzalı config kabul edildi: Hazır');
      const sig = SampleApp.signingOf(ready);
      await attachText(testInfo, 'Telefondaki durum kutusu', ready);
      expect(sig.required).toBe(2);
      expect(sig.signedBy).toEqual([setup.primary.keyId.slice(0, 12), setup.keys.second.keyId.slice(0, 12)]);
    });

    await test.step('Web: geçici test sunucusuna küçük bir vault dosyası yüklenir (sample-flags, public / plain)', async () => {
      dashboard = await fresh.openDashboard(browser, testInfo);
      vaultVersion = await dashboard.uploadVaultText('default-tls', VAULT_KEY, CONTENT);
      const cells = await dashboard.vaultRowCells(VAULT_KEY);
      await dashboard.snap(`Vault sekmesi: ${VAULT_KEY} v${vaultVersion}`);
      await attachText(testInfo, 'Dosya listesindeki satır', `${JSON.stringify(cells)}\n\niçerik: ${CONTENT}`);
      expect(vaultVersion).toBeGreaterThan(0);
    });

    await test.step('Mobil: vault dosyası iki imzayla doğrulanıp indiriliyor', async () => {
      await app.openVault();
      const result = await app.fetchVault(VAULT_KEY);
      await app.snap(`${VAULT_KEY} v${vaultVersion}: iki imza doğrulandı, indirildi`);
      await attachText(testInfo, 'Vault ekranı sonucu', result);
      expect(result).toContain(`${VAULT_KEY} v${vaultVersion} indirildi`);
      expect(result).toContain('imza doğrulandı');
    });

    await test.step('Terminal: vault yanıtının başlıklarında X-Vault-Signature (birincil) ve X-Vault-Signatures (iki imza) var; ikisi de geçerli', async () => {
      const res = await rawVault(VAULT_KEY);
      const version = Number(res.headers['x-vault-version']);
      const entries = String(res.headers['x-vault-signatures'] || '')
        .split(',')
        .map((e) => e.trim())
        .filter(Boolean)
        .map((e) => ({ keyId: e.slice(0, e.indexOf(':')), signature: e.slice(e.indexOf(':') + 1) }));
      const pubOf = { [setup.primary.keyId]: setup.primary.publicKey, [setup.keys.second.keyId]: setup.keys.second.pub };
      const checks = entries.map((e) => ({ ...e, ok: !!pubOf[e.keyId] && verifyVaultSignature(VAULT_KEY, version, res.body, e.signature, pubOf[e.keyId]) }));
      await attachText(
        testInfo,
        `GET https://localhost:${fresh.PORTS.https}/api/v1/vault/${VAULT_KEY} (geçici test sunucusunun pin'i doğrulandı)`,
        [
          `HTTP ${res.status}`,
          `X-Vault-Version   : ${res.headers['x-vault-version']}`,
          `X-Vault-Encryption: ${res.headers['x-vault-encryption']}`,
          `X-Vault-Signature : ${String(res.headers['x-vault-signature']).slice(0, 24)}…   (birincil; eski istemciler için)`,
          `X-Vault-Signatures: ${entries.length} giriş (keyId:imza)`,
          ...checks.map((c) => `   • ${c.keyId} (${names[c.keyId] || '?'}) : ${c.signature.slice(0, 16)}… → ${c.ok ? 'GEÇERLİ ✓' : 'GEÇERSİZ'}`),
          '',
          `gövde (${res.body.length} bayt): ${res.body.toString('utf8')}`,
          '',
          `İmzalanan standart metin: pinvault-vault-file:v1:${VAULT_KEY}:${version}:<sha256hex(gövde)>.`,
          'Cihaz bunu en az 2 imza şartıyla doğruluyor: iki ayrı güvenilen anahtardan geçerli imza gerekiyor.',
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(version).toBe(vaultVersion);
      expect(res.headers['x-vault-signature']).toBeTruthy();
      expect(checks.map((c) => c.keyId)).toEqual([setup.primary.keyId, setup.keys.second.keyId]);
      expect(checks.every((c) => c.ok)).toBe(true);
    });

    await test.step('Mobil: Ayarlar → tek imzaya dönülür → Hazır (gereken imza 1)', async () => {
      await app.backToMain();
      await app.openSettings();
      const result = await app.setTwoSignatures(false);
      await app.snapResult('tek imzaya dönüldü: Hazır');
      await attachText(testInfo, 'Ayarlar → Uygula sonucu', result);
      expect(result).toContain('Gereken imza: 1');
      expect(result).toContain('Hazır');
    });
  } finally {
    await test.step('Sunucu+Terminal: ortam sıfırlanır, lab-second anahtar dosyası ve vault dosyası silinir; telefona ana host için derlenen APK geri kurulur', async () => {
      const lines = ['$ ./scripts/env-override.sh reset', await lab.resetEnv({ force: true })];
      if (createdSecond) {
        fs.rmSync(`${fresh.DIR}/data/signing-key-second.pem`, { force: true });
        lines.push('$ rm data/signing-key-second.pem');
      }
      const del = await fresh.api(`/api/v1/config-apis/default-tls/vault/${VAULT_KEY}`, { method: 'DELETE' });
      lines.push(`$ curl -X DELETE ${fresh.WEB_URL}/api/v1/config-apis/default-tls/vault/${VAULT_KEY} → HTTP ${del.status}`);
      const info = await lab.signingKeyInfo();
      lines.push('', `imzalayıcılar: ${info.signers.map((s) => `${s.keyId.slice(0, 16)}… (${names[s.keyId] || '?'})`).join(', ')}`);
      await attachText(testInfo, 'Geri dönüş: geçici test sunucusu', lines.join('\n'));
      await lab.restoreMain(device, app, testInfo);
      expect(info.signers).toHaveLength(1);
    });
    if (dashboard) await dashboard.page.close();
  }
});
