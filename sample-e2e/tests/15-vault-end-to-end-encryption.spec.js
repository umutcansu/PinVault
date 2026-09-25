// Web → Mobil (uçtan uca şifreleme): dashboard'da end_to_end yüklenen dosya
// ağ trafiğinde cihazın RSA anahtarıyla şifrelenmiş gider; yalnızca cihaz çözer.
const { test, expect } = require('../lib/fixtures');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.e2e;

test('Vault uçtan uca şifreleme: dosya ağ trafiğinde şifreli, yalnızca cihaz çözer', async ({ app, dashboard, run }) => {
  const plaintext = `uçtan uca gizli: ${Date.now()}`;
  let deviceId;

  try {
    await test.step('Web: dosya end_to_end şifrelemeyle yüklenir', async () => {
      await dashboard.uploadVaultText(env.VAULT_API, KEY, plaintext, { policy: 'public', encryption: 'end_to_end' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${KEY} end_to_end ile yüklendi`);
    });

    await test.step('Mobil: dosya iner ve cihaz anahtarıyla çözülür', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      expect(status).toContain('indirildi');
      expect(status).toContain('cihaz anahtarıyla çözüldü');
      expect(status).toContain(plaintext);
      await app.snap('uçtan uca çözüldü');
    });

    await test.step('Ağ trafiği: aynı dosya şifreli gidiyor, içinde açık metin yok', async () => {
      const res = await hostApi.rawVaultDownload(KEY, deviceId);
      expect(res.status).toBe(200);
      expect(res.headers['x-vault-encryption']).toBe('end_to_end');
      expect(res.body.includes(Buffer.from(plaintext, 'utf8'))).toBe(false);
      // [4 bayt uzunluk][RSA ile sarılmış AES anahtarı][12 bayt IV][AES-GCM şifreli metin]
      const wrappedKeyLength = res.body.readUInt32BE(0);
      expect(wrappedKeyLength).toBeGreaterThanOrEqual(256);
      await test.info().attach('ağ trafiğindeki ham veri (ilk 64 bayt, hex)', {
        body: res.body.subarray(0, 64).toString('hex').replace(/(.{32})/g, '$1\n'),
        contentType: 'text/plain',
      });
    });

    await test.step('Web: dağıtım geçmişinde indirme görünür', async () => {
      await dashboard.expectDistribution(env.VAULT_API, { key: KEY, deviceModel: run.model, status: 'downloaded' });
      await dashboard.snap('dağıtım geçmişi');
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY);
  }
});
