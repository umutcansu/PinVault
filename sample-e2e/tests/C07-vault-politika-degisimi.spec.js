// C07 — Vault erişim politikasının dashboard'dan değiştirilmesi.
//
// Dosya detayındaki "Erişim politikası" kartı içeriğe ve sürüme dokunmadan
// `access_policy` / `encryption` alanlarını güncelliyor
// (PUT …/vault/{key}/policy). Aynı dosya public → token → public dolaşımında
// telefonun gördüğü davranış her adımda değişiyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, describeResponse, redact } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.secret;

test('Vault politika değişimi: public → token → public, telefon her adımda yeni kurala göre davranıyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const body = `politika-denemesi-${Date.now()}`;
  let version;
  let deviceId;
  let token;

  try {
    await test.step('Web: dosya public olarak yüklenir', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, body, { policy: 'public' });
      await dashboard.openVaultFileDetail(env.VAULT_API, KEY);
      await dashboard.snapVaultPolicy('erişim politikası kartı — public');
      expect(await dashboard.vaultPolicySummary(KEY)).toEqual({ policy: 'public', encryption: 'plain' });
    });

    await test.step('Mobil: token olmadan iniyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      await app.snap('public: token olmadan indi');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain(body);
    });

    await test.step('Web: politika token yapılır (içerik ve sürüm değişmeden)', async () => {
      const summary = await dashboard.setVaultPolicy(env.VAULT_API, KEY, { policy: 'token', encryption: 'plain' });
      await dashboard.snapVaultPolicy('erişim politikası kartı — token');
      expect(summary.policy).toBe('token');
      // Kaydetme sonrası sayfa dosya detayında kalıyor; liste için sekmeye dön.
      await dashboard.openConfigApiTab(env.VAULT_API, 'vault');
      const cells = await dashboard.vaultRowCells(KEY);
      await attachText(
        testInfo,
        `PUT /api/v1/config-apis/${env.VAULT_API}/vault/${KEY}/policy`,
        [
          `dosya listesi: v${cells.version}, ${cells.size}, politika=${cells.policy}, şifreleme=${cells.encryption}`,
          '',
          `Sürüm hâlâ v${version}: politika değişikliği içeriğe dokunmuyor, yani`,
          'telefondaki kopya "eski sürüm" sayılmıyor; yalnızca erişim kısıtlanıyor.',
        ].join('\n'),
      );
      expect(Number(cells.version.replace(/\D/g, ''))).toBe(version);
      expect(cells.policy).toContain('token');
    });

    await test.step('Mobil: token yokken aynı dosya 401', async () => {
      const status = await app.fetchVault(KEY);
      await app.snap('token politikası: 401');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
    });

    await test.step('Web: bu cihaz için token üretilir', async () => {
      token = await dashboard.generateVaultToken(env.VAULT_API, KEY, deviceId);
      await dashboard.snap('cihaz için token üretildi');
      expect(token).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    });

    await test.step('Mobil: token girilince iniyor', async () => {
      // Yerel kopya siliniyor ki sonuç 304 ("güncel") değil gerçek bir indirme olsun.
      await app.vaultClear(KEY);
      await app.saveVaultToken(token, KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('token ile indirildi');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain(body);
      await attachText(
        testInfo,
        'Token ile indirme',
        [`X-Vault-Token: ${redact(token)}`, `X-Device-Id: ${deviceId}`, '', status].join('\n'),
      );
    });

    await test.step('Web: politika public\'e döndürülür', async () => {
      const summary = await dashboard.setVaultPolicy(env.VAULT_API, KEY, { policy: 'public', encryption: 'plain' });
      await dashboard.snapVaultPolicy('erişim politikası kartı — public (geri)');
      expect(summary.policy).toBe('public');
    });

    await test.step('Mobil: token bellekten silinince de iniyor', async () => {
      // Token yalnızca bellekte (VaultTokens); uygulamanın yeniden açılması onu
      // siliyor. Saklı config ve sertifika korunuyor.
      await app.backToMain();
      app.relaunch();
      await app.waitReady();
      await app.openVault();
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('public: token olmadan yeniden indi');
      expect(status).toContain(`${KEY} v${version} indirildi`);
      expect(status).toContain(body);
    });

    await test.step('Ağ trafiği: token\'sız, tanınmayan bir cihazdan gelen istek de 200 alıyor', async () => {
      const res = await hostApi.rawVaultDownload(KEY, 'c07-yabanci-cihaz');
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — token yok, tanınmayan cihaz kimliği`,
        [
          describeResponse(res, { maxBody: 200 }),
          '',
          'public politikada erişim kontrolü yok: dosyanın gizliliğini yalnızca TLS ve',
          'pinleme koruyor. token politikası cihaz başına kontrolü geri getiriyor.',
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(res.body.toString('utf8')).toBe(body);
    });

    await test.step('Web: dağıtım geçmişi üç davranışı da kaydediyor', async () => {
      await dashboard.expectDistribution(env.VAULT_API, {
        key: KEY,
        deviceModel: run.model,
        status: 'downloaded',
      });
      await dashboard.snap('dağıtım geçmişi — politika değişiklikleri');
      const dists = await hostApi.vaultDistributions(env.VAULT_API, KEY);
      await attachText(
        testInfo,
        `GET /api/v1/config-apis/${env.VAULT_API}/vault/distributions/${KEY}`,
        dists
          .slice(0, 8)
          .map((d) => `${d.timestamp} ${d.status.padEnd(10)} v${d.version} auth=${d.authMethod} ${(d.failureReason || '').replace(/\s+/g, ' ').slice(0, 60)}`)
          .join('\n'),
      );
      expect(dists.filter((d) => d.status === 'downloaded').length).toBeGreaterThanOrEqual(3);
      expect(dists.some((d) => d.status === 'failed' && /401/.test(d.failureReason || ''))).toBe(true);
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
