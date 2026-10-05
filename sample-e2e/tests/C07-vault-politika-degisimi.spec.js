// C07 — Vault erişim politikasının dashboard'dan değiştirilmesi.
//
// Dosya detayındaki "Erişim politikası" kartı içeriğe dokunmadan
// `access_policy` / `encryption` alanlarını güncelliyor
// (PUT …/vault/{key}/policy). Kural değişince sürüm bir artar: eski kuralla
// (ör. şifresiz) inmiş kopyası olan cihazlar 304 almasın, dosyayı yeni
// kuralla yeniden çeksin. Aynı dosya public → token → public dolaşımında
// telefonun gördüğü davranış her adımda değişiyor: sunucu kuralı uygular,
// uygulamanın dosyayı nasıl tanımladığına bakmaz.
const { test, expect } = require('../lib/fixtures');
const { attachText, describeResponse } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

// Herkese açık sample-flags: uygulama onu public tanımlar ve token göndermez.
// Sunucu politikayı token yapınca uygulama ayarı ne olursa olsun reddeder.
// (Token'la indirme 14 ve C03'te: gizli dosyalar mTLS + token_mtls ile.)
const KEY = env.VAULT_KEYS.flags;

test('Vault politika değişimi: public → token → public, telefon her adımda yeni kurala göre davranıyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const body = `politika-denemesi-${Date.now()}`;
  let version;
  let deviceId;

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

    await test.step('Web: politika token yapılır (içerik aynı, sürüm bir artar)', async () => {
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
          `Sürüm v${version} → v${version + 1}: içerik aynı, ama kural değişince sürüm artıyor;`,
          'eski kuralla inmiş kopyalar "eski sürüm" sayılıp yeni kuralla yeniden çekiliyor.',
        ].join('\n'),
      );
      expect(Number(cells.version.replace(/\D/g, ''))).toBe(version + 1);
      expect(cells.policy).toContain('token');
    });

    await test.step('Mobil: token yokken aynı dosya 401', async () => {
      const status = await app.fetchVault(KEY);
      await app.snap('token politikası: 401');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
    });

    await test.step('Web: politika public\'e döndürülür', async () => {
      const summary = await dashboard.setVaultPolicy(env.VAULT_API, KEY, { policy: 'public', encryption: 'plain' });
      await dashboard.snapVaultPolicy('erişim politikası kartı — public (geri)');
      expect(summary.policy).toBe('public');
    });

    await test.step('Mobil: politika public\'e dönünce yeniden açılan uygulamada da iniyor', async () => {
      // Uygulama yeniden açılıyor (saklı config korunuyor) ve yerel kopya
      // siliniyor: sonuç 304 ("güncel") değil gerçek bir indirme olsun.
      await app.backToMain();
      app.relaunch();
      await app.waitReady();
      await app.openVault();
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('public: token olmadan yeniden indi');
      // public → token → public: iki kural değişikliği, iki sürüm.
      expect(status).toContain(`${KEY} v${version + 2} indirildi`);
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

    await test.step('Web: dağıtım geçmişi iki davranışı da kaydediyor (indirme ve 401)', async () => {
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
      expect(dists.filter((d) => d.status === 'downloaded').length).toBeGreaterThanOrEqual(2);
      expect(dists.some((d) => d.status === 'failed' && /401/.test(d.failureReason || ''))).toBe(true);
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
  }
});
