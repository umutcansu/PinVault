// B06 — Kayıt token'ının yaşam döngüsü.
//
// Token tek kullanımlık: kayıt sonrası listede "Kullanıldı" oluyor ve aynı
// token ikinci kez kabul edilmiyor. Süresi (ENROLLMENT_TOKEN_TTL_SECONDS)
// dolmuş bir token da reddediliyor. Düz metin token yalnızca üretim anında,
// tek seferlik bir diyalogda görünüyor; listede yalnızca maskeli önek var
// (sunucu SHA-256 hash'ini saklıyor).
//
// Yol boyunca dashboard'ın iki davranışı da kanıtlanıyor: "Client
// Sertifikaları" sekmesi yeniden çizildiğinde token listesi dolu geliyor ve
// süresi dolmuş token "Süresi doldu" olarak işaretleniyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { sleep } = require('../lib/android');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

test('mTLS: kayıt token\'ı tek kullanımlık ve süreli', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  const stamp = Date.now();
  const firstId = `b06-first-${stamp}`;
  const spareId = `b06-spare-${stamp}`;
  const expiredId = `b06-expired-${stamp}`;
  const freshId = `b06-fresh-${stamp}`;
  let firstToken;

  try {
    await test.step('Web: token üretiliyor — token\'ın tamamı yalnızca bir kez gösteriliyor', async () => {
      firstToken = await dashboard.generateEnrollmentToken(env.MTLS_API, firstId);
      const dialog = dashboard.lastDialog();
      const row = await dashboard.enrollmentTokenCells(firstId);
      await dashboard.snapTokenList(env.MTLS_API, `kayıt token'ı listesi (maskeli): ${firstId} bekliyor`, [
        { clientId: firstId, status: 'Bekliyor' },
      ]);
      await attachText(
        testInfo,
        'Token üretimi',
        [
          'Tek seferlik diyalog (token panelde kısaltıldı):',
          dialog.replace(firstToken, redact(firstToken)),
          '',
          `Listedeki satır: ${row}`,
          '',
          'Sunucu (EnrollmentTokenStore) yalnızca token\'ın SHA-256 hash\'ini ve maskeli',
          '8 karakterlik başını saklıyor; token\'ın kendisi geri alınamıyor.',
        ].join('\n'),
      );
      expect(firstToken).toMatch(/^[A-Za-z0-9_-]{32,}$/);
      expect(row).toContain('Bekliyor');
      expect(row).toContain(firstToken.slice(0, 8));
      expect(row).not.toContain(firstToken);
      const stored = (await hostApi.enrollmentTokens()).find((t) => t.clientId === firstId);
      expect(stored.token).not.toBe(firstToken);
      expect(stored.token).not.toContain(firstToken.slice(8));
    });

    await test.step('Mobil: token ile kayıt başarılı', async () => {
      await app.openMtls();
      expect(await app.enroll(firstToken)).toContain(`Kayıt başarılı — CN=PinVault Client: ${firstId}`);
      await app.snap('ilk kullanım: kayıt başarılı');
    });

    await test.step('Web: sekme yeniden açılınca liste dolu geliyor', async () => {
      await dashboard.refreshMtlsSection(env.MTLS_API);
      // Liste sekme çizildikten sonra asenkron doluyor (loadEnrollmentTokens).
      await expect.poll(() => dashboard.enrollmentTokenRowCount(), { timeout: 20_000 }).toBeGreaterThan(0);
      const count = await dashboard.enrollmentTokenRowCount();
      await dashboard.snapTokenList(env.MTLS_API, `sekme yeniden açıldı: liste dolu, ${firstId} kullanıldı`, [
        { clientId: firstId, status: 'Kullanıldı' },
      ]);
      const fromApi = (await hostApi.enrollmentTokens()).length;
      await attachText(
        testInfo,
        'Config API sekmesinde kayıt token\'ı listesi',
        [
          `Ekrandaki satır sayısı: ${count}`,
          `GET /api/v1/enrollment-tokens → ${fromApi} kayıt`,
          '',
          'Eskiden bu liste boş çiziliyordu: app.js renderConfigApiDetail, sekme fonksiyonu',
          '(renderMtlsSection) dönünce #content\'i başlık + sekme çubuğuyla birlikte yeniden',
          'yazıyor; asenkron loadEnrollmentTokens ise liste elemanını fetch\'ten ÖNCE',
          'alıyordu. O eleman yeniden yazmayla DOM\'dan kopuyor ve doldurulan liste hiçbir',
          'yerde görünmüyordu. Liste yalnızca "Token Üret" / "İptal Et" işlemlerinden hemen',
          'sonra görünüyordu. Liste elemanı artık fetch\'ten sonra aranıyor; sekme her',
          'açılışta sunucudaki kayıt sayısı kadar satır gösteriyor.',
        ].join('\n'),
      );
      expect(fromApi).toBeGreaterThan(0);
      expect(count).toBe(fromApi);
    });

    await test.step('Web: yeni token üretimi listeyi yeniliyor — ilk token "Kullanıldı"', async () => {
      await dashboard.generateEnrollmentToken(env.MTLS_API, spareId);
      const row = await dashboard.enrollmentTokenCells(firstId);
      await dashboard.snapTokenList(env.MTLS_API, `${firstId} kullanıldı, ${spareId} bekliyor`, [
        { clientId: firstId, status: 'Kullanıldı' },
        { clientId: spareId, status: 'Bekliyor' },
      ]);
      await attachText(testInfo, 'Kullanım sonrası satır', row);
      expect(row).toContain('Kullanıldı');
    });

    await test.step('Mobil: kayıt silinip aynı token ikinci kez deneniyor — reddediliyor', async () => {
      expect(await app.unenroll()).toContain('Kayıt silindi');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const result = await app.enroll(firstToken);
      await app.snap('ikinci kullanım reddedildi');
      expect(result).toContain('Kayıt başarısız');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await attachText(
        testInfo,
        'Aynı token ikinci kez',
        [
          result,
          '',
          'Sunucu EnrollmentTokenStore.validate "used = 0" koşuluyla arıyor; kullanıldı',
          'olarak işaretlenmiş token için null dönüyor → Config API 401 "Gecersiz token".',
        ].join('\n'),
      );
      await app.backToMain();
    });

    await test.step('Sunucu: token ömrü 5 saniyeye indiriliyor', async () => {
      await hostControl.setEnv({ ENROLLMENT_TOKEN_TTL_SECONDS: '5' });
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      await attachText(
        testInfo,
        'scripts/env-override.sh set ENROLLMENT_TOKEN_TTL_SECONDS=5',
        [
          'Container aynı veriyle yeniden oluşturuldu. Token ömrü (TTL) token ÜRETİLİRKEN',
          'okunuyor (EnrollmentTokenStore.create → expires_at = now + TTL), bu yüzden yeni',
          'token bu ayarla üretilmeli.',
        ].join('\n'),
      );
    });

    await test.step('Web+Mobil: süresi dolan token reddediliyor', async () => {
      const expiredToken = await dashboard.generateEnrollmentToken(env.MTLS_API, expiredId);
      await sleep(9000);
      await app.openMtls();
      const result = await app.enroll(expiredToken);
      await app.snap('süresi dolmuş token reddedildi');
      // Liste token üretildiği anda çizildi; o an token daha geçerliydi. Süre
      // durumunu görmek için sekme yeniden çiziliyor.
      await dashboard.refreshMtlsSection(env.MTLS_API);
      const row = await dashboard.enrollmentTokenCells(expiredId);
      await dashboard.snapTokenList(env.MTLS_API, `${expiredId} "Süresi doldu"`, [
        { clientId: expiredId, status: 'Süresi doldu' },
      ]);
      const listed = (await hostApi.enrollmentTokens()).find((t) => t.clientId === expiredId);
      await attachText(
        testInfo,
        'Süresi dolmuş token',
        [
          `token (kısaltılmış): ${redact(expiredToken)}`,
          'üretimden 9 saniye sonra denendi (token ömrü 5 s)',
          '',
          'Telefon:',
          result,
          '',
          `Listedeki satır: ${row}`,
          `GET /api/v1/enrollment-tokens → used=${listed.used}, expired=${listed.expired}, expiresAt=${listed.expiresAt}`,
          '',
          'Sunucu doğrulaması (EnrollmentTokenStore.validate) expires_at ile yapılıyor;',
          'liste artık aynı kuralı `expired` alanıyla API yanıtında veriyor ve dashboard satırı',
          '"Bekliyor" yerine "Süresi doldu" gösteriyor.',
        ].join('\n'),
      );
      expect(result).toContain('Kayıt başarısız');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      expect(listed.expired).toBe(true);
      expect(listed.used).toBe(false);
      expect(row).toContain('Süresi doldu');
      await app.backToMain();
    });

    await test.step('Sunucu: token ömrü varsayılana dönüyor, yeni token çalışıyor', async () => {
      await hostControl.resetEnv();
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      const freshToken = await dashboard.generateEnrollmentToken(env.MTLS_API, freshId);
      await app.openMtls();
      const result = await app.enroll(freshToken);
      await app.snap('varsayılan token ömrüyle kayıt yeniden çalışıyor');
      expect(result).toContain(`Kayıt başarılı — CN=PinVault Client: ${freshId}`);
      await attachText(testInfo, 'Varsayılan token ömrüyle (24 saat) kayıt', result);
      expect(await app.unenroll()).toContain('Kayıt silindi');
      await app.backToMain();
    });
  } finally {
    await hostControl.resetEnv().catch(() => {});
    await hostApi.revokeClientCertIfActive(firstId).catch(() => {});
    await hostApi.revokeClientCertIfActive(freshId).catch(() => {});
  }
});
