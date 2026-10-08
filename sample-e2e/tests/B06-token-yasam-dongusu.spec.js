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
//
// Son adım "bir cihaz, bir etkin kimlik" kuralını gösteriyor: telefonda kayıt
// silinse de sunucuda eski kimlik etkinken aynı cihaz yeni bir kimlikle kayıt
// olamıyor (409, token harcanmıyor); eski kimlik iptal edilince aynı token geçiyor.
//
// Bir de panelde başka bir telefonun kimliğine (ANDROID_ID) bağlanmış token:
// bu telefon onunla kayıt olamıyor (403 device_uid_mismatch) ve token harcanmıyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { sleep } = require('../lib/device');
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
  const otherId = `b06-other-${stamp}`;
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

    await test.step('Web+Mobil: başka bir telefona bağlı token bu telefonda reddediliyor (403 device_uid_mismatch), token harcanmıyor', async () => {
      await app.openMtls();
      const mine = app.mtlsDeviceId();
      // Başka bir telefonun kimliği (ANDROID_ID biçiminde, bu telefonunkinden farklı).
      const otherUid = mine === '00c0ffee00c0ffee' ? '00decaf000decaf0' : '00c0ffee00c0ffee';
      const otherToken = await dashboard.generateEnrollmentToken(env.MTLS_API, otherId, { deviceUid: otherUid });
      const row = await dashboard.enrollmentTokenCells(otherId);
      const result = await app.enroll(otherToken);
      await app.snap('başka telefona bağlı token reddedildi');
      const listed = (await hostApi.enrollmentTokens()).find((t) => t.clientId === otherId);
      const certs = (await hostApi.clientCerts()).filter((c) => c.id === otherId);
      await attachText(
        testInfo,
        'Başka bir telefona bağlı kayıt token\'ı',
        [
          `Bu telefonun kimliği (mTLS ekranı): ${mine}`,
          `Token panelde şu kimliğe bağlandı: ${otherUid}`,
          `Listedeki satır: ${row}`,
          '',
          'Telefon:',
          result,
          '',
          `GET /api/v1/enrollment-tokens → used=${listed.used}, deviceUid=${listed.deviceUid}`,
          `sunucuda ${otherId} için sertifika: ${certs.length}`,
          '',
          'Panelde "Cihaz kimliği (ANDROID_ID)" doldurulursa token yalnızca o telefona çalışıyor.',
          'Başka bir telefonun isteği token harcanmadan 403 device_uid_mismatch alıyor; doğru',
          'telefon aynı token\'la hâlâ kayıt olabilir. Sızan bir bağlı token başka telefonda işe yaramıyor.',
        ].join('\n'),
      );
      expect(row).toContain(otherUid);
      expect(result).toContain('Kayıt başarısız');
      expect(result).toContain('device_uid_mismatch');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      expect(listed.deviceUid).toBe(otherUid);
      expect(listed.used).toBe(false);
      expect(certs).toHaveLength(0);
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
          'Eskiden bu liste boş çiziliyordu: app-hosts.js renderConfigApiDetail, sekme fonksiyonu',
          '(renderMtlsSection) dönünce #content\'i başlık + sekme çubuğuyla birlikte yeniden',
          'yazıyor; asenkron loadEnrollmentTokens ise liste elemanını fetch\'ten ÖNCE',
          'alıyordu. O eleman yeniden yazmayla DOM\'dan kopuyor ve doldurulan liste hiçbir',
          'yerde görünmüyordu. Liste yalnızca "Token Üret" / "İptal Et" işlemlerinden hemen',
          'sonra görünüyordu. Liste elemanı artık fetch\'ten sonra aranıyor; sekme her',
          'açılışta sunucudaki kayıt sayısı kadar satır gösteriyor.',
        ].join('\n'),
      );
      expect(fromApi).toBeGreaterThan(0);
      // Liste sayfalı (varsayılan 10 satır): sayfada min(toplam, 10) satır
      // durur, sayfalayıcının "a-b / toplam" sayacı sunucudaki bütün token'ları sayar.
      expect(count).toBe(Math.min(fromApi, 10));
      const pager = await dashboard.page.locator('#enrollment-token-list').innerText();
      expect(pager).toContain(`/ ${fromApi}`);
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

    await test.step('Sunucu: token ömrü varsayılana dönüyor; aynı telefon yeni kimliğe, eskisi iptal edilince geçiyor', async () => {
      await hostControl.resetEnv();
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      const freshToken = await dashboard.generateEnrollmentToken(env.MTLS_API, freshId);
      await app.openMtls();

      // Telefondaki "Kaydı Sil" yalnızca telefondaki kaydı siler: sunucuda bu
      // cihaz (ANDROID_ID) hâlâ firstId olarak etkin. Bir cihaz aynı anda tek
      // etkin kimliğe sahip olabildiği için yeni kimlikle kayıt reddediliyor.
      const refused = await app.enroll(freshToken);
      await app.snap('eski kimlik etkinken yeni kimlikle kayıt reddediliyor');
      const refusal = ((await hostApi.auditLog({ action: 'client_cert_enroll_refused', limit: 5 })).entries || [])
        .find((e) => e.target === freshId);
      const pending = (await hostApi.enrollmentTokens()).find((t) => t.clientId === freshId);
      expect(refused).toContain('Kayıt başarısız');
      // Telefon nedeni söylüyor: "token geçersiz" değil, cihaz başka kimlikle kayıtlı.
      expect(refused).toContain('başka bir kimlikle kayıtlı');
      expect(refusal && refusal.summary).toContain(`is enrolled as ${firstId}`);
      expect(pending.used).toBe(false);

      // Yönetici eski kimliği iptal ediyor; aynı token (harcanmamıştı) şimdi geçiyor.
      expect(await hostApi.revokeClientCertIfActive(firstId)).toBe(true);
      const result = await app.enroll(freshToken);
      await app.snap('eski kimlik iptal edilince aynı token\'la kayıt çalışıyor');
      expect(result).toContain(`Kayıt başarılı — CN=PinVault Client: ${freshId}`);
      await attachText(
        testInfo,
        'Varsayılan token ömrüyle (24 saat) kayıt — bir cihaz, bir etkin kimlik',
        [
          'Eski kimlik etkinken, yeni kimliğin token\'ıyla:',
          refused,
          `Denetim kaydı: ${refusal.action} — ${refusal.summary}`,
          `Token listede: used=${pending.used} (reddedilen kayıt token\'ı harcamıyor)`,
          '',
          `Yönetici ${firstId} kimliğini iptal etti (DELETE /api/v1/client-certs/${firstId}); aynı token\'la:`,
          result,
          '',
          'Sunucu bir cihaz kimliğini (ANDROID_ID) aynı anda tek bir etkin kimliğe bağlıyor:',
          'token_mtls, şifreleme anahtarı kaydı ve 8092\'deki X-Device-Id kuralı bu bağa',
          'güveniyor. İkinci bir kimlik, iptal edilmemiş bir cihazı sahiplenemiyor (409).',
        ].join('\n'),
      );
      expect(await app.unenroll()).toContain('Kayıt silindi');
      await app.backToMain();
    });
  } finally {
    await hostControl.resetEnv().catch(() => {});
    // İptal + unut: token'lar telefona bağlı, kimlikler cihazı kanıtlıyor (bkz. retireClientIdentity).
    await hostApi.retireClientIdentity(firstId);
    await hostApi.retireClientIdentity(freshId);
  }
});
