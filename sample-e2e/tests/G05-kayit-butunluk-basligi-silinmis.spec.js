// G05 — Kayıt yanıtındaki P12 bütünlük başlığı silinirse.
//
// Kayıt (enrollment) sırasında sunucu cihaza bir PKCS#12 dosyası veriyor:
// istemci sertifikası + özel anahtar. Bu dosya mTLS kimliğinin kendisi, yani
// araya giren biri kendi ürettiği bir P12'yi yutturabilirse cihaz ondan sonra
// SALDIRGANIN kimliğiyle konuşur.
//
// Kütüphanenin şartı: sunucu P12 baytlarının SHA-256'sını `X-P12-SHA256`
// başlığında vermek zorunda (PinVault.validateP12). Başlık yoksa kurulum
// reddediliyor — "belki yoktur, devam edeyim" yok. Vekil tam da bu başlığı
// siliyor; gövdeye hiç dokunmuyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test('Kablo: X-P12-SHA256 başlığı silinince telefon sertifikayı kurmuyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  const stamp = Date.now();
  const tamperedClient = `g05-kurcalanmis-${stamp}`;
  const cleanClient = `g05-temiz-${stamp}`;
  const wire = {};
  let mitm;
  let tamperedToken;
  let cleanToken;

  try {
    await test.step('Web: iki tek kullanımlık kayıt token\'ı üretilir', async () => {
      tamperedToken = await dashboard.generateEnrollmentToken(env.MTLS_API, tamperedClient);
      cleanToken = await dashboard.generateEnrollmentToken(env.MTLS_API, cleanClient);
      await dashboard.snapTokenList(env.MTLS_API, `iki kayıt token'ı bekliyor: ${tamperedClient}, ${cleanClient}`, [
        { clientId: tamperedClient, status: 'Bekliyor' },
        { clientId: cleanClient, status: 'Bekliyor' },
      ]);
      expect(tamperedToken).toMatch(/^[A-Za-z0-9_-]{32,}$/);
      expect(cleanToken).not.toBe(tamperedToken);
    });

    await test.step('Mobil: cihaz henüz kayıtlı değil', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('kayıt öncesi');
      await app.backToMain();
    });

    await test.step("Vekil: host'un anahtarıyla saydam araya girilir", async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saydam vekil: telefon Hazır');
      expect(ready).toContain('Hazır — config v');
    });

    await test.step('Vekil: kayıt yanıtından X-P12-SHA256 silinir → telefon kurulumu reddediyor', async () => {
      mitm.setMutate((answer) => {
        const mutated = proxy.stripP12Hash(answer);
        if (mutated !== answer) {
          wire.path = answer.path;
          wire.status = answer.status;
          wire.before = { ...answer.headers };
          wire.after = { ...mutated.headers };
          wire.bodyLength = answer.body.length;
          wire.bodyHead = answer.body.subarray(0, 4).toString('hex');
        }
        return mutated;
      });

      device.clearLogcat();
      await app.openMtls();
      const status = await app.enroll(tamperedToken);
      await app.snap('başlık silinmiş: kayıt başarısız');
      expect(status).toContain('Kayıt başarısız');

      const logcat = device
        .logcat({ match: /X-P12-SHA256|Enrollment failed|SecurityException/, lines: 4000 })
        .split('\n')
        .slice(-8)
        .join('\n');
      await attachText(
        testInfo,
        `Kablodaki fark (POST ${wire.path})`,
        [
          `HTTP ${wire.status}, gövde ${wire.bodyLength} bayt (PKCS#12, başlangıç 0x${wire.bodyHead})`,
          '',
          'SUNUCUNUN GÖNDERDİĞİ BAŞLIKLAR',
          `  content-type  : ${wire.before['content-type']}`,
          `  x-p12-sha256  : ${redact(wire.before['x-p12-sha256'], 12)}`,
          '',
          'TELEFONUN ALDIĞI (vekil sildi)',
          `  content-type  : ${wire.after['content-type']}`,
          `  x-p12-sha256  : ${wire.after['x-p12-sha256'] === undefined ? '(yok)' : wire.after['x-p12-sha256']}`,
          '',
          'Gövde bayt bayt aynı — yalnızca bütünlük başlığı düştü.',
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
          '',
          'Cihazın günlüğü:',
          logcat || '(ilgili satır yok)',
        ].join('\n'),
      );
      expect(wire.before['x-p12-sha256']).toBeTruthy();
      expect(wire.after['x-p12-sha256']).toBeUndefined();
      expect(logcat).toMatch(/X-P12-SHA256/);
    });

    await test.step('Mobil: sertifika cihazda saklanmadı (Depolama ekranı)', async () => {
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
      await app.openStorage();
      const storage = await app.storageText();
      await app.snap('başlık silinmiş: sertifika saklanmadı');
      await attachText(
        testInfo,
        'Cihazdaki istemci sertifikası kaydı',
        [
          storage.split('\n').filter((line) => /İstemci sertifikası|kayıtlı|pinvault_client_cert|elle yüklenen/i.test(line)).join('\n'),
          '',
          'Doğrulama P12 diske YAZILMADAN önce yapılıyor: validateP12 önce hash,',
          'sonra PKCS12 biçim kontrolü; ikisi de geçmeden certStore.save çağrılmıyor.',
        ].join('\n'),
      );
      expect(storage).toContain('kayıtlı değil');
      await app.backToMain();
    });

    await test.step('Web: sunucu tarafında sertifika yine de üretildi ve token harcandı (not)', async () => {
      const certs = (await hostApi.clientCerts()).filter((c) => c.id === tamperedClient);
      const tokens = (await hostApi.enrollmentTokens()).filter((t) => t.clientId === tamperedClient);
      await dashboard.snapTokenList(env.MTLS_API, `${tamperedClient} token'ı "Kullanıldı" (sunucu tarafında harcandı)`, [
        { clientId: tamperedClient, status: 'Kullanıldı' },
      ]);
      await attachText(
        testInfo,
        'Sunucu tarafı: reddedilen kayıt sunucuda iz bırakıyor',
        [
          `istemci kimliği: ${tamperedClient}`,
          `üretilen sertifika sayısı: ${certs.length} (${certs.map((c) => (c.revoked ? 'iptal' : 'etkin')).join(', ') || '-'})`,
          `token durumu: ${tokens.map((t) => (t.used ? 'kullanıldı' : 'kullanılmadı')).join(', ') || '-'}`,
          '',
          'Sunucu isteği karşılayıp P12\'yi ürettiği ve tek kullanımlık token\'ı',
          'harcadığı için, istemci kurulumu reddetse bile kaydın sunucudaki izi',
          'kalıyor. Operasyon notu: böyle bir durumda sertifikanın iptal edilmesi',
          've yeni token verilmesi gerekir (bu senaryo sonunda yapılıyor).',
        ].join('\n'),
      );
      expect(certs.length).toBeGreaterThan(0);
    });

    await test.step('Vekil: kurcalama kalkınca ikinci token ile kayıt tamamlanıyor', async () => {
      mitm.setMutate(null);
      await app.openMtls();
      const status = await app.enroll(cleanToken);
      await app.snap('kurcalama kalktı: kayıt başarılı');
      expect(status).toContain(`Kayıt başarılı — CN=PinVault Client: ${cleanClient}`);
      expect(app.enrollState()).toContain(cleanClient);

      await app.backToMain();
      await app.openStorage();
      const storage = await app.storageText();
      await attachText(
        testInfo,
        'Kurulum sonrası cihazdaki sertifika kaydı',
        storage.split('\n').filter((line) => /İstemci sertifikası|kayıtlı|PKCS12/i.test(line)).join('\n'),
      );
      expect(storage).toContain('ham kayıt PKCS12 olarak açılıyor mu: hayır ✓ (şifreli)');
      await app.backToMain();
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      expect(await app.waitReady()).toContain('Hazır — config v');
      await app.snap('vekil kapandı: doğrudan sunucuyla Hazır');
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
    await hostApi.revokeClientCertIfActive(tamperedClient);
    await hostApi.revokeClientCertIfActive(cleanClient);
  }
});
