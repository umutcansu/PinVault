// G05 — Kayıt yanıtındaki sertifika zinciri değiştirilirse.
//
// Kayıtta (enrollment) telefon kendi anahtarını üretir (Android Keystore,
// dışarı çıkmaz) ve sunucuya yalnızca bir sertifika isteği (CSR) gönderir;
// sunucu istemci CA'sıyla imzaladığı sertifikayı, CA sertifikasıyla birlikte
// bir zincir olarak döndürür. Araya giren biri bu zinciri kendi ürettiğiyle
// değiştirebilirse cihazın mTLS kimliği onun istediği bir sertifika olur.
//
// Kütüphanenin şartları (ClientCertRenewer.acceptIssuedChain), sertifika
// diske yazılmadan önce:
//   • zincir en az iki sertifika (yaprak + onu imzalayan CA),
//   • yaprak TELEFONUN anahtarı için kesilmiş olmalı,
//   • clientCaPins verilmişse (örnek uygulama host.clientCaPin ile verir)
//     yaprak o pin'li CA tarafından imzalanmış olmalı.
// Sunucunun eskiden verdiği hazır P12 (anahtarı sunucu üretir) ise
// allowServerGeneratedKey() olmadan hiç kabul edilmiyor.
//
// Saldırgan vekil (sunucunun kendi TLS anahtarıyla, yani pin tutuyor) iki kez
// araya girer: önce zinciri BAŞKA bir anahtar için kesilmiş bir sertifikayla,
// sonra telefonun kendi anahtarı için ama KENDİ CA'sıyla imzaladığı bir
// sertifikayla değiştirir. İkisinde de telefon sertifikayı kurmaz; vekil
// bırakınca temiz kayıt tamamlanır.
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

/** Uygulamanın derlendiği istemci CA pin'i (global setup'ın yazdığı host.clientCaPin). */
function builtClientCaPin() {
  const props = fs.existsSync(env.PROPS_FILE) ? fs.readFileSync(env.PROPS_FILE, 'utf8') : '';
  const m = props.match(/^host\.clientCaPin=(.*)$/m);
  return m ? m[1].trim() : '';
}

const chainLines = (chain) =>
  chain.map((c, i) => `  [${i}] konu: ${c.subject}\n      yayımcı: ${c.issuer}\n      anahtar (SPKI pin): ${c.spki}`).join('\n');

test('Saldırı: kayıt yanıtındaki sertifika zinciri değiştirilir (başka anahtar / saldırganın CA\'sı) → telefon sertifikayı kurmuyor; temiz kayıt tamamlanıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  const stamp = Date.now();
  const otherKeyClient = `g05-baska-anahtar-${stamp}`;
  const rogueCaClient = `g05-sahte-ca-${stamp}`;
  const cleanClient = `g05-temiz-${stamp}`;
  const caPin = builtClientCaPin();
  const tokens = {};
  let mitm;

  /**
   * Vekil zinciri [mode] ile değiştirirken [token] ile kayıt dener. Telefonun
   * cevabını, kabloda değişeni ve cihaz günlüğünü kanıt olarak ekler.
   */
  async function tamperedEnrollment(mode, token, title) {
    const seen = [];
    mitm.setMutate(proxy.forgeEnrollmentChain(mode, seen));
    device.clearLogcat();
    await app.openMtls();
    const status = await app.enroll(token);
    await app.snap(`${title}: kayıt başarısız`);
    const logcat = device
      .logcat({ match: /Issued (chain|certificate)|clientCaPins|Enrollment failed|SecurityException/, lines: 4000 })
      .split('\n')
      .slice(-8)
      .join('\n');
    const wire = seen[0];
    await attachText(
      testInfo,
      `${title} (POST ${wire ? wire.path : '/api/v1/client-certs/enroll'})`,
      [
        'SUNUCUNUN GÖNDERDİĞİ ZİNCİR',
        wire ? chainLines(wire.before) : '(kayıt yanıtı görülmedi)',
        '',
        'TELEFONUN ALDIĞI ZİNCİR (saldırgan değiştirdi)',
        wire ? chainLines(wire.after) : '-',
        '',
        `uygulamanın istemci CA pin'i (host.clientCaPin): ${caPin || '(yok)'}`,
        '',
        'TELEFONUN CEVABI',
        status.split('\n').slice(0, 3).join('\n'),
        '',
        'Cihazın günlüğü:',
        logcat || '(ilgili satır yok)',
      ].join('\n'),
    );
    mitm.setMutate(null);
    return { status, logcat, wire };
  }

  /** Reddedilen kayıt sunucuda iz bırakır: sertifika kesildi, token harcandı. Kimlik iptal edilir. */
  async function serverTrace(clientId, title) {
    const certs = (await hostApi.clientCerts()).filter((c) => c.id === clientId);
    const toks = (await hostApi.enrollmentTokens()).filter((t) => t.clientId === clientId);
    const revoked = await hostApi.revokeClientCertIfActive(clientId);
    await attachText(
      testInfo,
      `${title}: sunucu tarafı`,
      [
        `istemci kimliği: ${clientId}`,
        `sunucunun kestiği sertifika: ${certs.length} (${certs.map((c) => (c.revoked ? 'iptal' : 'etkin')).join(', ') || '-'})`,
        `token durumu: ${toks.map((t) => (t.used ? 'kullanıldı' : 'kullanılmadı')).join(', ') || '-'}`,
        `iptal edildi: ${revoked ? 'evet' : 'hayır (zaten etkin değildi)'}`,
        '',
        'Sunucu isteği karşıladı (telefonun anahtarı için sertifika kesti, tek kullanımlık token',
        'harcandı); sertifikayı telefon kurmadı. Operasyon notu: böyle bir kimlik iptal edilir',
        've telefona yeni token verilir. Bir cihazın aynı anda tek etkin kimliği olabildiği için',
        'iptal edilmeden sonraki kayıt da reddedilirdi (device_already_enrolled).',
      ].join('\n'),
    );
    return certs;
  }

  try {
    await test.step('Web: üç tek kullanımlık kayıt token\'ı üretilir (iki saldırı denemesi + temiz kayıt)', async () => {
      tokens.otherKey = await dashboard.generateEnrollmentToken(env.MTLS_API, otherKeyClient);
      tokens.rogueCa = await dashboard.generateEnrollmentToken(env.MTLS_API, rogueCaClient);
      tokens.clean = await dashboard.generateEnrollmentToken(env.MTLS_API, cleanClient);
      await dashboard.snapTokenList(env.MTLS_API, 'üç kayıt token\'ı bekliyor', [
        { clientId: otherKeyClient, status: 'Bekliyor' },
        { clientId: rogueCaClient, status: 'Bekliyor' },
        { clientId: cleanClient, status: 'Bekliyor' },
      ]);
      expect(new Set(Object.values(tokens)).size).toBe(3);
      // Uygulama istemci CA pin'iyle derlenmiş olmalı: ikinci denemeyi yalnızca o yakalar.
      expect(caPin, 'host.clientCaPin boş: global setup istemci CA\'sını okuyamadı').toMatch(/^[A-Za-z0-9+/]{43}=$/);
    });

    await test.step('Mobil: cihaz henüz kayıtlı değil', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.snap('kayıt öncesi');
      await app.backToMain();
    });

    await test.step('Saldırgan: sunucunun kendi anahtarıyla araya girer, henüz bir şey değiştirmiyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: telefon Hazır');
      expect(ready).toContain('Hazır — config v');
    });

    await test.step('Saldırgan: kayıt yanıtındaki zinciri BAŞKA bir anahtar için kesilmiş sertifikayla değiştirir → telefon "Kayıt başarısız", sertifika kurulmadı', async () => {
      const { status, logcat, wire } = await tamperedEnrollment('other-key', tokens.otherKey, 'Başka anahtar için sertifika');
      expect(wire, 'vekil kayıt yanıtını görmedi').toBeTruthy();
      expect(wire.before.length).toBeGreaterThanOrEqual(2);
      expect(wire.after[0].spki).not.toBe(wire.before[0].spki);
      expect(status).toContain('Kayıt başarısız');
      expect(`${status}\n${logcat}`).toMatch(/not over this device's key/);
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
      await serverTrace(otherKeyClient, 'Başka anahtar için sertifika');
    });

    await test.step('Saldırgan: zinciri telefonun KENDİ anahtarı için ama kendi CA\'sıyla imzaladığı sertifikayla değiştirir → istemci CA pin\'i tutmuyor, telefon kurmuyor', async () => {
      const { status, logcat, wire } = await tamperedEnrollment('rogue-ca', tokens.rogueCa, 'Saldırganın CA\'sıyla imzalı sertifika');
      expect(wire, 'vekil kayıt yanıtını görmedi').toBeTruthy();
      // Yaprak telefonun anahtarı için (sunucununkiyle aynı SPKI), CA saldırganın.
      expect(wire.after[0].spki).toBe(wire.before[0].spki);
      expect(wire.after[1].spki).not.toBe(caPin);
      expect(wire.before[1].spki).toBe(caPin);
      expect(status).toContain('Kayıt başarısız');
      expect(`${status}\n${logcat}`).toMatch(/not signed by a pinned client CA/);
      expect(app.enrollState()).toContain('Kayıtlı değil');
      await app.backToMain();
      await serverTrace(rogueCaClient, 'Saldırganın CA\'sıyla imzalı sertifika');
    });

    await test.step('Mobil: cihazda istemci sertifikası saklanmadı (Depolama ekranı)', async () => {
      await app.openStorage();
      const storage = await app.storageText();
      await app.snap('iki saldırı denemesinden sonra: sertifika saklanmadı');
      await attachText(
        testInfo,
        'Cihazdaki istemci sertifikası kaydı',
        [
          storage.split('\n').filter((line) => /İstemci sertifikası|kayıtlı|pinvault_secure_client_cert|elle yüklenen/i.test(line)).join('\n'),
          '',
          'Zincir diske YAZILMADAN önce denetleniyor (acceptIssuedChain): en az iki sertifika,',
          'yaprak bu cihazın anahtarı için, istemci CA pin\'iyle imzalı. Biri tutmazsa',
          'certStore.saveChain hiç çağrılmıyor.',
        ].join('\n'),
      );
      expect(storage).toContain('kayıtlı değil');
      await app.backToMain();
    });

    await test.step('Saldırgan: değiştirmeyi bırakınca üçüncü token ile kayıt tamamlanıyor', async () => {
      mitm.setMutate(null);
      await app.openMtls();
      const status = await app.enroll(tokens.clean);
      await app.snap('saldırgan değiştirmeyi bıraktı: kayıt başarılı');
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
      expect(storage).toContain(`kayıtlı — CN=PinVault Client: ${cleanClient}`);
      expect(storage).not.toContain('EVET ✗ (şifresiz!)');
      await app.backToMain();
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      expect(await app.waitReady()).toContain('Hazır — config v');
      await app.snap('saldırgan vekil kapandı: doğrudan sunucuyla Hazır');
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
    // İptal + unut: token'lar telefona bağlı (bkz. retireClientIdentity). Saldırı
    // denemelerinin kimlikleri adım içinde yalnızca iptal edildi: unutmak anahtarı
    // emekliye ayırır, telefon bir sonraki denemede aynı anahtarı kullanıyor olabilir.
    for (const id of [otherKeyClient, rogueCaClient, cleanClient]) {
      await hostApi.retireClientIdentity(id);
    }
  }
});
