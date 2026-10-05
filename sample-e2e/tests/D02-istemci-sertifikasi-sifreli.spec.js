// D02 — İstemci sertifikası (P12) cihazda şifreli.
//
// ClientCertSecureStore P12 baytlarını `shared_prefs/pinvault_secure_client_cert.xml`
// içinde saklıyor: değer AES-256-GCM, kayıt adı HMAC, ikisinin anahtarı Android
// Keystore'da. Ham kayıt PKCS12 olarak açılmıyor (özel anahtarı dosyayı
// kopyalayan biri çıkaramaz), ama kütüphane aynı kaydı çözüp sertifikanın CN'ini
// gösterebiliyor ve mTLS el sıkışmasında kullanabiliyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, hexdump } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const PREFS = 'shared_prefs/pinvault_secure_client_cert.xml';

test('Depolama: istemci sertifikası şifreli saklanıyor, ham kayıt PKCS12 olarak açılmıyor', async ({
  app,
  device,
  dashboard,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const clientId = `d02-${Date.now()}`;
  const cn = `PinVault Client: ${clientId}`;

  try {
    await test.step('Mobil: kayıt öncesi depoda sertifika yok', async () => {
      await app.openStorage();
      const before = await app.refreshStorage();
      await app.snap('Depolama ekranı — kayıt öncesi');
      expect(before).toContain('kayıtlı değil');
      await app.backToMain();
    });

    await test.step('Web+Mobil: cihaz kayıt token\'ıyla sertifikasını alıyor', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      await dashboard.snapTokenList(env.MTLS_API, `kayıt token'ı üretildi: ${clientId} bekliyor`, [{ clientId, status: 'Bekliyor' }]);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=${cn}`);
      await app.snap('kayıt başarılı');
      expect(app.enrollState()).toContain(cn);
      await app.backToMain();
    });

    await test.step('Cihaz: ham kayıt şifreli, PKCS12 dosyası gibi başlamıyor', async () => {
      const xml = device.appFileText(env.APP_ID, PREFS);
      const entries = [...xml.matchAll(/<string name="([^"]+)">([^<]*)<\/string>/g)];
      expect(entries.length).toBeGreaterThan(0);
      const raw = Buffer.from(entries[0][2], 'base64');
      // PKCS12 dosyaları DER SEQUENCE ile başlar: 0x30 0x82 …
      const looksLikeP12 = raw[0] === 0x30 && raw[1] === 0x82;
      await attachText(
        testInfo,
        `adb shell run-as ${env.APP_ID} cat ${PREFS}`,
        [
          xml.length > 1200 ? `${xml.slice(0, 1200)}\n… (${xml.length - 1200} karakter daha)` : xml,
          '',
          `veri kaydı sayısı: ${entries.length}`,
          `kayıt adı (HMAC): ${entries[0][0]}`,
          `çözülmemiş değer: ${raw.length} bayt`,
          '',
          hexdump(raw, 64),
          '',
          `PKCS12 dosyalarının ilk baytlarıyla (30 82) başlıyor mu: ${looksLikeP12 ? 'EVET ✗' : 'hayır ✓'}`,
          `sertifika CN'i ("${clientId}") dosyada düz geçiyor mu: ${xml.includes(clientId) ? 'EVET ✗' : 'hayır ✓'}`,
          '',
          'Kayıt adı da şifreli olduğu için dosyaya bakan biri burada bir istemci',
          'sertifikası durduğunu bile anlayamıyor.',
        ].join('\n'),
      );
      expect(looksLikeP12).toBe(false);
      expect(xml).not.toContain(clientId);
      expect(xml).not.toContain('client_p12');
    });

    await test.step('Mobil: Depolama ekranı çözülmüş CN\'i gösteriyor, ham kaydı açamıyor', async () => {
      await app.openStorage();
      const text = await app.refreshStorage();
      await app.snap('Depolama ekranı — şifreli istemci sertifikası');
      await attachText(
        testInfo,
        'Depolama ekranı dökümü',
        [
          text,
          '',
          'Ekran iki şeyi ayrı ayrı gösteriyor: kütüphane kaydı çözüp CN\'i verebiliyor',
          '(PinVault.enrolledClientCN), aynı ham değer PKCS12 olarak açılmaya',
          'çalışıldığında açılmıyor.',
        ].join('\n'),
      );
      expect(text).toContain(`kayıtlı — CN=${cn}`);
      expect(text).toContain('ham kayıt PKCS12 olarak açılıyor mu: hayır ✓ (şifreli)');
      expect(text).toContain('pinvault_secure_client_cert.xml');
      expect(text).toContain('düz metin sızıntısı (host adı, IP, pin): yok');
      await app.backToMain();
    });

    await test.step('Mobil: aynı sertifikayla mTLS bağlantısı kuruluyor', async () => {
      await app.openMtls();
      const result = await app.expectMtls(true);
      await app.snap('şifreli depodan okunan sertifikayla mTLS bağlantısı');
      expect(result).toContain('HTTP 200');
      await attachText(
        testInfo,
        'mTLS bağlantısı',
        [result, '', 'Depodaki değer gerçekten kullanılabilir bir P12: yalnızca diskte şifreli.'].join('\n'),
      );
      await app.backToMain();
    });
  } finally {
    // İptal + unut: token telefona bağlı, kimlik cihazı kanıtlıyor (bkz. retireClientIdentity).
    await hostApi.retireClientIdentity(clientId);
  }
});
