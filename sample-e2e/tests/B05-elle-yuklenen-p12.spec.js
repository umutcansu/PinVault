// B05 — Elle yüklenen istemci sertifikası (ConfigApiBlock.clientKeystore).
//
// Kayıt akışı hiç kullanılmıyor: dashboard'da üretilen P12 dosyası cihazın
// files/ dizinine konuyor, uygulama onu `clientKeystore(bytes, password)` ile
// mTLS bloğuna veriyor ve cihaz bu sertifikayla hem mTLS Config API'ye hem de
// mock mTLS hedefine bağlanıyor.
//
// Yol boyunca sunucu davranışı da kanıtlanıyor: `client-certs/generate`
// sertifikayı truststore dosyasına yazdıktan sonra ayakta olan mTLS
// dinleyicilerini de tazeliyor, yani P12 indiği anda kullanılabiliyor
// (eskiden dinleyiciler yeniden başlatılana kadar reddediyordu).
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const WORK_DIR = path.join(env.LOCAL_DIR, 'b05');
const P12 = path.join(WORK_DIR, 'manual-client.p12');
const CERT_PEM = path.join(WORK_DIR, 'manual-cert.pem');
const KEY_PEM = path.join(WORK_DIR, 'manual-key.pem');
const CONFIG_URL = `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/certificate-config?signed=false`;

/** curl'ü elle yüklenen sertifikayla çalıştırır; başarı durumunu döndürür. */
function probe() {
  try {
    const out = execFileSync(
      'curl',
      ['-sS', '-k', '--cert', CERT_PEM, '--key', KEY_PEM, '-o', '/dev/null',
        '-w', 'HTTP %{http_code}', '--max-time', '15', CONFIG_URL],
      { encoding: 'utf8', timeout: 30_000 },
    );
    return out.includes('HTTP 200');
  } catch (e) {
    return false;
  }
}

test('mTLS: kayıt olmadan, elle yüklenen P12 ile bağlanma', async ({ app, device, dashboard }, testInfo) => {
  test.setTimeout(14 * 60 * 1000);
  const clientId = `b05-manual-${Date.now()}`;
  fs.mkdirSync(WORK_DIR, { recursive: true });

  try {
    await test.step('Web: dashboard\'da istemci sertifikası üretilir (P12 dosyası indirilir)', async () => {
      await dashboard.generateClientCert(env.MTLS_API, clientId, { saveTo: P12 });
      execFileSync('openssl', ['pkcs12', '-in', P12, '-passin', 'pass:changeit', '-nokeys', '-out', CERT_PEM]);
      execFileSync('openssl', ['pkcs12', '-in', P12, '-passin', 'pass:changeit', '-nocerts', '-nodes', '-out', KEY_PEM]);
      const subject = execFileSync('openssl', ['x509', '-in', CERT_PEM, '-noout', '-subject'], { encoding: 'utf8' }).trim();
      await dashboard.snap(`istemci sertifikası üretildi: ${clientId}`);
      await attachText(
        testInfo,
        'İndirilen P12',
        [`${path.basename(P12)} — ${fs.statSync(P12).size} bayt`, subject, 'parola: changeit'].join('\n'),
      );
      expect(subject).toContain(clientId);
    });

    await test.step('Terminal: çalışan mTLS Config API yeni sertifikayı hemen tanıyor', async () => {
      // Elle hiçbir şey yapılmıyor; yalnızca dinleyicinin yeniden başlatma
      // sonrası soketi açması bekleniyor (sunucu yanıtı dönmeden restart'ı
      // tetikliyor, kabul döngüsü birkaç yüz ms sonra hazır oluyor).
      await expect.poll(probe, { timeout: 30_000, intervals: [500, 1000, 2000] }).toBe(true);
      const out = await attachCommand(
        testInfo,
        'curl --cert (üretimden hemen sonra, elle yeniden başlatma yok)',
        'curl',
        ['-sS', '-k', '--cert', CERT_PEM, '--key', KEY_PEM, '-o', '/dev/null',
          '-w', 'HTTP %{http_code}\n', '--max-time', '20', CONFIG_URL],
      );
      await attachText(
        testInfo,
        'Yeni istemci sertifikası çalışan mTLS sunucularına anında yansıyor',
        [
          out.trim(),
          '',
          'POST /api/v1/client-certs/generate (ve /upload) sertifikayı',
          'data/certs/client-truststore.jks dosyasına ekledikten sonra mTLS Config',
          'API\'leri ve mock mTLS sunucularını güncel truststore ile yeniden',
          'başlatıyor — /client-certs/enroll ve DELETE /client-certs/{id} ile aynı',
          'ortak yardımcı (Main.kt refreshMtlsTrust). Eskiden yalnızca dosya',
          'yazılıyordu ve çalışan sunucular sertifikayı "certificate unknown"',
          'ile reddediyordu.',
        ].join('\n'),
      );
      expect(out).toContain('HTTP 200');
    });

    await test.step('Web: mTLS sunucuları elle yeniden başlatılınca da sertifika kabul ediliyor', async () => {
      const report = await mtlsScope.refreshTrust(dashboard);
      await dashboard.snap('mTLS sunucuları yeniden başlatıldı');
      const out = await attachCommand(
        testInfo,
        'curl --cert (yeniden başlatmadan sonra)',
        'curl',
        ['-sS', '-k', '--cert', CERT_PEM, '--key', KEY_PEM, '-o', '/dev/null',
          '-w', 'HTTP %{http_code}\n', '--max-time', '20', CONFIG_URL],
      );
      await attachText(testInfo, 'Dashboard işlemleri', report);
      expect(out).toContain('HTTP 200');
    });

    await test.step('Web: mTLS Config API\'ye host\'lar eklenir', async () => {
      const report = await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await dashboard.snap('mTLS Config API\'nin host\'ları hazır');
      await attachText(testInfo, 'mTLS Config API\'deki host\'lar', report);
    });

    await test.step('Terminal: P12 cihazın uygulama dizinine kopyalanır', async () => {
      device.pushToApp(env.APP_ID, P12, 'files/manual-client.p12');
      const listing = device.appFiles(env.APP_ID, 'files');
      await attachText(
        testInfo,
        `adb push + run-as ${env.APP_ID} (files/)`,
        [`kaynak: ${P12}`, `hedef : files/manual-client.p12`, '', listing.trim()].join('\n'),
      );
      expect(listing).toContain('manual-client.p12');
    });

    await test.step('Mobil: "P12 içe aktar" ile sertifika mTLS bloğuna veriliyor', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const result = await app.toggleManualP12();
      await app.snap('elle P12 içe aktarıldı');
      expect(result).toContain(`P12 içe aktarıldı — CN=PinVault Client: ${clientId}`);
      expect(app.enrollState()).toContain('Elle yüklenen P12 kullanılıyor');
      await attachText(
        testInfo,
        'Uygulamanın sonucu',
        [result, '', 'Kayıt (enroll) yapılmadı: sertifika depoda değil, dosyadan okunup',
          'ConfigApiBlock.clientKeystore(bytes, "changeit") ile veriliyor.'].join('\n'),
      );
      await app.backToMain();
    });

    await test.step('Mobil: Depolama ekranı elle yüklenen P12\'yi gösteriyor', async () => {
      await app.openStorage();
      const text = await app.storageText();
      await app.snap('Depolama: elle yüklenen P12');
      await attachText(
        testInfo,
        'Depolama ekranı (ilgili satırlar)',
        text.split('\n').filter((l) => /İstemci sertifikası|kayıtlı|elle yüklenen/i.test(l)).join('\n'),
      );
      expect(text).toContain('elle yüklenen P12');
      expect(text).toContain('(kullanılıyor)');
      await app.backToMain();
    });

    await test.step('Mobil: mTLS config modunda iki hedefe de bağlanıyor', async () => {
      await app.openSettings();
      expect(await app.applyMode('MTLS_CONFIG')).toContain('Hazır — config v');
      await app.backToMain();
      await app.snap('elle P12 ile mTLS config modu hazır');
      await app.openMtls();
      const api = await app.expectMtls(true);
      await app.snap('elle P12 ile Config API bağlantısı');
      const mock = await app.expectMockMtls(true);
      await app.snap('elle P12 ile mock mTLS host bağlantısı');
      await app.backToMain();
      expect(api).toContain('HTTP 200');
      expect(mock).toContain('HTTP 200');
      await attachText(testInfo, 'Elle P12 ile iki bağlantı', [api, '', mock].join('\n'));
    });

    await test.step('Mobil: TLS moduna dönülüp elle P12 bırakılıyor', async () => {
      await app.openSettings();
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
      await app.openMtls();
      const result = await app.toggleManualP12();
      expect(result).toContain('Elle P12 bırakıldı');
      expect(app.enrollState()).toContain('Kayıtlı değil');
      expect(app.enrollState()).not.toContain('Elle yüklenen P12 kullanılıyor');
      await app.snap('elle P12 bırakıldı');
      await app.backToMain();
    });
  } finally {
    await mtlsScope.reset().catch(() => {});
    await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
