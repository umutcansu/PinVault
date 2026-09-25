// B08 — Dışarıdan üretilmiş bir istemci sertifikasının truststore'a yüklenmesi.
//
// Sertifika ve özel anahtar openssl ile bu makinede üretiliyor; sunucuya
// yalnızca PEM sertifika yükleniyor (özel anahtar hiç gitmiyor). Sunucu onu
// client-truststore.jks'e ekliyor ve o anahtar/sertifika çiftiyle mTLS Config
// API'ye bağlanılabiliyor. İptal edilince aynı çift reddediliyor.
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const WORK_DIR = path.join(env.LOCAL_DIR, 'b08');
const KEY = path.join(WORK_DIR, 'outside-key.pem');
const CERT = path.join(WORK_DIR, 'outside-cert.pem');
const CONFIG_URL = `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/certificate-config?signed=false`;

/** curl'ü istemci sertifikasıyla çalıştırır; { ok, output } döner. */
function probe() {
  try {
    const out = execFileSync(
      'curl',
      ['-sS', '-k', '--cert', CERT, '--key', KEY, '-o', '/dev/null', '-w', 'HTTP %{http_code}', '--max-time', '15', CONFIG_URL],
      { encoding: 'utf8', timeout: 30_000 },
    );
    return { ok: out.includes('HTTP 200'), output: out.trim() };
  } catch (e) {
    return { ok: false, output: `${e.stdout || ''}${e.stderr || ''}`.trim() || `exit ${e.status}` };
  }
}

test('mTLS: dışarıdan yüklenen istemci sertifikası truststore\'a girer ve iptal edilebilir', async ({
  dashboard,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const clientId = `b08-outside-${Date.now()}`;
  fs.mkdirSync(WORK_DIR, { recursive: true });

  try {
    await test.step('Terminal: openssl ile anahtar çifti ve sertifika üretiliyor', async () => {
      const out = await attachCommand(testInfo, 'openssl req -x509 (self-signed istemci sertifikası)', 'openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', KEY, '-out', CERT, '-days', '30',
        '-subj', `/CN=${clientId}/O=SamplePinVaultE2E/C=TR`,
      ]);
      const subject = execFileSync('openssl', ['x509', '-in', CERT, '-noout', '-subject', '-dates'], {
        encoding: 'utf8',
      });
      await attachText(
        testInfo,
        'Üretilen sertifika',
        [
          out.trim(),
          subject.trim(),
          '',
          `özel anahtar: ${path.basename(KEY)} — yalnızca bu makinede kalıyor`,
          `sertifika    : ${path.basename(CERT)} — sunucuya yüklenecek olan`,
        ].join('\n'),
      );
      expect(subject).toContain(clientId);
    });

    await test.step('Web: sertifika "Client Cert Yükle" ile truststore\'a ekleniyor', async () => {
      const response = await dashboard.uploadTrustedClientCert(env.MTLS_API, clientId, CERT);
      await dashboard.snap(`dışarıdan yüklenen sertifika: ${clientId}`);
      const cert = (await hostApi.clientCerts()).find((c) => c.id === clientId);
      await attachText(
        testInfo,
        'POST /api/v1/client-certs/upload',
        [
          response,
          '',
          `listedeki kayıt: id=${cert.id}, commonName=${cert.commonName}, revoked=${cert.revoked}`,
          '',
          'Sunucu CertificateService.importClientCertificate: sertifikayı X.509 olarak',
          'okuyup client-truststore.jks\'e takma adla ekliyor. Özel anahtar istenmiyor.',
        ].join('\n'),
      );
      expect(cert.revoked).toBe(false);
      expect(cert.commonName).toContain(clientId);
    });

    await test.step('Terminal: yüklenen sertifika, sunucu elle yeniden başlatılmadan kabul ediliyor', async () => {
      // Yükleme dinleyicileri yeniden başlatıyor; kabul döngüsü birkaç yüz ms
      // sonra hazır olabiliyor. Elle hiçbir tazeleme yapılmıyor.
      let after = { ok: false, output: '' };
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        after = probe();
        if (after.ok) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      await attachText(
        testInfo,
        'curl --cert (yüklemeden sonra, elle yeniden başlatma yok)',
        [
          after.output,
          '',
          '/client-certs/upload truststore dosyasını güncelledikten sonra çalışan',
          'mTLS sunucularını da yeniden başlatıyor (Main.kt refreshMtlsTrust;',
          '/client-certs/generate, /enroll ve iptal adresi de aynı yardımcıyı kullanıyor).',
          'Eskiden yalnızca dosya yazılıyordu; sunucu açılışta okuduğu truststore\'u',
          'kullanmaya devam ettiği için aynı anahtar/sertifika çifti reddediliyordu.',
        ].join('\n'),
      );
      expect(after.ok).toBe(true);
    });

    await test.step('Web+Terminal: mTLS Config API elle yeniden başlatılınca da aynı çift kabul ediliyor', async () => {
      const report = await mtlsScope.refreshTrust(dashboard, { withMock: false });
      await dashboard.snap('mTLS Config API yeniden başlatıldı');
      const out = await attachCommand(testInfo, 'curl --cert --key (yeniden başlatmadan sonra)', 'curl', [
        '-sS', '-k', '--cert', CERT, '--key', KEY, '-o', '/dev/null',
        '-w', 'HTTP %{http_code}\n', '--max-time', '20', CONFIG_URL,
      ]);
      await attachText(
        testInfo,
        'Dashboard işlemi + sonuç',
        [
          report,
          '',
          'Sunucuya hiç gitmemiş bir özel anahtarla mTLS el sıkışması tamamlandı:',
          'güven yalnızca yüklenen sertifikadan geliyor.',
        ].join('\n'),
      );
      expect(out).toContain('HTTP 200');
    });

    await test.step('Web: sertifika iptal ediliyor', async () => {
      await dashboard.revokeClientCert(env.MTLS_API, clientId);
      await dashboard.expectClientCert(env.MTLS_API, clientId, { revoked: true });
      await dashboard.snap('dışarıdan yüklenen sertifika iptal edildi');
      const cert = (await hostApi.clientCerts()).find((c) => c.id === clientId);
      expect(cert.revoked).toBe(true);
    });

    await test.step('Terminal: iptal edilen sertifikayla bağlantı reddediliyor', async () => {
      // İptal mTLS dinleyicilerini yeniden başlatıyor; ilk deneme kısa bir
      // geçişe denk gelebiliyor.
      let last = { ok: true, output: '' };
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline) {
        last = probe();
        if (!last.ok) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      await attachText(
        testInfo,
        'curl --cert --key (iptalden sonra)',
        [
          last.output,
          '',
          'DELETE /api/v1/client-certs/{id} sertifikayı truststore\'dan siliyor ve mTLS',
          'sunucularını yeni truststore ile yeniden başlatıyor; el sıkışma artık',
          '"certificate unknown" hatasıyla başarısız oluyor.',
        ].join('\n'),
      );
      expect(last.ok).toBe(false);
    });
  } finally {
    await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
