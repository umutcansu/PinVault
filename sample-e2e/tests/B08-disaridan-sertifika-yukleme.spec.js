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
const CA_KEY = path.join(WORK_DIR, 'outside-ca-key.pem');
const CA_CERT = path.join(WORK_DIR, 'outside-ca-cert.pem');
const OPENSSL_CONF = path.join(WORK_DIR, 'client-leaf.cnf');
const CA_CONF = path.join(WORK_DIR, 'ca.cnf');
const V1_KEY = path.join(WORK_DIR, 'outside-v1-key.pem');
const V1_CERT = path.join(WORK_DIR, 'outside-v1-cert.pem');
const CONFIG_URL = `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/certificate-config?signed=false`;

/**
 * Yönetim adresine panelin gönderdiği formun aynısını yollar (clientId + dosya).
 * Reddedilen yüklemede panel satır çizmediği için sonucu doğrudan okumak gerekiyor.
 */
async function uploadDirect(clientId, certPath) {
  const form = new FormData();
  form.append('clientId', clientId);
  form.append('file', new Blob([fs.readFileSync(certPath)]), path.basename(certPath));
  const res = await fetch(`${env.WEB_URL}/api/v1/client-certs/upload`, {
    method: 'POST',
    headers: { 'X-API-Key': env.API_KEY },
    body: form,
  });
  return { status: res.status, body: (await res.text()).trim() };
}

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
    await test.step('Terminal: CA sertifikası istemci sertifikası diye yüklenemiyor', async () => {
      // Bir CA sertifikası truststore'a girseydi, anahtarının imzaladığı HER
      // sertifika mTLS'te kabul edilirdi: tek yüklemeyle listede olmayan istemciler.
      const caId = `${clientId}-ca`;
      fs.writeFileSync(CA_CONF, [
        '[req]', 'distinguished_name = dn', 'x509_extensions = ca', '[dn]', '[ca]',
        'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign', '',
      ].join('\n'));
      await attachCommand(testInfo, 'openssl req -x509 (CA:TRUE, keyCertSign)', 'openssl', [
        'req', '-x509', '-config', CA_CONF, '-newkey', 'rsa:2048', '-nodes',
        '-keyout', CA_KEY, '-out', CA_CERT, '-days', '30',
        '-subj', `/CN=${caId}/O=SamplePinVaultE2E/C=TR`,
      ]);
      const ext = execFileSync('openssl', ['x509', '-in', CA_CERT, '-noout', '-text'], { encoding: 'utf8' });
      const res = await uploadDirect(caId, CA_CERT);
      const listed = (await hostApi.clientCerts()).some((c) => c.id === caId);
      await attachText(
        testInfo,
        'POST /api/v1/client-certs/upload (CA sertifikası)',
        [
          `HTTP ${res.status} ${res.body}`,
          '',
          (ext.match(/X509v3 Basic Constraints:[^\n]*\n[^\n]*/) || ['Basic Constraints yok'])[0].trim(),
          `listede: ${listed}`,
          '',
          'Sunucu CA sertifikasını (basicConstraints CA veya keyCertSign) ve',
          'clientAuth kullanımı yazmayan sertifikayı istemci olarak kabul etmiyor.',
        ].join('\n'),
      );
      expect(res.status).toBe(400);
      expect(res.body).toContain('CA certificate');
      expect(listed).toBe(false);

      // Eklentisiz (v1) bir sertifika "CA değilim" diyemez; JSSE böyle bir
      // güven çapasının başka sertifika imzalamasına izin verir. O da reddediliyor.
      const v1Id = `${clientId}-v1`;
      fs.writeFileSync(path.join(WORK_DIR, 'v1.cnf'), '[req]\ndistinguished_name = dn\n[dn]\n');
      execFileSync('openssl', ['req', '-x509', '-config', path.join(WORK_DIR, 'v1.cnf'), '-newkey', 'rsa:2048', '-nodes',
        '-keyout', V1_KEY, '-out', V1_CERT, '-days', '30', '-subj', `/CN=${v1Id}/O=SamplePinVaultE2E/C=TR`], { encoding: 'utf8' });
      const v1Version = execFileSync('openssl', ['x509', '-in', V1_CERT, '-noout', '-text'], { encoding: 'utf8' }).match(/Version: (\d+)/);
      const v1 = await uploadDirect(v1Id, V1_CERT);
      await attachText(
        testInfo,
        'POST /api/v1/client-certs/upload (eklentisiz v1 sertifika)',
        [`sertifika sürümü: ${v1Version ? v1Version[1] : '?'}`, `HTTP ${v1.status} ${v1.body}`].join('\n'),
      );
      expect(v1.status).toBe(400);
      expect(v1.body).toMatch(/version 1 certificate|extended key usage/);
      expect((await hostApi.clientCerts()).some((c) => c.id === v1Id)).toBe(false);
    });

    await test.step('Terminal: openssl ile anahtar çifti ve istemci sertifikası üretiliyor', async () => {
      fs.writeFileSync(OPENSSL_CONF, [
        '[req]',
        'distinguished_name = dn',
        'x509_extensions = client_leaf',
        '[dn]',
        '[client_leaf]',
        'basicConstraints = critical, CA:FALSE',
        'keyUsage = critical, digitalSignature, keyEncipherment',
        'extendedKeyUsage = clientAuth',
        '',
      ].join('\n'));
      const out = await attachCommand(testInfo, 'openssl req -x509 (self-signed istemci sertifikası, CA:FALSE + clientAuth)', 'openssl', [
        'req', '-x509', '-config', OPENSSL_CONF, '-newkey', 'rsa:2048', '-nodes',
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
