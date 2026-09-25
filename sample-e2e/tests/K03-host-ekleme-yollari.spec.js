// Kurulum yolculuğu K6: host ekleme üç yolla — elle pin, sunucuda sertifika
// üretme, URL'den pin çekme — ve hatalı biçimli pin'in reddi. Geçici test
// sunucusunda çalışır (her ekleme config sürümünü artırır).
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const MANUAL_HOST = 'manual.sample';
const GENERATED_HOST = 'generated.sample';
const FETCH_HOST = env.TARGET_HOST;
const BROKEN_HOST = 'bozuk.sample';
const UPLOAD_HOST = 'uploaded.sample';
const UPLOAD_JKS = 'k03-upload-source.jks';

/** Taze config'ten host adları. */
async function hostsOf() {
  const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
  return (cfg.json.pins || []).map((p) => p.hostname);
}

test('Kurulum: host dört yolla eklenir (elle, sertifika üreterek, URL\'den, dosya yükleyerek); hatalı pin reddedilir', async ({ browser }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  await fresh.ensure();

  const dashboard = await fresh.openDashboard(browser, testInfo);
  const page = dashboard.page;

  try {
    await test.step('Web: pin\'ler elle girilerek host eklenir (K6)', async () => {
      const pins = [hostApi.randomPin(), hostApi.randomPin()];
      await dashboard.addHostManual('default-tls', MANUAL_HOST, pins);
      await dashboard.openHost(MANUAL_HOST);
      await dashboard.snap(`elle eklenen host: ${MANUAL_HOST}`);
      expect(await hostsOf()).toContain(MANUAL_HOST);
      await attachText(
        testInfo,
        'Elle girilen pin\'ler (44 karakter, Base64)',
        pins.map((p) => `${p}  (${p.length} karakter)`).join('\n'),
      );
    });

    await test.step('Web: sertifika sunucuda üretilerek host eklenir (K6)', async () => {
      await dashboard.addHostGenerate('default-tls', GENERATED_HOST);
      await dashboard.openHost(GENERATED_HOST);
      await dashboard.snap(`sunucuda üretilen sertifikayla host: ${GENERATED_HOST}`);
      const status = await fresh.api(`/api/v1/hosts/${GENERATED_HOST}/status?configApiId=default-tls`);
      await attachText(
        testInfo,
        `GET /api/v1/hosts/${GENERATED_HOST}/status`,
        `HTTP ${status.status}\n${status.text}`,
      );
      expect(status.json.keystorePath).toBeTruthy();
    });

    await test.step('Web: pin\'ler verilen URL\'deki sunucudan çekilerek host eklenir (K6)', async () => {
      await dashboard.addHostFromUrl('default-tls', `https://${FETCH_HOST}`);
      await expect(dashboard.hostItem(FETCH_HOST)).toBeVisible({ timeout: 30_000 });
      await dashboard.openHost(FETCH_HOST);
      await dashboard.snap(`URL'den çekilen pin'lerle host: ${FETCH_HOST}`);

      // Sunucunun çektiği pin'ler hedefin canlı zinciriyle aynı olmalı.
      const live = await hostApi.livePins(FETCH_HOST);
      const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
      const entry = cfg.json.pins.find((p) => p.hostname === FETCH_HOST);
      await attachText(
        testInfo,
        'Sunucunun çektiği pin\'ler ↔ hedefin şu an sunduğu sertifika zinciri',
        [`sunucu : ${entry.sha256.join('\n         ')}`, `hedef  : ${live.join('\n         ')}`].join('\n'),
      );
      expect(entry.sha256).toEqual(live);
    });

    await test.step('Web: JKS/P12 dosyası yüklenerek host eklenir (K6)', async () => {
      // Dışarıda üretilmiş anahtar çifti (container'daki keytool); "Yükle"
      // sekmesi dosyayı sunucuya verir, pin'ler sertifikadan hesaplanır.
      fs.rmSync(path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), { force: true });
      fresh.compose([
        'exec', '-T', 'pinvault-host', 'keytool', '-genkeypair',
        '-alias', 'server', '-keyalg', 'RSA', '-keysize', '2048',
        '-dname', `CN=${UPLOAD_HOST}, O=PinVault E2E`,
        '-ext', `SAN=dns:${UPLOAD_HOST}`,
        '-validity', '365',
        '-keystore', `/data/certs/${UPLOAD_JKS}`,
        '-storepass', 'changeit', '-keypass', 'changeit',
      ]);
      const pem = fresh.compose([
        'exec', '-T', 'pinvault-host', 'keytool', '-exportcert', '-rfc',
        '-alias', 'server', '-keystore', `/data/certs/${UPLOAD_JKS}`, '-storepass', 'changeit',
      ]);
      const certPin = hostApi.spkiPin(new crypto.X509Certificate(pem).raw);
      const result = await dashboard.addHostUpload('default-tls', UPLOAD_HOST, path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), 'changeit');
      await dashboard.openHost(UPLOAD_HOST);
      await dashboard.snapHostSummary(`JKS yükleyerek eklenen host: ${UPLOAD_HOST}`);
      const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
      const entry = cfg.json.pins.find((p) => p.hostname === UPLOAD_HOST);
      await attachText(
        testInfo,
        '"Dosya Yükle" sekmesi → POST /api/v1/hosts/upload-cert',
        [
          `yüklenen dosya: ${UPLOAD_JKS} (keytool, RSA 2048, parola changeit)`,
          `sertifikadan hesaplanan pin (keytool -exportcert çıktısından): ${certPin}`,
          '',
          `sunucu yanıtı: ${result}`,
          `config'teki pin'ler: ${entry ? entry.sha256.join(' | ') : '(yok)'}`,
          '',
          'Zincirde tek sertifika var, bu yüzden yedek pin birinci pin\'le aynı (importCertificate).',
        ].join('\n'),
      );
      expect(entry).toBeTruthy();
      expect(entry.sha256[0]).toBe(certPin);
    });

    await test.step('Web: hatalı biçimli pin reddedilir (K6)', async () => {
      const before = await hostsOf();
      const toast = await dashboard.addHostManualExpectingRejection('default-tls', BROKEN_HOST, [
        'kisa-pin',
        hostApi.randomPin(),
      ]);
      await dashboard.snap('hatalı biçimli pin reddedildi');
      await attachText(testInfo, 'Dashboard yanıtı', `girilen pin: "kisa-pin" (8 karakter)\ntoast: ${toast}`);
      expect(await hostsOf()).toEqual(before);
    });
  } finally {
    // Taze örnek sonraki senaryolarda da kullanılıyor: eklenen host'ları geri al.
    const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
    const keep = (cfg.json.pins || []).filter(
      (p) => ![MANUAL_HOST, GENERATED_HOST, FETCH_HOST, BROKEN_HOST, UPLOAD_HOST].includes(p.hostname),
    );
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } });
    fs.rmSync(path.join(fresh.DIR, 'data/certs', UPLOAD_JKS), { force: true });
    await page.close();
  }
});
