// H01 — Sunucu bağımsızlığı: kendi backend'in, kendi uç yolların.
//
// PinVault'un hiçbir yolu sabit değil: config, sağlık, kayıt, host sertifikası
// ve vault raporu uçlarının yolları ConfigApiBlock'ta tanımlanıyor. Bu
// senaryoda demo-server hiç kullanılmıyor; harness Mac'te kendi küçük HTTPS
// backend'ini açıyor (lib/custom-backend.js):
//
//   GET  /ping                → sağlık
//   GET  /ssl/pins            → kendi EC anahtarıyla imzalı config
//   GET  /files/<anahtar>     → vault dosyası (X-Vault-Version + imza)
//   POST /analytics/vault     → vault indirme raporu
//   POST /auth/register       → kayıt (bu örnek desteklemiyor: 501)
//
// Uygulamanın CUSTOM_BACKEND modu bu backend'e bağlanıyor; bootstrap pin'leri
// ve imzalama public key'i derleme sırasında APK'ya gömüldü. Kanıt: backend'in
// gördüğü istek yolları, telefonun ekranı ve ana host'un günlüğünde bu süre
// boyunca tek bir config/vault isteği olmaması.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const customBackend = require('../lib/custom-backend');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

/** Ana host günlüğünde işaret: o andan sonrasını ayırmak için son satır. */
function logMark() {
  const lines = hostControl.logs(5).trim().split('\n');
  return lines[lines.length - 1] || '';
}

function logsSince(mark) {
  const all = hostControl.logs(800);
  const idx = mark ? all.lastIndexOf(mark) : -1;
  return idx >= 0 ? all.slice(idx + mark.length) : all;
}

test('Sunucu bağımsızlığı: uygulama kendi backend\'ine özel uç yollarıyla bağlanıyor', async ({
  app,
  run,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);

  const flags = `ozel-backend-bayraklari-${Date.now()}`;
  let backend;
  let mark;

  try {
    await test.step('Terminal: harness kendi backend\'ini açar (kendi TLS ve imzalama anahtarıyla)', async () => {
      mark = logMark();
      backend = await customBackend.start({ pins: run.goodPins, vaultFiles: { [KEY]: flags } });
      const material = customBackend.material();
      await attachText(
        testInfo,
        'Harness backend\'i (demo-server değil)',
        [
          `adres          : ${backend.url}`,
          `TLS pin'leri   : ${material.pins.join(', ')}`,
          `APK'daki pin'ler: ${run.custom.pins.join(', ')}`,
          `imzalama public key: ${redact(material.signingPublicKey, 20)}`,
          `APK'daki key       : ${redact(run.custom.signingPublicKey, 20)}`,
          '',
          'Uç yolları (ConfigApiBlock ile eşleşiyor):',
          '  configEndpoint     = ssl/pins',
          '  healthEndpoint     = ping',
          '  enrollmentEndpoint = auth/register',
          '  clientCertEndpoint = certs/client',
          '  vaultReportEndpoint= analytics/vault',
          `  vaultFile(${KEY}).endpoint = files/${KEY}`,
          '',
          `dağıtılan pin'ler: ${TARGET_HOST} → ${run.goodPins.length} pin`,
          `vault dosyası    : ${KEY} = "${flags}" (v${backend.fileVersion(KEY)})`,
        ].join('\n'),
      );
      expect(material.pins).toEqual(run.custom.pins);
      expect(material.signingPublicKey).toBe(run.custom.signingPublicKey);
    });

    await test.step('Mobil: Ayarlar\'dan "Özel backend" moduna geçilir', async () => {
      await app.openSettings();
      const applied = await app.applyMode('CUSTOM_BACKEND');
      await app.snap('özel backend modu uygulandı');
      expect(applied).toContain('Hazır — config v');
      await app.backToMain();
      const status = app.status();
      await app.snap('özel backend: ana ekran');
      await attachText(
        testInfo,
        'Telefonun ekranı (özel backend modu)',
        status.split('\n').slice(0, 8).join('\n'),
      );
      expect(SampleApp.modeOf(status)).toBe('özel backend');
      expect(status).toContain(backend.url);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(backend.version);
    });

    await test.step('Mobil: config\'ten gelen pin\'lerle hedefe bağlanılıyor', async () => {
      const request = await app.testLibraryClient();
      await app.snap('özel backend: hedefe pinli bağlantı');
      expect(request).toContain('Pinned bağlantı başarılı');
    });

    await test.step(`Mobil: vault dosyası özel yoldan (files/${KEY}) iniyor`, async () => {
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('özel backend: vault dosyası indi');
      expect(status).toContain(`${KEY} v${backend.fileVersion(KEY)} indirildi`);
      expect(status).toContain('imza doğrulandı');
      expect(status).toContain(flags);
      await app.backToMain();
    });

    await test.step('Terminal: backend\'in gördüğü istek yolları', async () => {
      await attachText(
        testInfo,
        `Harness backend'ine gelen istekler (${backend.requests.length} adet)`,
        [
          ...backend.requests.map((r, i) => `${String(i + 1).padStart(2)}. ${r}`),
          '',
          'Kütüphanenin varsayılan yolları (api/v1/certificate-config, health,',
          'api/v1/vault/…) hiç kullanılmadı; yalnızca blokta tanımlı özel yollar',
          'çağrıldı. Vault indirme raporu da özel yola (analytics/vault) gitti.',
        ].join('\n'),
      );
      const paths = backend.requests.join('\n');
      expect(paths).toContain('GET /ssl/pins');
      expect(paths).toContain('GET /ping');
      expect(paths).toContain(`GET /files/${KEY}`);
      expect(paths).toContain('POST /analytics/vault');
      expect(paths).not.toContain('certificate-config');
    });

    await test.step('Sunucu: ana host bu süre boyunca hiç config/vault isteği almadı', async () => {
      const window = logsSince(mark);
      const requestLines = window
        .split('\n')
        .filter((line) => /io\.ktor\.server\.Application - \d{3}/.test(line))
        .map((line) => line.replace(/^.*Application - /, '').trim());
      const configOrVault = requestLines.filter((l) => /certificate-config|\/api\/v1\/vault\//.test(l));
      await attachText(
        testInfo,
        'Ana host (demo-server) günlüğü — özel backend modundayken',
        [
          `pencerede ${requestLines.length} istek satırı var:`,
          ...requestLines.slice(-20).map((l) => `  ${l}`),
          '',
          `config / vault isteği: ${configOrVault.length} (${configOrVault.join(' | ') || 'yok ✓'})`,
          '',
          'Görünen istekler docker healthcheck\'in GET /health\'i ve uygulamanın',
          'telemetri POST\'ları (client-report). Telemetri uygulamanın kendi',
          'tercihi — PinVaultBackendReporter hâlâ ana host\'a rapor gönderiyor —',
          'ama pin config\'i ve vault dosyası artık oradan gelmiyor.',
        ].join('\n'),
      );
      expect(configOrVault, 'ana host\'a config/vault isteği gitmemeli').toHaveLength(0);
    });

    await test.step('Mobil: TLS moduna dönülür, ana host yeniden config kaynağı', async () => {
      await app.openSettings();
      const applied = await app.applyMode('TLS');
      await app.backToMain();
      const status = app.status();
      await app.snap('TLS moduna dönüldü');
      expect(applied).toContain('Hazır — config v');
      expect(SampleApp.modeOf(status)).toBe('TLS config');
      expect(status).toContain(`https://${env.LAN_IP}:${env.CONFIG_API_PORT}/`);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    if (backend) await backend.stop();
  }
});
