// A21: ara sertifika (CA) pini. Pin, sitenin kendi sertifikası yerine onu
// imzalayan CA'nın sertifikasına konabilir; site aynı CA'dan yeni anahtarla
// sertifika aldığında telefon bağlanmaya devam eder.
//
// Kütüphane CA zinciri doğrulamadığı için (kendinden imzalı sertifikalar da
// kabul) CA pini ancak sitenin sertifikası o CA'ya gerçekten bağlanıyorsa
// sayılır: yapraktan pinlenen sertifikaya kadar imzalar doğrulanır. Aksi
// hâlde saldırgan gerçek CA sertifikasını kendi sahte sertifikasının arkasına
// ekleyip geçerdi. Senaryo ikisini de gösterir: test CA'sının imzaladığı
// sertifika CA pininden geçer, gerçek CA'yı arkasına ekleyen saldırgan geçemez.
//
// Ana host'un mock TLS host'unda çalışır; sonunda host'un sertifikası sunucuda
// yeniden üretilir ve sonraki senaryolar yeni pin'leri temel alır (A20 gibi).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const proxy = require('../lib/proxy');
const state = require('../lib/state');
const testCa = require('../lib/testCa');
const env = require('../lib/env');

const MOCK = env.MOCK_TLS_HOST;

test('Web+Mobil: CA pini, CA\'nın imzaladığı sertifikayı kabul ediyor; gerçek CA\'yı sahte sertifikanın arkasına ekleyen saldırganı reddediyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'saldırı adımı iptables DNAT ister; yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  let ca;
  let mitm;
  let caPins;

  const waitForServedLeaf = async (pin) => {
    // Dinleyici yeni keystore ile ayağa kalksın; emülatörün saati yeni
    // sertifikanın başlangıç saatini geçsin (bkz. A20).
    let validFromMs = 0;
    await expect
      .poll(
        async () => {
          const cert = await hostApi.servedCert(env.MOCK_TLS_PORT, MOCK).catch(() => null);
          validFromMs = cert ? cert.validFromMs : 0;
          return cert && cert.pin;
        },
        { timeout: 60_000, intervals: [500, 1000, 2000] },
      )
      .toBe(pin);
    await expect.poll(() => device.epochMs(), { timeout: 30_000, intervals: [1000] }).toBeGreaterThan(validFromMs + 1000);
  };

  try {
    await test.step('Terminal: test CA\'sı ve mock host için onun imzaladığı sertifika üretilir', async () => {
      ca = testCa.create(MOCK);
      await attachText(
        testInfo,
        'openssl ile üretilen zincir (.local/chain-ca)',
        [
          `CA      : ${ca.ca.subject}`,
          `          pin ${ca.ca.pin}`,
          `sertifika: ${ca.leaf.subject}  (veren: ${ca.leaf.issuer})`,
          `          pin ${ca.leaf.pin}`,
          '',
          'bundle.p12: sertifika + anahtarı + CA sertifikası (zincir), parola changeit.',
        ].join('\n'),
      );
      expect(ca.leaf.issuer).toBe(ca.ca.subject);
    });

    await test.step('Web: sertifika zinciri mock host\'a yüklenir; mock host zinciri sunar', async () => {
      const res = await dashboard.uploadHostCert(MOCK, ca.p12, ca.p12Password);
      await waitForServedLeaf(ca.leaf.pin);
      const served = await hostApi.servedChainPins(env.MOCK_TLS_PORT, MOCK);
      await dashboard.snapHostSummary(`${MOCK}: yüklenen sertifikanın pin'leri`);
      await attachText(
        testInfo,
        'POST /api/v1/hosts/<host>/upload-cert (bundle.p12)',
        [
          `HTTP ${res.status} ${res.body}`,
          '',
          `mock host'un sunduğu zincir (yapraktan başlayarak): ${served.join(' → ')}`,
          '',
          'Sunucu yayımladığı ikinci pin için kendi yedek anahtarını üretip sakladı.',
        ].join('\n'),
      );
      expect(res.json.sha256Pins[0]).toBe(ca.leaf.pin);
      expect(served).toEqual([ca.leaf.pin, ca.ca.pin]);
    });

    await test.step('Web: pin listesi CA pini + yedek olarak değiştirilir (sitenin kendi pini listede yok)', async () => {
      const current = await dashboard.viewedPins(MOCK);
      caPins = [ca.ca.pin, current[1]];
      const v0 = await dashboard.version();
      await dashboard.setPins(MOCK, caPins);
      await expect.poll(() => dashboard.version(), { timeout: 30_000 }).toBe(v0 + 1);
      await dashboard.snapHostSummary(`${MOCK}: CA pini + yedek, v${v0 + 1}`);
      await attachText(
        testInfo,
        `${MOCK} pin listesi`,
        [
          `önce : ${current.join(' | ')}`,
          `sonra: ${caPins.join(' | ')}`,
          '',
          `Sitenin kendi pini (${ca.leaf.pin.slice(0, 12)}…) listede yok; yalnızca onu imzalayan CA'nın pini var.`,
        ].join('\n'),
      );
      expect(await dashboard.viewedPins(MOCK)).toEqual(caPins);
    });

    await test.step('Mobil: telefon yeni listeyi alıyor ve CA pini üzerinden bağlanıyor', async () => {
      const status = await app.refreshConfig();
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      device.clearLogcat();
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap('CA pini: bağlantı başarılı');
      await app.backToMain();
      const log = device.logcat({ tags: ['DynamicSSLManager'] });
      await attachText(
        testInfo,
        'Telefondaki sonuç ve kütüphane günlüğü',
        [
          result,
          '',
          log,
          '',
          'Sitenin sertifikası listede değil; kütüphane zincirdeki CA sertifikasının pinini',
          'buldu ve sitenin sertifikasının gerçekten o CA tarafından imzalandığını doğruladı.',
        ].join('\n'),
      );
      expect(result).toContain('host bağlantısı başarılı');
      expect(log).toContain(`Pin verified ✓ — host=${MOCK}`);
      expect(log).toContain(`issuer pin sha256/${ca.ca.pin.slice(0, 12)}`);
    });

    await test.step('Saldırgan: sahte sertifikanın arkasına gerçek CA sertifikasını ekleyip araya girer', async () => {
      mitm = await proxy.start({ material: ca.forgedMaterial(), upstreamPort: env.MOCK_TLS_PORT });
      device.redirectTcp(env.LAN_IP, env.MOCK_TLS_PORT, env.PROXY_PORT);
      const rules = device.rootShell('iptables -t nat -S OUTPUT');
      await attachText(
        testInfo,
        'Saldırganın sunduğu zincir ve yönlendirme',
        [
          `1. sahte sertifika : ${ca.forged.subject}  (veren: ${ca.forged.issuer})`,
          `                     pin ${ca.forged.pin}  — saldırganın kendi anahtarıyla imzalı`,
          `2. GERÇEK CA       : ${ca.ca.subject}`,
          `                     pin ${ca.ca.pin}  — telefonun listesindeki pin`,
          '',
          'Veren adı gerçek CA\'yla aynı; imza tutmuyor.',
          '',
          `iptables: ${env.LAN_IP}:${env.MOCK_TLS_PORT} → ${env.LAN_IP}:${env.PROXY_PORT}`,
          rules.trim(),
        ].join('\n'),
      );
      expect(ca.forged.issuer).toBe(ca.ca.subject);
      expect(rules).toContain(`--dport ${env.MOCK_TLS_PORT}`);
    });

    await test.step('Mobil: telefon sahte zinciri reddediyor; saldırgana tek istek bile ulaşmıyor', async () => {
      // DNAT yalnızca yeni bağlantıları yakalar: uygulama yeniden açılır (saklı config korunur).
      app.relaunch();
      await app.waitReady();
      await app.tapButton('clearLogButton');
      device.clearLogcat();
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap('sahte zincir: bağlantı reddedildi');
      await app.backToMain();
      const events = await app.waitForEvent(`[✗ UYUŞMAZLIK] ${MOCK}`);
      await app.snap('olay listesi: pin uyuşmazlığı');
      const log = device.logcat({ tags: ['DynamicSSLManager'] });
      await attachText(
        testInfo,
        'Telefondaki sonuç, olay listesi ve kütüphane günlüğü',
        [
          result,
          '',
          events,
          '',
          log,
          '',
          `saldırgana ulaşan HTTP isteği: ${mitm.requests.length}`,
          `saldırganın gördüğü el sıkışma hataları: ${mitm.handshakeErrors.slice(0, 3).join(' | ') || '(yok)'}`,
        ].join('\n'),
      );
      expect(result).toContain('host bağlantısı reddedildi');
      expect(mitm.requests).toHaveLength(0);
      expect(log).toContain(`Pin mismatch for ${MOCK}`);
      expect(log).not.toContain(`Pin verified ✓ — host=${MOCK}`);
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
    // Mock host'u sunucunun ürettiği bir sertifikaya döndür; sonraki
    // senaryolar yeni pin'leri temel alır.
    const toast = await dashboard.renewHostCert(MOCK);
    const pins = await dashboard.viewedPins(MOCK);
    run.baseline[MOCK] = pins;
    state.write(run);
    await waitForServedLeaf(pins[0]);
    const status = await app.refreshConfig();
    await attachText(testInfo, 'Mock host sunucunun ürettiği sertifikaya döndü', [`toast: ${toast}`, `pin'ler: ${pins.join(' | ')}`, '', status].join('\n'));
    await app.openMtls();
    expect(await app.mockTls()).toContain('host bağlantısı başarılı');
    await app.backToMain();
  }
});
