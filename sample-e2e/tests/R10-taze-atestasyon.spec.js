// R10 — Taze atestasyon (ATTESTATION.md §3.1).
//
// Bir anahtarın atestasyon zinciri anahtar üretilirken bir kez yapılır; kayıttaki
// zincir cihazın o günkü halini söyler. ATTESTATION_FRESH_INTERVAL_SECONDS açıkken
// host, aralık dolan Android cihaza yanıtında `"freshAttestation": "due"` der;
// kütüphane sonraki turda yalnızca o tur için (nonce + cihaz + kayıtlı anahtar
// challenge'ıyla) bir Keystore anahtarı üretir, zincirini `freshAttestationChain`
// olarak gönderir ve anahtarı siler. Host zinciri doğrular ve kayıttaki donanım
// bilgisini tazeler.
//
// Emülatörün Keystore'u yazılım seviyesindedir: zincir donanım güvencesi taşımaz,
// host onu "yenilenecek donanım bilgisi yok" diye sayar (bayrak yok). Bu test akışı
// uçtan uca gösterir (host ister → uygulama üretip gönderir → host kaydeder → bir
// daha istemez); donanım zincirinin kuralları (kilidi açılmış bootloader, yazılıma
// düşürülmüş anahtar, başka turun challenge'ı, iptal edilmiş sertifika, gecikme)
// sunucu testlerinde sahte Google kökü zincirleriyle sınanır (AttestationRoutesTest).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;
const INTERVAL = 60;

async function setFreshInterval(value) {
  const saved = await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { ATTESTATION_FRESH_INTERVAL_SECONDS: value } } });
  expect(saved.status, `ayar kaydedilemedi: ${saved.text}`).toBe(200);
  await hostControl.stop();
  await hostControl.start();
}

test('R10 Taze atestasyon: aralık dolunca host taze zincir ister, uygulama o tura özel anahtarın zincirini gönderir, host kaydı tazeler', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step(`Hazırlık: politika gevşek, taze atestasyon her ${INTERVAL} sn`, async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT }, { revealReasons: true });
      await setFreshInterval(String(INTERVAL));
      const view = (await hostApi.api('/api/v1/server-settings')).json;
      expect(view.settings.find((s) => s.key === 'ATTESTATION_FRESH_INTERVAL_SECONDS').running).toBe(String(INTERVAL));
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await app.backToMain();
    });

    await test.step('Mobil: atestasyon geçer; kayıt aralıktan eskiyse host taze zincir ister', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record, 'cihaz kaydı yok').toBeTruthy();
      // Yeni kaydolduysa aralık kayıttan başlar: dolana kadar beklenir.
      const age = (Date.now() - Date.parse(record.freshAttestedAt || record.firstSeen)) / 1000;
      if (age < INTERVAL + 2) await new Promise((r) => setTimeout(r, (INTERVAL + 2 - age) * 1000));
    });

    await test.step('Mobil: sonraki turlar taze zinciri taşır; host kaydeder ve bir daha istemez', async () => {
      let record;
      for (let i = 0; i < 3; i += 1) {
        await app.attest();
        record = await res.deviceRecord(SCOPE, deviceId);
        if (record.freshAttestedAt) break;
      }
      expect(record.freshResult, `taze zincir gelmedi: ${JSON.stringify(record)}`).toBeTruthy();
      expect(record.freshAttestedAt).toBeTruthy();
      expect(Date.now() - Date.parse(record.freshAttestedAt)).toBeLessThan(5 * 60 * 1000);
      // Emülatör: yazılım seviyesi zincir, yenilenecek donanım bilgisi yok, bayrak yok.
      expect(record.freshFacts).toBeNull();
      expect(res.reasonsOf(record)).not.toContain('fresh_attestation_failed');
      expect(record.lastWarnings || []).not.toContain('fresh_attestation_failed');
      attachText(testInfo, 'Cihaz kaydı (taze atestasyon)', JSON.stringify({
        deviceId, keyAttestation: record.keyAttestation, freshResult: record.freshResult,
        freshAttestedAt: record.freshAttestedAt, freshFacts: record.freshFacts, lastWarnings: record.lastWarnings,
      }, null, 2));
      await app.snap('taze atestasyon: host zinciri kaydetti');
    });

    await test.step('Web: cihaz kaydı panelde', async () => {
      await dashboard.openConfigApiTab(SCOPE, 'attestation');
      await dashboard.snap('panel: atestasyon sekmesi (taze atestasyon açık)');
    });
  } finally {
    await setFreshInterval('').catch(() => {});
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
  }
});
