// R11 — Token anomalisi (ATTESTATION.md §5.2).
//
// Kanıt (R09) token'ı cihaza bağlar ama rootlu bir telefon başkaları için kanıt
// imzalayabilir; çalınmış bir token da kanıt istenmeyen bir backend'de dağıtılabilir.
// İkisini ele veren trafiğin şeklidir: bir cihazın token'ı çok sayıda adresten ya da
// hiçbir insanın yapmayacağı sıklıkta. Mock host'lar (PINVAULT_TOKEN_ANOMALY=warn) her
// cihazın token kullanımını sayar; sınırı aşan cihazı sunucuya bildirir; cihazın
// sonraki turları ATTESTATION_ANOMALY_TTL_SECONDS boyunca `token_anomaly` yükseltir
// (strict: reddedilir, yeni token yok). Yönetici temizleyince cihaz yine geçer.
//
// Testten tüm istekler aynı adresten gelir; bu yüzden istek sayısı sınırı küçük tutulur
// (adres sınırı sunucu testlerinde sınanır).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');
const tokens = require('../lib/tokens');

const SCOPE = env.VAULT_API;
const MAX_REQUESTS = 20;
const SETTINGS = ['PINVAULT_TOKEN_ANOMALY', 'PINVAULT_TOKEN_ANOMALY_MAX_REQUESTS'];

async function saveSettings(values) {
  const saved = await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values } });
  expect(saved.status, `ayar kaydedilemedi: ${saved.text}`).toBe(200);
}

test('R11 Token anomalisi: bir cihazın token\'ı script hızında kullanılınca bildirilir, cihaz reddedilir; temizlenince geçer', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step(`Hazırlık: politika gevşek + token_anomaly reddeder; mock host token ister ve sayar (> ${MAX_REQUESTS} istek / 10 dk)`, async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT, token_anomaly: 'reject' }, { revealReasons: true });
      await saveSettings({ PINVAULT_TOKEN_ANOMALY: 'warn', PINVAULT_TOKEN_ANOMALY_MAX_REQUESTS: String(MAX_REQUESTS) });
      // HS256: "çalınmış" token ortak sırla üretilir (ES256'da özel anahtar sunucudan çıkmaz);
      // kanıt şartı kapalı: burada sayılan, token'ın kendisinin kullanımı.
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true', PINVAULT_TOKEN_ALG: 'HS256', PINVAULT_TOKEN_REQUIRE_PROOF: 'false' });
      await hostControl.stop();
      await hostControl.start();
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await app.backToMain();
      await res.clearDeviceOverrides(SCOPE, deviceId);
      await hostApi.api(`${res.devicePath(SCOPE, deviceId)}/anomaly`, { method: 'DELETE' }).catch(() => {});
    });

    await test.step('Mobil: atestasyon geçer, mock host 200', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
    });

    await test.step(`Ağ: cihazın token'ı başka bir makineden script hızında (${MAX_REQUESTS + 5} istek) kullanılır → host bildirir`, async () => {
      const record = await res.deviceRecord(SCOPE, deviceId);
      const token = await tokens.liftedToken(SCOPE, deviceId, tokens.jwkThumbprint(record.publicKey));
      const statuses = [];
      for (let i = 0; i < MAX_REQUESTS + 5; i += 1) {
        statuses.push((await hostApi.mockTlsRequest('/', { headers: { 'PinVault-Token': token } })).status);
      }
      expect(statuses.every((s) => s === 200), `warn: istekler yine karşılanır (${statuses.join(',')})`).toBeTruthy();
      const flagged = await res.deviceRecord(SCOPE, deviceId);
      expect(flagged.anomalyAt, 'cihaz bildirilmeliydi').toBeTruthy();
      expect(flagged.anomalyReason).toContain('requests');
      attachText(testInfo, 'Cihaz kaydı (anomali)', JSON.stringify({ deviceId, anomalyAt: flagged.anomalyAt, anomalyReason: flagged.anomalyReason }, null, 2));
    });

    await test.step('Mobil: sonraki atestasyon token_anomaly ile KALDI, token yok, mock host 401', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('token_anomaly');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('token anomalisi: atestasyon kaldı');
    });

    await test.step('Web: audit kaydı ve panel', async () => {
      const audit = await hostApi.api('/api/v1/audit-log?action=attestation_token_anomaly&limit=5');
      expect(audit.status).toBe(200);
      expect(JSON.stringify(audit.json)).toContain(deviceId);
      await dashboard.openConfigApiTab(SCOPE, 'attestation');
      await dashboard.snap('panel: token_anomaly ile reddedilen cihaz');
    });

    await test.step('Yönetici anomaliyi temizler → Mobil: atestasyon yine geçer', async () => {
      const cleared = await hostApi.api(`${res.devicePath(SCOPE, deviceId)}/anomaly`, { method: 'DELETE' });
      expect(cleared.status, cleared.text).toBe(200);
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
    });
  } finally {
    await saveSettings(Object.fromEntries(SETTINGS.map((k) => [k, '']))).catch(() => {});
    if (deviceId) {
      await hostApi.api(`${res.devicePath(SCOPE, deviceId)}/anomaly`, { method: 'DELETE' }).catch(() => {});
      await res.clearDeviceOverrides(SCOPE, deviceId);
    }
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
