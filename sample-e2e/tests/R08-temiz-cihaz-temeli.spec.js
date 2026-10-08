// R08 — Temiz cihaz temeli (yanlış alarm yok).
//
// Dayanıklılık senaryolarının tersi: tehdit YOKKEN tespitin SUSMASI gerekir.
// Politika gerçek tehdit sinyallerini (rooted, hooking_framework, debugger,
// app_integrity, cloner) `reject` yapar; buna rağmen temiz bir cihaz GEÇER,
// çünkü bu sinyaller gerçekten temizdir. `emulator` ve `debuggable` ortam
// gereği (emülatör / debug derlemesi) uyarıya çekilir. Böylece kütüphanenin
// sağlam bir cihazı hatalı reddetmediği (false positive) gösterilir.
//
// En değerli koşum gerçek, root'suz telefondadır (ANDROID_SERIAL=<seri>
// E2E_ANDROID_ID=<mTLS ekranındaki Cihaz kimliği>); orada emulator de temizdir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

// Tehdit sinyalleri sıkı (reject); ortam sinyalleri uyarı.
const STRICT_THREATS = {
  rooted: 'reject',
  hooking_framework: 'reject',
  debugger: 'reject',
  app_integrity: 'reject',
  cloner: 'reject',
  emulator: 'warn',
  debuggable: 'warn',
  unknown_installer: 'warn',
  adb_enabled: 'ignore',
  software_key: 'warn',
  key_unattested: 'warn',
  old_patch_level: 'warn',
  play_integrity: 'warn',
  play_integrity_missing: 'warn',
};

test('R08 Temiz cihaz: tehdit sinyalleri reject olsa bile temiz cihaz atestasyonu geçer (yanlış alarm yok)', async ({ app, device }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step('Hazırlık: tehdit sinyalleri sıkı (reject), ortam sinyalleri uyarı', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, STRICT_THREATS, { revealReasons: true });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Temiz cihaz: hiçbir tehdit sinyali yükselmez, atestasyon GEÇER', async () => {
      const text = await app.attest();
      expect(text, `temiz cihaz geçmeliydi:\n${text}`).toContain('Atestasyon geçti');
      await app.snap('temiz cihaz: atestasyon geçti (tehdit yok)');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('pass');
      const reasons = res.reasonsOf(record);
      // Hiçbir tehdit sinyali reddetmemiş olmalı.
      for (const threat of ['rooted', 'hooking_framework', 'debugger', 'app_integrity', 'cloner']) {
        expect(reasons, `temiz cihazda '${threat}' yükselmemeliydi`).not.toContain(threat);
      }
      // Gerçek cihaz kanıtı: tehdit sinyalleri uyarılarda da olmamalı.
      const warnings = res.warningsOf(record);
      for (const threat of ['rooted', 'hooking_framework', 'debugger']) {
        expect(warnings, `temiz cihazda '${threat}' uyarısı da olmamalı`).not.toContain(threat);
      }
      attachText(testInfo, 'Cihaz kaydı (temiz)', JSON.stringify(record, null, 2));
    });
  } finally {
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
  }
});
