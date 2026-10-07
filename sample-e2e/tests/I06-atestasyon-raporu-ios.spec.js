// I06 — iOS: atestasyon raporu iOS biçiminde.
//
// Kütüphane açılışta ve "Atestasyon" düğmesiyle uygulamayı ve cihazı ölçüp
// raporu kimlik anahtarıyla imzalayarak gönderiyor. iOS raporu: platform "ios",
// app.bundleId / teamId / installer (simülatörde "simulator"), device bloğu
// (osName, model, keySecurityLevel) ve sinyaller (emulator, debuggable, …).
// App Attest simülatörde yok: rapor verdictProvider taşımıyor, sunucu
// key_unattested sayıyor. Politika emulator / debuggable / unknown_installer /
// key_unattested'ı yalnızca uyarı sayınca telefon token alıyor.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const SCOPE = env.VAULT_API;
const POLICY = `/api/v1/config-apis/${SCOPE}/attestation/policy`;
const WARN_ONLY = { emulator: 'warn', debuggable: 'warn', unknown_installer: 'warn', key_unattested: 'warn' };

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: iOS rapor biçimi ve App Attest (Android karşılığı 16: Key Attestation + Play Integrity)');

function parse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Sinyal yükseldi mi: { flag: true, evidence: [...] } (ya da düz true). */
function raised(signal) {
  if (signal === true) return true;
  if (signal && typeof signal === 'object') return signal.flag === true || signal.raised === true || signal.value === true || signal.detected === true;
  return false;
}

test('iOS: atestasyon raporu platform ios, bundleId, installer simulator ve emulator sinyaliyle saklanıyor; App Attest yok; uyarı politikasıyla token alınıyor', async ({
  app,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step('Hazırlık: politika emulator, debuggable, unknown_installer ve key_unattested\'ı uyarı sayar', async () => {
      original = (await hostApi.api(POLICY)).json;
      expect(original && original.flags, 'politika okunamadı').toBeTruthy();
      const next = { ...original, revealReasons: true, flags: { ...original.flags, ...WARN_ONLY } };
      const res = await hostApi.api(POLICY, { method: 'PUT', body: next });
      expect(res.status, res.text).toBe(200);
      await attachText(testInfo, `PUT ${POLICY}`, [
        'önce:', JSON.stringify(original.flags, null, 2), '', 'test için:', JSON.stringify(res.json.flags || next.flags, null, 2),
      ].join('\n'));
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId);
      await app.backToMain();
    });

    await test.step('Mobil: "Atestasyon" → geçti, PinVault-Token alındı, uyarılar emulator ve key_unattested', async () => {
      const text = await app.attest();
      await app.snap('atestasyon geçti — token alındı');
      await attachText(testInfo, 'Sonuç kutusu', text);
      expect(text).toContain('Atestasyon geçti');
      expect(text).toMatch(/PinVault-Token \(\d+ karakter/);
      expect(text).toContain('emulator');
      expect(text).toContain('HTTP 200');
    });

    await test.step('Sunucu: saklanan rapor iOS biçiminde — platform, bundleId, installer, emulator sinyali, verdictProvider yok', async () => {
      const row = hostApi.dbQuery(
        `SELECT platform, last_result, last_warnings, last_reasons, verdict_provider, app_attest_result, last_report FROM attested_devices WHERE config_api_id='${SCOPE}' AND device_id='${deviceId}';`,
        { mode: 'json' },
      );
      const [db] = parse(row) || [];
      expect(db, 'attested_devices kaydı yok').toBeTruthy();
      const report = parse(db.last_report) || {};
      const record = (await hostApi.api(`/api/v1/config-apis/${SCOPE}/attestation/devices/${encodeURIComponent(deviceId)}`)).json;
      const warnings = parse(db.last_warnings) || [];
      await attachText(testInfo, `attested_devices (${SCOPE} / ${deviceId}) — sqlite3`, [
        `platform          : ${db.platform}`,
        `last_result       : ${db.last_result}`,
        `last_warnings     : ${db.last_warnings}`,
        `last_reasons      : ${db.last_reasons}`,
        `verdict_provider  : ${db.verdict_provider ?? '(NULL)'}`,
        `app_attest_result : ${db.app_attest_result ?? '(NULL)'}`,
        '',
        'last_report (sunucunun sakladığı, app / device / signals blokları):',
        JSON.stringify(report, null, 2),
      ].join('\n'));
      await attachText(testInfo, 'Panel API\'si — cihaz kaydı', JSON.stringify(record, null, 2));
      expect(db.platform).toBe('ios');
      expect(db.last_result).toBe('pass');
      expect(report.app && report.app.bundleId).toBe(env.APP_ID);
      expect(report.app && report.app.installer).toBe('simulator');
      expect(report.signals, 'raporda sinyal bloğu yok').toBeTruthy();
      expect(raised(report.signals.emulator), `emulator sinyali: ${JSON.stringify(report.signals.emulator)}`).toBe(true);
      expect(report).not.toHaveProperty('verdictProvider');
      expect(db.verdict_provider).toBeNull();
      expect(warnings).toEqual(expect.arrayContaining(['emulator', 'key_unattested']));
    });
  } finally {
    if (original) await hostApi.api(POLICY, { method: 'PUT', body: original }).catch(() => {});
  }
});
