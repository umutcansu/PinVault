// R05 — Hata ayıklayıcı (debugger) tespiti (DebuggerProbe + atestasyon zinciri).
//
// Debuggable uygulamanın sürecine JDWP üzerinden ham bir hata ayıklayıcı bağlanır
// (el sıkışma + bir komut; jdb gibi thread askıya almaz):
// `Debug.isDebuggerConnected()` true olur, DebuggerProbe `debugger` sinyalini
// yükseltir. Host politikası `debugger: reject` iken telefon KALIR ve token
// alamaz; debugger ayrılınca ve yeniden atestasyon olunca sinyal düşer ve
// telefon GEÇER. Böylece reddi özel olarak `debugger` sinyalinin yaptığı ve
// bağlı bir hata ayıklayıcının gerçekten yakalandığı kanıtlanır.
//
// `debuggable` bayrağı (uygulamanın debug derlemesi olması) ile karıştırılmaz:
// o her zaman yükselir ve burada uyarıya çekilir; `debugger` yalnızca canlı bir
// JDWP oturumu varken yükselir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

test('R05 Debugger: bağlı JDWP oturumunda debugger sinyali yükselir ve reddedilir; ayrılınca geçer', async ({ app, device }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let original;
  let deviceId;
  let detach;

  try {
    await test.step('Önkoşul: uygulama debuggable (JDWP\'ye açık)', async () => {
      const info = device.shell(`dumpsys package ${env.APP_ID}`);
      expect(/\bflags=\[[^\]]*\bDEBUGGABLE\b/.test(info), 'uygulama debuggable olmalı (debug/e2e derlemesi)').toBeTruthy();
    });

    await test.step('Hazırlık: politika yalnızca debugger\'ı reddeder; mock host token ister', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT, debugger: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Hata ayıklayıcısız: atestasyon geçer (debugger yok, sadece debuggable uyarısı)', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('debugger yok: atestasyon geçti');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(res.reasonsOf(record)).not.toContain('debugger');
    });

    await test.step('Hata ayıklayıcı bağlanır → Mobil: debugger reddedilir, token yok, mock host 401', async () => {
      detach = await res.attachDebugger(device, env.APP_ID);
      // JDWP el sıkışmasının oturması için kısa bir bekleme.
      await new Promise((r) => setTimeout(r, 2500));
      const connected = device.shell(`su 0 sh -c 'cat /proc/$(pidof ${env.APP_ID})/status'`);
      const tracer = (connected.match(/TracerPid:\s*(\d+)/) || [])[1];
      attachText(testInfo, 'JDWP bağlıyken /proc/status', `TracerPid: ${tracer}`);

      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('debugger');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('debugger bağlı: atestasyon kaldı, mock host 401');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('debugger');
      attachText(testInfo, 'Cihaz kaydı (debugger reddedildi)', JSON.stringify(record, null, 2));
    });

    await test.step('Hata ayıklayıcı ayrılır → Mobil: debugger düşer, atestasyon yeniden GEÇER', async () => {
      await detach();
      detach = null;
      await new Promise((r) => setTimeout(r, 2500));
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('debugger ayrıldı: atestasyon yeniden geçti');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('pass');
      expect(res.reasonsOf(record)).not.toContain('debugger');
    });
  } finally {
    if (detach) await detach().catch(() => {});
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
