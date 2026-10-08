// R03 — Adı değiştirilmiş frida (kütüphane adı gizlense de runtime izleri kalır).
//
// Saldırgan frida ikilisinin/gadget'ının adını değiştirebilir (burada
// libgadget.so yerine libhelper.so). Böylece `/proc/self/maps`'teki DOSYA ADI
// artık "frida"/"gadget" içermez — isim tabanlı tespit kaçar. Ama frida'nın
// çalışma zamanı thread'leri (`gum-js-loop` / `gmain` / `gdbus` / `pool-frida`)
// adlarını korur; HookingProbe bunları da tarar ve `hooking_framework`'ü yine
// yükseltir. Politika `hooking_framework: reject` iken telefon KALIR ve mock
// host 401 döner. Yani ikiliyi yeniden adlandırmak tespiti atlatmaz.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

test('R03 Frida (adı değişik): maps adı frida içermese de thread izleriyle hooking_framework yükselir ve reddedilir', async ({ app, device }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  test.skip(!device.isEmulator(), 'frida gadget yalnızca tek kullanımlık emülatörde yüklenir');
  test.skip(!res.fridaGadgetAvailable(), 'frida-gadget .so yok (sample-e2e/.local/frida)');

  let original;
  let deviceId;

  try {
    await test.step('Hazırlık: gadget\'ı "libhelper.so" adıyla yükle, politika hooking_framework\'ü reddetsin', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT, hooking_framework: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      res.plantFridaGadget(device, env.APP_ID, { soName: 'libhelper.so' });
      await app.relaunch();
      await app.waitReady();

      const pid = device.shell(`su 0 pidof ${env.APP_ID}`).trim().split(/\s+/)[0];
      const maps = device.shell(`su 0 cat /proc/${pid}/maps`);
      const loadedSo = maps.split('\n').map((l) => l.trim().split(/\s+/).pop()).filter((p) => /libhelper\.so$/.test(p || ''))[0];
      const comms = device.shell(`su 0 sh -c 'cat /proc/${pid}/task/*/comm'`);
      const fridaThreads = comms.split('\n').map((t) => t.trim()).filter((t) => /gum|frida|gmain|gdbus|pool-frida/i.test(t));
      // Yüklenen .so'nun adı "frida"/"gadget" içermiyor; ama frida thread'leri var.
      expect(loadedSo || '', 'yeniden adlandırılmış gadget yüklenmeliydi').toMatch(/libhelper\.so$/);
      expect(loadedSo).not.toMatch(/frida|gadget/i);
      expect(fridaThreads.length, `frida thread izi görünmedi:\n${comms}`).toBeGreaterThan(0);
      attachText(testInfo, 'Adı değişik .so + frida thread\'leri', `maps: ${loadedSo}\nthreads:\n${fridaThreads.join('\n')}`);

      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Mobil: thread izleriyle hooking_framework yükselir → KALDI, mock host 401', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('hooking_framework');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('adı değişik frida yine tespit edildi: atestasyon kaldı, 401');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('hooking_framework');
      attachText(testInfo, 'Cihaz kaydı (hooking, adı değişik)', JSON.stringify(record, null, 2));
    });
  } finally {
    res.removeFridaGadget(device, env.APP_ID);
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
