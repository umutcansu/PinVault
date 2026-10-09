// R02 — Frida / hooking çerçevesi tespiti (HookingProbe + atestasyon zinciri).
//
// Gerçek frida-gadget uygulamanın sürecine LD_PRELOAD ile yüklenir (wrap.<pkg>);
// adres uzayında `frida-gadget` / `gum-js-loop` / `gmain` / `gdbus` /
// `pool-frida` thread'lerini ve maps'te kendi .so'sunu bırakır. HookingProbe tam
// da bunları arar ve `hooking_framework` sinyalini yükseltir. Host politikası
// `hooking_framework: reject` iken telefon KALIR, token alamaz ve token isteyen
// mock host 401 döner. Gadget kaldırılınca (aynı politikayla) aynı telefon GEÇER.
//
// Not (ortam): gadget + LD_PRELOAD sunucu ve ptrace gerektirmez. frida-server
// yolu da bu emülatörlerde çalışır (17.19.0 hariç); MobSF dinamik koşusu
// (2026-10-09) onunla aynı reddi gösterdi. Araçlar yoksa test atlanır (skip). Gerçek telefon root'lanmaz; gadget
// yalnızca debuggable derlemeye ve yalnızca emülatörde yüklenir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

test('R02 Frida: gadget yüklü uygulamada hooking_framework yükselir, reddedilir, mock host 401; kaldırılınca geçer', async ({ app, device }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  test.skip(!device.isEmulator(), 'frida gadget yalnızca tek kullanımlık emülatörde yüklenir (gerçek telefon root\'lanmaz)');
  test.skip(!res.fridaGadgetAvailable(), 'frida-gadget .so yok (sample-e2e/.local/frida); indirilince koşar');

  let original;
  let deviceId;
  let planted = false;

  try {
    await test.step('Hazırlık: gadget yükle, politika yalnızca hooking_framework reddetsin, mock host token istesin', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT, hooking_framework: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      res.plantFridaGadget(device, env.APP_ID);
      planted = true;
      await app.relaunch(); // launchFresh DEĞİL: veri + gadget + kimlik anahtarı korunur
      await app.waitReady();

      // Gadget gerçekten yüklendi mi (kanıt): süreç thread'lerinde frida izleri.
      const comms = device.shell(`su 0 sh -c 'cat /proc/$(pidof ${env.APP_ID})/task/*/comm'`);
      const fridaThreads = comms.split('\n').map((t) => t.trim()).filter((t) => /gum|frida|gmain|gdbus|pool-frida/i.test(t));
      expect(fridaThreads.length, `gadget süreçte görünmedi:\n${comms}`).toBeGreaterThan(0);
      attachText(testInfo, 'Süreçte frida izleri (thread adları)', fridaThreads.join('\n'));

      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Mobil: hooking_framework reddedilir → atestasyon KALDI, token yok, mock host 401', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('hooking_framework');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('frida tespit edildi: atestasyon kaldı, mock host 401');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('hooking_framework');
      attachText(testInfo, 'Cihaz kaydı (hooking reddedildi)', JSON.stringify(record, null, 2));
    });

    await test.step('Gadget kaldırılır → aynı politikayla hooking düşer, atestasyon GEÇER ve token alır', async () => {
      res.removeFridaGadget(device, env.APP_ID);
      planted = false;
      await app.relaunch();
      await app.waitReady();
      // Gadget gitti mi (kanıt): artık frida thread'i yok.
      const comms = device.shell(`su 0 sh -c 'cat /proc/$(pidof ${env.APP_ID})/task/*/comm'`);
      expect(comms).not.toMatch(/gum-js-loop|frida-gadget|pool-frida/i);

      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('gadget kaldırıldı: atestasyon geçti, mock host 200');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(res.reasonsOf(record)).not.toContain('hooking_framework');
    });
  } finally {
    res.removeFridaGadget(device, env.APP_ID); // wrap'i her durumda temizle (yoksa sonraki açılış CANNOT LINK)
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
