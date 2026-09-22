// Testlerden sonra: cihazdaki geçici ağ kurallarını kaldır, host'u ayağa
// kaldır, ortam değişkeni ezmelerini geri al, temel pin durumuna dön, test
// vault dosyalarını sil, açtığımız emülatörü kapat.
const env = require('./lib/env');
const hostApi = require('./lib/hostApi');
const hostControl = require('./lib/hostControl');
const freshHost = require('./lib/freshHost');
const state = require('./lib/state');
const { Device } = require('./lib/android');

module.exports = async () => {
  // Kurulum ve yıkıcı sunucu senaryolarının kullandığı ikinci host örneği
  // (.local/host-fresh) tamamen silinir; ana host'a dokunulmaz.
  try {
    await freshHost.destroy();
  } catch (e) {
    console.warn(`[e2e] Taze host örneği silinemedi: ${e.message}`);
  }

  const run = state.read();
  if (!run) return;
  const device = new Device(run.serial);
  try {
    if (device.isEmulator()) device.clearNetRules();
  } catch {
    /* cihaz kapanmış olabilir */
  }
  try {
    await hostControl.resetEnv();
    await hostApi.restoreBaseline(run.baseline);
    for (const key of Object.values(env.VAULT_KEYS)) {
      await hostApi.deleteVaultFile(env.VAULT_API, key);
      await hostApi.deleteVaultFile(env.MTLS_API, key);
    }
  } catch (e) {
    console.warn(`[e2e] Sunucu durumu geri yüklenemedi: ${e.message}`);
  }
  if (run.booted && process.env.E2E_KEEP_EMULATOR !== '1') {
    try {
      device.adb(['emu', 'kill']);
    } catch {
      /* zaten kapalı */
    }
  }
  state.clear();
};
