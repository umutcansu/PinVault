// Gizli vault dosyaları için ortak hazırlık.
//
// Örnek uygulama sample-secret, sample-e2e ve sample-mtls-secret'i yalnızca
// cihaz mTLS'e kayıtlıyken tanımlar: mTLS bloğunda, token_mtls politikasıyla
// ve ekran kilidi zorunlu (userAuth REQUIRED; secret ve mtls-secret ayrıca
// encryption USER_AUTH). Cihaza özel RSA anahtarı da (end_to_end) ancak o
// zaman üretilir ve her Config API'ye kaydedilir. Bu yüzden gizli dosya ya da
// cihaz anahtarı gerektiren senaryolar şunu yapar:
//
//   1. (istenirse) emülatöre geçici bir ekran kilidi PIN'i koyar,
//   2. mTLS Config API'nin host listesini hazırlar,
//   3. cihazı dashboard'da üretilen, telefona bağlı (ANDROID_ID) kayıt
//      token'ıyla kaydeder: sunucu cihaz kimliğini kanıtlanmış sayar, token_mtls
//      dosyaları ve mTLS üzerinden anahtar değişimi ancak böyle açılır,
//   4. Ayarlar → "Uygula ve yeniden başlat" (TLS modu): mTLS bloğu ve gizli
//      dosyalar gelir, ekran kilidi ve RSA anahtarları kaydedilir.
//
// [cleanup] kaydı iptal edip unutur, mTLS kapsamını sıfırlar ve PIN'i kaldırır.
const { expect } = require('@playwright/test');
const env = require('./env');
const hostApi = require('./hostApi');
const mtlsScope = require('./mtlsScope');

/**
 * [state] = { clientId } — senaryonun tuttuğu nesne; adım adım doldurulur
 * (lock, enrolled), yarıda kalsa da [cleanup] neyi geri alacağını bilir.
 */
async function prepare({ app, device, dashboard }, state, { screenLock = true } = {}) {
  if (screenLock) state.lock = device.setScreenLockPin(env.SCREEN_LOCK_PIN);
  // Önceki koşulardan kalan cihaz anahtarları silinir; bu kurulum kendi
  // anahtarlarını aşağıdaki init'te kaydeder.
  await app.openVault();
  const deviceId = app.deviceId();
  await hostApi.forgetDeviceKeys(deviceId, [env.VAULT_API, env.MTLS_API]);
  await app.backToMain();
  await mtlsScope.ensureHosts(dashboard, [env.LAN_IP]);
  // Telefonun ekranda gösterdiği kimliğe bağlı token (adb'den okunanla aynı).
  const token = await dashboard.generateEnrollmentToken(env.MTLS_API, state.clientId, { deviceUid: deviceId });
  await app.openMtls();
  state.enrolled = await app.enroll(token);
  expect(state.enrolled).toContain(`Kayıt başarılı — CN=PinVault Client: ${state.clientId}`);
  await app.backToMain();
  // Gizli dosyalar ve mTLS bloğu bir sonraki PinVault kurulumunda tanımlanır.
  await app.openSettings();
  expect(await app.applyMode('TLS')).toContain('Hazır — config v');
  await app.backToMain();
  return state;
}

async function cleanup({ device }, state) {
  if (!state) return;
  await mtlsScope.reset().catch(() => {});
  // İptal + unut: bağlı token cihazı kanıtlar, yalnızca iptal sonraki
  // senaryoların token'lı indirmelerini de keserdi (bkz. retireClientIdentity).
  await hostApi.retireClientIdentity(state.clientId);
  if (state.lock) {
    try {
      device.clearScreenLock(env.SCREEN_LOCK_PIN, state.lock);
    } catch {
      /* cihaz yanıt vermiyorsa asıl hatayı gölgelemesin */
    }
  }
}

module.exports = { prepare, cleanup };
