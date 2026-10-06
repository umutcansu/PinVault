// Platform seçici: E2E_PLATFORM=ios ise lib/ios.js (simülatör), değilse
// lib/android.js (adb). İkisinin Device sınıfı aynı yöntem adlarını ve dönüş
// biçimlerini taşır; senaryolar ve sayfa nesneleri cihaza buradan ulaşır.
// Platforma özgü bir doğrulama gerekiyorsa `device.platform` ('android' | 'ios').
const env = require('./env');

const impl = env.PLATFORM === 'ios' ? require('./ios') : require('./android');

/** Durum dosyasındaki seri numarasıyla (Android seri no / simülatör UDID) cihaz nesnesi. */
function createDevice(serial) {
  return new impl.Device(serial);
}

module.exports = {
  PLATFORM: env.PLATFORM,
  Device: impl.Device,
  createDevice,
  sleep: impl.sleep,
  testDeviceUid: impl.testDeviceUid,
};
