// A18: imzalı config'in geçerlilik süresi. Sunucu her yanıtı imzalarken
// `issuedAt` / `expiresAt` zamanlarını ekler (CONFIG_TTL_SECONDS). İstemci
// `expiresAt <= now` olan bir payload'ı imzası geçerli olsa bile uygulamaz:
// ele geçirilmiş eski bir yanıt sonsuza kadar tekrar gönderilemesin diye.
//
// Kanıt için TTL 60 saniyeye düşürülür ve cihazın saati iki saat ileri alınır;
// telefon yenilemeyi "expired" diyerek reddeder. Saklı config'in de süresi
// geçmiştir: pinli istekler, taze bir config gelene kadar reddedilir (fail
// closed). Eskiden saklı config süresiz kullanılıyordu; Config API'ye giden
// trafiği engelleyen biri cihazı eski (ele geçmiş) pin'lerde sonsuza kadar
// tutabiliyordu. Saat ve TTL geri alınınca yenileme ve pinli istek yeniden çalışır.
//
// Saat kaydırma root ister: yalnızca emülatör.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');

const TTL_SECONDS = 60;
const CLOCK_SHIFT_S = 2 * 60 * 60;

/** Sunucunun imzalı yanıtındaki tazelik damgaları. */
async function freshnessStamp() {
  const res = await hostApi.api('/api/v1/certificate-config', { withKey: false });
  const payload = JSON.parse(JSON.parse(res.text).payload);
  return {
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    ttlSeconds: Math.round((payload.expiresAt - payload.issuedAt) / 1000),
  };
}

test('Sunucu+Mobil: süresi geçmiş imzalı config reddedilir, süresi geçmiş saklı config ile bağlantı kurulmaz', async ({
  app,
  device,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'Cihaz saati yalnızca emülatörde ileri alınabilir');
  test.setTimeout(10 * 60 * 1000);

  let version;
  let shifted = false;

  try {
    await test.step('Sunucu: config\'in geçerlilik süresi (CONFIG_TTL_SECONDS) 60 saniyeye düşürülür', async () => {
      await hostControl.setEnv({ CONFIG_TTL_SECONDS: String(TTL_SECONDS) });
      const stamp = await freshnessStamp();
      await attachText(
        testInfo,
        'GET /api/v1/certificate-config (imzalı) — düzenlenme ve bitiş zamanı',
        [
          `issuedAt : ${stamp.issuedAt}  (${new Date(stamp.issuedAt).toISOString()})`,
          `expiresAt: ${stamp.expiresAt}  (${new Date(stamp.expiresAt).toISOString()})`,
          `süre     : ${stamp.ttlSeconds} s  (CONFIG_TTL_SECONDS=${TTL_SECONDS})`,
          '',
          'scripts/env-override.sh set CONFIG_TTL_SECONDS=60 — .env\'e dokunmadan',
          'container yeni değerle yeniden oluşturuldu.',
        ].join('\n'),
      );
      expect(stamp.ttlSeconds).toBe(TTL_SECONDS);
    });

    await test.step('Mobil: saat doğruyken kısa süre sorun değil — yenileme çalışıyor', async () => {
      // Uygulama TTL değişmeden önce açıldığı için baştan kurulur.
      app.launchFresh();
      const ready = await app.waitReady();
      version = SampleApp.hostVersion(ready, TARGET_HOST);
      const status = await app.refreshConfig();
      await app.snap(`kısa geçerlilik süresiyle yenileme çalışıyor (v${version})`);
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    });

    await test.step('Mobil: cihaz saati iki saat ileri alınır', async () => {
      device.shiftClock(CLOCK_SHIFT_S);
      shifted = true;
      const deviceNow = device.clockText();
      await attachText(
        testInfo,
        device.platform === 'ios' ? 'Uygulamanın saati (E2E denetim dosyası: clockOffsetSeconds)' : 'Cihaz saati (adb shell date)',
        [
          `cihaz : ${deviceNow}`,
          `Mac   : ${new Date().toString()}`,
          '',
          `Kaydırma: +${CLOCK_SHIFT_S / 3600} saat. Sunucunun verdiği geçerlilik süresi ${TTL_SECONDS} s;`,
          'yani cihazın saatine göre her yeni config çoktan süresi geçmiş sayılır.',
        ].join('\n'),
      );
    });

    await test.step('Mobil: yenileme "expired" (süresi geçmiş) hatasıyla reddediliyor, eski config yerinde kalıyor', async () => {
      const status = await app.refreshConfig();
      await app.snap('süresi geçmiş config reddedildi');
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toContain('Config yenilenemedi');
      expect(status).toContain('Signed config expired');
      // Reddedilen config uygulanmadı: saklı sürüm aynı.
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
    });

    await test.step('Mobil: süresi geçmiş saklı config ile pinli istek reddedilir (fail closed)', async () => {
      const result = await app.testLibraryClient();
      await app.snap('süresi geçmiş config ile bağlantı reddedildi');
      await attachText(testInfo, 'Telefondaki sonuç', result);
      expect(result).toContain('Bağlantı başarısız');
      expect(result).toContain('Pin config expired');
    });

    await test.step('Mobil: saat geri alınır → yenileme yeniden çalışıyor', async () => {
      device.shiftClock(-CLOCK_SHIFT_S);
      shifted = false;
      const status = await app.refreshConfig();
      await app.snap('saat düzeldi, yenileme çalışıyor');
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(status).not.toContain('Config yenilenemedi');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBe(version);
      const result = await app.testLibraryClient();
      await app.snap('taze config ile bağlantı yeniden kuruldu');
      expect(result).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Sunucu: geçerlilik süresi varsayılana döner (24 saat)', async () => {
      await hostControl.resetEnv();
      const stamp = await freshnessStamp();
      await attachText(
        testInfo,
        'CONFIG_TTL_SECONDS geri alındıktan sonraki geçerlilik süresi',
        `${stamp.ttlSeconds} s (${Math.round(stamp.ttlSeconds / 3600)} saat)`,
      );
      expect(stamp.ttlSeconds).toBeGreaterThan(TTL_SECONDS);
      const status = await app.refreshConfig();
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
    });
  } finally {
    if (shifted) {
      try {
        device.shiftClock(-CLOCK_SHIFT_S);
      } catch {
        /* cihaz yanıt vermiyorsa teardown ilgilenir */
      }
    }
    await hostControl.resetEnv();
  }
});
