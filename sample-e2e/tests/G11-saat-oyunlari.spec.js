// G11 — Saat oyunları: config'in zaman damgaları ve telefonun saati.
//
// İmzalı config iki zaman taşır: `issuedAt` (üretildiği an) ve `expiresAt`
// (geçerliliğinin bittiği an). Saldırganın saatle oynayarak deneyebileceği iki şey:
//
//   1. İleri tarihli config: `issuedAt`'ı gelecekte bir config telefona
//      yutturulursa replay kontrolü o tarihi "son görülen" sayar ve sunucunun
//      bundan sonraki BÜTÜN gerçek config'lerini "eski" diye reddettirir
//      (telefonu kilitler). Kütüphane telefonun saatinden bir saatten fazla
//      ileride olan `issuedAt`'ı reddeder (MAX_CLOCK_SKEW_MS).
//   2. Saati geri alma: süresi dolmuş bir config, telefonun saati geri alınınca
//      yeniden "geçerli" görünürdü. Süre kararları TrustedClock'la veriliyor:
//      görülen en yüksek zamanı saklar ve geri gitmez; saat geri alınsa da
//      süresi dolmuş config dirilmez.
//
// Saldırgan proxy host'un laboratuvar imza anahtarıyla yeniden imzalar
// (imza doğru, yalnızca zamanlar oynanmış); Config API'yi kapatarak telefonun
// taze config almasını engeller. Saat kaydırma: Android'de emülatörün saati
// (root), iOS'ta uygulamanın saati (control.json).
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const env = require('../lib/env');

const iso = (ms) => new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const isConfig = (answer) => answer.path.startsWith('/api/v1/certificate-config');

/**
 * Config yanıtını aynı pin'lerle, verilen zamanlarla yeniden imzalar
 * ({ issuedAt, expiresAt } her istekte hesaplanır). Gördüklerini [seen]'e yazar.
 */
function retime(stamp, seen) {
  const sign = proxy.hostSigner();
  return (answer) => {
    if (!isConfig(answer) || answer.status !== 200) return answer;
    const json = JSON.parse(answer.body.toString('utf8'));
    const payload = JSON.parse(json.payload);
    const { issuedAt, expiresAt } = stamp();
    payload.issuedAt = issuedAt;
    payload.expiresAt = expiresAt;
    const nextPayload = JSON.stringify(payload);
    if (seen) seen.push({ issuedAt, expiresAt });
    // Tek imza: çoklu imzalayıcı biçimi (signatures) varsa kaldırılır, tekil imza belirleyici olur.
    const { signatures, ...rest } = json;
    return { ...answer, body: Buffer.from(JSON.stringify({ ...rest, payload: nextPayload, signature: sign(nextPayload) })) };
  };
}

/** Config API'ye ulaşılamıyor (saldırgan trafiği kesiyor). */
const blockConfig = (answer) =>
  isConfig(answer) ? { ...answer, status: 503, body: Buffer.from('{"error":"unavailable"}') } : answer;

test('Saldırı: ileri tarihli config reddediliyor; süresi dolan config telefonun saati geri alınınca dirilmiyor', async ({
  app,
  device,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'trafik yönlendirmesi ve saat kaydırma yalnızca emülatörde / simülatörde');
  test.setTimeout(12 * 60 * 1000);

  const SKEW_AHEAD_MS = 2 * 60 * 60 * 1000;
  const SHORT_TTL_MS = 90 * 1000;
  const ROLLBACK_S = 60 * 60;
  let mitm;
  let shifted = 0;
  let expiresAt;

  try {
    await test.step('Saldırgan: araya girer, trafiği değiştirmeden geçirir → telefon config\'i alıyor', async () => {
      device.syncClockToHost();
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('başlangıç: config uygulandı');
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).not.toBeNull();
    });

    await test.step('Saldırgan: issuedAt\'ı iki saat ileri alıp yeniden imzalar → telefon "saatimden ileride" diyerek reddediyor', async () => {
      const seen = [];
      mitm.setMutate(retime(() => {
        const issuedAt = Date.now() + SKEW_AHEAD_MS;
        return { issuedAt, expiresAt: issuedAt + 60 * 60 * 1000 };
      }, seen));
      const status = await app.refreshConfig();
      await app.snap('ileri tarihli config reddedildi');
      const sent = seen[seen.length - 1] || {};
      await attachText(
        testInfo,
        'İleri tarihli config',
        [
          `saldırganın issuedAt'ı : ${sent.issuedAt}  (${sent.issuedAt ? iso(sent.issuedAt) : '-'})`,
          `telefonun saati        : ${device.clockText()}`,
          'imza                   : host\'un imza anahtarıyla yeniden atıldı (geçerli)',
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Kabul edilseydi bu issuedAt "son görülen" olurdu ve sunucunun sonraki iki saat',
          'boyunca verdiği bütün config\'ler "eski tarihli" diye reddedilirdi.',
        ].join('\n'),
      );
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/ahead of this device/i);
    });

    // Gerçekte saldırgan imzalayamaz; bu adım sunucunun CONFIG_TTL_SECONDS'ı kısa
    // tutulmuş gibi kısa ömürlü bir config üretir (laboratuvar kısayolu, sunucu yeniden başlamaz).
    await test.step(`Laboratuvar: geçerliliği ${SHORT_TTL_MS / 1000} saniye olan bir config imzalanır (kısa CONFIG_TTL_SECONDS gibi) → telefon uyguluyor`, async () => {
      const seen = [];
      mitm.setMutate(retime(() => {
        const issuedAt = Date.now();
        return { issuedAt, expiresAt: issuedAt + SHORT_TTL_MS };
      }, seen));
      const status = await app.refreshConfig();
      await app.snap('kısa ömürlü config uygulandı');
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expiresAt = seen[seen.length - 1].expiresAt;
    });

    await test.step('Saldırgan: Config API trafiğini keser, config\'in süresi dolar → uygulama açılışta "süresi doldu" diyor', async () => {
      mitm.setMutate(blockConfig);
      const wait = Math.max(0, expiresAt - Date.now()) + 15_000;
      await sleep(wait);
      app.relaunch();
      const status = await app.waitInitFailed();
      await app.snap('saklı config\'in süresi doldu, taze config alınamıyor: başlatılamadı');
      await attachText(
        testInfo,
        'Süresi dolan saklı config',
        [
          `config expiresAt : ${expiresAt}  (${iso(expiresAt)})`,
          `telefonun saati  : ${device.clockText()}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
        ].join('\n'),
      );
      expect(status).toMatch(/expired/i);
    });

    await test.step('Saldırgan: telefonun saatini bir saat geri alır (expiresAt\'tan önceye) → config yine de süresi dolmuş sayılıyor', async () => {
      device.shiftClock(-ROLLBACK_S);
      shifted -= ROLLBACK_S;
      app.relaunch();
      const status = await app.waitInitFailed();
      await app.snap('saat geri alındı: süresi dolan config dirilmedi');
      await attachText(
        testInfo,
        'Saat geri alındı',
        [
          `config expiresAt      : ${expiresAt}  (${iso(expiresAt)})`,
          `telefonun saati (yeni): ${device.clockText()}  — expiresAt'tan ÖNCE`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Yalnızca duvar saatine bakılsaydı config yeniden "geçerli" olurdu. TrustedClock',
          'görülen en yüksek zamanı saklıyor ve geri gitmiyor; süre kararı ona göre.',
        ].join('\n'),
      );
      expect(status).toMatch(/expired/i);
      expect(app.node('testButton').enabled).toBe(false);
    });

    await test.step('Saat düzeltilir, saldırgan çekilir → telefon sunucunun gerçek config\'iyle Hazır', async () => {
      device.shiftClock(-shifted);
      shifted = 0;
      device.syncClockToHost();
      mitm.setMutate(null);
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saat doğru, saldırgan yok: Hazır');
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      expect(ready).toContain('Hazır');
    });
  } finally {
    if (shifted) device.shiftClock(-shifted);
    device.syncClockToHost();
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
