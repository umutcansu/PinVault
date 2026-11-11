// G10 — İmzalı görünümü başka bir isteğe cevap olarak verme (M6).
//
// Sunucu config'in daraltılmış görünümlerini de imzalıyor: `?hosts=` ile
// istenen host'lar, X-Device-Id ile cihazın izin listesi (ACL). Bu görünümler
// sunucunun gerçek imzasını taşır. Saldırgan bunlardan birini alıp başka bir
// isteğe cevap olarak verirse imza yine geçerlidir; 2.9.0'a kadar telefon da
// kabul ediyordu:
//
//   • bütün config'i isteyen telefona tek host'luk görünüm → telefon diğer
//     bütün host'ların pin'lerini düşürür (o host'lar pinsiz kalır),
//   • kapsamlı (wantPinsFor) telefona başka host'ların ya da başka bir cihazın
//     görünümü → telefon istemediği pin'leri uygular.
//
// 2.9.0'dan beri imzalı payload hangi isteğe cevap olduğunu `view` alanında
// söylüyor ({"hosts": [...], "deviceId": "..."}); kütüphane bunu kendi isteğiyle
// karşılaştırıp uymayan görünümü uygulamadan reddediyor
// (crypto/ConfigViewBinding, iOS'ta aynısı). Senaryo:
//
//   1. saldırgan araya girer, telefon bütün config'i alır,
//   2. saldırgan sunucudan imzalı ?hosts=<hedef> görünümünü alıp telefonun
//      bütün config isteğine verir → reddedilir, diğer host'ların pin'leri durur,
//   3. telefon kapsamlı moda alınır (wantPinsFor hedef),
//   4. saldırgan başka host'un görünümünü verir → reddedilir,
//   5. saldırgan aynı host'un BAŞKA cihaz için imzalanmış görünümünü verir → reddedilir,
//   6. saldırgan çekilince telefon kendi görünümünü sorunsuz uyguluyor.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const API = env.VAULT_API;

const setDefaultAcl = (hosts) =>
  hostApi.api(`/api/v1/config-apis/${API}/default-host-acl`, { method: 'PUT', body: { hostnames: hosts } });

const viewOf = (signed) => JSON.stringify(signed.config.view ?? null);
const hostsOf = (signed) => (signed.config.pins || []).map((p) => p.hostname).join(', ') || '(boş)';

test('Saldırı: imzalı daraltılmış görünüm başka bir isteğe verilirse (bütün config yerine tek host, başka host, başka cihaz) telefon reddediyor ve pin\'leri yerinde kalıyor', async ({
  app,
  device,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'trafik yönlendirmesi yalnızca emülatörde / simülatörde kurulabilir');
  test.setTimeout(12 * 60 * 1000);

  let mitm;
  let deviceId;
  let scopedOn = false;

  try {
    await test.step('Web: varsayılan izin listesi (Default ACL) hedef host ve mock TLS host olarak ayarlanır (daraltılmış görünümler boş olmasın)', async () => {
      const res = await setDefaultAcl([TARGET_HOST, env.MOCK_TLS_HOST]);
      await attachText(testInfo, `PUT /api/v1/config-apis/${API}/default-host-acl`, `HTTP ${res.status} ${res.text.trim()}`);
      expect(res.status).toBe(200);
    });

    await test.step('Mobil: cihaz kimliği okunur (telefonun X-Device-Id değeri)', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.snap('cihaz kimliği');
      await app.backToMain();
      expect(deviceId.length).toBeGreaterThan(4);
    });

    await test.step('Saldırgan: araya girer, trafiği değiştirmeden geçirir → telefon bütün config\'i alıyor', async () => {
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: bütün config uygulandı');
      expect(SampleApp.hostVersion(ready, TARGET_HOST)).not.toBeNull();
      expect(SampleApp.hostVersion(ready, env.LAN_IP)).not.toBeNull();
      expect(SampleApp.hostVersion(ready, env.MOCK_TLS_HOST)).not.toBeNull();
    });

    await test.step(`Saldırgan: sunucudan imzalı ?hosts=${TARGET_HOST} görünümünü alır, telefonun BÜTÜN config isteğine verir → telefon reddediyor`, async () => {
      const narrowed = await hostApi.signedViewRaw({ hosts: [TARGET_HOST] });
      mitm.setMutate(proxy.replayConfig(narrowed.raw));
      const status = await app.refreshConfig();
      await app.snap('tek host\'luk görünüm bütün config yerine verildi: reddedildi');
      await attachText(
        testInfo,
        'Saldırganın verdiği yanıt: sunucunun imzaladığı daraltılmış görünüm',
        [
          `istek (saldırganın)  : GET /api/v1/certificate-config?hosts=${TARGET_HOST}`,
          `payload.view         : ${viewOf(narrowed)}`,
          `içindeki host'lar    : ${hostsOf(narrowed)}`,
          `issuedAt             : ${narrowed.config.issuedAt}`,
          `imza                 : ${redact(narrowed.envelope.signature || '', 20)} — sunucunun gerçek imzası`,
          '',
          'telefonun isteği     : GET /api/v1/certificate-config (bütün config, ?hosts= yok)',
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Uygulansaydı telefon yalnızca hedef host\'un pin\'lerini tutar, diğer host\'lar',
          '(host\'un kendi IP\'si, mock host\'lar) pinsiz kalırdı.',
        ].join('\n'),
      );
      expect(narrowed.config.view, 'sunucu daraltılmış görünüme view yazmalı').toBeTruthy();
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/narrowed view/i);
      // Saklı config bozulmadı: diğer host'ların pin'leri duruyor.
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).not.toBeNull();
      mitm.setMutate(null);
    });

    await test.step(`Mobil: Ayarlar'da "Yalnızca hedef host'un pin'lerini iste" açılır (wantPinsFor ${TARGET_HOST}) → telefon kendi görünümünü alıyor`, async () => {
      await app.openSettings();
      const applied = await app.setScopedPins(true);
      scopedOn = true;
      expect(applied).toContain('Pin kapsamı: yalnızca');
      await app.backToMain();
      const status = await app.waitReady();
      await app.snap('pin kapsamı açık: yalnızca hedef host');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).toBeNull();
    });

    await test.step(`Saldırgan: başka host'un (${env.MOCK_TLS_HOST}) bu cihaz için imzalanmış görünümünü verir → telefon reddediyor`, async () => {
      const other = await hostApi.signedViewRaw({ hosts: [env.MOCK_TLS_HOST], deviceId });
      mitm.setMutate(proxy.replayConfig(other.raw));
      const status = await app.refreshConfig();
      await app.snap('başka host\'un görünümü verildi: reddedildi');
      await attachText(
        testInfo,
        'Başka host\'un görünümü',
        [
          `telefonun isteği : ?hosts=${TARGET_HOST}, X-Device-Id: ${deviceId}`,
          `verilen view     : ${viewOf(other)}`,
          `içindeki host'lar: ${hostsOf(other)}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
        ].join('\n'),
      );
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/another host set/i);
      expect(SampleApp.hostVersion(status, TARGET_HOST)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).toBeNull();
    });

    await test.step(`Saldırgan: aynı host'un BAŞKA cihaz için imzalanmış görünümünü verir → telefon reddediyor`, async () => {
      const foreign = await hostApi.signedViewRaw({ hosts: [TARGET_HOST], deviceId: 'baska-cihaz' });
      mitm.setMutate(proxy.replayConfig(foreign.raw));
      const status = await app.refreshConfig();
      await app.snap('başka cihazın görünümü verildi: reddedildi');
      await attachText(
        testInfo,
        'Başka cihazın görünümü',
        [
          `telefonun isteği : ?hosts=${TARGET_HOST}, X-Device-Id: ${deviceId}`,
          `verilen view     : ${viewOf(foreign)}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'Cihaz izin listeleri farklı olabilir: başka cihazın görünümünü uygulamak, bu',
          'cihazın görmemesi gereken host\'ların pin\'lerini almak demek.',
        ].join('\n'),
      );
      expect(status).toContain('Config yenilenemedi');
      expect(status).toMatch(/another device id/i);
    });

    await test.step('Saldırgan çekilir → telefon kendi görünümünü uyguluyor, pinli istek başarılı', async () => {
      mitm.setMutate(null);
      const status = await app.refreshConfig();
      await app.snap('saldırgan kurcalamayı bıraktı: kendi görünümü');
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Mobil: pin kapsamı kapatılır, yönlendirme kaldırılır → bütün host\'lar geri geliyor', async () => {
      await app.openSettings();
      const applied = await app.setScopedPins(false);
      scopedOn = false;
      expect(applied).toContain("Pin kapsamı: bütün host'lar");
      await app.backToMain();
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      const status = await app.waitReady();
      await app.snap('saldırgan yok, kapsam kapalı: bütün host\'lar');
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).not.toBeNull();
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
    await setDefaultAcl([]);
    if (scopedOn) {
      try {
        await app.backToMain();
        await app.openSettings();
        await app.setScopedPins(false);
        await app.backToMain();
      } catch {
        /* sonraki senaryo uygulamayı verisi silinmiş açar */
      }
    }
  }
});
