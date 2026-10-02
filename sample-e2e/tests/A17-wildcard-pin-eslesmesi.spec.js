// A17: joker alan adlı (wildcard) pin girdileri. `*.example.com` TEK bir
// alt alan adını kapsar, yani `www.example.com` bu girdiyle
// bağlanır. Buna karşılık `*.com` gibi yalnızca uzantıdan oluşan joker
// kütüphane tarafından sessizce yok sayılır: yanlış yazılmış tek bir satır
// bütün .com alan adlarına izin vermesin diye. Sunucu joker alan adını
// denetlemeden kabul ediyor (host adı biçimi kontrol edilmiyor), bu yüzden
// ayrımı yapan taraf kütüphanedir (PinHostMatcher).
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const SUB_WILDCARD = `*.${TARGET_HOST.split('.').slice(1).join('.')}`; // *.example.com
const TLD_WILDCARD = `*.${TARGET_HOST.split('.').pop()}`; // *.com

/** Test yarıda kalırsa wildcard girdileri config'te kalmasın. */
async function removeWildcards() {
  const cfg = await hostApi.getConfig();
  const pins = cfg.pins.filter((p) => !p.hostname.startsWith('*.'));
  if (pins.length === cfg.pins.length) return;
  await hostApi.api('/api/v1/certificate-config', {
    method: 'PUT',
    body: { version: 0, pins, forceUpdate: false },
  });
}

test(`Web+Mobil: joker alan adı ${SUB_WILDCARD} hedefi kapsıyor, *.com (yalnızca uzantı) yok sayılıyor`, async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);

  try {
    await test.step(`Web: tam adlı host silinir, yerine ${SUB_WILDCARD} eklenir`, async () => {
      await dashboard.openHost(TARGET_HOST);
      await dashboard.snap(`tam adlı host soldaki listede ve başlıkta: ${TARGET_HOST}`);
      await dashboard.deleteHost(TARGET_HOST);
      await dashboard.addHostManual(env.VAULT_API, SUB_WILDCARD, run.goodPins);
      await dashboard.snap(`joker alan adlı host eklendi: ${SUB_WILDCARD}`);
      const cfg = await hostApi.getConfig();
      await attachText(
        testInfo,
        'Sunucu joker alan adını denetlemeden kabul ediyor',
        [
          `Config'teki host'lar: ${cfg.pins.map((p) => p.hostname).join(', ')}`,
          `${SUB_WILDCARD} pin'leri = hedefin şu anki sertifikasının pin'leri (${run.goodPins[0].slice(0, 12)}…)`,
          '',
          'Sunucu host adının biçimini denetlemiyor (validatePinConfig yalnızca',
          'boş alan ve pin biçimine bakıyor); joker alan adı kuralını uygulayan',
          'taraf kütüphanedeki PinHostMatcher.',
        ].join('\n'),
      );
      expect(cfg.pins.map((p) => p.hostname)).toContain(SUB_WILDCARD);
      expect(cfg.pins.map((p) => p.hostname)).not.toContain(TARGET_HOST);
    });

    await test.step('Mobil: config yenilenir — pin girdisi joker alan adıyla geliyor', async () => {
      const status = await app.refreshConfig();
      await app.snap(`config'te ${SUB_WILDCARD}`);
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, SUB_WILDCARD)).not.toBeNull();
      expect(SampleApp.hostVersion(status, TARGET_HOST)).toBeNull();
    });

    await test.step('Mobil: hedefe pinli istek joker alan adıyla geçiyor (* yalnızca tek bir alt alan adını kapsar)', async () => {
      const result = await app.testLibraryClient();
      await app.snap('joker alan adlı pin ile bağlantı başarılı');
      await attachText(
        testInfo,
        `Tek alt alan adı eşleşmesi: ${SUB_WILDCARD} → ${TARGET_HOST}`,
        [
          result.split('\n').slice(0, 3).join('\n'),
          '',
          `* yerine gelen kısım: "${TARGET_HOST.split('.')[0]}" (nokta içermiyor) → eşleşir.`,
          'PinHostMatcher.match: iki alt alan adlı bir ad (a.b.example.com) ya da',
          'alt alan adı olmayan example.com aynı girdiyle EŞLEŞMEZ.',
        ].join('\n'),
      );
      expect(result).toContain('Pinned bağlantı başarılı');
      await app.waitForEvent(`[✓] ${TARGET_HOST}`);
    });

    await test.step('Web: joker alan adı yalnızca uzantıya genişletilir (*.com)', async () => {
      await dashboard.deleteHost(SUB_WILDCARD);
      await dashboard.addHostManual(env.VAULT_API, TLD_WILDCARD, run.goodPins);
      await dashboard.snap(`yalnızca uzantıdan oluşan joker eklendi: ${TLD_WILDCARD}`);
      const cfg = await hostApi.getConfig();
      expect(cfg.pins.map((p) => p.hostname)).toContain(TLD_WILDCARD);
    });

    await test.step('Mobil: *.com config\'e giriyor ama kütüphane onu eşleştirmiyor', async () => {
      const status = await app.refreshConfig();
      await app.snap(`config'te ${TLD_WILDCARD}`);
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, TLD_WILDCARD)).not.toBeNull();

      const result = await app.testLibraryClient();
      await app.snap('*.com ile bağlantı reddedildi');
      await attachText(
        testInfo,
        `Yalnızca uzantıdan oluşan joker eşleşmiyor: ${TLD_WILDCARD}`,
        [
          `Config'te girdi var: ${TLD_WILDCARD} → pin v${SampleApp.hostVersion(status, TLD_WILDCARD)}`,
          '',
          result.split('\n').slice(0, 4).join('\n'),
          '',
          'PinHostMatcher.match: "*." sonrasındaki kısım nokta içermiyorsa',
          '(com, tr, net…) girdi atlanır; tek bir yanlış satır o uzantıdaki bütün',
          'alan adlarına izin vermesin diye. Eşleşme bulunamayınca bağlantı reddedilir',
          '(şüphede bağlantıya izin verilmez); telefonun sistem sertifikalarına geri',
          'dönülmez.',
        ].join('\n'),
      );
      expect(result).toContain('Bağlantı başarısız');
      expect(result).toContain('No pin entry for hostname');
    });

    await test.step('Web: tam adlı host geri eklenir, telefon yeniden bağlanır', async () => {
      await dashboard.deleteHost(TLD_WILDCARD);
      await dashboard.addHostManual(env.VAULT_API, TARGET_HOST, run.goodPins);
      await dashboard.snap('tam adlı host geri geldi');
      const status = await app.refreshConfig();
      await app.snap('tam adlı host ile config');
      expect(SampleApp.hostVersion(status, TARGET_HOST)).not.toBeNull();
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    await removeWildcards();
  }
});
