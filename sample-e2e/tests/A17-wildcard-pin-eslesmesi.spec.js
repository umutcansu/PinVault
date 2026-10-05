// A17: joker alan adlı (wildcard) pin girdileri. `*.example.com` TEK bir
// alt alan adını kapsar, yani `www.example.com` bu girdiyle
// bağlanır. Buna karşılık `*.com` gibi yalnızca uzantıdan oluşan joker
// kabul edilmez: yanlış yazılmış tek bir satır bütün .com alan adlarına izin
// vermesin diye. Sunucu böyle bir girdiyi kayıt anında 400 ile reddeder
// (HostPatternRules); kütüphane de aynı kuralı uygular ve böyle bir girdi
// taşıyan config'in tamamını reddeder (PinConfigValidator), yani sunucu
// kuralı atlansa bile telefon onu uygulamaz.
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

test(`Web+Mobil: joker alan adı ${SUB_WILDCARD} hedefi kapsıyor, *.com (yalnızca uzantı) sunucuda reddediliyor`, async ({
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

    await test.step('Web: yalnızca uzantıdan oluşan joker (*.com) sunucuda reddediliyor', async () => {
      const before = await hostApi.getConfig();
      const res = await hostApi.api('/api/v1/certificate-config', {
        method: 'PUT',
        body: { version: 0, pins: before.pins.concat([{ hostname: TLD_WILDCARD, sha256: run.goodPins }]), forceUpdate: false },
      });
      const after = await hostApi.getConfig();
      await attachText(
        testInfo,
        `PUT /api/v1/certificate-config — ${TLD_WILDCARD} eklenmek istendi`,
        [
          `HTTP ${res.status} ${res.text}`,
          '',
          `config'teki host'lar: ${after.pins.map((p) => p.hostname).join(', ')}`,
          '',
          'Sunucu joker alan adını kayıt anında denetliyor: "*." sonrasında kayıtlı bir alan adı',
          'olmalı (*.example.com). Yalnızca uzantı (*.com, *.com.tr) ya da adres kabul edilmiyor.',
          'Kütüphane aynı kuralı uygular; böyle bir girdi taşıyan imzalı bir config gelse bile',
          'telefon config\'in tamamını reddeder ve eskisiyle devam eder.',
        ].join('\n'),
      );
      expect(res.status).toBe(400);
      expect(res.text).toContain(TLD_WILDCARD);
      expect(after.pins.map((p) => p.hostname)).not.toContain(TLD_WILDCARD);
    });

    await test.step('Web: tam adlı host geri eklenir, telefon yeniden bağlanır', async () => {
      await dashboard.deleteHost(SUB_WILDCARD);
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
