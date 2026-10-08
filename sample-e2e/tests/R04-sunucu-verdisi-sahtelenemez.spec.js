// R04 — Sunucunun verdiği karar sahtelenemez (anahtar atestasyonu).
//
// İstemci içindeki ölçümler (root, emülatör, hooking, imza…) ele geçirilmiş bir
// cihazda hook'lanıp "temiz" raporlanabilir. Bu senaryo o durumu, bütün
// İSTEMCİ-ÖLÇÜMLÜ bayrakları "ignore" yaparak taklit eder (istemci ne derse
// desin yok sayılır). Yine de sunucunun KENDİ yargıladığı `key_unattested` —
// cihazın kimlik anahtarının donanım (Android Key Attestation) zincirine bağlı
// olup olmadığı; bu emülatörde `attested=false`, `untrusted_root` — açık kalır.
// Politika `key_unattested: reject` iken telefon KALIR, token alamaz ve mock
// host 401 döner. Yani istemci bütün kendi sinyallerini gizlese bile, cihazın
// SAHTELEYEMEDİĞİ sunucu verdisi geçişi engeller. `key_unattested` gevşetilince
// (aynı diğer bayraklarla) telefon GEÇER; böylece kapıyı özel olarak bu
// sunucu-yargılı sinyalin tuttuğu kanıtlanır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;

// İstemcinin ölçtüğü her sinyal yok sayılır (hook'lanmış/yalan söyleyen istemci taklidi).
const CLIENT_SIGNALS_IGNORED = {
  rooted: 'ignore',
  emulator: 'ignore',
  debugger: 'ignore',
  debuggable: 'ignore',
  hooking_framework: 'ignore',
  app_integrity: 'ignore',
  cloner: 'ignore',
  unknown_installer: 'ignore',
  adb_enabled: 'ignore',
  software_key: 'ignore',
  old_patch_level: 'ignore',
  play_integrity: 'ignore',
  play_integrity_missing: 'ignore',
};

test('R04 Sunucu verdisi: istemci bütün sinyallerini gizlese de sahtelenemeyen key_unattested reddeder; gevşetilince geçer', async ({ app, device }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step('Önkoşul: cihazın anahtarı donanıma attested değil (sunucu kaydı)', async () => {
      // Emülatörün Keystore anahtarı güvenilir donanım köküne zincirlenmez.
      // Bunu ilk atestasyondan sonra cihaz kaydındaki keyAttestation ile görürüz.
    });

    await test.step('Hazırlık: bütün istemci sinyalleri ignore, yalnızca key_unattested reject; mock host token ister', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...CLIENT_SIGNALS_IGNORED, key_unattested: 'reject' }, { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Mobil: istemci sinyalleri yok sayılsa da key_unattested reddeder → KALDI, mock host 401', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('key_unattested');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('sunucu verdisi: key_unattested reddetti, 401');

      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('reject');
      expect(res.reasonsOf(record)).toContain('key_unattested');
      // Sahtelenemez kanıt: sunucu kaydı anahtarı attested görmüyor.
      expect(record.keyAttestation && record.keyAttestation.attested).toBeFalsy();
      attachText(testInfo, 'Cihaz kaydı (key_unattested, sunucu yargısı)', JSON.stringify(record, null, 2));
    });

    await test.step('key_unattested gevşetilince → aynı cihaz GEÇER (kapıyı tutan oydu)', async () => {
      await res.setPolicy(SCOPE, { key_unattested: 'warn' });
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('key_unattested warn: atestasyon geçti, 200');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record.lastResult).toBe('pass');
    });
  } finally {
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
