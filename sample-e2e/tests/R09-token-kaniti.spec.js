// R09 — Çalınan token (istek başına sahiplik kanıtı, PinVault-Proof).
//
// PinVault-Token kısa ömürlü bir bilettir; tek başına "taşıyan kullanır"
// (bearer). Rootlu bir telefondan ya da bir log/bellek dökümünden çalınan token,
// süresi bitene kadar başka bir makineden de kullanılabilirdi. Kütüphane
// proofOfPossession() ile her isteğe, token'ın `cnf.jkt` ile adını verdiği
// kimlik anahtarıyla imzalı bir DPoP kanıtı (RFC 9449) ekler; host
// PINVAULT_TOKEN_REQUIRE_PROOF=true iken kanıtsız ya da başka anahtarla
// imzalanmış kanıtlı isteği 401'le reddeder (ATTESTATION.md §5.1).
//
// Test, "çalınmış token"u host'un token sırrıyla aynı iddialarla (aynı cihaz,
// aynı cnf.jkt) üretir: cihazdan kopyalanmış bir token'ın birebir aynısıdır.
// Önce kanıt istenmezken bu token'ın tek başına geçtiği (eski durum), sonra
// kanıt istenince geçmediği, uygulamanın kendisinin ise (anahtar cihazda)
// geçmeye devam ettiği gösterilir.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');
const tokens = require('../lib/tokens');

const SCOPE = env.VAULT_API;
const jwkThumbprint = tokens.jwkThumbprint;
const liftedToken = (deviceId, jkt) => tokens.liftedToken(SCOPE, deviceId, jkt);
const attackerProof = tokens.attackerProof;
const reason = tokens.reasonOf;

test('R09 Token çalınması: kanıt zorunluyken cihazdan alınan token tek başına ve başka anahtarla 401; uygulamanın kendisi geçer', async ({ app, device, dashboard }, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  let original;
  let deviceId;
  let jkt;

  async function requireProof(on) {
    const saved = await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { PINVAULT_TOKEN_REQUIRE_PROOF: on ? 'true' : '' } } });
    expect(saved.status, `ayar kaydedilemedi: ${saved.text}`).toBe(200);
    // Kaydedilen ayar bir sonraki açılışta geçerli. Mock host'lar token istesin; ortam
    // zaten öyleyse compose container'ı yeniden kurmaz, bu yüzden ayrıca yeniden başlatılır.
    await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
    await hostControl.stop();
    await hostControl.start();
  }

  try {
    await test.step('Hazırlık: politika gevşek (emülatör geçsin), mock host token ister, kanıt istemez', async () => {
      original = await res.getPolicy(SCOPE);
      await res.setPolicy(SCOPE, { ...res.LENIENT }, { revealReasons: true });
      await requireProof(false);
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      await hostApi.forgetRevokedIdentitiesOf(deviceId).catch(() => {});
      await app.backToMain();
    });

    await test.step('Mobil: atestasyon geçer, mock host 200 (kütüphane token ve kanıtı ekler)', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      const record = await res.deviceRecord(SCOPE, deviceId);
      expect(record && record.publicKey, 'cihaz anahtarı kayıtlı olmalı').toBeTruthy();
      jkt = jwkThumbprint(record.publicKey);
      attachText(testInfo, 'Cihaz anahtarı (cnf.jkt)', `deviceId ${deviceId}\nspkiSha256 ${record.spkiSha256}\njkt ${jkt}`);
    });

    await test.step('Ağ (eski durum): kanıt istenmezken çalınan token başka makineden TEK BAŞINA geçer', async () => {
      const token = await liftedToken(deviceId, jkt);
      const r = await hostApi.mockTlsRequest('/', { headers: { 'PinVault-Token': token } });
      expect(r.status, `kanıt istenmezken token tek başına geçmeli: ${r.body}`).toBe(200);
      attachText(testInfo, 'Kanıt istenmiyor: çalınan token', `HTTP ${r.status}`);
    });

    await test.step('Host kanıt ister (PINVAULT_TOKEN_REQUIRE_PROOF=true)', async () => {
      await requireProof(true);
      const view = (await hostApi.api('/api/v1/server-settings')).json;
      const s = view.settings.find((x) => x.key === 'PINVAULT_TOKEN_REQUIRE_PROOF');
      expect(s && s.running).toBe('true');
    });

    await test.step('Ağ: çalınan token tek başına 401 proof_missing; saldırganın anahtarıyla kanıt 401 proof_key', async () => {
      const token = await liftedToken(deviceId, jkt);
      const alone = await hostApi.mockTlsRequest('/', { headers: { 'PinVault-Token': token } });
      expect(alone.status).toBe(401);
      expect(alone.headers['www-authenticate'] || '').toContain('PinVault-Token');
      expect(reason(alone)).toBe('proof_missing');

      const url = `https://localhost:${env.MOCK_TLS_PORT}/`;
      const forged = await hostApi.mockTlsRequest('/', { headers: { 'PinVault-Token': token, 'PinVault-Proof': attackerProof(token, url) } });
      expect(forged.status).toBe(401);
      expect(reason(forged)).toBe('proof_key');
      attachText(testInfo, 'Kanıt isteniyor: çalınan token', [
        `Token tek başına: HTTP ${alone.status} ${alone.body}`,
        `Saldırganın anahtarıyla kanıt: HTTP ${forged.status} ${forged.body}`,
      ].join('\n'));
    });

    await test.step('Mobil: anahtarı taşıyan uygulamanın kendisi geçmeye devam eder', async () => {
      await app.relaunch();
      await app.waitReady();
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('kanıt zorunlu: uygulama token + kanıtla mock host 200');
    });

    await test.step('Web: panelde ayar açık görünür', async () => {
      await dashboard.openSetup?.().catch?.(() => {});
      await dashboard.snap('panel: PINVAULT_TOKEN_REQUIRE_PROOF açık');
    });
  } finally {
    // Ayarı geri al; resetEnv container'ı yeniden kurar ve boş ayarla açar.
    await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { PINVAULT_TOKEN_REQUIRE_PROOF: '' } } }).catch(() => {});
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
