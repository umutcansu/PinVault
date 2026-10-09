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
const crypto = require('crypto');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');
const res = require('../lib/resilience');

const SCOPE = env.VAULT_API;
const b64url = (buf) => Buffer.from(buf).toString('base64url');

/** Cihazın anahtarının RFC 7638 JWK parmak izi (token'daki cnf.jkt). */
function jwkThumbprint(spkiBase64) {
  const jwk = crypto.createPublicKey({ key: Buffer.from(spkiBase64, 'base64'), format: 'der', type: 'spki' }).export({ format: 'jwk' });
  return b64url(crypto.createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`).digest());
}

/** Host'un o an etkin sırrıyla, cihaza verilmiş gibi bir PinVault-Token (çalınmış kopya). */
async function liftedToken(deviceId, jkt) {
  const listed = await hostApi.api('/api/v1/attestation/token-secrets');
  expect(listed.status, `token sırları okunamadı: ${listed.text}`).toBe(200);
  const active = listed.json.secrets.find((s) => s.kid === listed.json.active);
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: active.kid }));
  const payload = b64url(JSON.stringify({
    iss: 'pinvault', sub: deviceId, aud: SCOPE, iat: now, exp: now + 300, jti: b64url(crypto.randomBytes(12)),
    did: deviceId, arc: '00000000', pol: 1, cnf: { jkt },
  }));
  const signature = crypto.createHmac('sha256', Buffer.from(active.secret, 'base64')).update(`${header}.${payload}`).digest();
  return `${header}.${payload}.${b64url(signature)}`;
}

/** Saldırganın kendi anahtarıyla, isteğe ve token'a uygun bir DPoP kanıtı. */
function attackerProof(token, url) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const header = b64url(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } }));
  const payload = b64url(JSON.stringify({
    jti: b64url(crypto.randomBytes(16)), htm: 'GET', htu: url, iat: Math.floor(Date.now() / 1000),
    ath: b64url(crypto.createHash('sha256').update(token).digest()),
  }));
  const signature = crypto.sign('sha256', Buffer.from(`${header}.${payload}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${header}.${payload}.${b64url(signature)}`;
}

function reason(response) {
  try { return JSON.parse(response.body).reason; } catch { return response.body; }
}

test('R09 Token çalınması: kanıt zorunluyken cihazdan alınan token tek başına ve başka anahtarla 401; uygulamanın kendisi geçer', async ({ app, device, dashboard }, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  let original;
  let deviceId;
  let jkt;

  async function requireProof(on) {
    const saved = await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { PINVAULT_TOKEN_REQUIRE_PROOF: on ? 'true' : '' } } });
    expect(saved.status, `ayar kaydedilemedi: ${saved.text}`).toBe(200);
    // Kaydedilen ayar bir sonraki açılışta geçerli: container mock host'lar token isterken yeniden kurulur.
    await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
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
    await hostApi.api('/api/v1/server-settings', { method: 'PUT', body: { values: { PINVAULT_TOKEN_REQUIRE_PROOF: '' } } }).catch(() => {});
    if (deviceId) await res.clearDeviceOverrides(SCOPE, deviceId);
    if (original) await hostApi.api(res.policyPath(SCOPE), { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
