// PinVault-Token'lar ve kanıtlar (ATTESTATION.md §5): R09 ve R11'in "cihazdan çalınmış"
// token'ı. Host'un etkin sırrıyla, cihaza verilmiş gibi aynı iddialar (aynı cihaz, aynı
// cnf.jkt) taşıyan bir token üretilir: cihazdan kopyalanmış bir token'ın birebir aynısı.
const crypto = require('crypto');
const { expect } = require('@playwright/test');
const hostApi = require('./hostApi');

const b64url = (buf) => Buffer.from(buf).toString('base64url');

/** Cihaz anahtarının RFC 7638 JWK parmak izi (token'daki cnf.jkt). */
function jwkThumbprint(spkiBase64) {
  const jwk = crypto.createPublicKey({ key: Buffer.from(spkiBase64, 'base64'), format: 'der', type: 'spki' }).export({ format: 'jwk' });
  return b64url(crypto.createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`).digest());
}

/** Host'un o an etkin sırrıyla, [deviceId]'ye [scope] için verilmiş gibi bir PinVault-Token. */
async function liftedToken(scope, deviceId, jkt) {
  const listed = await hostApi.api('/api/v1/attestation/token-secrets');
  expect(listed.status, `token sırları okunamadı: ${listed.text}`).toBe(200);
  const active = listed.json.secrets.find((s) => s.kid === listed.json.active);
  expect(active && active.secret, 'etkin anahtar HS256 değil: bu test host\'u PINVAULT_TOKEN_ALG=HS256 ile açmalı').toBeTruthy();
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: active.kid }));
  const payload = b64url(JSON.stringify({
    iss: 'pinvault', sub: deviceId, aud: scope, iat: now, exp: now + 300, jti: b64url(crypto.randomBytes(12)),
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

function reasonOf(response) {
  try { return JSON.parse(response.body).reason || JSON.parse(response.body).error; } catch { return response.body; }
}

module.exports = { jwkThumbprint, liftedToken, attackerProof, reasonOf };
