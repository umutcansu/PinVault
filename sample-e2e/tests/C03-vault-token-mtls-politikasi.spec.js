// C03 — Vault `token_mtls` politikası.
//
// En sıkı politika: dosya hem cihaza özel bir token hem de istemci sertifikası
// ister. Sunucu, doğrulanmış sertifikanın CN'inden ("PinVault Client: <id>")
// istemci kimliğini çıkarıp X-Device-Id ile eşleştiriyor; token enrollment'ta
// kimlik yönetici tarafından seçildiği için `client_certs.device_uid` üzerinden
// de bağlanabiliyor. Sızmış bir token, özel anahtar olmadan işe yaramıyor.
//
// Kanıt: telefonda token'sız red → token'la indirme; ağ trafiğinde dört durum
// (sertifikasız el sıkışma, TLS dinleyicide geçerli token'la bile red, yanlış
// cihazın sertifikasıyla red, kendi kimliğiyle kabul).
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachFailingCommand, describeResponse, redact } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.mtlsSecret;
const WORK_DIR = path.join(env.LOCAL_DIR, 'c03');
const P12 = path.join(WORK_DIR, 'other-client.p12');
const CERT_PEM = path.join(WORK_DIR, 'other-client-cert.pem');
const KEY_PEM = path.join(WORK_DIR, 'other-client-key.pem');
const MTLS_URL = `https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/vault/${KEY}`;

/** P12'yi https/curl'ün kullanabileceği sertifika + anahtar dosyalarına ayırır. */
function splitP12(p12, password = 'changeit') {
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nokeys', '-out', CERT_PEM]);
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nocerts', '-nodes', '-out', KEY_PEM]);
  return execFileSync('openssl', ['x509', '-in', CERT_PEM, '-noout', '-subject'], { encoding: 'utf8' }).trim();
}

/**
 * mTLS dinleyicisine ham vault isteği. Sertifika üretimi ve kayıt dinleyiciyi
 * yeniden başlattığı için kısa bir yeniden deneme penceresi var.
 */
async function mtlsDownload(opts, attempts = 8) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      return await hostApi.rawVaultDownload(KEY, opts.deviceId, {
        port: env.MTLS_API_PORT,
        token: opts.token,
        certFile: CERT_PEM,
        keyFile: KEY_PEM,
      });
    } catch (e) {
      last = e;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw last;
}

test('Vault token_mtls: token + istemci sertifikası birlikte gerekiyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  const stamp = Date.now();
  const deviceCertId = `c03-cihaz-${stamp}`;
  const otherCertId = `c03-baska-${stamp}`;
  const secret = `mtls-gizli-${stamp}`;
  let deviceId;
  let deviceToken;
  let otherToken;
  let tlsScopeToken;
  fs.mkdirSync(WORK_DIR, { recursive: true });

  try {
    await test.step('Mobil: cihaz kimliği okunur', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.snap('vault ekranı — cihaz kimliği');
      await app.backToMain();
      expect(deviceId).toMatch(/^[0-9a-f]{16}$/);
    });

    await test.step('Web: başka bir cihaza ait istemci sertifikası üretilir', async () => {
      await dashboard.generateClientCert(env.MTLS_API, otherCertId, { saveTo: P12 });
      const subject = splitP12(P12);
      await dashboard.snapClientCertTable(`başka istemci sertifikası: ${otherCertId}`);
      await attachText(
        testInfo,
        'Karşılaştırma için ikinci istemci sertifikası',
        [`subject: ${subject}`, `${fs.statSync(P12).size} bayt P12`,
          'Bu sertifika GEÇERLİ ve sunucunun güvendiği listede (truststore); ama başka bir kimliğe ait.'].join('\n'),
      );
      expect(subject).toContain(otherCertId);
    });

    await test.step('Mobil: cihaz kayıt token\'ıyla kendi sertifikasını alır', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, deviceCertId);
      await app.openMtls();
      expect(await app.enroll(token)).toContain(`Kayıt başarılı — CN=PinVault Client: ${deviceCertId}`);
      await app.snap('cihaz kaydı tamam');
      await app.backToMain();
      const certs = await hostApi.clientCerts();
      const mine = certs.find((c) => c.id === deviceCertId);
      await attachText(
        testInfo,
        'Sunucudaki istemci sertifikası kaydı',
        [
          `clientId=${mine.id}`,
          `deviceUid=${mine.deviceUid || '(yok)'}`,
          `revoked=${mine.revoked}`,
          '',
          'token_mtls\'te cihazı eşleştirmenin ikinci yolu bu: sertifikadaki ad (CN)',
          `yöneticinin seçtiği "${deviceCertId}", cihazın ANDROID_ID\'si ise "${deviceId}".`,
          'Kütüphane kayıt isteğinde deviceUid gönderdiği için sunucu ikisini',
          'birbirine bağlayabiliyor.',
        ].join('\n'),
      );
      expect(mine.deviceUid).toBe(deviceId);
    });

    await test.step('Web: mTLS Config API\'nin host listesi hazırlanır, dosya token_mtls ile yüklenir', async () => {
      const report = await mtlsScope.ensureHosts(dashboard, [env.LAN_IP]);
      const version = await dashboard.uploadVaultText(env.MTLS_API, KEY, secret, { policy: 'token_mtls' });
      const cells = await dashboard.vaultRowCells(KEY);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${env.MTLS_API} vault dosyaları`);
      await attachText(testInfo, `${env.MTLS_API} host listesi`, report);
      expect(cells.policy).toContain('token_mtls');
      expect(version).toBeGreaterThan(0);
    });

    await test.step('Mobil: mTLS config moduna geçilir, token yokken indirme 401', async () => {
      await app.openSettings();
      expect(await app.applyMode('MTLS_CONFIG')).toContain('Hazır — config v');
      await app.backToMain();
      expect(await app.waitReady()).toContain('Mod: mTLS config');
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('token_mtls: token yok → 401');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
    });

    await test.step('Web: bu cihaz için vault token\'ı üretilir', async () => {
      deviceToken = await dashboard.generateVaultToken(env.MTLS_API, KEY, deviceId);
      await dashboard.snap(`${KEY} için cihaz token'ı üretildi`);
      expect(deviceToken).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    });

    await test.step('Mobil: token + istemci sertifikasıyla dosya iniyor', async () => {
      await app.openVault();
      await app.saveVaultToken(deviceToken, KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('token_mtls: dosya indi');
      expect(status).toContain(`${KEY} v`);
      expect(status).toContain('indirildi');
      expect(status).toContain('mTLS bloğu: istemci sertifikası + token');
      expect(status).toContain(secret);
      await attachText(
        testInfo,
        'Telefonun kullandığı kimlik bilgileri',
        [
          `X-Device-Id: ${deviceId}`,
          `X-Vault-Token: ${redact(deviceToken)}`,
          `istemci sertifikası CN: PinVault Client: ${deviceCertId}`,
          '',
          'Üçü birden gerekiyor; sunucu sertifikadaki addan (CN) çıkardığı kimliği',
          'client_certs.device_uid üzerinden X-Device-Id ile eşleştiriyor.',
        ].join('\n'),
      );
      await dashboard.expectDistribution(env.MTLS_API, {
        key: KEY,
        deviceModel: run.model,
        status: 'downloaded',
      });
      await dashboard.snap('dağıtım geçmişi — token_mtls indirmesi');
    });

    await test.step('Ağ trafiği: sertifikasız istek mTLS portunda daha bağlantı kurulurken kesiliyor', async () => {
      const out = await attachFailingCommand(
        testInfo,
        `curl -k ${MTLS_URL} (istemci sertifikası yok)`,
        'curl',
        ['-sS', '-k', '--max-time', '15', '-H', `X-Device-Id: ${deviceId}`, MTLS_URL],
      );
      expect(out).toMatch(/alert|handshake|SSL|TLS|reset/i);
    });

    await test.step('Ağ trafiği: TLS portunda geçerli token bile yetmiyor (401)', async () => {
      // Aynı anahtar, TLS kapsamına da token_mtls olarak yükleniyor: böylece
      // politika kapısı el sıkışma katmanından ayrı olarak görülebiliyor.
      await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, { policy: 'token_mtls' });
      tlsScopeToken = await dashboard.generateVaultToken(env.VAULT_API, KEY, deviceId);
      const res = await hostApi.rawVaultDownload(KEY, deviceId, { token: tlsScopeToken });
      await attachText(
        testInfo,
        `GET https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/vault/${KEY} — geçerli token, sertifika yok`,
        [
          describeResponse(res, { maxBody: 256 }),
          '',
          'Token kabul edildi ("yanlış token" hatası gelmedi), istek yine de reddedildi:',
          'token_mtls politikalı dosya, istemci sertifikası olmayan bağlantıya verilmiyor.',
        ].join('\n'),
      );
      expect(res.status).toBe(401);
      expect(res.body.toString('utf8')).toContain('mTLS client certificate required');
    });

    await test.step('Ağ trafiği: başka cihazın sertifikasıyla bu cihazın token\'ı reddediliyor', async () => {
      const res = await mtlsDownload({ deviceId, token: deviceToken });
      await attachText(
        testInfo,
        `GET ${MTLS_URL} — sertifika "${otherCertId}", X-Device-Id "${deviceId}"`,
        [
          describeResponse(res, { maxBody: 256 }),
          '',
          'Sertifika geçerli ve sunucu ona güveniyor; token da geçerli. Uymayan tek şey',
          'kimlik: sertifikadaki addan (CN) çıkan kimlik ne X-Device-Id\'ye eşit ne de',
          'o sertifikanın device_uid\'sine. Çalınan bir token, başka bir cihazın',
          'sertifikası ve anahtarıyla kullanılamıyor.',
        ].join('\n'),
      );
      expect(res.status).toBe(401);
      expect(res.body.toString('utf8')).toContain('Device identity mismatch');
    });

    await test.step('Ağ trafiği: aynı sertifika kendi kimliğiyle 200 alıyor', async () => {
      otherToken = await dashboard.generateVaultToken(env.MTLS_API, KEY, otherCertId);
      const res = await mtlsDownload({ deviceId: otherCertId, token: otherToken });
      await attachText(
        testInfo,
        `GET ${MTLS_URL} — sertifika "${otherCertId}", X-Device-Id "${otherCertId}"`,
        [
          describeResponse(res, { maxBody: 256 }),
          '',
          'Doğrudan eşleşme (certClientId == deviceId): otomatik kayıtta CN zaten',
          'ANDROID_ID olduğu için gerçek kullanımda çalışan yol bu.',
        ].join('\n'),
      );
      expect(res.status).toBe(200);
      expect(res.body.toString('utf8')).toBe(secret);
    });

    await test.step('Mobil: yanlış token ile indirme reddediliyor', async () => {
      await app.openVault();
      await app.saveVaultToken('bu-token-yanlis-0000000000000000', KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('yanlış token → 401');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
    });

    await test.step('Web: dağıtım geçmişinde token_mtls kayıtları', async () => {
      // En yeni kayıt yanlış token denemesi: geçmiş başarılıyı da başarısızı da
      // nedeniyle birlikte tutuyor.
      await dashboard.expectDistribution(env.MTLS_API, {
        key: KEY,
        deviceModel: run.model,
        status: 'failed',
      });
      await dashboard.snap('dağıtım geçmişi — token_mtls (başarılı + başarısız)');
      const dists = await hostApi.vaultDistributions(env.MTLS_API, KEY);
      await attachText(
        testInfo,
        `GET /api/v1/config-apis/${env.MTLS_API}/vault/distributions/${KEY}`,
        dists
          .slice(0, 6)
          .map((d) => `${d.timestamp} ${d.status.padEnd(10)} v${d.version} auth=${d.authMethod} ${d.failureReason || ''}`)
          .join('\n'),
      );
      expect(dists.some((d) => d.status === 'downloaded' && d.authMethod === 'token_mtls')).toBe(true);
      expect(dists.some((d) => d.status === 'failed')).toBe(true);
    });

    await test.step('Mobil: TLS moduna dönülüyor', async () => {
      await app.backToMain();
      await app.openSettings();
      expect(await app.applyMode('TLS')).toContain('Hazır — config v');
      await app.backToMain();
      expect(await app.waitReady()).toContain('Mod: TLS config');
      await app.snap('TLS moduna dönüldü');
    });
  } finally {
    await hostApi.deleteVaultFile(env.MTLS_API, KEY).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
    await mtlsScope.reset().catch(() => {});
    await hostApi.revokeClientCertIfActive(otherCertId).catch(() => {});
    await hostApi.revokeClientCertIfActive(deviceCertId).catch(() => {});
  }
});
