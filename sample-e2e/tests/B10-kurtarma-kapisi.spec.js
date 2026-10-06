// B10 — Süresi dolmuş istemci sertifikası kurtarma kapısından yenilenir.
//
// mTLS Config API (6652) süresi dolmuş sertifikayı el sıkışmada reddeder; o
// sertifikayla cihaz config bile çekemez. Kütüphane bu durumda yenilemeyi
// bloğun renewalUrl'ine götürür: host'un kurtarma kapısı (6656 → 8083),
// istemci sertifikası istemeyen ve yalnızca yenileme yapan bir TLS dinleyici.
// Kapının sertifikasını sunucu CA'sı imzalar; uygulama bu port için CA'ya
// pinler (host.recoveryPins). Kimlik kanıtı CSR'ın imzası: kayıttaki anahtar.
//
// Senaryo kısa ömürlü bir sertifikayla (test kancası, 40 s) kayıt olur ve süre
// dolana kadar kütüphaneyi yeniden başlatmaz. Yeniden başlatılsaydı sertifika,
// süresi dolmadan mTLS üzerinden yenilenirdi (ömrünün son üçte biri). Sonra
// mTLS config moduna geçer: ilk açılışta sertifikanın süresi dolmuş, yenileme
// kapıdan geçer ve mod hazır olur.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const { sleep } = require('../lib/device');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const mtlsScope = require('../lib/mtlsScope');
const env = require('../lib/env');

const DOOR = `https://${env.LAN_IP}:${env.RECOVERY_PORT}`;
const TTL_SECONDS = 40;

async function certRecord(clientId) {
  const certs = (await hostApi.api('/api/v1/client-certs')).json || [];
  return certs.find((c) => c.id === clientId);
}

test('mTLS: süresi dolmuş sertifika kurtarma kapısından yenilenir', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  const clientId = `b10-${Date.now()}`;
  let token;
  let expiresAt;

  try {
    await test.step('Sunucu: test kancası açılır; mTLS Config API\'ye host\'lar eklenir', async () => {
      await hostControl.setEnv({ ALLOW_TEST_HOOKS: 'true' });
      await dashboard.page.reload();
      await expect(dashboard.page.locator('#host-list .api-header').first()).toBeVisible();
      const report = await mtlsScope.ensureHosts(dashboard, [env.LAN_IP, env.MOCK_MTLS_HOST]);
      await attachText(testInfo, 'mTLS Config API\'deki host\'lar', report);
    });

    await test.step('Terminal: kurtarma kapısı dışarı açık, sertifikasını sunucu CA\'sı imzalıyor', async () => {
      const door = (await hostApi.api('/api/v1/recovery-door')).json;
      await attachCommand(testInfo, `curl ${DOOR}/health (istemci sertifikası yok)`, 'curl', [
        '-sS', '-k', '--max-time', '15', `${DOOR}/health`,
      ]);
      const chain = await attachCommand(testInfo, `openssl s_client ${env.LAN_IP}:${env.RECOVERY_PORT} — sertifika zinciri`, 'sh', [
        '-c', `echo | openssl s_client -connect ${env.LAN_IP}:${env.RECOVERY_PORT} -showcerts 2>/dev/null | grep -E " s:| i:"`,
      ]);
      await attachText(
        testInfo,
        'GET /api/v1/recovery-door',
        [
          JSON.stringify(door, null, 2),
          '',
          'Uygulamaya derlemede verilen (sample-host.properties):',
          `host.recoveryPort=${env.RECOVERY_PORT}  → mTLS bloğunun renewalUrl'i ${DOOR}/`,
          `host.recoveryPins=${(door.caPins || []).join(',')}  → yalnızca ${env.LAN_IP}:${env.RECOVERY_PORT} için`,
        ].join('\n'),
      );
      expect(door.running).toBe(true);
      expect(chain).toContain('PinVault Server CA');
    });

    await test.step(`Web: kayıt token\'ı; bu kimliğin sertifikası ${TTL_SECONDS} saniye yaşayacak (test kancası)`, async () => {
      token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      const hook = await hostApi.api('/api/v1/test-hooks/client-cert-ttl', {
        method: 'POST',
        body: { clientId, ttlSeconds: TTL_SECONDS },
      });
      await attachText(testInfo, 'POST /api/v1/test-hooks/client-cert-ttl', `HTTP ${hook.status} ${hook.text}`);
      expect(hook.status).toBe(200);
    });

    await test.step('Mobil: kayıt (TLS modu) — kısa ömürlü sertifika', async () => {
      await app.openMtls();
      const status = await app.enroll(token);
      await app.snap('kısa ömürlü sertifikayla kayıt');
      expect(status).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
      const record = await certRecord(clientId);
      expiresAt = Date.parse(record.notAfter);
      await attachText(
        testInfo,
        'Sunucudaki kayıt',
        [`notAfter=${record.notAfter}`, `renewCount=${record.renewCount}`, `keyType=${record.keyType} (anahtar telefonda, CSR ile)`].join('\n'),
      );
      expect(record.keyType).toBe('csr');
      expect(record.renewCount || 0).toBe(0);
      await app.backToMain();
    });

    await test.step('Bekleme: sertifikanın süresi doluyor (kütüphane bu arada yeniden başlatılmıyor)', async () => {
      const waitMs = expiresAt - Date.now() + 5_000;
      if (waitMs > 0) await sleep(waitMs);
      await attachText(testInfo, 'Süre doldu', `şimdi ${new Date().toISOString()} > notAfter ${new Date(expiresAt).toISOString()}`);
      expect(Date.now()).toBeGreaterThan(expiresAt);
    });

    await test.step('Mobil: mTLS config moduna geçiş — sertifika kapıdan yenileniyor, mod hazır', async () => {
      await app.openSettings();
      const result = await app.applyMode('MTLS_CONFIG');
      await app.backToMain();
      const status = await app.waitReady();
      await app.snap('kapıdan yenilendi: mTLS config modu hazır');
      await attachText(testInfo, 'Ayarlar sonucu ve telefon durum kutusu', [result, '', status].join('\n'));
      expect(result).toContain('Hazır — config v');
      expect(status).toContain('Mod: mTLS config');
    });

    await test.step('Sunucu: yenileme kurtarma kapısından geldi', async () => {
      const record = await certRecord(clientId);
      const renewed = ((await hostApi.auditLog({ action: 'client_cert_renewed', limit: 10 })).entries || [])
        .find((e) => e.target === clientId);
      await attachText(
        testInfo,
        'Sunucu kaydı ve denetim kaydı',
        [
          `GET /api/v1/client-certs → renewCount=${record.renewCount}, notAfter=${record.notAfter}`,
          `denetim kaydı: ${renewed && renewed.action} — ${renewed && renewed.summary}`,
          `kapsam: ${renewed && renewed.configApiId}  (recovery = kurtarma kapısı; 6651/6652 kendi adlarıyla yazılır)`,
          `ayrıntı: ${renewed && renewed.detail}`,
          '',
          'Yenilenen sertifika varsayılan ömürle (90 gün) verildi; test kancası tek seferlikti.',
        ].join('\n'),
      );
      expect(record.renewCount).toBe(1);
      expect(Date.parse(record.notAfter)).toBeGreaterThan(Date.now() + 24 * 3600 * 1000);
      expect(renewed && renewed.configApiId).toBe('recovery');
      expect(renewed && renewed.summary).toContain('via recovery');
    });

    await test.step('Mobil: yenilenen sertifikayla mTLS bağlantısı geçiyor', async () => {
      await app.openMtls();
      const status = await app.expectMtls(true);
      await app.snap('yenilenen sertifikayla mTLS bağlantısı');
      expect(status).toContain('HTTP 200');
      await app.backToMain();
    });
  } finally {
    await hostControl.resetEnv().catch(() => {});
    await mtlsScope.reset().catch(() => {});
    // İptal + unut: token telefona bağlı, kimlik cihazı kanıtlıyor (bkz. retireClientIdentity).
    await hostApi.retireClientIdentity(clientId);
  }
});
