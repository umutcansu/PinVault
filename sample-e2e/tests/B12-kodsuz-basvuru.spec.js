// B12 — Kodsuz başvuru: telefon token ya da kod girmeden başvurur, yönetici onaylar.
//
// Bir modemin MAC filtresi gibi: panelde "Kodsuz başvurular" anahtarı açıkken
// uygulamayı açan her cihaz hiçbir şey girmeden başvurabilir ve "Onay bekleyen
// cihazlar" listesine düşer; yönetici onaylamadan hiçbiri sertifika alamaz.
// Cihaza bir şey taşımak gerekmez: telefon kendi anahtarını üretir, onaydan
// sonra sertifikasını aynı anahtarla imzalayarak alır. Doğrulama kodu (anahtarın
// özetinden) telefonda ve panelde aynı görünür; yönetici doğru cihazı onaylar.
// Anahtar kapatılınca yeni cihaz token'sız başvuramaz.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

async function requestWithCode(code) {
  return ((await hostApi.api('/api/v1/enrollment-requests')).json || []).find((r) => r.verificationCode === code);
}

test('Kodsuz başvuru: telefon bir şey girmeden başvurur, panelde aynı doğrulama koduyla görünür, onaylanınca kayıt olur', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  let clientId;
  let code;

  try {
    await test.step('Web: Client Sertifikaları → "Kodsuz başvurular" anahtarı açılır', async () => {
      await dashboard.setOpenApplications(env.MTLS_API, true);
      await dashboard.snapElement('kodsuz başvurular açık', '#enrollment-requests-card');
      const mode = (await hostApi.api('/api/v1/enrollment-mode', { withKey: false })).json;
      const open = (await hostApi.api('/api/v1/enrollment-open')).json;
      await attachText(
        testInfo,
        'Sunucu: anahtar ve sınırlar',
        [
          `GET /api/v1/enrollment-mode (anahtarsız, cihazların gördüğü) → ${JSON.stringify(mode)}`,
          `GET /api/v1/enrollment-open → açık: ${open.enabled}, bekleyen en fazla ${open.maxPending}, ` +
            `bir adresten 10 dakikada ${open.rateLimitPer10Minutes} başvuru, cevapsız başvuru ${open.requestTtlHours} saatte düşer`,
        ].join('\n'),
      );
      expect(mode.openApplications).toBe(true);
      expect(open.enabled).toBe(true);
    });

    await test.step('Mobil: mTLS ekranında "Otomatik kayıt" — hiçbir şey girilmeden → "Onay bekleniyor" ve doğrulama kodu', async () => {
      await app.openMtls();
      const status = await app.autoEnrollAwaitingApproval();
      await app.snap('telefon onay bekliyor (kodsuz)');
      clientId = /kimlik: (\S+)/.exec(status)[1];
      code = /doğrulama kodu: (\S+)/.exec(status)[1];
      expect(clientId).toMatch(/^device-[0-9a-z]{6}$/);
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
      expect(app.enrollState()).toContain(code);
    });

    await test.step('Web: başvuru "Onay bekleyen cihazlar"da aynı doğrulama koduyla görünüyor', async () => {
      let request = await requestWithCode(code);
      if (request && request.heldBy) {
        // Bir cihaz aynı anda tek etkin kimlik taşır: önceki senaryolardan kalan etkin kimliği iptal edilir.
        await hostApi.revokeClientCertIfActive(request.heldBy);
        await attachText(testInfo, 'Bu telefonun önceki etkin kimliği iptal edildi', `heldBy: ${request.heldBy}`);
        await dashboard.openConfigApiTab(env.MTLS_API, 'mtls');
        request = await requestWithCode(code);
      }
      const row = dashboard.enrollmentRequestRow(code);
      await expect(row).toBeVisible({ timeout: 30_000 });
      await expect(row).toContainText(clientId);
      await expect(row).toContainText('kodsuz başvuru');
      await dashboard.snapElement('panelde aynı doğrulama kodu', '#enrollment-requests-card');
      await attachText(testInfo, 'GET /api/v1/enrollment-requests', JSON.stringify(request, null, 2));
      expect(request.status).toBe('pending');
      expect(request.openApplication).toBe(true);
      expect(request.clientId).toBe(clientId);
    });

    await test.step('Web: Onayla', async () => {
      await dashboard.approveEnrollmentRequest(code);
      await dashboard.snap('onaylandı');
    });

    await test.step('Mobil: telefon kendiliğinden kayıt oluyor', async () => {
      const result = await app.awaitEnrollResult();
      await app.snap('onaydan sonra kayıt başarılı (kodsuz)');
      expect(result).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
    });

    await test.step('Mobil: yeni sertifikayla mTLS bağlantısı geçiyor', async () => {
      const status = await app.expectMtls(true);
      await app.snap('kodsuz kayıtla mTLS');
      expect(status).toContain('HTTP 200');
    });

    await test.step('Web: anahtar kapatılır → yeni bir cihaz token\'sız başvuramaz (curl, 403)', async () => {
      await dashboard.setOpenApplications(env.MTLS_API, false);
      await dashboard.snapElement('kodsuz başvurular kapalı', '#enrollment-requests-card');
      const out = await attachCommand(testInfo, 'Token\'sız yeni bir cihaz (curl + openssl)', 'sh', [
        '-c',
        [
          'set -e; d=$(mktemp -d); cd "$d"',
          'openssl ecparam -name prime256v1 -genkey -noout -out k.pem 2>/dev/null',
          'openssl req -new -key k.pem -subj /CN=x -outform DER -out c.der 2>/dev/null',
          `printf '{"deviceId":"curl-device","deviceAlias":"curl","csr":"%s"}' "$(base64 < c.der | tr -d '\\n')" > b.json`,
          `curl -sk -w '\\nHTTP %{http_code}' -X POST https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/client-certs/enroll -H 'Content-Type: application/json' -H 'X-PinVault-Features: p12password,csr' --data @b.json`,
        ].join('; '),
      ]);
      expect(out).toContain('HTTP 403');
      expect(out).toContain('Token required');
    });

    await test.step('Sunucu: kimlik telefonun anahtarında; denetim kaydında her adım', async () => {
      const record = ((await hostApi.api('/api/v1/client-certs')).json || []).find((c) => c.id === clientId);
      const actions = ['enrollment_open_changed', 'enrollment_request_pending', 'enrollment_request_approved', 'client_cert_issued'];
      const entries = ((await hostApi.auditLog({ limit: 60 })).entries || [])
        .filter((e) => actions.includes(e.action) && (e.target === clientId || e.action === 'enrollment_open_changed'))
        .slice(0, 6)
        .reverse();
      await attachText(
        testInfo,
        'Sunucu kayıtları',
        [
          `GET /api/v1/client-certs → ${clientId}: keyType=${record && record.keyType}, notAfter=${record && record.notAfter}`,
          '',
          'Denetim kaydı (eskiden yeniye):',
          ...entries.map((e) => `  ${e.at}  ${e.action}  [${e.actor}]  ${e.summary}`),
        ].join('\n'),
      );
      expect(record.keyType).toBe('csr');
      expect(entries.map((e) => e.action)).toEqual(expect.arrayContaining(actions));
      const pending = entries.find((e) => e.action === 'enrollment_request_pending');
      expect(pending.summary).toContain('without a code');
      expect(pending.summary).toContain(code);
    });
  } finally {
    await hostApi.api('/api/v1/enrollment-open', { method: 'PUT', body: { enabled: false } }).catch(() => {});
    if (clientId) await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
