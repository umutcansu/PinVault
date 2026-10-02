// B11 — Kayıt kodu: tek kod birden çok cihaza; her cihaz yönetici onayıyla.
//
// Cihaz başına token üretmek yerine panelde bir kayıt politikası oluşturulur
// (mTLS Config API → Client Sertifikaları → Kayıt politikaları): ad, en fazla
// kaç cihaz, kaç gün ve "Her cihaz için onay iste". Kod bir kez, QR'ıyla
// gösterilir. Telefon aynı kodu token alanına yazar; sunucu cihaza kendi
// kimliğini (<ad>-xxxxxx) ayırır ama sertifikayı onaya kadar vermez: telefon
// "Onay bekleniyor" der. Yönetici "Onay bekleyen cihazlar"da cihazı görür
// (model, IP, zaman) ve onaylar; telefon birkaç saniyede bir sorduğu için
// kaydı kendiliğinden tamamlar. Cihaz anahtarıyla tanınır: soran isteğin
// numarası tek başına hiçbir şey almaz. Sonunda Durdur: kod artık geçmez.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const qrDecode = require('../lib/qrDecode');
const env = require('../lib/env');

async function policyNamed(name) {
  return ((await hostApi.api('/api/v1/enrollment-policies')).json || []).find((p) => p.name === name);
}

async function requestOf(clientId) {
  return ((await hostApi.api('/api/v1/enrollment-requests')).json || []).find((r) => r.clientId === clientId);
}

test('Kayıt kodu: telefon onay bekler, yönetici onaylayınca kayıt kendiliğinden tamamlanır', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const name = `e2e-saha-${Date.now() % 1_000_000}`;
  let code;
  let clientId;

  try {
    await test.step('Web: Kayıt politikaları → en fazla 3 cihaz, 1 gün, her cihaz için onay → Politika oluştur', async () => {
      code = await dashboard.createEnrollmentPolicy(env.MTLS_API, { name, maxDevices: 3, validDays: 1, requireApproval: true });
      await dashboard.snapElement('kod bir kez gösteriliyor (QR ile)', '#enrollment-policies-card');
      const policy = await policyNamed(name);
      await attachText(
        testInfo,
        'Panelin gösterdiği kod ve sunucudaki kayıt',
        [
          `kod: ${code}`,
          '',
          'GET /api/v1/enrollment-policies (kodun kendisi yok, yalnızca ilk grubu):',
          JSON.stringify(policy, null, 2),
        ].join('\n'),
      );
      expect(code).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){4}$/);
      expect(JSON.stringify(policy)).not.toContain(code);
      expect(policy.codePrefix).toBe(code.slice(0, 5));
      expect(policy.requireApproval).toBe(true);
    });

    await test.step('Terminal: paneldeki QR okutulunca kodun kendisi çıkıyor (macOS QR okuyucusu)', async () => {
      const png = await dashboard.elementScreenshot('#policy-code-box svg', testInfo.outputPath('policy-qr.png'));
      const decoded = await attachCommand(testInfo, 'QR okuyucu (CoreImage)', 'osascript', ['-l', 'JavaScript', qrDecode.scriptPath(), png]);
      expect(decoded.trim()).toBe(code);
    });

    await test.step('Mobil: mTLS ekranında kod küçük harfle girilir → "Onay bekleniyor"', async () => {
      await app.openMtls();
      const status = await app.enrollAwaitingApproval(code.toLowerCase());
      await app.snap('telefon onay bekliyor');
      expect(status).toContain('Onay bekleniyor');
      clientId = /kimlik: (\S+)/.exec(status)[1];
      expect(clientId.startsWith(`${name}-`)).toBe(true);
      expect(app.enrollState()).toContain('onay bekliyor');
    });

    await test.step('Web: "Onay bekleyen cihazlar" kartında telefon görünüyor (model, IP, zaman)', async () => {
      let request = await requestOf(clientId);
      if (request && request.heldBy) {
        // Bir cihaz aynı anda tek etkin kimlik taşır: önceki senaryoların bu
        // telefona verdiği kimlik etkinse onaydan önce iptal edilir.
        await hostApi.revokeClientCertIfActive(request.heldBy);
        await attachText(testInfo, 'Bu telefonun önceki etkin kimliği iptal edildi', `heldBy: ${request.heldBy}`);
        await dashboard.openConfigApiTab(env.MTLS_API, 'mtls');
        request = await requestOf(clientId);
      }
      await expect(dashboard.enrollmentRequestRow(clientId)).toBeVisible({ timeout: 30_000 });
      await dashboard.snapElement('panelde onay bekleyen cihaz', '#enrollment-requests-card');
      await attachText(testInfo, 'GET /api/v1/enrollment-requests', JSON.stringify(request, null, 2));
      expect(request.status).toBe('pending');
      expect(request.heldBy || null).toBeNull();
    });

    await test.step('Web: Onayla', async () => {
      await dashboard.approveEnrollmentRequest(clientId);
      await dashboard.snap('onaylandı');
    });

    await test.step('Mobil: telefon kendiliğinden kayıt oluyor (birkaç saniyede bir soruyor)', async () => {
      const result = await app.awaitEnrollResult();
      await app.snap('onaydan sonra kayıt başarılı');
      expect(result).toContain(`Kayıt başarılı — CN=PinVault Client: ${clientId}`);
    });

    await test.step('Sunucu: kimlik telefonun anahtarında, politika 1/3, denetim kaydında her adım', async () => {
      const record = ((await hostApi.api('/api/v1/client-certs')).json || []).find((c) => c.id === clientId);
      const policy = await policyNamed(name);
      const request = await requestOf(clientId);
      const actions = ['enrollment_policy_created', 'enrollment_request_pending', 'enrollment_request_approved', 'client_cert_issued'];
      const entries = ((await hostApi.auditLog({ limit: 60 })).entries || [])
        .filter((e) => actions.includes(e.action) && (e.target === clientId || e.target === name))
        .reverse();
      await attachText(
        testInfo,
        'Sunucu kayıtları',
        [
          `GET /api/v1/client-certs → ${clientId}: keyType=${record && record.keyType}, notAfter=${record && record.notAfter}`,
          `GET /api/v1/enrollment-policies → ${name}: ${policy.usedCount}/${policy.maxDevices} cihaz, bekleyen ${policy.pendingCount}`,
          `GET /api/v1/enrollment-requests → ${request.status}, onaylayan ${request.decidedBy}, kaynak ${request.sourceIp}`,
          '',
          'Denetim kaydı (eskiden yeniye):',
          ...entries.map((e) => `  ${e.at}  ${e.action}  [${e.actor}]  ${e.summary}`),
        ].join('\n'),
      );
      expect(record.keyType).toBe('csr');
      expect(policy.usedCount).toBe(1);
      expect(policy.pendingCount).toBe(0);
      expect(request.status).toBe('issued');
      expect(entries.map((e) => e.action)).toEqual(expect.arrayContaining(actions));
    });

    await test.step('Mobil: yeni sertifikayla mTLS bağlantısı geçiyor', async () => {
      const status = await app.expectMtls(true);
      await app.snap('yeni sertifikayla mTLS');
      expect(status).toContain('HTTP 200');
    });

    await test.step('Web: Durdur → aynı kod artık reddediliyor (kullanılmış token gibi 401)', async () => {
      await dashboard.stopEnrollmentPolicy(name);
      await dashboard.snapElement('politika durduruldu', '#enrollment-policies-card');
      const out = await attachCommand(testInfo, 'Durdurulan kodla yeni bir cihaz (curl + openssl)', 'sh', [
        '-c',
        [
          'set -e; d=$(mktemp -d); cd "$d"',
          'openssl ecparam -name prime256v1 -genkey -noout -out k.pem 2>/dev/null',
          'openssl req -new -key k.pem -subj /CN=x -outform DER -out c.der 2>/dev/null',
          `printf '{"token":"%s","deviceAlias":"curl","csr":"%s"}' '${code}' "$(base64 < c.der | tr -d '\\n')" > b.json`,
          `curl -sk -w '\\nHTTP %{http_code}' -X POST https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/client-certs/enroll -H 'Content-Type: application/json' -H 'X-PinVault-Features: p12password,csr' --data @b.json`,
        ].join('; '),
      ]);
      expect(out).toContain('HTTP 401');
    });
  } finally {
    const policy = await policyNamed(name).catch(() => null);
    if (policy && !policy.stoppedAt) await hostApi.api(`/api/v1/enrollment-policies/${policy.id}/stop`, { method: 'POST' }).catch(() => {});
    if (clientId) await hostApi.revokeClientCertIfActive(clientId).catch(() => {});
  }
});
