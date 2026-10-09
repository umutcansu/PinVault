// 16 — Atestasyon ve PinVault-Token (Approov'un çalışma mantığı).
//
// Telefon açılışta ve 5 dakikada bir uygulamayı ve cihazı ölçüp raporu
// Keystore anahtarıyla imzalayarak host'a gönderir; host politikaya göre
// karar verir, geçen cihaz 5 dakikalık PinVault-Token alır ve kütüphane bunu
// pinli isteklere ekler. Mock TLS host MOCK_HOST_REQUIRE_TOKEN=true ile
// token'sız isteği reddeder.
//
// Uygulama debug derlemesi olduğu için `debuggable` yükselir; hazırlık onu
// uyarı sayar. Testler emülatörde koştuğu için `emulator` bayrağı da yükselir. Senaryo bunu
// kullanır: politika emülatörü "warn" sayarken telefon GEÇER ve mock host
// token'lı isteği 200 ile kabul eder; politika "reject" yapılınca aynı
// telefon KALIR, token alamaz ve mock host 401 döner. Ek açıklama (forcePass)
// kalan cihazı politikayı değiştirmeden geçirir. Panelde cihazın son kararı,
// ARC'si ve nedenleri görünür. Sonunda politika ve ortam eski haline döner.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const SCOPE = env.VAULT_API; // uygulamanın TLS bloğunun Config API kimliği (default-tls)
const POLICY = `/api/v1/config-apis/${SCOPE}/attestation/policy`;

/** Politikayı okur; `flags` nesnesini verilen değerlerle değiştirip geri yazar. */
async function setPolicy(flags, extra = {}) {
  const current = (await hostApi.api(POLICY)).json;
  const next = { ...current, ...extra, flags: { ...current.flags, ...flags } };
  const res = await hostApi.api(POLICY, { method: 'PUT', body: next });
  expect(res.status, `politika yazılamadı: ${res.text}`).toBe(200);
  return res.json;
}

/** Panel API'sinden bu telefonun son atestasyon kaydı (cihaz kimliğine göre). */
async function deviceRecord(deviceId) {
  const res = await hostApi.api(`/api/v1/config-apis/${SCOPE}/attestation/devices/${encodeURIComponent(deviceId)}`);
  return res.status === 200 ? res.json : null;
}

test('Atestasyon: geçen telefon token alır ve mock host kabul eder; politika sıkılaşınca kalır ve 401 alır', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(12 * 60 * 1000);
  let original;
  let deviceId;

  try {
    await test.step('Hazırlık: politika emülatörü uyarı sayar; mock host token ister', async () => {
      original = (await hostApi.api(POLICY)).json;
      expect(original && original.flags, 'politika okunamadı').toBeTruthy();
      // E2E emülatörü root'ludur (su ile ANDROID_ID okunur): rooted da uyarı sayılır.
      await setPolicy({ rooted: 'warn', emulator: 'warn', debuggable: 'warn', unknown_installer: 'warn', adb_enabled: 'ignore', software_key: 'warn', key_unattested: 'warn' },
        { revealReasons: true });
      await hostControl.setEnv({ MOCK_HOST_REQUIRE_TOKEN: 'true' });
      await app.relaunch();
      await app.waitReady();
      await app.openVault();
      deviceId = app.deviceId();
      // Önceki senaryolar (12, B grubu) bu telefonun kimliğini iptal etmiş olabilir.
      await hostApi.forgetRevokedIdentitiesOf(deviceId);
      await app.backToMain();
      attachText(testInfo, 'Politika (test için)', JSON.stringify((await hostApi.api(POLICY)).json, null, 2));
    });

    await test.step('Mobil: atestasyon geçer, token gelir, token\'lı istek mock host\'ta 200', async () => {
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toMatch(/PinVault-Token \(\d+ karakter/);
      expect(text).toContain('HTTP 200');
      expect(text).toContain('uyarı: ');
      expect(text).toContain('emulator');
      await app.snap('atestasyon geçti, token alındı, mock host 200');
      // Durum kutusu şimdi eylemin sonucunu gösteriyor; açılış ekranındaki
      // atestasyon satırı uygulama yeniden açılınca (açılıştaki turla) gelir.
      await app.relaunch();
      await app.waitReady();
      await app.waitFor('statusView', (n) => /🛡 Atestasyon: GEÇTİ · arc [0-9a-f]{8}/.test(n.text), {
        timeout: 60_000, what: 'durum kutusunda "Atestasyon: GEÇTİ"',
      });
    });

    await test.step('Web: cihaz panelde "pass" olarak, ARC\'siyle görünür', async () => {
      const record = await deviceRecord(deviceId);
      expect(record, 'cihaz kaydı yok').toBeTruthy();
      expect(record.lastResult).toBe('pass');
      expect(record.lastArc).toMatch(/^[0-9a-f]{8}$/);
      expect(record.warnings || record.lastWarnings || []).toContain('emulator');
      attachText(testInfo, 'Cihaz kaydı (geçti)', JSON.stringify(record, null, 2));
      await dashboard.openConfigApiTab(SCOPE, 'attestation');
      await dashboard.snap('panel: atestasyon sekmesi, cihaz geçti');
    });

    await test.step('Web: politika emülatörü reddeder → Mobil: KALDI, token yok, mock host 401', async () => {
      await setPolicy({ emulator: 'reject' });
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('emulator');
      expect(text).toMatch(/HTTP 401/);
      await app.snap('atestasyon kaldı, mock host 401');
      const record = await deviceRecord(deviceId);
      expect(record.lastResult).toBe('reject');
      expect((record.rejectionReasons || record.lastReasons || []).join(',')).toContain('emulator');
      attachText(testInfo, 'Cihaz kaydı (kaldı)', JSON.stringify(record, null, 2));
    });

    await test.step('Web: cihaza "geçir" ek açıklaması → Mobil: aynı politikayla GEÇER, token anno taşır', async () => {
      const res = await hostApi.api(`/api/v1/config-apis/${SCOPE}/attestation/devices/${encodeURIComponent(deviceId)}`, {
        method: 'PUT', body: { forcePass: true, forceFail: false, annotations: ['e2e-forced'] },
      });
      expect(res.status, res.text).toBe(200);
      const text = await app.attest();
      expect(text).toContain('Atestasyon geçti');
      expect(text).toContain('HTTP 200');
      await app.snap('forcePass ile geçti');
    });

    await test.step('Web: cihaza "düşür" → Mobil: KALDI (force_fail)', async () => {
      const res = await hostApi.api(`/api/v1/config-apis/${SCOPE}/attestation/devices/${encodeURIComponent(deviceId)}`, {
        method: 'PUT', body: { forcePass: false, forceFail: true, annotations: [] },
      });
      expect(res.status, res.text).toBe(200);
      const text = await app.attest();
      expect(text).toContain('Atestasyon KALDI');
      expect(text).toContain('force_fail');
      await app.snap('forceFail ile kaldı');
    });

    await test.step('Ağ trafiği: token olmadan mock host 401, geçersiz token da 401', async () => {
      // `/health` token kontrolünden muaf (sağlık yoklaması); kök korunur.
      const bare = await hostApi.mockTlsRequest('/');
      expect(bare.status).toBe(401);
      expect(bare.headers['www-authenticate'] || '').toContain('PinVault-Token');
      const forged = await hostApi.mockTlsRequest('/', { headers: { 'PinVault-Token': 'eyJhbGciOiJIUzI1NiJ9.e30.sahte' } });
      expect(forged.status).toBe(401);
      attachText(testInfo, 'Mock host, token yok', `HTTP ${bare.status}\n${JSON.stringify(bare.headers, null, 2)}`);
    });
  } finally {
    if (deviceId) {
      await hostApi.api(`/api/v1/config-apis/${SCOPE}/attestation/devices/${encodeURIComponent(deviceId)}`, {
        method: 'PUT', body: { forcePass: false, forceFail: false, annotations: [] },
      }).catch(() => {});
    }
    if (original) await hostApi.api(POLICY, { method: 'PUT', body: original }).catch(() => {});
    await hostControl.resetEnv().catch(() => {});
  }
});
