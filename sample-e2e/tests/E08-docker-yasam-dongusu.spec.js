// E11: Docker yaşam döngüsü. `docker compose down` + `up -d` sonrası veriler
// (pin config, vault dosyaları, sunucu sertifikası, imzalama anahtarı) yerinde
// kalır; Config API'ler ve mock hedef host'lar auto-start ile geri gelir.
// Taze host örneği üzerinde (ana host'a dokunulmaz).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

const VAULT_KEY = 'e08-kalici';
const TEMP_API = 'e08-gecici';
const CONTENT = `{"kalici":"${Date.now()}"}`;

async function snapshot() {
  const cfg = (await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false })).json;
  const all = (await fresh.api('/api/v1/all-configs')).json || [];
  const files = (await fresh.api('/api/v1/config-apis/default-tls/vault')).json || [];
  const status = (await fresh.api(`/api/v1/hosts/${env.MOCK_TLS_HOST}/status?configApiId=default-tls`)).json || {};
  const signing = (await fresh.api('/api/v1/signing-key', { withKey: false })).json;
  return {
    version: cfg.version,
    pins: cfg.pins.map((p) => `${p.hostname} v${p.version} ${p.sha256[0].slice(0, 10)}…`).sort(),
    // Yalnızca çalışan dinleyiciler karşılaştırılır: "durduruldu" bilgisi
    // sunucunun belleğinde tutuluyor, yeniden açılışta listede görünmüyor.
    apis: all.filter((a) => a.running).map((a) => `${a.id}:${a.port}`).sort(),
    stoppedApis: all.filter((a) => !a.running).map((a) => `${a.id}:${a.port}`).sort(),
    files: files.map((f) => `${f.key} v${f.version} ${f.access_policy}/${f.encryption}`).sort(),
    mockRunning: status.mockServerRunning === true,
    bootstrapPins: fresh.hostPins().slice(0, 2),
    signingPublicKey: signing.publicKey,
  };
}

function render(label, s) {
  return [
    `── ${label} ──`,
    `config sürümü     : v${s.version}`,
    `pin'ler           : ${s.pins.join(' | ')}`,
    `çalışan API'ler   : ${s.apis.join(' | ')}`,
    `durdurulmuş API'ler: ${s.stoppedApis.join(' | ') || '(yok)'}`,
    `vault dosyaları   : ${s.files.join(' | ') || '(yok)'}`,
    `mock host çalışıyor: ${s.mockRunning}`,
    `bootstrap pin     : ${s.bootstrapPins[0].slice(0, 16)}…`,
    `imzalama public   : ${s.signingPublicKey.slice(0, 24)}…`,
  ].join('\n');
}

test('Sunucu: docker compose down/up sonrası veriler kalıcı, Config API ve mock host\'lar geri geliyor', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  // Taze örnek KEYSTORE_PASSWORD ile kurulmuş olmalı (K01 böyle kurar); tek
  // başına koşulurken eski bir kopya varsa yeniden kurulur.
  if (fresh.exists() && fresh.readEnv().KEYSTORE_PASSWORD !== fresh.KEYSTORE_PASSWORD) await fresh.destroy();
  await fresh.ensure();

  let before;
  try {
    await test.step('Sunucu: kapatmadan önceki durum (pin, vault, sertifika)', async () => {
      await fetch(`${fresh.WEB_URL}/api/v1/config-apis/default-tls/vault/${VAULT_KEY}?policy=public&encryption=plain`, {
        method: 'PUT',
        headers: { 'X-API-Key': fresh.apiKey(), 'Content-Type': 'application/octet-stream' },
        body: CONTENT,
      });
      // Elle durdurulmuş bir Config API: açılıştan sonra ne olduğunu göreceğiz.
      await fresh.api('/api/v1/config-apis/start', { method: 'POST', body: { id: TEMP_API, port: 8098, mode: 'tls' } });
      await fresh.api('/api/v1/config-apis/stop', { method: 'POST', body: { id: TEMP_API } });

      before = await snapshot();
      await attachText(testInfo, 'Kapatmadan önce', render('ÖNCE', before));
      expect(before.files.join()).toContain(VAULT_KEY);
      expect(before.mockRunning).toBe(true);
      expect(before.stoppedApis.join()).toContain(TEMP_API);
    });

    await test.step('Terminal: docker compose down', async () => {
      const out = fresh.compose(['down']);
      const ps = fresh.compose(['ps']);
      await attachText(testInfo, 'docker compose down', `$ docker compose down\n${out}\n$ docker compose ps\n${ps}`);
      expect(await fresh.isHealthy()).toBe(false);
    });

    await test.step('Terminal: docker compose up -d → sağlıklı', async () => {
      const out = fresh.compose(['up', '-d']);
      await fresh.waitHealthy();
      const ps = fresh.compose(['ps']);
      await attachText(testInfo, 'docker compose up -d', `$ docker compose up -d\n${out}\n$ docker compose ps\n${ps}`);
      expect(await fresh.isHealthy()).toBe(true);
    });

    await test.step('Sunucu: veriler ve dinleyiciler aynı', async () => {
      // Config API'ler ve mock host'lar açılışta auto-start ediliyor; birkaç
      // saniye sürebilir.
      await expect
        .poll(async () => (await snapshot()).mockRunning, { timeout: 60_000, intervals: [1000, 2000] })
        .toBe(true);
      const after = await snapshot();
      await attachText(testInfo, 'Açıldıktan sonra', `${render('ÖNCE', before)}\n\n${render('SONRA', after)}`);
      expect(after.pins).toEqual(before.pins);
      expect(after.version).toBe(before.version);
      expect(after.files).toEqual(before.files);
      expect(after.apis).toEqual(expect.arrayContaining(before.apis));
      expect(after.bootstrapPins).toEqual(before.bootstrapPins);
      expect(after.signingPublicKey).toBe(before.signingPublicKey);

      // Elle durdurulan Config API auto_start kaydıyla geri geliyor: durdurma
      // yalnızca sunucu çalışırken geçerli, yeniden açılışta kalıcı değil.
      await attachText(
        testInfo,
        'Durdurulmuş Config API yeniden açılışta',
        [
          `önce  : ${TEMP_API} durduruldu (listede running=false)`,
          `sonra : ${after.apis.join(' | ')}`,
          '',
          'POST /api/v1/config-apis/stop yalnızca belleği değiştiriyor; DB\'deki',
          'auto_start=1 kaydı kaldığı için sunucu açılışta dinleyiciyi yeniden başlatıyor.',
          'Kalıcı kapatma için "API Sil" (config-apis/delete) gerekiyor.',
        ].join('\n'),
      );
      expect(after.apis.join()).toContain(TEMP_API);
    });

    await test.step('Web: down/up sonrası dashboard — Config API\'ler ve host\'lar yerinde', async () => {
      const dashboard = await fresh.openDashboard(browser, testInfo);
      try {
        await dashboard.openHost(env.MOCK_TLS_HOST);
        await dashboard.snap(`down/up sonrası dashboard: ${env.MOCK_TLS_HOST} host sayfası`);
      } finally {
        await dashboard.page.close();
      }
    });

    await test.step('Sunucu: KEYSTORE_PASSWORD — keystore\'lar bu parolayla yazılıyor, "changeit" ile açılmıyor', async () => {
      const keystore = '/data/certs/demo-server.jks';
      const ok = fresh.compose(['exec', '-T', 'pinvault-host', 'keytool', '-list', '-keystore', keystore, '-storepass', fresh.KEYSTORE_PASSWORD]);
      let wrong;
      try {
        fresh.compose(['exec', '-T', 'pinvault-host', 'keytool', '-list', '-keystore', keystore, '-storepass', 'changeit']);
        wrong = '(açıldı — beklenmiyordu)';
      } catch (err) {
        wrong = `${err.stdout || ''}${err.stderr || ''}[exit ${err.status}]`;
      }
      const listing = fresh.compose(['exec', '-T', 'pinvault-host', 'sh', '-c', 'ls -l /data/certs']);
      await attachText(
        testInfo,
        'keytool -list /data/certs/demo-server.jks — KEYSTORE_PASSWORD ile / changeit ile',
        [
          `.env: KEYSTORE_PASSWORD=${'*'.repeat(fresh.KEYSTORE_PASSWORD.length)} (${fresh.KEYSTORE_PASSWORD.length} karakter, maskeli)`,
          '',
          '$ keytool -list -keystore /data/certs/demo-server.jks -storepass $KEYSTORE_PASSWORD',
          ok.trim(),
          '',
          '$ keytool -list -keystore /data/certs/demo-server.jks -storepass changeit',
          wrong.trim(),
          '',
          '$ ls -l /data/certs',
          listing.trim(),
          '',
          'CertificateService.KEYSTORE_PASSWORD: env var boşsa "changeit" (yalnızca demo);',
          'sunucu keystore\'u, truststore ve üretilen P12\'ler bu parolayla yazılıyor.',
        ].join('\n'),
      );
      expect(fresh.readEnv().KEYSTORE_PASSWORD).toBe(fresh.KEYSTORE_PASSWORD);
      expect(ok).toContain('PrivateKeyEntry');
      expect(wrong).toMatch(/password was incorrect|Keystore was tampered/i);
    });

    await test.step('Sunucu: vault dosyasının içeriği de aynı', async () => {
      const res = await fetch(`${fresh.WEB_URL}/api/v1/config-apis/default-tls/vault`, {
        headers: { 'X-API-Key': fresh.apiKey() },
      });
      const list = await res.json();
      const entry = list.find((f) => f.key === VAULT_KEY);
      await attachText(
        testInfo,
        'Vault dosyası (açılıştan sonra)',
        `${VAULT_KEY} v${entry.version} · ${entry.size} bayt · ${entry.access_policy}/${entry.encryption}\nyüklenen içerik: ${CONTENT}`,
      );
      expect(Number(entry.size)).toBe(Buffer.byteLength(CONTENT));
    });
  } finally {
    await fresh.api(`/api/v1/config-apis/default-tls/vault/${VAULT_KEY}`, { method: 'DELETE' }).catch(() => {});
    await fresh.api('/api/v1/config-apis/delete', { method: 'POST', body: { id: TEMP_API } }).catch(() => {});
  }
});
