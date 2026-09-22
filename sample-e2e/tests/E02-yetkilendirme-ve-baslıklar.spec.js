// Not: anonim mod denemeleri ana host'un IMAJINI kullanır ama ayrı bir
// container'da (kendi portunda, kendi boş veritabanıyla) koşar; ne ana host
// ne de taze örnek etkilenir.
// E2: yönetim uçları API anahtarı ister (anahtarsız 401, yanlış anahtar 403),
// cihaz uçları anahtarsız çalışır, yanıtlar güvenlik başlıklarıyla gelir;
// API_KEY ayarlı değilken sunucu açılmayı reddeder ve ALLOW_ANONYMOUS_ADMIN
// ile açılınca uyarı loglar.
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, redact } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const { Dashboard } = require('../lib/dashboard');
const env = require('../lib/env');

const VAULT_KEY = 'e02-public';

const ADMIN_ENDPOINTS = [
  ['GET', '/api/v1/all-configs'],
  ['GET', '/api/v1/connection-history'],
  ['GET', '/api/v1/client-certs'],
  ['GET', '/api/v1/cert-expiry'],
  ['GET', '/api/v1/client-devices'],
  ['GET', `/api/v1/certificate-config/history/${env.TARGET_HOST}`],
  ['GET', '/api/v1/config-apis/default-tls/vault'],
];

const DEVICE_ENDPOINTS = [
  ['GET', '/api/v1/certificate-config'],
  ['GET', '/api/v1/signing-key'],
  ['GET', '/api/v1/enrollment-mode'],
];

test('Sunucu: yönetim uçları anahtar ister, cihaz uçları anahtarsız çalışır; anonim mod uyarı verir', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);

  // Cihaz ucu kanıtı için herkese açık bir vault dosyası.
  await fetch(`${env.WEB_URL}/api/v1/config-apis/${env.VAULT_API}/vault/${VAULT_KEY}?policy=public&encryption=plain`, {
    method: 'PUT',
    headers: { 'X-API-Key': env.API_KEY, 'Content-Type': 'application/octet-stream' },
    body: 'e02 herkese acik icerik',
  });

  try {
    await test.step('Sunucu: yönetim uçları anahtarsız 401, yanlış anahtarla 403', async () => {
      const rows = [];
      for (const [method, pathname] of ADMIN_ENDPOINTS) {
        const none = await hostApi.api(pathname, { method, withKey: false });
        const wrong = await fetch(env.WEB_URL + pathname, { method, headers: { 'X-API-Key': 'yanlis-anahtar' } });
        rows.push(`${method.padEnd(4)} ${pathname.padEnd(52)} anahtarsız=${none.status}  yanlış=${wrong.status}`);
        expect(none.status).toBe(401);
        expect(wrong.status).toBe(403);
      }
      const ok = await hostApi.api('/api/v1/all-configs');
      rows.push('', `GET  /api/v1/all-configs (doğru anahtar ${redact(env.API_KEY)}) → ${ok.status}`);
      await attachText(testInfo, 'Yönetim uçları — X-API-Key kontrolü', rows.join('\n'));
      expect(ok.status).toBe(200);
    });

    await test.step('Web: yanlış anahtarla dashboard veri alamıyor (istem sonrası host ağacı boş)', async () => {
      // Anahtarsız yeni sayfa: dashboard prompt ile anahtar sorar; yanlış
      // anahtar 403 aldığı için host ağacı çizilmez.
      const page = await browser.newPage();
      const view = new Dashboard(page, testInfo);
      Dashboard.attachDialogs(page, view);
      view.answerPrompt('yanlis-anahtar');
      try {
        await page.goto(`${env.WEB_URL}/`);
        await expect.poll(() => view.dialogs.length, { timeout: 20_000 }).toBeGreaterThan(0);
        await expect(page.locator('#host-list .api-header')).toHaveCount(0);
        await view.snap('yanlış anahtar: host ağacı boş (istem metni panelde)');
        await attachText(
          testInfo,
          'Tarayıcı istemi (prompt) ve sonucu',
          [
            ...view.dialogs.map((d, i) => `#${i + 1} ${d}`),
            '',
            'Girilen: "yanlis-anahtar" → sunucu 403 → dashboard veri çizmiyor, anahtarı yeniden soruyor.',
          ].join('\n'),
        );
      } finally {
        await page.close();
      }
    });

    await test.step('Sunucu: cihaz uçları anahtarsız çalışır', async () => {
      const rows = [];
      for (const [method, pathname] of DEVICE_ENDPOINTS) {
        const res = await hostApi.api(pathname, { method, withKey: false });
        rows.push(`${method.padEnd(4)} ${pathname.padEnd(40)} → ${res.status}`);
        expect(res.status).toBe(200);
      }
      // Rapor ve cihaz public key kaydı da anahtarsız kabul edilir.
      const report = await fetch(`${env.WEB_URL}/api/v1/connection-history/client-report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname: env.TARGET_HOST,
          status: 'healthy',
          responseTimeMs: 12,
          pinMatched: true,
          deviceModel: 'E2E-Probe',
          deviceManufacturer: 'Harness',
        }),
      });
      rows.push(`POST /api/v1/connection-history/client-report    → ${report.status}`);
      expect([200, 201]).toContain(report.status);

      // Config API portundan (telefonun gerçekten kullandığı yol) pinli indirme.
      const wire = await hostApi.rawVaultDownload(VAULT_KEY, 'e02-cihaz');
      rows.push(
        '',
        `Config API :${env.CONFIG_API_PORT} üzerinden GET /api/v1/vault/${VAULT_KEY} (anahtarsız, pin doğrulandı) → ${wire.status}`,
        `X-Vault-Version: ${wire.headers['x-vault-version']} · içerik: ${wire.body.toString('utf8')}`,
      );
      rows.push('', 'Not: /api/v1/vault/{key} yalnızca Config API dinleyicilerinde var; yönetim portu 404 döner.');
      await attachText(testInfo, 'Cihaz uçları — anahtar istemeyen allowlist', rows.join('\n'));
      expect(wire.status).toBe(200);
    });

    await test.step('Sunucu: güvenlik başlıkları (curl -I)', async () => {
      const out = await attachCommand(testInfo, 'curl -I yönetim portu', 'curl', ['-sS', '-I', `${env.WEB_URL}/`]);
      for (const header of ['content-security-policy', 'x-frame-options', 'x-content-type-options']) {
        expect(out.toLowerCase()).toContain(header);
      }
    });

    await test.step('Sunucu: API_KEY yokken açılmayı reddeder (fail-fast)', async () => {
      const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', env.CONTAINER], {
        encoding: 'utf8',
      }).trim();
      let out;
      try {
        out = execFileSync('docker', ['run', '--rm', image], { encoding: 'utf8', timeout: 180_000 });
      } catch (e) {
        out = `${e.stdout || ''}${e.stderr || ''}`;
      }
      const line = out.split('\n').find((l) => l.includes('API_KEY env var is not set')) || out.slice(0, 500);
      await attachText(
        testInfo,
        `docker run ${image} (API_KEY yok, ALLOW_ANONYMOUS_ADMIN yok)`,
        [`$ docker run --rm ${image}`, line, '', 'Container açılmadan çıkıyor: yönetim uçları asla anahtarsız açılmaz.'].join('\n'),
      );
      expect(line).toContain('Refusing to start with anonymous admin access');
    });

    await test.step('Sunucu: ALLOW_ANONYMOUS_ADMIN=true uyarı logluyor ve anahtarsız yönetime izin veriyor', async () => {
      const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', env.CONTAINER], {
        encoding: 'utf8',
      }).trim();
      execFileSync('docker', ['rm', '-f', 'pinvault-anon-probe'], { stdio: 'ignore' });
      execFileSync('docker', [
        'run', '-d', '--name', 'pinvault-anon-probe',
        '-e', 'ALLOW_ANONYMOUS_ADMIN=true',
        '-p', '6799:8080',
        image,
      ], { encoding: 'utf8', timeout: 120_000 });
      try {
        let status = 0;
        for (let i = 0; i < 60 && status !== 200; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          status = await fetch('http://localhost:6799/api/v1/all-configs').then((r) => r.status).catch(() => 0);
        }
        const logs = execFileSync('docker', ['logs', 'pinvault-anon-probe'], { encoding: 'utf8' });
        const warn = logs.split('\n').filter((l) => l.includes('ALLOW_ANONYMOUS_ADMIN')).slice(0, 1).join('\n');
        await attachText(
          testInfo,
          'docker run -e ALLOW_ANONYMOUS_ADMIN=true (yalıtılmış container, :6799)',
          [
            warn,
            '',
            `GET /api/v1/all-configs (anahtarsız) → ${status}`,
            '',
            'Ana host bu modda değil: .env\'deki API_KEY zorunlu (docker-compose.yml → API_KEY:?).',
          ].join('\n'),
        );
        expect(warn).toContain('authentication DISABLED');
        expect(status).toBe(200);
      } finally {
        execFileSync('docker', ['rm', '-f', 'pinvault-anon-probe'], { stdio: 'ignore' });
      }
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, VAULT_KEY);
  }
});
