// Not: anonim mod denemeleri ana host'un IMAJINI kullanır ama ayrı bir
// container'da (kendi portunda, kendi boş veritabanıyla) koşar; ne ana host
// ne de geçici test sunucusu etkilenir.
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

test('Sunucu: yönetim uçları API anahtarı ister, cihaz uçları anahtarsız çalışır; anahtarsız yönetim modu uyarı loglar', async ({
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
    await test.step('Sunucu: yönetim uçları anahtarsız isteğe 401, yanlış anahtara 403 döner', async () => {
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

    await test.step("Web: dashboard'a yanlış API anahtarı girilince hiç veri gelmiyor (host listesi boş)", async () => {
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
        await view.snap('yanlış anahtar: host listesi boş (tarayıcının anahtar sorusu panelde)');
        await attachText(
          testInfo,
          'Tarayıcının anahtar sorusu (prompt) ve sonucu',
          [
            ...view.dialogs.map((d, i) => `#${i + 1} ${d}`),
            '',
            'Girilen: "yanlis-anahtar" → sunucu 403 → dashboard veri göstermiyor, anahtarı yeniden soruyor.',
          ].join('\n'),
        );
      } finally {
        await page.close();
      }
    });

    await test.step('Sunucu: telefonun kullandığı uçlar anahtarsız çalışır', async () => {
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
      await attachText(testInfo, 'Cihaz uçları — anahtarsız erişilebilen uçlar (izin listesi)', rows.join('\n'));
      expect(wire.status).toBe(200);
    });

    await test.step('Sunucu: yanıtlar güvenlik başlıklarıyla geliyor (curl -I)', async () => {
      const out = await attachCommand(testInfo, 'curl -I yönetim portu', 'curl', ['-sS', '-I', `${env.WEB_URL}/`]);
      for (const header of ['content-security-policy', 'x-frame-options', 'x-content-type-options']) {
        expect(out.toLowerCase()).toContain(header);
      }
    });

    await test.step('Sunucu: API_KEY verilmemişse açılmayı reddediyor', async () => {
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

    await test.step('Sunucu: parolalar (KEYSTORE_PASSWORD, VAULT_AT_REST_PASSWORD, SIGNING_KEY_PASSWORD) verilmemişse açılmayı reddediyor', async () => {
      const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', env.CONTAINER], {
        encoding: 'utf8',
      }).trim();
      let out;
      try {
        out = execFileSync('docker', ['run', '--rm', '-e', 'API_KEY=e02-probe', image], { encoding: 'utf8', timeout: 180_000 });
      } catch (e) {
        out = `${e.stdout || ''}${e.stderr || ''}`;
      }
      const line = out.split('\n').find((l) => l.includes('Refusing to start with the demo values')) || out.slice(0, 500);
      await attachText(
        testInfo,
        `docker run ${image} (API_KEY var, parolalar yok, ALLOW_DEMO_SECRETS yok)`,
        [
          `$ docker run --rm -e API_KEY=… ${image}`,
          line,
          '',
          'Container açılmadan çıkıyor: kaynak koddaki demo parolalarıyla (changeit, sabit vault anahtarı,',
          'şifresiz imza anahtarı) sunucu kendiliğinden açılmaz. Demo profili bu üçünü setup.sh ile üretir.',
        ].join('\n'),
      );
      expect(line).toContain('KEYSTORE_PASSWORD');
      expect(line).toContain('Refusing to start with the demo values');
    });

    await test.step('Sunucu: ALLOW_ANONYMOUS_ADMIN=true uyarı logluyor; anahtarsız yönetim yalnızca bu makineden (ANONYMOUS_ADMIN_PEERS olmadan köprü ağ geçidi 403 peer_not_allowed)', async () => {
      const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', env.CONTAINER], {
        encoding: 'utf8',
      }).trim();
      // Yayımlanan porttan gelen istek container'a Docker'ın köprü ağının ağ geçidinden
      // (varsayılan bridge: 172.17.0.1) gelir, loopback'ten değil. Anahtarsız modda sunucu
      // yalnızca loopback'e ve ANONYMOUS_ADMIN_PEERS'e cevap verir.
      let gateway = '';
      try {
        gateway = execFileSync('docker', ['network', 'inspect', 'bridge', '-f', '{{range .IPAM.Config}}{{.Gateway}} {{end}}'], {
          encoding: 'utf8',
        }).trim().split(/\s+/)[0];
      } catch {
        /* aşağıdaki varsayılan */
      }
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(gateway)) gateway = '172.17.0.1';
      // Linux'ta yayımlanan porttan gelen bağlantı köprü ağ geçidinden, macOS/Windows Docker
      // Desktop'ta sanal makinenin ağ geçidinden (192.168.65.1) geliyor.
      const peers = `${gateway},192.168.65.0/24`;

      /** Anahtarsız probe container'ını [extraEnv] ile açar, ilk cevabı (ya da 60 sn) bekler. */
      async function startProbe(extraEnv) {
        execFileSync('docker', ['rm', '-f', 'pinvault-anon-probe'], { stdio: 'ignore' });
        execFileSync('docker', [
          'run', '-d', '--name', 'pinvault-anon-probe',
          '-e', 'ALLOW_ANONYMOUS_ADMIN=true',
          // Yalıtılmış deneme: parolalar sunucunun demo değerleriyle (yoksa açılmaz).
          '-e', 'ALLOW_DEMO_SECRETS=true',
          // Anahtarsız modda yönetim dinleyicisi 127.0.0.1'e bağlanır; container'ın
          // içinde bu, yayımlanan porttan erişilemez demek. Bu yüzden 0.0.0.0, ve
          // istekler yalnızca localhost:6799 adresiyle gelirse cevaplanır (DNS rebinding).
          '-e', 'MANAGEMENT_BIND=0.0.0.0',
          '-e', 'MANAGEMENT_ALLOWED_HOSTS=localhost:6799',
          ...extraEnv.flatMap((e) => ['-e', e]),
          '-p', '6799:8080',
          image,
        ], { encoding: 'utf8', timeout: 120_000 });
        let res = { status: 0, text: '' };
        for (let i = 0; i < 60 && res.status === 0; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          res = await fetch('http://localhost:6799/api/v1/all-configs')
            .then(async (r) => ({ status: r.status, text: await r.text() }))
            .catch(() => ({ status: 0, text: '' }));
        }
        return res;
      }

      try {
        // 1) ANONYMOUS_ADMIN_PEERS yok: istek doğru adla (localhost:6799) gelse de kaynağı
        //    köprü ağ geçidi, loopback değil → 403 peer_not_allowed.
        const refused = await startProbe([]);
        await attachText(
          testInfo,
          'docker run -e ALLOW_ANONYMOUS_ADMIN=true (ANONYMOUS_ADMIN_PEERS yok, :6799)',
          [
            `GET http://localhost:6799/api/v1/all-configs (anahtarsız) → ${refused.status} ${refused.text.trim().slice(0, 200)}`,
            '',
            'Host başlığı izinli (localhost:6799) ama bağlantının kaynağı container\'ın gözünden Docker\'ın',
            `köprü ağ geçidi (${gateway}), loopback değil. Host başlığı istemcinin sözü; kaynak adres değil.`,
            'Anahtarsız yönetim yalnızca bu makineden gelen bağlantıya cevap veriyor: ağdaki başka bir',
            'program "Host: localhost" yazarak yönetime erişemiyor.',
          ].join('\n'),
        );
        expect(refused.status).toBe(403);
        expect(refused.text).toContain('peer_not_allowed');

        // 2) Köprü ağ geçidi ANONYMOUS_ADMIN_PEERS'e eklenince aynı istek cevaplanıyor.
        const ok = await startProbe([`ANONYMOUS_ADMIN_PEERS=${peers}`]);
        // Aynı container, bu makinenin başka bir adıyla (127.0.0.1): anahtarsız modda yönetim
        // yalnızca MANAGEMENT_ALLOWED_HOSTS'taki adla cevap verir (DNS rebinding'e karşı).
        const other = await fetch('http://127.0.0.1:6799/api/v1/all-configs').then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, text: e.message }));
        const logs = execFileSync('docker', ['logs', 'pinvault-anon-probe'], { encoding: 'utf8' });
        const warn = logs.split('\n').filter((l) => l.includes('authentication DISABLED')).slice(0, 1).join('\n');
        await attachText(
          testInfo,
          `docker run -e ALLOW_ANONYMOUS_ADMIN=true -e ANONYMOUS_ADMIN_PEERS=${peers} (yalıtılmış container, :6799)`,
          [
            warn,
            '',
            `GET http://localhost:6799/api/v1/all-configs (anahtarsız) → ${ok.status}`,
            `GET http://127.0.0.1:6799/api/v1/all-configs (anahtarsız, izinli olmayan ad) → ${other.status} ${other.text.trim().slice(0, 160)}`,
            '',
            'Container -e MANAGEMENT_BIND=0.0.0.0 -e MANAGEMENT_ALLOWED_HOSTS=localhost:6799 ile açıldı: anahtarsız modda',
            'sunucu yönetim dinleyicisini kendiliğinden 127.0.0.1\'e bağlar (container içinde dışarıdan erişilemezdi) ve',
            'isteğe yalnızca izinli adla gelirse cevap verir; başka bir adla (ör. saldırganın 127.0.0.1\'e yönlendirdiği',
            'bir alan adı) gelen istek 403 host_not_allowed alır.',
            `ANONYMOUS_ADMIN_PEERS=${peers}: yayımlanan porttan gelen bağlantının kaynağı (köprü ağ geçidi ya da Docker Desktop ağ geçidi) bu makine sayılıyor.`,
            '',
            'Ana host bu modda değil: .env\'deki API_KEY zorunlu (docker-compose.yml → API_KEY:?).',
          ].join('\n'),
        );
        expect(warn).toContain('authentication DISABLED');
        expect(ok.status).toBe(200);
        expect(other.status).toBe(403);
        expect(other.text).toContain('host_not_allowed');
      } finally {
        execFileSync('docker', ['rm', '-f', 'pinvault-anon-probe'], { stdio: 'ignore' });
      }
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, VAULT_KEY);
  }
});
