// Kurulum yolculuğu K0–K3: gereksinimler, depo, setup.sh (.env + imzalama
// anahtarı), API anahtarı yokken compose'un başlamayı reddetmesi,
// `docker compose up -d --build`, Flyway migration'ları ve smoke-test.
//
// Bütün adımlar host'un İKİNCİ, taze bir örneği üzerinde koşar
// (SamplePinVaultE2E/.local/host-fresh, portlar 6750–6754). Ana host'a
// dokunulmaz: sertifikası ya da imzalama anahtarı değişirse telefondaki APK'nın
// gömülü pin'leri geçersiz olur ve diğer senaryolar çöker.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, attachFailingCommand, redact } = require('../lib/evidence');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

test('Kurulum: gereksinimler, setup.sh, docker compose up ve smoke-test — sıfırdan taze host', async ({
  browser,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);

  await test.step('Terminal: gereksinim sürümleri (K0)', async () => {
    const tools = [
      ['docker', ['--version']],
      ['docker', ['compose', 'version']],
      ['node', ['--version']],
      ['openssl', ['version']],
      ['jq', ['--version']],
      ['curl', ['--version']],
      [env.ADB, ['--version']],
      ['rsync', ['--version']],
    ];
    const lines = [];
    for (const [file, args] of tools) {
      try {
        const out = require('child_process').execFileSync(file, args, { encoding: 'utf8', timeout: 30_000 });
        lines.push(`$ ${path.basename(file)} ${args.join(' ')}\n${out.split('\n')[0]}`);
      } catch (e) {
        lines.push(`$ ${path.basename(file)} ${args.join(' ')}\n(bulunamadı) ${e.message}`);
      }
    }
    const javaHome = process.env.JAVA_HOME || '';
    try {
      const java = javaHome ? path.join(javaHome, 'bin/java') : 'java';
      const out = require('child_process').execFileSync(java, ['-version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000 });
      lines.push(`$ java -version\n${out.split('\n')[0]}`);
    } catch (e) {
      lines.push(`$ java -version\n${(e.stderr || e.message).toString().split('\n')[0]}`);
    }
    await attachText(testInfo, 'Gereksinim sürümleri (docker, node, java, adb, openssl)', lines.join('\n\n'));
    expect(lines.join('\n')).toContain('Docker version');
  });

  await test.step('Terminal: dört depo ve taze host kopyası (K1)', async () => {
    const parent = path.resolve(env.ROOT, '..');
    const repos = ['PinVault', 'SamplePinVaultHost', 'SamplePinVaultClient', 'SamplePinVaultE2E'];
    const lines = repos.map((name) => {
      const dir = path.join(parent, name);
      const entries = fs.existsSync(dir)
        ? fs.readdirSync(dir).filter((e) => !e.startsWith('.')).slice(0, 12).join('  ')
        : '(yok)';
      return `${name}/\n    ${entries}`;
    });
    await attachText(testInfo, 'Kardeş depolar', `${parent}\n\n${lines.join('\n\n')}`);

    // Taze örnek: host deposunun data/ ve .env hariç kopyası.
    await fresh.destroy();
    fresh.copyTree();
    await attachCommand(
      testInfo,
      'Taze host kopyası (data/ ve .env hariç)',
      'ls',
      ['-la', fresh.DIR],
    );
    expect(fs.existsSync(path.join(fresh.DIR, 'docker-compose.yml'))).toBe(true);
    expect(fs.existsSync(path.join(fresh.DIR, '.env'))).toBe(false);
  });

  await test.step('Terminal: API anahtarı yokken compose başlamayı reddeder (K2)', async () => {
    const out = await attachFailingCommand(
      testInfo,
      '.env yokken: docker compose config',
      'docker',
      ['compose', 'config'],
      { cwd: fresh.DIR, env: { ...process.env, API_KEY: '' } },
    );
    expect(out).toContain('API_KEY');
    expect(out).toMatch(/API_KEY bos|required variable/i);
  });

  await test.step('Terminal: scripts/setup.sh — .env, API anahtarı, imzalama anahtarı (K2)', async () => {
    const setupOut = await attachCommand(testInfo, 'scripts/setup.sh', './scripts/setup.sh', [], { cwd: fresh.DIR });
    expect(setupOut).toContain('API_KEY üretildi');
    expect(setupOut).toContain('Signing key');

    // Portlar ana host'unkiyle çakışmasın; sunucu kaynağı yerel PinVault checkout'u.
    fresh.configureEnv();

    const masked = fs
      .readFileSync(fresh.envFile(), 'utf8')
      .split('\n')
      .filter((l) => l.trim() && !l.trim().startsWith('#'))
      .map((l) => (l.startsWith('API_KEY=') ? `API_KEY=${redact(fresh.apiKey())}` : l))
      .map((l) => (l.startsWith('KEYSTORE_PASSWORD=') ? 'KEYSTORE_PASSWORD=<maskeli>' : l))
      .join('\n');
    await attachText(testInfo, '.env (API anahtarı maskeli)', masked);

    await attachCommand(testInfo, 'Dosya izinleri', 'ls', ['-l', '.env', 'data/signing-key.pem'], { cwd: fresh.DIR });
    const mode = (fs.statSync(path.join(fresh.DIR, 'data/signing-key.pem')).mode & 0o777).toString(8);
    expect(mode).toBe('600');

    // İmzalama anahtarı: iki satır Base64 (PKCS8 private + X.509 SPKI public).
    // Panele yalnızca public yarısı girer.
    const publicLine = fresh.signingKeyRaw().split('\n')[1].trim();
    const pem = `-----BEGIN PUBLIC KEY-----\n${publicLine.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
    const pemFile = path.join(fresh.DIR, 'data/signing-public.pem');
    fs.writeFileSync(pemFile, pem);
    const keyText = await attachCommand(testInfo, 'İmzalama anahtarının public yarısı (openssl)', 'openssl', [
      'pkey', '-pubin', '-in', pemFile, '-text', '-noout',
    ]);
    expect(keyText).toMatch(/prime256v1|P-256/);
    fs.unlinkSync(pemFile);
  });

  await test.step('Terminal: docker compose up -d --build (K3)', async () => {
    await attachCommand(testInfo, 'docker compose up -d --build', 'docker', ['compose', 'up', '-d', '--build'], {
      cwd: fresh.DIR,
      timeout: 15 * 60 * 1000,
    });
    await fresh.waitHealthy();
    await attachCommand(testInfo, 'docker compose ps', 'docker', ['compose', 'ps'], { cwd: fresh.DIR });
    const health = await fresh.api('/health', { withKey: false });
    await attachText(testInfo, 'GET /health', `HTTP ${health.status}\n${health.text}`);
    expect(health.status).toBe(200);
  });

  await test.step('Sunucu: Flyway migration logları (K3)', async () => {
    const logs = fresh.compose(['logs', '--tail', '400']);
    const migration = logs
      .split('\n')
      .filter((l) => /flyway|migrat|schema/i.test(l))
      .join('\n');
    await attachText(testInfo, 'docker compose logs | Flyway', migration);
    expect(migration).toMatch(/Successfully applied \d+ migrations/);
    expect(migration).toContain('baseline');
  });

  await test.step('Terminal: provision.sh — mTLS Config API ve mock host\'lar (K3)', async () => {
    const out = await attachCommand(testInfo, 'scripts/provision.sh', './scripts/provision.sh', [], { cwd: fresh.DIR });
    expect(out).toContain('mTLS Config API');
    expect(out).toContain('mock-tls.sample');
    expect(out).toContain('mock-mtls.sample');
  });

  await test.step('Terminal: smoke-test.sh bütün kontroller PASS (K3)', async () => {
    const out = await attachCommand(testInfo, 'scripts/smoke-test.sh', './scripts/smoke-test.sh', [], { cwd: fresh.DIR });
    expect(out).toContain('0 FAIL');
    expect(out).toContain('ECDSA imzası');
    expect(out).toContain(`SAN ${env.LAN_IP} içeriyor`);
  });

  await test.step('Web: taze host dashboard\'unun ilk hâli (K3)', async () => {
    const dashboard = await fresh.openDashboard(browser, testInfo);
    try {
      const hosts = await dashboard.hostNames();
      await dashboard.snap('taze host: dashboard ilk açılış (provision.sh sonrası)');
      await attachText(
        testInfo,
        'Ağaçtaki Config API\'ler ve host\'lar',
        [`host'lar: ${hosts.join(', ')}`, '', 'default-tls (TLS) + sample-mtls (mTLS); host\'un kendi pin kaydı ve iki mock hedef.'].join('\n'),
      );
      expect(hosts).toContain(env.LAN_IP);
      expect(hosts).toContain(env.MOCK_TLS_HOST);
    } finally {
      await dashboard.page.close();
    }
  });
});
