// S05 — Harici komut imzalayıcısı (KMS benzeri, SIGNER_INPUT=digest).
//
// Sunucu imzayı kendisi atmak zorunda değil: CONFIG_SIGNERS=command ile
// imzalanacak baytların SHA-256 özetini (32 bayt) bir komuta stdin'den verir,
// imzayı stdout'tan alır. Üretimde bu komut bir bulut KMS'i (ör. `aws kms sign
// --message-type DIGEST`), Vault transit ya da onay isteyen başka bir imza
// servisidir; özel anahtar sunucuya hiç gelmez. Sunucu dönen her imzayı
// komutun public key'i ile doğrular: yanlış anahtarla dönen bir imza cihaza
// asla gitmez.
//
// Test için kurulan "KMS" geçici test sunucusunun data/kms dizininde: P-256
// anahtar, public key PEM ve özeti imzalayıp her çağrıyı calls.log'a yazan sign.sh.
//   1. komut EK imzalayıcı olarak açılır (local,command),
//   2. KMS anahtarı anahtar setiyle telefonlara bildirilir, sunucu yalnızca komutla imzalar,
//   3. telefon KMS anahtarının imzasını kabul eder; calls.log her imzayı gösterir,
//   4. komut yanlış anahtarla imzalarsa sunucu yanıtı vermez (503; nedeni
//      yalnızca sunucu günlüğünde, istemciye imzalayıcı ayrıntısı gitmez).
//
// Geçici test sunucusunda çalışır; sonunda ortam sıfırlanır, data/kms silinir,
// ana APK geri kurulur.
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const offlineKeys = require('../lib/offlineKeys');
const lab = require('../lib/signingLab');

const SIGN_SH = `#!/bin/sh
# Laboratuvar "KMS"i. PinVault sunucusu imzalanacak baytların SHA-256 özetini
# (32 bayt, SIGNER_INPUT=digest) stdin'den verir; imza (DER, Base64) stdout'a.
# Gerçek bir KMS'te imza satırı ör. \`aws kms sign --message-type DIGEST …\` olur
# ve özel anahtar bu makinede değil KMS'te durur.
set -eu
dir=/data/kms
key="$dir/key.pem"
# Laboratuvar: hata enjeksiyonu (yanlış anahtarla imza) — senaryonun son adımı.
if [ -f "$dir/use-wrong-key" ]; then key="$dir/wrong.pem"; fi
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
sig="$(openssl pkeyutl -sign -inkey "$key" -pkeyopt digest:sha256 -in "$tmp" | openssl base64 -A)"
printf '%s sign digest=%s… (%s bayt) key=%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
  "$(od -An -tx1 "$tmp" | tr -d ' \\n' | cut -c1-16)" "$(wc -c < "$tmp" | tr -d ' ')" "$(basename "$key")" >> "$dir/calls.log"
printf '%s' "$sig"
`;

const KEYGEN = [
  'mkdir -p /data/kms && cd /data/kms',
  'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem',
  'chmod 600 key.pem',
  'openssl pkey -in key.pem -pubout -out pub.pem',
  'touch calls.log',
  'ls -l',
].join(' && ');

const COMMAND_ENV = {
  SIGNER_COMMAND: '/data/kms/sign.sh',
  SIGNER_PUBLIC_KEY_FILE: '/data/kms/pub.pem',
  SIGNER_INPUT: 'digest',
};
const COMMAND_DISPLAY = 'SIGNER_COMMAND=/data/kms/sign.sh SIGNER_PUBLIC_KEY_FILE=/data/kms/pub.pem SIGNER_INPUT=digest';
const recoveryDisplay = () => `RECOVERY_PUBLIC_KEYS="$(cat ${lab.REL_KEYS}/${lab.KEYS.recovery}.pub)"`;

/** Container içinde komut (docker compose exec); stdin verilebilir. */
function inContainer(script, input) {
  return lab.run('docker', ['compose', 'exec', '-T', 'pinvault-host', 'sh', '-c', script], { input });
}

function callsLog() {
  return inContainer('cat /data/kms/calls.log 2>/dev/null || true').split('\n').filter(Boolean);
}

test('Sunucu+Mobil: dış komutla imzalama (KMS benzeri, komuta yalnızca SHA-256 özeti gider) — her imzayı komut atıyor, sunucu doğruluyor; telefon KMS anahtarının imzasını kabul ediyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(30 * 60 * 1000);
  const app = new SampleApp(device, testInfo);
  let dashboard;
  let setup;
  let kms;
  let N;
  let names = {};
  let createdKms = false;

  try {
    await test.step('Terminal+Mobil: bu test için derlenen uygulama kurulur; telefon geçici test sunucusunun birincil anahtarıyla Hazır', async () => {
      setup = await lab.setup(device, testInfo);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('bu test için derlenen uygulama: birincil anahtarla Hazır');
      expect(SampleApp.signingOf(ready).signedBy).toEqual([setup.primary.keyId.slice(0, 12)]);
      names = { [setup.primary.keyId]: 'sunucunun birincil anahtarı', [setup.keys.recovery.keyId]: lab.KEYS.recovery };
    });

    await test.step('Terminal: "KMS" hazırlanır — data/kms: P-256 anahtar, public key PEM ve özeti imzalayan sign.sh (her çağrı calls.log\'a yazılır)', async () => {
      createdKms = true;
      await lab.op(testInfo, 'KMS anahtarı (container içinde üretilir; private key bu sayfaya girmez)', {
        display: `docker compose exec -T pinvault-host sh -c '${KEYGEN}'`,
        file: 'docker',
        args: ['compose', 'exec', '-T', 'pinvault-host', 'sh', '-c', KEYGEN],
      });
      await lab.op(testInfo, 'İmzalayan komut: /data/kms/sign.sh', {
        display: "docker compose exec -T pinvault-host sh -c 'cat > /data/kms/sign.sh && chmod 755 /data/kms/sign.sh' < sign.sh",
        file: 'docker',
        args: ['compose', 'exec', '-T', 'pinvault-host', 'sh', '-c', 'cat > /data/kms/sign.sh && chmod 755 /data/kms/sign.sh && ls -l /data/kms/sign.sh'],
        input: SIGN_SH,
        note: `sign.sh:\n${SIGN_SH}`,
      });
      const pem = fs.readFileSync(path.join(fresh.DIR, 'data/kms/pub.pem'), 'utf8');
      const pub = pem.split('\n').filter((l) => l && !l.startsWith('-----')).join('');
      kms = { pub, keyId: offlineKeys.keyIdOf(pub) };
      names[kms.keyId] = 'KMS (command)';
      await attachText(
        testInfo,
        'KMS public key (data/kms/pub.pem)',
        [pem.trim(), '', `anahtar kimliği: ${kms.keyId}`].join('\n'),
      );
      expect(pem).toContain('BEGIN PUBLIC KEY');
    });

    await test.step('Sunucu: komut imzalayıcısı EK imzalayıcı olarak açılır (CONFIG_SIGNERS=local,command, SIGNER_INPUT=digest)', async () => {
      await lab.setEnv(testInfo, 'env-override.sh: yerel anahtar + komut imzalayıcısı', {
        CONFIG_SIGNERS: 'local,command',
        ...COMMAND_ENV,
        RECOVERY_PUBLIC_KEYS: setup.keys.recovery.pub,
      }, { display: `./scripts/env-override.sh set CONFIG_SIGNERS=local,command ${COMMAND_DISPLAY} ${recoveryDisplay()}` });
      const status = await lab.signingStatus();
      await attachText(testInfo, 'GET /api/v1/signing/status → imzalayıcılar', lab.describeSigners(status.signers));
      expect(status.signers.map((s) => s.type)).toEqual(['local', 'command']);
      expect(status.signers[1].keyId).toBe(kms.keyId);
      expect(status.signers[1].description).toBe('External command sign.sh');
    });

    await test.step('Web: İmzalama sekmesi — command imzalayıcısı (yalnızca program adı görünür, argüman/gizli değer yok)', async () => {
      dashboard = await fresh.openDashboard(browser, testInfo);
      await dashboard.openSigning('default-tls');
      const rows = await dashboard.signerRows();
      await dashboard.snapCard('#signers-card', 'İmzalayıcılar: local (birincil) + command (KMS)');
      await attachText(
        testInfo,
        'Dashboard → İmzalama → İmzalayıcılar',
        rows.map((r) => `${r.name} [${r.type}]${r.primary ? ' birincil' : ''} — ${r.keyId} — ${r.description}`).join('\n'),
      );
      expect(rows.map((r) => r.type)).toEqual(['local', 'command']);
      expect(rows[1].keyId).toBe(kms.keyId);
    });

    await test.step('Terminal+Sunucu: KMS anahtarı set vN = {birincil, KMS} ile telefonlara bildirilir; ardından sunucu yalnızca komutla imzalar (CONFIG_SIGNERS=command)', async () => {
      N = await lab.nextKeySetVersion();
      const file = lab.labFile(`keyset-kms-v${N}.json`);
      await lab.op(testInfo, `signing-keys.sh keyset: v${N} = sunucunun imzalayıcıları (birincil + KMS)`, {
        display: `./scripts/signing-keys.sh keyset -v ${N} -k server -s ${lab.KEYS.recovery} -o ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(N), '-k', 'server', '-s', lab.KEYS.recovery, '-o', file.rel],
        note: () => lab.describeKeySet(JSON.parse(fs.readFileSync(file.abs, 'utf8')), names),
      });
      const up = await lab.op(testInfo, `signing-keys.sh upload: v${N}`, {
        display: `./scripts/signing-keys.sh upload ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['upload', file.rel],
      });
      expect(up).toContain('HTTP 200');
      await lab.setEnv(testInfo, 'env-override.sh: yalnızca komut imzalayıcısı', {
        CONFIG_SIGNERS: 'command',
        ...COMMAND_ENV,
        RECOVERY_PUBLIC_KEYS: setup.keys.recovery.pub,
      }, { display: `./scripts/env-override.sh set CONFIG_SIGNERS=command ${COMMAND_DISPLAY} ${recoveryDisplay()}` });
      const status = await lab.signingStatus();
      await attachText(
        testInfo,
        'GET /api/v1/signing/status',
        [
          lab.describeSigners(status.signers),
          '',
          `anahtar seti: v${status.keySet.version} → ${status.keySet.keyIds.map((id) => `${id.slice(0, 16)}… (${names[id] || '?'})`).join(', ')}`,
        ].join('\n'),
      );
      expect(status.signers.map((s) => s.keyId)).toEqual([kms.keyId]);
      expect(status.keySet.version).toBe(N);
    });

    await test.step('Mobil: config yenile → KMS anahtarının imzası kabul edildi, set vN uygulandı', async () => {
      const before = callsLog().length;
      const status = await app.refreshConfig();
      await app.snap('config KMS komutuyla imzalı: kabul edildi');
      const after = callsLog().length;
      const sig = SampleApp.signingOf(status);
      await attachText(
        testInfo,
        'Telefon: config yenile',
        [
          status.split('\n').filter((l) => /Config|İmza|imzalayan/.test(l)).join('\n'),
          '',
          `KMS anahtar kimliği (sunucu): ${kms.keyId}`,
          `calls.log: yenilemeden önce ${before} satır, sonra ${after} satır`,
        ].join('\n'),
      );
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(sig.keySetVersion).toBe(N);
      expect(sig.signedBy).toEqual([kms.keyId.slice(0, 12)]);
      expect(after).toBeGreaterThan(before);
    });

    await test.step('Terminal: calls.log her imzayı gösteriyor; GET /api/v1/signing/status komut imzalayıcısını ve sayaçları gösteriyor', async () => {
      const log = await lab.op(testInfo, 'KMS çağrı günlüğü', {
        display: "docker compose exec -T pinvault-host sh -c 'wc -l < /data/kms/calls.log; tail -n 12 /data/kms/calls.log'",
        file: 'docker',
        args: ['compose', 'exec', '-T', 'pinvault-host', 'sh', '-c', 'wc -l < /data/kms/calls.log; tail -n 12 /data/kms/calls.log'],
        note: 'Her satır bir imza: sunucu imzalanacak baytların SHA-256 özetini (32 bayt) komuta verdi.',
      });
      const status = await lab.signingStatus();
      await attachText(
        testInfo,
        'GET /api/v1/signing/status',
        JSON.stringify({ signers: status.signers.map(({ name, type, keyId, description }) => ({ name, type, keyId, description })), cache: status.cache }, null, 2),
      );
      expect(log).toMatch(/sign digest=[0-9a-f]{16}… \(32 bayt\) key=key\.pem/);
      expect(status.signers[0].type).toBe('command');
    });

    await test.step('Sunucu: komut başka bir anahtarla imzalarsa sunucu o imzayı cihazlara göndermiyor (her imza pub.pem ile doğrulanıyor)', async () => {
      const inject = 'cd /data/kms && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out wrong.pem && chmod 600 wrong.pem && touch use-wrong-key';
      await lab.op(testInfo, 'Kasıtlı hata: KMS yanlış anahtarla imzalasın', {
        display: `docker compose exec -T pinvault-host sh -c '${inject}'`,
        file: 'docker',
        args: ['compose', 'exec', '-T', 'pinvault-host', 'sh', '-c', inject],
      });
      const bad = await fresh.api('/api/v1/certificate-config', { withKey: false });
      const logs = lab.run('sh', ['-c', 'docker compose logs --tail 200 pinvault-host 2>&1 | grep -i "does not verify" | tail -n 2 || true']);
      const lastCall = callsLog().slice(-1)[0] || '';
      inContainer('rm -f /data/kms/use-wrong-key /data/kms/wrong.pem');
      const good = await fresh.api('/api/v1/certificate-config', { withKey: false });
      await attachText(
        testInfo,
        'Yanlış anahtarla imza → sunucu config göndermiyor (503); düzelince yine imzalı config geliyor',
        [
          `$ curl -s ${fresh.WEB_URL}/api/v1/certificate-config`,
          `HTTP ${bad.status}`,
          bad.text.trim(),
          '',
          `calls.log son satır: ${lastCall}`,
          logs.trim() ? `sunucu günlüğü: ${logs.trim()}` : '',
          '',
          "$ docker compose exec -T pinvault-host rm -f /data/kms/use-wrong-key /data/kms/wrong.pem",
          `$ curl -s ${fresh.WEB_URL}/api/v1/certificate-config → HTTP ${good.status}, keyId ${good.json && good.json.keyId}`,
          '',
          'CommandSigner her imzayı SIGNER_PUBLIC_KEY_FILE ile doğruluyor: yanlış ayarlanmış ya da',
          'ele geçirilmiş bir imzalayıcı, cihazların reddedeceği (ya da başka anahtara ait) bir imzayı',
          'sunucudan hiç dışarı çıkaramıyor. Nedeni yalnızca sunucu günlüğüne yazılıyor; API anahtarı',
          'göndermeyen istemci imzalayıcı ayrıntısı (KMS kimliği, komut çıktısı) görmüyor, yalnızca 503 alıyor.',
        ]
          .filter((l, i, a) => l !== '' || a[i - 1] !== '')
          .join('\n'),
      );
      expect(bad.status).toBe(503);
      expect(bad.text).toContain('Config signing is temporarily unavailable');
      expect(bad.text).not.toContain('does not verify');
      expect(logs).toContain('does not verify with its configured public key');
      expect(lastCall).toContain('key=wrong.pem');
      expect(good.status).toBe(200);
      expect(good.json.keyId).toBe(kms.keyId);
    });
  } finally {
    await test.step('Sunucu+Terminal: ortam sıfırlanır, data/kms silinir; telefona ana host için derlenen APK geri kurulur', async () => {
      const lines = ['$ ./scripts/env-override.sh reset', await lab.resetEnv({ force: true })];
      if (createdKms) {
        try {
          inContainer('rm -rf /data/kms');
        } catch {
          /* container yanıt vermiyorsa dosyalar Mac tarafından silinir */
        }
        fs.rmSync(path.join(fresh.DIR, 'data/kms'), { recursive: true, force: true });
        lines.push("$ docker compose exec -T pinvault-host rm -rf /data/kms");
      }
      const info = await lab.signingKeyInfo();
      lines.push('', `imzalayıcılar: ${info.signers.map((s) => `${s.keyId.slice(0, 16)}… (${names[s.keyId] || '?'})`).join(', ')}`);
      lines.push(`data/kms var mı: ${fs.existsSync(path.join(fresh.DIR, 'data/kms')) ? 'EVET' : 'hayır'}`);
      await attachText(testInfo, 'Geri dönüş: geçici test sunucusu', lines.join('\n'));
      await lab.restoreMain(device, app, testInfo);
      if (setup) expect(info.keyId).toBe(setup.primary.keyId);
    });
    if (dashboard) await dashboard.page.close();
  }
});
