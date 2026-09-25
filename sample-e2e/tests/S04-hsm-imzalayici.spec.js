// S04 — HSM imzalayıcısı (SoftHSM üzerinden PKCS#11).
//
// Sunucu config'leri, anahtarı bir HSM'in İÇİNDE üretilmiş ve dışarı
// çıkarılamayan (CKA_SENSITIVE, CKA_EXTRACTABLE=false) bir anahtarla
// imzalayabiliyor: sunucuyu ele geçiren anahtarı kopyalayamaz. SoftHSM gerçek
// bir HSM'in PKCS#11 arayüzünü taklit eder; aynı ayarlar üreticinin PKCS#11
// modülüyle çalışır (PKCS11_LIBRARY değişir).
//
// HSM anahtarı YENİ bir imza anahtarıdır; sahadaki uygulamalar onu bir
// imzalama anahtarı setiyle öğrenir:
//   1. SoftHSM token'ı hazırlanır, HSM EK imzalayıcı olarak açılır (local,pkcs11),
//   2. pkcs11-tool anahtarın "never extractable" ve yalnızca imza yetkili
//      (Usage: sign) olduğunu gösterir, data/
//      altında dosyası yoktur,
//   3. set vN = {birincil, HSM}, vN+1 = {HSM} yayımlanır, yerel anahtar geri
//      çekilir (CONFIG_SIGNERS=pkcs11),
//   4. telefon config'i HSM'in imzasıyla kabul eder.
//
// Geçici test sunucusunda çalışır. Token (data/softhsm) yerinde bırakılır; zararsız.
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const lab = require('../lib/signingLab');

const recoveryExtra = () => `EXTRA_ENV="RECOVERY_PUBLIC_KEYS=$(cat ${lab.REL_KEYS}/${lab.KEYS.recovery}.pub)"`;

test('Sunucu+Web+Mobil: HSM imzalayıcısı (SoftHSM/PKCS#11) — anahtar HSM token\'ının içinde, dışarı çıkarılamıyor; anahtar setiyle telefonlara bildirilince telefon HSM\'in imzasını kabul ediyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(30 * 60 * 1000);
  const app = new SampleApp(device, testInfo);
  let dashboard;
  let setup;
  let hsm;
  let N;
  let names = {};

  try {
    await test.step('Terminal+Mobil: bu test için derlenen uygulama kurulur; telefon geçici test sunucusunun birincil anahtarıyla Hazır (anahtar seti v0)', async () => {
      setup = await lab.setup(device, testInfo);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('bu test için derlenen uygulama: birincil anahtarla Hazır');
      const sig = SampleApp.signingOf(ready);
      expect(sig.signedBy).toEqual([setup.primary.keyId.slice(0, 12)]);
      names = { [setup.primary.keyId]: 'sunucunun birincil anahtarı (yerel dosya)', [setup.keys.recovery.keyId]: lab.KEYS.recovery };
    });

    await test.step('Terminal: SoftHSM token\'ı hazırlanır (softhsm-init.sh init) — PIN .env\'e yazılır, ekrana gelmez', async () => {
      const out = await lab.op(testInfo, 'softhsm-init.sh init', {
        display: './scripts/softhsm-init.sh init',
        file: './scripts/softhsm-init.sh',
        args: ['init'],
        note: () => {
          const pinLines = fs.readFileSync(fresh.envFile(), 'utf8').split('\n').filter((l) => l.startsWith('PKCS11_PIN='));
          return `$ grep -c '^PKCS11_PIN=' .env\n${pinLines.length}   (değer panele girmez; .env 0600)`;
        },
      });
      expect(out).toMatch(/SoftHSM token 'pinvault' (oluşturuldu|zaten hazır)/);
    });

    await test.step('Sunucu: HSM EK imzalayıcı olarak açılır (CONFIG_SIGNERS=local,pkcs11, PKCS11_GENERATE_KEY=true) — anahtar token içinde üretilir', async () => {
      await lab.op(testInfo, 'softhsm-init.sh enable (yerel anahtar + HSM)', {
        display: `SIGNERS=local,pkcs11 ${recoveryExtra()} ./scripts/softhsm-init.sh enable`,
        file: './scripts/softhsm-init.sh',
        args: ['enable'],
        env: { SIGNERS: 'local,pkcs11', EXTRA_ENV: `RECOVERY_PUBLIC_KEYS=${setup.keys.recovery.pub}` },
        note: 'enable → env-override.sh set CONFIG_SIGNERS=local,pkcs11 PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so PKCS11_PIN=<.env> PKCS11_GENERATE_KEY=true RECOVERY_PUBLIC_KEYS=…',
      });
      await lab.waitConfigApi();
      const logs = lab.run('sh', ['-c', 'docker compose logs --tail 400 pinvault-host 2>&1 | grep -i "Pkcs11Signer" || true']);
      const status = await lab.signingStatus();
      hsm = status.signers.find((s) => s.type === 'pkcs11');
      if (hsm) names[hsm.keyId] = 'HSM (pkcs11)';
      await attachText(
        testInfo,
        'Sunucu günlüğü + GET /api/v1/signing/status',
        [
          '$ docker compose logs pinvault-host | grep Pkcs11Signer',
          logs.trim() || '(satır yok)',
          '',
          'imzalayıcılar (* birincil):',
          lab.describeSigners(status.signers),
        ].join('\n'),
      );
      expect(status.signers.map((s) => s.type)).toEqual(['local', 'pkcs11']);
      expect(hsm.description).toContain('PKCS#11 HSM key');
      expect(status.signers[0].keyId).toBe(setup.primary.keyId);
    });

    await test.step('Web: İmzalama sekmesi — pkcs11 imzalayıcısı (tür rozeti, açıklama)', async () => {
      dashboard = await fresh.openDashboard(browser, testInfo);
      await dashboard.openSigning('default-tls');
      const rows = await dashboard.signerRows();
      await dashboard.snapCard('#signers-card', 'İmzalayıcılar: local (birincil) + pkcs11 (HSM)');
      await attachText(
        testInfo,
        'Dashboard → İmzalama → İmzalayıcılar',
        rows.map((r) => `${r.name} [${r.type}]${r.primary ? ' birincil' : ''} — ${r.keyId} — ${r.description}`).join('\n'),
      );
      expect(rows.map((r) => r.type)).toEqual(['local', 'pkcs11']);
      expect(rows[1].keyId).toBe(hsm.keyId);
      expect(rows[1].description).toContain('libsofthsm2.so');
    });

    await test.step('Terminal: softhsm-init.sh show — özel anahtar "sensitive, always sensitive, never extractable, local" (dışarı çıkarılamaz) ve yalnızca imza atabilir (Usage: sign); data/ altında anahtar dosyası yok', async () => {
      const shown = await lab.op(testInfo, 'softhsm-init.sh show (pkcs11-tool --list-objects)', {
        display: './scripts/softhsm-init.sh show',
        file: './scripts/softhsm-init.sh',
        args: ['show'],
      });
      const listing = await lab.op(testInfo, 'data/ ve SoftHSM token dizini', {
        display: 'ls -la data; ls -la data/softhsm/tokens/*/',
        file: 'sh',
        args: ['-c', 'ls -la data; echo; ls -la data/softhsm/tokens/*/'],
        note: [
          'data/ altında yalnızca yerel birincil anahtar (signing-key.pem) var; HSM anahtarı için dosya yok.',
          'Token dizinindeki .object dosyaları SoftHSM\'in kendi (PIN\'den türetilen anahtarla şifreli)',
          'nesne deposu; gerçek bir HSM\'de bu katman donanımın içindedir.',
        ].join('\n'),
      });
      // pkcs11-tool her nesneyi sütun 0'da başlatır; yalnızca özel anahtarın satırları.
      const privateBlock = shown.slice(shown.indexOf('Private Key Object')).split(/\n(?=\S[^\n]*Object)/)[0];
      expect(shown).toContain('Private Key Object; EC');
      expect(privateBlock).toMatch(/Access:\s+sensitive, always sensitive, never extractable, local/);
      // Şifre çözme, anahtar sarma, sign-recover ya da türetme yetkisi yok.
      expect(privateBlock).toMatch(/Usage:\s+sign\s*$/m);
      expect(shown).toContain('pinvault-config-signing');
      expect(listing).not.toMatch(/signing-key-.*pkcs11|\.p8|hsm.*\.pem/i);
    });

    await test.step('Terminal: set vN = {birincil, HSM} ve vN+1 = {HSM} kurtarma anahtarıyla imzalanıp yüklenir', async () => {
      N = await lab.nextKeySetVersion();
      const first = lab.labFile(`keyset-hsm-v${N}.json`);
      await lab.op(testInfo, `signing-keys.sh keyset: v${N} = sunucunun imzalayıcıları (birincil + HSM)`, {
        display: `./scripts/signing-keys.sh keyset -v ${N} -k server -s ${lab.KEYS.recovery} -o ${first.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(N), '-k', 'server', '-s', lab.KEYS.recovery, '-o', first.rel],
        note: () => lab.describeKeySet(JSON.parse(fs.readFileSync(first.abs, 'utf8')), names),
      });
      const up1 = await lab.op(testInfo, `signing-keys.sh upload: v${N}`, {
        display: `./scripts/signing-keys.sh upload ${first.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['upload', first.rel],
      });
      const second = lab.labFile(`keyset-hsm-v${N + 1}.json`);
      await lab.op(testInfo, `signing-keys.sh keyset: v${N + 1} = yalnızca HSM`, {
        display: [
          `HSM_PUB="$(curl -s ${fresh.WEB_URL}/api/v1/signing-key | jq -r '.signers[] | select(.keyId=="${hsm.keyId}") | .publicKey')"`,
          `$ ./scripts/signing-keys.sh keyset -v ${N + 1} -k "$HSM_PUB" -s ${lab.KEYS.recovery} -o ${second.rel}`,
        ].join('\n'),
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(N + 1), '-k', hsm.publicKey, '-s', lab.KEYS.recovery, '-o', second.rel],
        note: () => lab.describeKeySet(JSON.parse(fs.readFileSync(second.abs, 'utf8')), names),
      });
      const up2 = await lab.op(testInfo, `signing-keys.sh upload: v${N + 1} (uyarı: yerel anahtar sette yok)`, {
        display: `./scripts/signing-keys.sh upload ${second.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['upload', second.rel],
      });
      const a1 = JSON.parse(up1.slice(0, up1.lastIndexOf('HTTP')).trim());
      const a2 = JSON.parse(up2.slice(0, up2.lastIndexOf('HTTP')).trim());
      expect(up1).toContain('HTTP 200');
      expect(up2).toContain('HTTP 200');
      expect(new Set(a1.keyIds)).toEqual(new Set([setup.primary.keyId, hsm.keyId]));
      expect(a2.keyIds).toEqual([hsm.keyId]);
      expect(a2.warnings.join('\n')).toContain(setup.primary.keyId.slice(0, 12));
    });

    await test.step('Sunucu: yerel anahtar geri çekilir — yalnızca HSM imzalıyor (CONFIG_SIGNERS=pkcs11)', async () => {
      await lab.op(testInfo, 'softhsm-init.sh enable (yalnızca HSM)', {
        display: `SIGNERS=pkcs11 ${recoveryExtra()} ./scripts/softhsm-init.sh enable`,
        file: './scripts/softhsm-init.sh',
        args: ['enable'],
        env: { SIGNERS: 'pkcs11', EXTRA_ENV: `RECOVERY_PUBLIC_KEYS=${setup.keys.recovery.pub}` },
      });
      await lab.waitConfigApi();
      const status = await lab.signingStatus();
      await attachText(
        testInfo,
        'GET /api/v1/signing/status',
        [
          'imzalayıcılar:',
          lab.describeSigners(status.signers),
          '',
          `anahtar seti: v${status.keySet.version} → ${status.keySet.keyIds.map((id) => `${id.slice(0, 16)}… (${names[id] || '?'})`).join(', ')}`,
          `sette olmayan aktif imzalayıcı: ${status.keySet.activeSignersMissing.length ? status.keySet.activeSignersMissing.join(', ') : 'yok ✓'}`,
          `"Anahtarı Yenile" mümkün mü (canRegenerate): ${status.canRegenerate}  (birincil artık HSM: anahtar değişikliği HSM tarafında yapılır)`,
        ].join('\n'),
      );
      expect(status.signers.map((s) => s.keyId)).toEqual([hsm.keyId]);
      expect(status.keySet.version).toBe(N + 1);
      expect(status.keySet.activeSignersMissing).toEqual([]);
      expect(status.canRegenerate).toBe(false);
    });

    await test.step('Mobil: config yenile → HSM\'in imzası kabul edildi, set vN+1 uygulandı; Depolama ekranı: güvenilen tek anahtar HSM\'inki', async () => {
      const status = await app.refreshConfig();
      await app.snap('config HSM ile imzalı: kabul edildi');
      const sig = SampleApp.signingOf(status);
      await app.openStorage();
      const detail = SampleApp.signingDetailOf(await app.storageText());
      await app.snap(`Depolama: set v${N + 1}, güvenilen HSM anahtarı`);
      await attachText(
        testInfo,
        'Telefon: config yenile + Depolama',
        [
          status.split('\n').filter((l) => /Config|İmza|imzalayan/.test(l)).join('\n'),
          '',
          detail.text,
          '',
          `HSM anahtar kimliği (sunucu): ${hsm.keyId}`,
        ].join('\n'),
      );
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(sig.keySetVersion).toBe(N + 1);
      expect(sig.trusted).toBe(1);
      expect(sig.signedBy).toEqual([hsm.keyId.slice(0, 12)]);
      expect(detail.trusted).toEqual([hsm.keyId]);
      await app.backToMain();
    });
  } finally {
    await test.step('Sunucu+Terminal: ortam sıfırlanır (yeniden yerel imzalayıcı), SoftHSM token\'ı yerinde kalır; telefona ana host için derlenen APK geri kurulur', async () => {
      const out = await lab.resetEnv({ force: true });
      const info = await lab.signingKeyInfo();
      await attachText(
        testInfo,
        'Geri dönüş: geçici test sunucusu',
        [
          '$ ./scripts/env-override.sh reset   (softhsm-init.sh disable ile aynı)',
          out,
          '',
          `imzalayıcılar: ${info.signers.map((s) => `${s.keyId.slice(0, 16)}… (${names[s.keyId] || '?'})`).join(', ')}`,
          'SoftHSM token\'ı data/softhsm altında kalıyor (zararsız; CONFIG_SIGNERS onu seçmedikçe kullanılmaz).',
        ].join('\n'),
      );
      await lab.restoreMain(device, app, testInfo);
      if (setup) expect(info.keyId).toBe(setup.primary.keyId);
    });
    if (dashboard) await dashboard.page.close();
  }
});
