// S02 — İmzalama anahtarı seti: anahtar değiştirme (rotasyon), iptal ve sunucu
// tarafındaki kontrol.
//
// Uygulamaya imzalama anahtarlarının yanında bir de KURTARMA anahtarı gömülü
// (recoveryPublicKeys). Kurtarma anahtarı config imzalamaz; yalnızca
// "cihazlar şu imzalama anahtarlarına güvensin" diyen sürümlü bir listeyi
// (anahtar seti) imzalar. Set çevrimdışı imzalanır (signing-keys.sh keyset),
// sunucu yalnızca doğrular ve her imzalı config'e ekler; cihaz daha yeni bir
// seti uygular ve o andan sonra TAM OLARAK setteki anahtarlara güvenir —
// listede olmayan anahtar İPTAL edilmiştir, artık ona güvenilmez. Böylece
// uygulama güncellemesi olmadan anahtar değiştirilir ve çalınmış bir anahtar
// geri çekilir.
//
//   1. sunucu seti cihaz gibi doğruluyor: kurtarma anahtarıyla imzalanmamış
//      set 422, sunucunun kendi imzalayıcılarını içermeyen set 409,
//   2. anahtar değiştirme: yeni anahtar (lab-next) ikinci imzalayıcı, set vN = {birincil, next},
//   3. iptal: set vN+1 = {next}; telefon artık yalnızca next'e güveniyor,
//   4. iptal edilen anahtarla imzalı config "revoked by signing-key set" ile
//      reddediliyor, saklı config ile pinli bağlantı sürüyor; set etkinken
//      "anahtarı yenile" 409,
//   5. set uygulama yeniden açılınca da geçerli (şifreli tercih dosyasında).
//
// Geçici test sunucusunda çalışır. Sunucudaki set tablosu yalnızca eklenir;
// sürümler GET /api/v1/signing/status'tan hesaplanır.
const fs = require('fs');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');
const lab = require('../lib/signingLab');

const recoveryDisplay = () => `RECOVERY_PUBLIC_KEYS="$(cat ${lab.REL_KEYS}/${lab.KEYS.recovery}.pub)"`;

test('Sunucu+Web+Mobil: anahtar seti (telefonun güvendiği imza anahtarları) — kurtarma anahtarıyla anahtar değiştirme, iptal edilen anahtarın reddi, sunucu tarafındaki kontrol', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(40 * 60 * 1000);
  const app = new SampleApp(device, testInfo);
  let dashboard;
  let setup;
  let next;
  let names = {};
  let createdNext = false;
  let N;

  try {
    await test.step('Terminal+Mobil: bu test için derlenen uygulama kurulur; telefon APK\'ya gömülü anahtarlarla Hazır (anahtar seti v0)', async () => {
      setup = await lab.setup(device, testInfo);
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('bu test için derlenen uygulama: Hazır, anahtar seti v0');
      const sig = SampleApp.signingOf(ready);
      expect(sig.keySetVersion).toBe(0);
      expect(sig.trusted).toBe(3);
      names = {
        [setup.primary.keyId]: 'sunucunun birincil anahtarı',
        [setup.keys.backup.keyId]: lab.KEYS.backup,
        [setup.keys.second.keyId]: lab.KEYS.second,
        [setup.keys.recovery.keyId]: lab.KEYS.recovery,
      };
    });

    await test.step('Sunucu: RECOVERY_PUBLIC_KEYS ayarlanır; sunucu gelen setleri, cihazdaki kurtarma anahtarıyla doğrulayacak', async () => {
      await lab.setEnv(testInfo, 'env-override.sh: kurtarma anahtarının public key\'i', {
        RECOVERY_PUBLIC_KEYS: setup.keys.recovery.pub,
      }, { display: `./scripts/env-override.sh set ${recoveryDisplay()}` });
      const status = await lab.signingStatus();
      await attachText(
        testInfo,
        'GET /api/v1/signing/status → keySet',
        [
          JSON.stringify(status.keySet, null, 2),
          '',
          `kurtarma anahtarı ${lab.KEYS.recovery}: ${setup.keys.recovery.keyId}`,
        ].join('\n'),
      );
      expect(status.keySet.enabled).toBe(true);
      expect(status.keySet.recoveryKeyIds).toEqual([setup.keys.recovery.keyId]);
    });

    await test.step('Web: imzalama anahtarıyla (kurtarma anahtarı DEĞİL) imzalanmış set yüklenir → 422, set reddedildi', async () => {
      const version = await lab.nextKeySetVersion();
      const file = lab.labFile('keyset-imza-anahtariyla.json');
      await lab.op(testInfo, 'Operatör hatası ya da çalınmış imza anahtarı: set lab-backup ile imzalanır', {
        display: `./scripts/signing-keys.sh keyset -v ${version} -k server,${lab.KEYS.backup} -s ${lab.KEYS.backup} -o ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(version), '-k', `server,${lab.KEYS.backup}`, '-s', lab.KEYS.backup, '-o', file.rel],
      });
      const wireText = fs.readFileSync(file.abs, 'utf8').trim();
      dashboard = await fresh.openDashboard(browser, testInfo);
      const upload = await dashboard.uploadKeySet('default-tls', wireText);
      await dashboard.snapCard('#keyset-card', 'Anahtar seti kartı: set reddedildi (422)');
      await attachText(
        testInfo,
        'Dashboard → "Seti Yükle" (PUT /api/v1/signing-keyset)',
        [
          lab.describeKeySet(JSON.parse(wireText), names),
          '',
          `HTTP ${upload.status}`,
          upload.body,
          '',
          `kartın sonuç kutusu: ${upload.result}`,
        ].join('\n'),
      );
      expect(upload.status).toBe(422);
      expect(upload.body).toContain('0 of 1 required recovery signature(s) are valid');
      expect(upload.result).toContain('reddedildi');
      expect((await lab.signingStatus()).keySet.version).toBe(version - 1);
    });

    await test.step('Terminal: kurtarma anahtarıyla imzalı ama yalnızca sunucunun hiç kullanmadığı bir anahtarı listeleyen set → 409', async () => {
      const version = await lab.nextKeySetVersion();
      const file = lab.labFile('keyset-sunucu-anahtari-yok.json');
      await lab.op(testInfo, 'Set: yalnızca lab-second (sunucu bu anahtarla imzalamıyor), lab-recovery ile imzalı', {
        display: `./scripts/signing-keys.sh keyset -v ${version} -k ${lab.KEYS.second} -s ${lab.KEYS.recovery} -o ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(version), '-k', lab.KEYS.second, '-s', lab.KEYS.recovery, '-o', file.rel],
      });
      const out = await lab.op(testInfo, 'signing-keys.sh upload → sunucu seti reddediyor', {
        display: `./scripts/signing-keys.sh upload ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['upload', file.rel],
        note: [
          'Setin imzası geçerli (kurtarma imzası doğru) ama sunucu bu anahtarla imza atmıyor:',
          'cihazlar seti uygular uygulamaz bu sunucudan gelen HER config\'i reddederdi. Sunucu bunu',
          'cihazlara dağıtmadan önce durduruyor (409); önce yeni anahtar imzalayıcı olarak eklenmeli.',
        ].join('\n'),
      });
      expect(out).toContain('HTTP 409');
      expect(out).toContain("only 0 of this server's signers are in the set");
      expect((await lab.signingStatus()).keySet.version).toBe(version - 1);
    });

    await test.step('Sunucu: anahtar değiştirme (rotasyon) başlıyor — yeni anahtar (lab-next) üretilir ve ikinci imzalayıcı olarak kurulur (CONFIG_SIGNERS=local,local:next)', async () => {
      next = await lab.showKey(testInfo, lab.KEYS.next, 'signing-keys.sh: yeni imzalama anahtarı (lab-next)');
      names[next.keyId] = lab.KEYS.next;
      await lab.op(testInfo, 'Operatör: yeni anahtarı ikinci yerel imzalayıcı olarak kur', {
        display: `./scripts/signing-keys.sh install ${lab.KEYS.next} next`,
        file: './scripts/signing-keys.sh',
        args: ['install', lab.KEYS.next, 'next'],
      });
      createdNext = true;
      await lab.setEnv(testInfo, 'env-override.sh: iki imzalayıcı', {
        CONFIG_SIGNERS: 'local,local:next',
        RECOVERY_PUBLIC_KEYS: setup.keys.recovery.pub,
      }, { display: `./scripts/env-override.sh set CONFIG_SIGNERS=local,local:next ${recoveryDisplay()}` });
      const info = await lab.signingKeyInfo();
      await attachText(
        testInfo,
        'GET /api/v1/signing-key → imzalayıcılar',
        info.signers.map((s) => `${s.keyId}  (${names[s.keyId] || '?'})`).join('\n'),
      );
      expect(info.signers.map((s) => s.keyId)).toEqual([setup.primary.keyId, next.keyId]);
    });

    await test.step('Terminal: set vN = {birincil, lab-next}, kurtarma anahtarıyla imzalanıp yüklenir (signing-keys.sh keyset + upload)', async () => {
      N = await lab.nextKeySetVersion();
      const file = lab.labFile(`keyset-v${N}.json`);
      await lab.op(testInfo, `signing-keys.sh keyset: v${N} = sunucunun imzalayıcıları, lab-recovery ile imzalı`, {
        display: `./scripts/signing-keys.sh keyset -v ${N} -k server -s ${lab.KEYS.recovery} -o ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(N), '-k', 'server', '-s', lab.KEYS.recovery, '-o', file.rel],
        note: () => `${file.rel}:\n${lab.describeKeySet(JSON.parse(fs.readFileSync(file.abs, 'utf8')), names)}`,
      });
      const out = await lab.op(testInfo, `signing-keys.sh upload: set v${N}`, {
        display: `./scripts/signing-keys.sh upload ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['upload', file.rel],
      });
      expect(out).toContain('HTTP 200');
      const answer = JSON.parse(out.slice(0, out.lastIndexOf('HTTP')).trim());
      expect(answer.version).toBe(N);
      expect(answer.warnings).toEqual([]);
      expect(new Set(answer.keyIds)).toEqual(new Set([setup.primary.keyId, next.keyId]));
    });

    await test.step(`Mobil: config yenile → set uygulandı; Depolama ekranı: güvenilen iki anahtar, set kurtarma anahtarıyla imzalı`, async () => {
      const status = await app.refreshConfig();
      await app.snap(`set v${N} uygulandı: config'i iki anahtar imzalamış`);
      const sig = SampleApp.signingOf(status);
      await app.openStorage();
      const detail = SampleApp.signingDetailOf(await app.storageText());
      await app.snap(`Depolama: anahtar seti v${N}, iki güvenilen anahtar`);
      await attachText(
        testInfo,
        'Telefon: config yenile + Depolama (PinVault.signingStatus)',
        [
          status.split('\n').filter((l) => /Config|İmza|imzalayan/.test(l)).join('\n'),
          '',
          detail.text,
          '',
          ...detail.trusted.map((id) => `güvenilen ${id} = ${names[id] || '?'}`),
        ].join('\n'),
      );
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(sig.keySetVersion).toBe(N);
      expect(sig.trusted).toBe(2);
      expect(sig.signedBy).toEqual([setup.primary.keyId.slice(0, 12), next.keyId.slice(0, 12)]);
      expect(detail.fromServer).toBe(true);
      expect(new Set(detail.trusted)).toEqual(new Set([setup.primary.keyId, next.keyId]));
      expect(detail.recovery).toEqual([setup.keys.recovery.keyId]);
      await app.backToMain();
    });

    await test.step('Web: iptal — set vN+1 = {yalnızca lab-next} dashboard\'dan yüklenir; yanıtta eski birincil anahtar için uyarı var', async () => {
      const file = lab.labFile(`keyset-v${N + 1}.json`);
      await lab.op(testInfo, `signing-keys.sh keyset: v${N + 1} = yalnızca lab-next (eski birincil listede yok, yani iptal edildi)`, {
        display: `./scripts/signing-keys.sh keyset -v ${N + 1} -k ${lab.KEYS.next} -s ${lab.KEYS.recovery} -o ${file.rel}`,
        file: './scripts/signing-keys.sh',
        args: ['keyset', '-v', String(N + 1), '-k', lab.KEYS.next, '-s', lab.KEYS.recovery, '-o', file.rel],
      });
      const wireText = fs.readFileSync(file.abs, 'utf8').trim();
      await dashboard.reload();
      const upload = await dashboard.uploadKeySet('default-tls', wireText);
      await dashboard.snapRange('#signers-card', '#keyset-card', `İmzalayıcılar + anahtar seti v${N + 1}: birincil sette yok (uyarı)`);
      const rows = await dashboard.signerRows();
      const answer = JSON.parse(upload.body);
      await attachText(
        testInfo,
        `Dashboard → "Seti Yükle": v${N + 1}`,
        [
          lab.describeKeySet(JSON.parse(wireText), names),
          '',
          `HTTP ${upload.status}`,
          JSON.stringify(answer, null, 2),
          '',
          'İmzalayıcılar kartı (✓ sette / ✗ sette değil):',
          ...rows.map((r) => `  ${r.name.padEnd(12)} ${r.keyId.slice(0, 16)}… ${r.inSet ? '✓' : '✗'}`),
        ].join('\n'),
      );
      expect(upload.status).toBe(200);
      expect(answer.version).toBe(N + 1);
      expect(answer.keyIds).toEqual([next.keyId]);
      expect(answer.warnings).toHaveLength(1);
      expect(answer.warnings[0]).toContain(setup.primary.keyId.slice(0, 12));
      expect(rows.map((r) => r.inSet)).toEqual([false, true]);
    });

    await test.step('Mobil: config yenile → set vN+1 uygulandı: telefon yalnızca lab-next\'e güveniyor, config\'i de lab-next imzalamış', async () => {
      const status = await app.refreshConfig();
      await app.snap(`set v${N + 1}: güvenilen tek anahtar lab-next`);
      const sig = SampleApp.signingOf(status);
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(sig.keySetVersion).toBe(N + 1);
      expect(sig.trusted).toBe(1);
      expect(sig.signedBy).toEqual([next.keyId.slice(0, 12)]);
    });

    await test.step('Sunucu: sunucu tekrar yalnızca ESKİ birincil anahtarla imzalamaya başlar (CONFIG_SIGNERS=local)', async () => {
      await lab.setEnv(testInfo, 'env-override.sh: yalnızca eski birincil', {
        CONFIG_SIGNERS: 'local',
        RECOVERY_PUBLIC_KEYS: setup.keys.recovery.pub,
      }, { display: `./scripts/env-override.sh set CONFIG_SIGNERS=local ${recoveryDisplay()}` });
      const status = await lab.signingStatus();
      await attachText(
        testInfo,
        'GET /api/v1/signing/status',
        [
          'imzalayıcılar:',
          lab.describeSigners(status.signers),
          '',
          `anahtar seti: v${status.keySet.version}, listelenen: ${status.keySet.keyIds.map((id) => `${id.slice(0, 16)}… (${names[id] || '?'})`).join(', ')}`,
          `activeSignersMissing (bu seti uygulamış cihazların reddedeceği imzalayıcılar): ${status.keySet.activeSignersMissing.map((id) => `${id.slice(0, 16)}… (${names[id] || '?'})`).join(', ')}`,
        ].join('\n'),
      );
      expect(status.signers.map((s) => s.keyId)).toEqual([setup.primary.keyId]);
      expect(status.keySet.activeSignersMissing).toEqual([setup.primary.keyId]);
    });

    await test.step('Mobil: config yenile → iptal edilen anahtarın imzası reddediliyor; telefon saklı config\'le pinli bağlantı kurmaya devam ediyor', async () => {
      const status = await app.refreshConfig();
      await app.snap('iptal edilen anahtarla imzalı config reddedildi');
      await attachText(testInfo, 'Telefondaki durum kutusu (config yenile)', status);
      expect(status).toContain('Config yenilenemedi');
      expect(status).toContain('Config signature verification failed');
      expect(status).toContain(`Signed by a key revoked by signing-key set v${N + 1}`);
      expect(status).toContain(setup.primary.keyId);
      await app.openMtls();
      const pinned = await app.mockTls();
      await app.snap('saklı config\'le mock-tls.sample\'a pinli bağlantı başarılı');
      await attachText(
        testInfo,
        'Saklı config\'le pinli istek (mock-tls.sample)',
        [
          pinned,
          '',
          'Reddedilen config kaydedilmedi; önceki (doğrulanmış) config ve pin\'leri yerinde.',
          'Set de yerinde: iptal geri alınmadı.',
        ].join('\n'),
      );
      expect(pinned).toContain('host bağlantısı başarılı');
      await app.backToMain();
    });

    await test.step('Web: anahtar seti etkinken "Anahtarı Yenile" düğmesi kapalı; API de 409 döndürüyor', async () => {
      await dashboard.reload();
      await dashboard.openSigning('default-tls');
      const state = await dashboard.regenerateState();
      await dashboard.snapRange('.tab-bar', '#content > .notice-warn', '"Anahtarı Yenile" devre dışı: set etkin');
      const api = await fresh.api('/api/v1/signing-key/regenerate', { method: 'POST' });
      await attachText(
        testInfo,
        'Anahtarı Yenile: düğme ve API',
        [
          `düğme devre dışı: ${state.disabled}`,
          `uyarı: ${state.notice}`,
          '',
          `$ curl -X POST ${fresh.WEB_URL}/api/v1/signing-key/regenerate -H 'X-API-Key: …'`,
          `HTTP ${api.status}`,
          api.text,
          '',
          'Yeni üretilen bir anahtar hiçbir sette olmazdı; seti uygulamış cihazlar onunla imzalanan',
          'her config\'i reddederdi. Anahtar değiştirme (rotasyon) set üzerinden yapılır.',
        ].join('\n'),
      );
      expect(state.disabled).toBe(true);
      expect(api.status).toBe(409);
      expect(api.text).toContain('A signing-key set is active');
      expect((await lab.signingKeyInfo()).keyId).toBe(setup.primary.keyId);
    });

    await test.step('Mobil: uygulama verisi silinmeden yeniden açılır → set vN+1 hâlâ geçerli; şifreli SharedPreferences dosyasında saklanıyor', async () => {
      app.relaunch();
      const ready = await app.waitReady();
      await app.openStorage();
      const storage = await app.storageText();
      const detail = SampleApp.signingDetailOf(storage);
      await app.snap(`yeniden açılış: Depolama hâlâ set v${N + 1}`);
      const prefs = device.appFiles(env.APP_ID, 'shared_prefs');
      await attachText(
        testInfo,
        'Yeniden açılış sonrası: Depolama + shared_prefs',
        [
          `durum: ${ready.split('\n')[0]}`,
          '',
          detail.text,
          '',
          `$ adb shell run-as ${env.APP_ID} ls -la shared_prefs`,
          prefs.trim(),
          '',
          'Set pinvault_signing_keys.xml\'de (EncryptedSharedPreferences) saklanıyor; config deposundan',
          'ayrı tutulduğu için reset/rollback onu silmiyor, yedeklemeye de girmiyor.',
        ].join('\n'),
      );
      expect(detail.keySetVersion).toBe(N + 1);
      expect(detail.trusted).toEqual([next.keyId]);
      expect(prefs).toContain('pinvault_signing_keys.xml');
    });
  } finally {
    await test.step('Sunucu+Terminal: geçici test sunucusunun ortamı sıfırlanır, data/signing-key-next.pem silinir; telefona ana host için derlenen APK geri kurulur', async () => {
      const lines = [`$ ./scripts/env-override.sh reset`, await lab.resetEnv({ force: true })];
      // Önce ortam (local:next artık yok), sonra dosya: tersi sunucuya yeni anahtar ürettirirdi.
      if (createdNext) {
        fs.rmSync(`${fresh.DIR}/data/signing-key-next.pem`, { force: true });
        lines.push('$ rm data/signing-key-next.pem');
      }
      const status = await lab.signingStatus();
      lines.push(
        '',
        `imzalayıcılar: ${status.signers.map((s) => `${s.name} ${s.keyId.slice(0, 16)}…`).join(', ')}`,
        `anahtar seti özelliği: ${status.keySet.enabled ? 'açık' : 'kapalı'} (RECOVERY_PUBLIC_KEYS yok → set dağıtılmıyor)`,
        'Not: sunucudaki set tablosuna yalnızca ekleme yapılır; sonraki senaryolar sürümü status\'tan hesaplar.',
      );
      await attachText(testInfo, 'Geri dönüş: geçici test sunucusu', lines.join('\n'));
      await lab.restoreMain(device, app, testInfo);
      expect(status.signers).toHaveLength(1);
    });
    if (dashboard) await dashboard.page.close();
  }
});
