// U01 — Sürüm yükseltme. Uygulamanın önceki sürümü (örnek uygulamanın main
// dalı, Maven Central'daki PinVault 2.0.9) temiz kurulur, güncel sunucuya
// karşı hazır olur, mTLS için kayıt olur ve bir vault dosyası indirir. Sonra
// güncel APK üstüne kurulur (adb install -r: veri silinmez). Yeni sürüm
// yeniden kayıt ya da indirme istemeden açılmalı: saklı config okunur, eski
// sürümün sakladığı sertifikayla mTLS bağlantısı geçer, eski sürümün
// indirdiği dosya güncel sayılır, eski sürümün planladığı arka plan işi yeni
// sürümün koduyla çalışır.
const { test, expect } = require('../lib/fixtures');
const path = require('path');
const env = require('../lib/env');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const oldRelease = require('../lib/oldRelease');
const { SampleApp } = require('../lib/sampleApp');
const { attachText } = require('../lib/evidence');

const KEY = env.VAULT_KEYS.flags;

/** Kurulu paketin sürüm ve kurulum zamanları (güncelleme mi, yeni kurulum mu). */
function packageInfo(device) {
  return device
    .shell(`dumpsys package ${env.APP_ID}`)
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => /^(versionName|firstInstallTime|lastUpdateTime|pkgFlags)=/.test(l))
    .filter((l, i, all) => all.indexOf(l) === i)
    .join('\n');
}

test('Sürüm yükseltme: önceki sürümle (PinVault 2.0.9) kurulan uygulama güncellenince kaydı, config\'i, vault dosyası ve arka plan işi korunur', async ({
  device,
  run,
  dashboard,
}, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  const clientId = `e2e-upgrade-${Date.now()}`;
  const cn = `CN=PinVault Client: ${clientId}`;
  const content = `{"feature":"upgrade","run":"${Date.now()}"}`;
  const app = new SampleApp(device, testInfo);
  let old;
  let oldConfigVersion;
  let vaultVersion;
  let before;

  await device.ensureOnline();
  device.syncClockToHost();
  await hostControl.ensureUp();
  await hostApi.restoreBaseline(run.baseline);

  try {
    await test.step('Terminal: önceki sürüm derlenir (örnek uygulamanın main dalı, Maven Central\'daki PinVault)', async () => {
      old = oldRelease.buildApk(env.PROPS_FILE);
      await attachText(
        testInfo,
        `Önceki sürüm: SamplePinVaultClient ${old.ref} (${old.commit}) + PinVault ${old.version}`,
        [
          `$ git worktree add --detach .local/upgrade/sample-client-old ${old.commit}`,
          `$ ./gradlew assembleDebug -Ppinvault.localPath= -PsampleHostProps=${env.PROPS_FILE}`,
          old.built ? old.log.trim().split('\n').slice(-3).join('\n') : '(daha önce derlenmişti)',
          '$ ./gradlew -q app:dependencies --configuration debugRuntimeClasspath | grep pinvault',
          old.dependency,
          '',
          `APK: .local/upgrade/${path.basename(old.file)}`,
          `Güncel APK: ${path.relative(env.CLIENT_DIR, env.APK)} (${env.VARIANT} derlemesi, yerel PinVault kaynağı)`,
        ].join('\n'),
      );
      expect(old.dependency).toContain(`io.github.umutcansu:pinvault:${old.version}`);
    });

    await test.step('Mobil: önceki sürüm temiz kurulur ve güncel sunucuya karşı hazır olur', async () => {
      try {
        device.adb(['uninstall', env.APP_ID]);
      } catch {
        /* kurulu değildi */
      }
      const out = device.adb(['install', '-t', old.file]);
      app.launchFresh();
      const status = await app.waitReady();
      oldConfigVersion = Number(status.match(/config v(\d+)/)[1]);
      await attachText(testInfo, 'Önceki sürüm kuruldu', [`$ adb install -t ${path.basename(old.file)}`, out.trim(), '', packageInfo(device)].join('\n'));
      await app.snap(`önceki sürüm (PinVault ${old.version}) hazır: config v${oldConfigVersion}`);
    });

    await test.step('Web + Mobil: önceki sürüm token\'la kayıt olur, mTLS bağlantısı geçer', async () => {
      const token = await dashboard.generateEnrollmentToken(env.MTLS_API, clientId);
      await app.openMtls();
      const status = await app.enroll(token);
      expect(status).toContain(`Kayıt başarılı — ${cn}`);
      await app.expectMtls(true);
      await app.snap('önceki sürüm: kayıtlı, mTLS bağlantısı başarılı');
      await app.backToMain();
    });

    await test.step('Mobil: önceki sürüm yeniden açılır; kayıtlı olduğu için mTLS Config API bloğunu da kurar', async () => {
      device.clearLogcat();
      app.relaunch();
      await app.waitReady();
      const lines = device.logcat({ match: /Loaded stored config|No stored config|Config updated|Init ready/ });
      await attachText(
        testInfo,
        'Önceki sürümün ikinci açılışı (logcat): iki blok',
        [
          lines || '(satır yok)',
          '',
          'İlk blok (sample-host) saklı config\'le açılıyor. mTLS Config API bu kurulumda boş',
          'pin listesi yayınlıyor, bu yüzden ikinci blok için saklanacak config yok. Önceki sürüm',
          'ilk config gelene kadar sistem sertifikalarına güveniyordu ("client using system',
          'defaults"); güncel sürüm o arada bağlantıyı reddediyor.',
        ].join('\n'),
      );
      await app.snap('önceki sürüm yeniden açıldı: TLS ve mTLS blokları');
    });

    await test.step('Web + Mobil: vault dosyası yüklenir, önceki sürüm indirir', async () => {
      vaultVersion = await dashboard.uploadVaultText(env.VAULT_API, KEY, content, { policy: 'public' });
      await app.openVault();
      const status = await app.fetchVault(KEY);
      expect(status).toContain(`${KEY} v${vaultVersion} indirildi`);
      expect(status).toContain(content);
      await app.snap(`önceki sürüm: ${KEY} v${vaultVersion} indirildi`);
      await app.backToMain();
    });

    await test.step('Mobil: önceki sürümün telefonda sakladıkları', async () => {
      await app.openStorage();
      before = await app.storageText();
      await attachText(testInfo, 'Depolama ekranı (önceki sürüm)', before);
      await app.snap('önceki sürümün depolama ekranı');
      await app.backToMain();
    });

    await test.step('Terminal: güncel sürüm üstüne kurulur (adb install -r: uygulama verisi silinmez)', async () => {
      const installedBefore = packageInfo(device);
      device.shell(`am force-stop ${env.APP_ID}`);
      const out = device.adb(['install', '-r', '-t', env.APK]);
      const installedAfter = packageInfo(device);
      await attachText(
        testInfo,
        'Güncelleme: aynı paket, ilk kurulum zamanı aynı, güncelleme zamanı yeni',
        [`$ adb install -r -t ${path.basename(env.APK)}`, out.trim(), '', 'Önce:', installedBefore, '', 'Sonra:', installedAfter].join('\n'),
      );
      expect(out).toContain('Success');
      const first = (s) => (s.match(/firstInstallTime=(.*)/) || [])[1];
      const last = (s) => (s.match(/lastUpdateTime=(.*)/) || [])[1];
      expect(first(installedAfter)).toBe(first(installedBefore));
      expect(last(installedAfter)).not.toBe(last(installedBefore));
    });

    await test.step('Mobil: yeni sürüm açılır; saklı config okunur, yeniden kayıt gerekmez', async () => {
      device.clearLogcat();
      app.relaunch();
      const status = await app.waitReady();
      const newVersion = Number(status.match(/config v(\d+)/)[1]);
      expect(newVersion).toBeGreaterThanOrEqual(oldConfigVersion);
      const lines = device.logcat({ match: /Loaded stored config|No stored config|Init ready|Config updated|Config signature verified/ });
      await attachText(
        testInfo,
        'Yeni sürümün açılış log\'u (logcat)',
        [
          lines || '(satır yok)',
          '',
          'İlk satır TLS bloğunun (sample-host): önceki sürümün sakladığı config okunuyor, sunucudaki',
          'sürümle aynı olduğu için yeniden uygulanmıyor. İkinci blok (mTLS Config API) önceki sürümde',
          'de config saklamamıştı (yayınlanan liste boş).',
        ].join('\n'),
      );
      // Bloklar sırayla kurulur: ilk yükleme satırı TLS bloğunun.
      const loads = lines.split('\n').filter((l) => /Loaded stored config|No stored config/.test(l));
      expect(loads[0]).toContain(`Loaded stored config — version: ${oldConfigVersion}`);
      await app.snap(`yeni sürüm hazır: config v${newVersion}`);
    });

    await test.step('Mobil: önceki sürümün sakladığı sertifikayla mTLS bağlantısı geçer', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain(cn);
      const status = await app.expectMtls(true);
      expect(status).toContain('HTTP 200');
      await app.snap('yeni sürüm: önceki sürümün sertifikasıyla mTLS başarılı');
      await app.backToMain();
    });

    await test.step('Mobil: önceki sürümün indirdiği vault dosyası yeni sürümde okunur ve güncel sayılır', async () => {
      await app.openVault();
      const info = await app.vaultInfo(KEY);
      expect(info).toContain(`v${vaultVersion}`);
      expect(await app.fetchVault(KEY)).toContain(`${KEY} güncel (v${vaultVersion})`);
      await app.snap(`yeni sürüm: ${KEY} güncel (v${vaultVersion}), yeniden indirilmedi`);
      await app.backToMain();
    });

    await test.step('Mobil: arka plan güncelleme işi yeni sürümün koduyla çalışır', async () => {
      // WorkManager periyodik işi zamanı gelmeden çalıştırmaz (zorlansa bile
      // erteler): senaryo 11 gibi saat bir periyot ileri alınır, sonra geri.
      device.clearLogcat();
      let ids = [];
      let lines = '';
      device.shiftClock(16 * 60);
      try {
        ids = device.runScheduledJobs(env.APP_ID);
        expect(ids.length).toBeGreaterThan(0);
        for (let i = 0; i < 30 && !/CertificateUpdateWorker started/.test(lines); i++) {
          await new Promise((r) => setTimeout(r, 1000));
          lines = device.logcat({ match: /CertificateUpdateWorker|Could not create Worker|Fetching config update|Config unchanged|already current/ });
        }
      } finally {
        device.shiftClock(-16 * 60);
      }
      await attachText(testInfo, `Saat 16 dk ileri alındı, JobScheduler işleri zorla çalıştırıldı (${ids.join(', ')}) — logcat`, lines || '(satır yok)');
      expect(lines).toContain('CertificateUpdateWorker started');
      expect(lines).not.toContain('Could not create Worker');
    });
  } finally {
    await hostApi.revokeClientCertIfActive(clientId);
    try {
      await hostApi.deleteVaultFile(env.VAULT_API, KEY);
    } catch {
      /* yüklenmemişti */
    }
    // Sonraki senaryolar güncel APK'nın temiz kurulumuyla başlasın.
    device.adb(['install', '-r', '-t', env.APK]);
    app.launchFresh();
    await app.waitReady();
    await hostApi.restoreBaseline(run.baseline);
  }
});
