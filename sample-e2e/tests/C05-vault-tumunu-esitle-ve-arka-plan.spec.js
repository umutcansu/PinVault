// C05 — "Tümünü eşitle" ve arka plan eşitlemesi (updateWithPins).
//
// `sample-model` tek `updateWithPins(true)` dosyası: hem PinVault.syncAllFiles()
// hem de WorkManager'ın periyodik görevi onu çekiyor. `sample-flags` bayrağı
// kapalı olduğu için eşitlemeye hiç girmiyor.
//
// Arka plan adımı hiçbir düğmeye basmadan kanıtlanıyor: emülatörün saati bir
// periyot ileri alınıp planlı iş zorlanıyor, sonuç sunucunun dağıtım
// geçmişinden ve cihaz günlüğünden okunuyor (senaryo 11'deki desen).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const MODEL = env.VAULT_KEYS.model;
const FLAGS = env.VAULT_KEYS.flags;
const PERIOD_PLUS_MARGIN_S = 16 * 60;

test('Vault eşitleme: "Tümünü eşitle" ve arka plan görevi updateWithPins(true) dosyasını indiriyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'Arka plan adımı için saat yalnızca emülatörde ileri alınabilir');
  test.setTimeout(8 * 60 * 1000);
  const stamp = Date.now();
  let v1;
  let deviceId;

  try {
    await test.step('Web: eşitlenecek ve eşitlenmeyecek iki dosya yüklenir', async () => {
      v1 = await dashboard.uploadVaultText(env.VAULT_API, MODEL, `model-v1-${stamp}`, { policy: 'public' });
      await dashboard.uploadVaultText(env.VAULT_API, FLAGS, `flags-v1-${stamp}`, { policy: 'public' });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'iki vault dosyası');
      await attachText(
        testInfo,
        'Uygulamadaki tanımlar (App.java)',
        [
          `${MODEL}: storage(ENCRYPTED_FILE) + updateWithPins(true) → eşitlemeye girer`,
          `${FLAGS}: varsayılan depo, updateWithPins yok → yalnızca elle indirilir`,
        ].join('\n'),
      );
    });

    await test.step('Mobil: "Tümünü eşitle" yalnızca updateWithPins(true) dosyasını indiriyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.syncAll();
      await app.snap('tümünü eşitle — ilk sürüm');
      expect(status).toContain('Eşitleme tamamlandı');
      expect(status).toContain(`${MODEL} → v${v1} indirildi`);
      expect(status).not.toContain(FLAGS);
      await attachText(testInfo, 'Tümünü eşitle sonucu', status);
    });

    await test.step('Web: model dosyası güncellenir', async () => {
      expect(await dashboard.uploadVaultText(env.VAULT_API, MODEL, `model-v2-${stamp}`, { policy: 'public' }))
        .toBe(v1 + 1);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${MODEL} v${v1 + 1} yüklendi`);
    });

    await test.step('Mobil: "Tümünü eşitle" yeni sürümü indiriyor', async () => {
      const status = await app.syncAll();
      await app.snap(`tümünü eşitle — v${v1 + 1}`);
      expect(status).toContain(`${MODEL} → v${v1 + 1} indirildi`);
      const again = await app.syncAll();
      expect(again).toContain(`${MODEL} → güncel (v${v1 + 1})`);
      await attachText(
        testInfo,
        'İkinci eşitleme (değişiklik yok)',
        [again, '', 'Sürüm aynıysa sunucu 304 ("değişmedi") dönüyor, kütüphane AlreadyCurrent (zaten güncel) sonucunu veriyor.'].join('\n'),
      );
    });

    await test.step('Web: dosya bir kez daha güncellenir (telefona dokunulmayacak)', async () => {
      expect(await dashboard.uploadVaultText(env.VAULT_API, MODEL, `model-v3-${stamp}`, { policy: 'public' }))
        .toBe(v1 + 2);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', `${MODEL} v${v1 + 2} yüklendi`);
    });

    await test.step('Mobil: arka plan görevi dosyayı düğmeye basmadan indiriyor', async () => {
      device.clearLogcat();
      device.shiftClock(PERIOD_PLUS_MARGIN_S);
      try {
        const jobs = device.runScheduledJobs(env.APP_ID);
        expect(jobs.length, 'WorkManager görevi planlı').toBeGreaterThan(0);
        // Kanıt sunucudan: yeni sürüm için bir indirme kaydı düşmeli.
        await expect
          .poll(
            async () => {
              const dists = await hostApi.vaultDistributions(env.VAULT_API, MODEL);
              return dists.some((d) => d.deviceId === deviceId && d.version === v1 + 2 && d.status === 'downloaded');
            },
            { timeout: 90_000, intervals: [2000, 3000] },
          )
          .toBe(true);
        const log = device.logcat({ match: /CertificateUpdateWorker|Vault file (updated|saved)/ });
        await attachText(
          testInfo,
          'logcat — periyodik görev ve vault eşitlemesi',
          [
            `hemen çalıştırılan JobScheduler işleri: ${jobs.join(', ')}`,
            '',
            log || '(ilgili satır yok)',
            '',
            'CertificateUpdateWorker.doWork: önce updateNow(), sonra syncAllFiles().',
            'Vault eşitlemesi config güncellemesinden bağımsız çalışıyor — config',
            'değişmese bile dosya sürümü artmışsa iniyor.',
          ].join('\n'),
        );
        expect(log).toContain('CertificateUpdateWorker');
      } finally {
        device.shiftClock(-PERIOD_PLUS_MARGIN_S);
      }
    });

    await test.step('Web: dağıtım geçmişinde arka plan indirmesi görünüyor', async () => {
      await dashboard.expectDistribution(env.VAULT_API, {
        key: MODEL,
        deviceModel: run.model,
        status: 'downloaded',
        version: v1 + 2,
      });
      await dashboard.snap(`dağıtım geçmişi — arka planda v${v1 + 2}`);
    });

    await test.step('Mobil: "Bilgi" sunucuya gitmeden saklı içeriği gösteriyor, yeni sürüm gelmiş', async () => {
      const info = await app.vaultInfo(MODEL);
      await app.snap(`arka plan sonrası saklı içerik v${v1 + 2}`);
      expect(info).toContain(`sürüm: v${v1 + 2}`);
      expect(info).toContain(`model-v3-${stamp}`);
      expect(info).toContain('sunucuya gidilmedi');
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, MODEL).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, FLAGS).catch(() => {});
  }
});
