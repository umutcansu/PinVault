// I05 — iOS: periyodik güncelleme (BGTaskScheduler yerine uygulama içi zamanlayıcı).
//
// Örnek uygulama init tamamlanınca schedulePeriodicUpdates çağırıyor. Cihazda
// iş bir BGAppRefreshTaskRequest olur; simülatörde BGTaskScheduler.submit hata
// verir ve kütüphane aynı işi süreç içinde bir zamanlayıcıyla çalıştırır.
// İşin durumları (ENQUEUED / RUNNING / CANCELLED) PinVault.scheduledTasks()'tan,
// harness'a report.json ile ulaşır (pinvault-e2e/report.json, PinVaultE2E).
// "Şimdi çalıştır" (Android: cmd jobscheduler run -f) Darwin bildirimidir:
// com.example.sampleclient.e2e.runScheduledWork.
//
// Kanıt: report.json'daki durumlar; iptal ve yeniden planlama; panelde pin
// değişince bildirimle çalışan iş yeni config'i hiçbir düğmeye basılmadan getiriyor.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/device');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test.skip(({ device }) => device.platform !== 'ios', 'Yalnızca iOS: uygulama içi zamanlayıcı ve report.json (Android karşılığı 11 ve A27: WorkManager)');

test('iOS: periyodik iş report.json\'da ENQUEUED / CANCELLED / RUNNING; bildirimle çalışan iş yeni config\'i düğmeye basmadan getiriyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);
  const tasks = () => (device.report(env.APP_ID) || {}).scheduledTasks || [];
  const panel = (title, extra = []) => attachText(testInfo, title, [
    `$ ${device.jobsSourceLabel(env.APP_ID)}`,
    JSON.stringify(device.report(env.APP_ID), null, 2),
    ...(extra.length ? ['', ...extra] : []),
  ].join('\n'));
  let firstId;
  let secondId;
  let v0;

  try {
    await test.step('Mobil: açılışta iş planlı — report.json ENQUEUED; BGTaskScheduler simülatörde reddediyor', async () => {
      await expect.poll(() => tasks().filter((t) => t.state === 'ENQUEUED').length, { timeout: 30_000 }).toBe(1);
      firstId = tasks().find((t) => t.state === 'ENQUEUED').id;
      const log = device.logcat({ match: /BGTaskScheduler|Periodic certificate updates/ });
      await panel('report.json — açılış', [
        'log show (SSLCertificateUpdater):',
        log || '(satır yok)',
      ]);
      expect(log).toMatch(/BGTaskScheduler refused the request .* in-process scheduler/);
      await app.openSettings();
      const info = await app.workInfo();
      await app.snapResult('Ayarlar → Planlı iş: ENQUEUED');
      expect(info).toContain(firstId);
      expect(info).toMatch(/ENQUEUED|RUNNING/);
    });

    await test.step('Mobil: "İşi iptal et" → report.json CANCELLED, etkin iş yok', async () => {
      const result = await app.cancelWork();
      await app.snapResult('iş iptal edildi');
      await expect.poll(() => tasks().find((t) => t.id === firstId)?.state, { timeout: 20_000 }).toBe('CANCELLED');
      await panel('report.json — iptal sonrası', ['Ayarlar ekranının sonucu:', result]);
      expect(device.jobSchedulerJobs(env.APP_ID)).toHaveLength(0);
      expect(result).toContain('iptal edildi');
    });

    await test.step('Mobil: "İşi planla" → yeni iş ENQUEUED, eskisi CANCELLED olarak listede', async () => {
      const result = await app.scheduleWork();
      await app.snapResult('iş yeniden planlandı');
      await expect.poll(() => tasks().filter((t) => t.state === 'ENQUEUED').length, { timeout: 20_000 }).toBe(1);
      secondId = tasks().find((t) => t.state === 'ENQUEUED').id;
      await panel('report.json — yeniden planlandı', ['Ayarlar ekranının sonucu:', result]);
      expect(secondId).not.toBe(firstId);
      expect(tasks().find((t) => t.id === firstId)?.state).toBe('CANCELLED');
      expect(result).toContain('planlandı');
      await app.backToMain();
    });

    await test.step('Web: hedef host\'a yedek pin eklenir (sürüm +1)', async () => {
      await dashboard.openHost(TARGET_HOST);
      v0 = await dashboard.version();
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, hostApi.randomPin()]);
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      await dashboard.snapHostSummary(`yedek pin eklendi, v${v0 + 1}`);
    });

    await test.step('Mobil: Config API yanıt vermezken "şimdi çalıştır" → iş report.json\'da RUNNING', async () => {
      // Bir çalışma birkaç on milisaniye sürer; Config API'ye giden bağlantı yanıt
      // vermeyen yerel sunucuya yönlendirilince iş istek beklerken RUNNING'de kalır.
      device.blockTcp(env.LAN_IP, env.CONFIG_API_PORT, 'drop');
      await sleep(1000);
      const ids = device.runScheduledJobs(env.APP_ID);
      expect(ids).toContain(secondId);
      await expect.poll(() => tasks().find((t) => t.id === secondId)?.state, { timeout: 20_000, intervals: [100] }).toBe('RUNNING');
      await panel('report.json — iş çalışırken (Config API yanıt vermiyor)', [
        `$ xcrun simctl spawn ${device.udid} notifyutil -p ${env.APP_ID}.e2e.runScheduledWork`,
        '',
        device.describeNetRules('filter'),
      ]);
      await app.snap('iş çalışıyor — Config API yanıt vermiyor');
      device.clearNetRules();
      // Bağlantı kesilince çalışma "yeniden dene" ile biter: ENQUEUED, deneme sayısı artar.
      await expect.poll(() => tasks().find((t) => t.id === secondId)?.state, { timeout: 60_000, intervals: [500] }).toBe('ENQUEUED');
      await panel('report.json — çalışma bitti (yeniden denenecek)');
    });

    await test.step('Mobil: "şimdi çalıştır" bildirimi → yeni config düğmeye basmadan geliyor', async () => {
      const ids = device.runScheduledJobs(env.APP_ID);
      expect(ids).toContain(secondId);
      const events = await app.waitForEvent(`[config] UPDATED v${v0 + 1}`, 60_000);
      await app.snap('arka plan işi yeni config\'i uyguladı — düğmeye basılmadı');
      await expect.poll(() => tasks().find((t) => t.id === secondId)?.state, { timeout: 20_000 }).toBe('ENQUEUED');
      await panel('report.json — iş çalıştıktan sonra', [
        `$ xcrun simctl spawn ${device.udid} notifyutil -p ${env.APP_ID}.e2e.runScheduledWork`,
        '',
        'Olay listesi (ana ekran):',
        events.split('\n').filter((l) => l.includes('[config]')).slice(0, 5).join('\n'),
      ]);
      expect(tasks().find((t) => t.id === secondId)?.runAttemptCount).toBe(0);
    });

    await test.step('Mobil: istek yeni sürümle yapılıyor', async () => {
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await app.waitForEvent(`[✓] ${TARGET_HOST}  pin v${v0 + 1}`);
      await app.snap(`istek pin v${v0 + 1} ile başarılı`);
    });
  } finally {
    try {
      device.clearNetRules();
    } catch {
      /* kural yok */
    }
    if (v0 !== undefined) await dashboard.setPins(TARGET_HOST, run.goodPins).catch(() => {});
  }
});
