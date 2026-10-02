// A27 — WorkManager iş yönetimi.
//
// Örnek uygulama init tamamlanınca periyodik güncelleme işini planlıyor
// (schedulePeriodicUpdates, 15 dk). Ayarlar ekranındaki üç düğme kütüphanenin
// üç çağrısını kullanıyor:
//   • "Planlı iş"   → PinVault.getScheduledWorkInfo: iş kimliği, durumu, deneme sayısı
//   • "İşi iptal et" → PinVault.cancelPeriodicUpdates: iş JobScheduler'dan düşer
//   • "İşi planla"  → PinVault.schedulePeriodicUpdates: iş geri gelir
// Kanıt iki kaynaktan: telefonun sonuç kutusu ve `dumpsys jobscheduler`
// (WorkManager işleri sistemin JobScheduler'ında SystemJobService kaydı olarak
// görünür; iptalde kayıt silinir).
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const env = require('../lib/env');

test('Mobil: planlı WorkManager işi listeleniyor, iptal edilince JobScheduler\'dan siliniyor, yeniden planlanınca geri geliyor', async ({
  app,
  device,
}, testInfo) => {
  test.setTimeout(6 * 60 * 1000);
  const readJobs = () => device.jobSchedulerJobs(env.APP_ID);
  const jobsPanel = (jobs) => [`$ dumpsys jobscheduler | grep ${env.APP_ID}`, ...(jobs.length ? jobs.map((j) => `  ${j}`) : ['  (kayıt yok)'])];

  await test.step('Mobil: Ayarlar → "Planlı iş" — periyodik güncelleme işi listede', async () => {
    await app.openSettings();
    const result = await app.workInfo();
    await app.snapResult('planlı iş listesi: periyodik güncelleme ENQUEUED');
    const jobs = readJobs();
    await attachText(
      testInfo,
      'PinVault.getScheduledWorkInfo + dumpsys jobscheduler',
      [
        result,
        '',
        ...jobsPanel(jobs),
        '',
        'İş, örnek uygulamanın init callback\'inde schedulePeriodicUpdates(15 dk, REPLACE)',
        'ile planlanıyor; kütüphane WorkManager\'da "ssl_cert" etiketiyle tutuyor.',
      ].join('\n'),
    );
    expect(result).toContain('Planlı işler');
    expect(result).toMatch(/ENQUEUED|RUNNING/);
    expect(jobs.length, 'JobScheduler kaydı').toBeGreaterThan(0);
  });

  await test.step('Mobil: "İşi iptal et" → planlı iş yok, JobScheduler kaydı siliniyor', async () => {
    const result = await app.cancelWork();
    await app.snapResult('iş iptal edildi: etkin planlı iş yok');
    await expect.poll(() => readJobs().length, { timeout: 20_000, intervals: [1000, 2000] }).toBe(0);
    const jobs = readJobs();
    await attachText(
      testInfo,
      'PinVault.cancelPeriodicUpdates + dumpsys jobscheduler',
      [
        result,
        '',
        ...jobsPanel(jobs),
        '',
        'cancelUniqueWork: WorkManager işi iptal ediyor ve sistemin JobScheduler',
        'kaydını siliyor. getScheduledWorkInfo etiketli bütün işleri (iptal edilenler',
        'CANCELLED durumuyla) listeler; etkin (ENQUEUED/RUNNING) iş kalmadı.',
      ].join('\n'),
    );
    expect(result).toContain('iptal edildi');
    expect(result).toMatch(/planlı iş yok|CANCELLED/);
    expect(result).not.toMatch(/ENQUEUED|RUNNING/);
    expect(jobs).toHaveLength(0);
  });

  await test.step('Mobil: "İşi planla" → iş geri geliyor', async () => {
    const result = await app.scheduleWork();
    await app.snapResult('iş yeniden planlandı: listede ve JobScheduler\'da');
    await expect.poll(() => readJobs().length, { timeout: 20_000, intervals: [1000, 2000] }).toBeGreaterThan(0);
    const jobs = readJobs();
    await attachText(
      testInfo,
      'PinVault.schedulePeriodicUpdates + dumpsys jobscheduler',
      [result, '', ...jobsPanel(jobs), '', 'Yeni periyodik iş (15 dk) kuyruğa alındı; JobScheduler kaydı geri geldi.'].join('\n'),
    );
    expect(result).toContain('planlandı');
    expect(result).toContain('Planlı işler');
    expect(result).toMatch(/ENQUEUED|RUNNING/);
    expect(jobs.length).toBeGreaterThan(0);
    await app.backToMain();
  });
});
