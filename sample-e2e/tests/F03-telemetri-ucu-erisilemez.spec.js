// F03: cihaz raporlarının (telemetri) gönderildiği adrese ulaşılamazken
// uygulama akıcı kalmalı. Bağlantı olayları TLS el sıkışma thread'inde değil,
// tek başına bir dispatcher thread'inde (PinVault-Listener) işleniyor ve kuyruk
// sınırlı; taşan iş sessizce atılıyor. Böylece yanıt vermeyen bir rapor
// sunucusu istekleri geciktiremiyor.
//
// Raporlar Config API portuna gider (config'le aynı dinleyici, aynı pin'ler;
// telefon yönetim portuna bağlanmaz). Emülatörde o porta giden TCP iptables ile
// DROP edilir: paketler sessizce düşer, yani her rapor 5 saniyelik bağlantı
// zaman aşımına takılır. Pinli istekler bu sırada da normal hızında
// tamamlanmalı. Aynı port config'i de sunduğu için bu sürede config yenileme
// başarısız olur; uygulama saklı config'le çalışmaya devam eder.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/device');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const SAMPLES = 3;

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

/** [SAMPLES] kez pinli istek yapar; her birinin süresini (ms) döndürür. */
async function timedRequests(app) {
  const durations = [];
  for (let i = 0; i < SAMPLES; i++) {
    const startedAt = Date.now();
    const result = await app.testLibraryClient();
    durations.push(Date.now() - startedAt);
    expect(result).toContain('Pinned bağlantı başarılı');
  }
  return durations;
}

/** Bu cihazın hedefe ait, [since]'ten yeni telemetri kayıtları. */
async function reportsSince(model, since) {
  const rows = await hostApi.connectionHistory(TARGET_HOST);
  return rows.filter((e) => e.deviceModel === model && Date.parse(e.timestamp) >= since);
}

test('Mobil+Sunucu: cihaz raporları (telemetri) gönderilemezken pinli istekler yavaşlamıyor, uygulama donmuyor', async ({
  app,
  device,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables kuralı yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  let baseline;
  let blocked;

  try {
    await test.step('Mobil+Sunucu: raporlar giderken üç istek — süreler ve sunucudaki kayıtlar', async () => {
      const marker = Date.now();
      await sleep(2000);
      baseline = await timedRequests(app);
      await app.snap('raporlar gidiyor: üç başarılı istek');
      await expect
        .poll(async () => (await reportsSince(run.model, marker)).length, { timeout: 30_000 })
        .toBeGreaterThan(0);
      const reports = await reportsSince(run.model, marker);
      await attachText(
        testInfo,
        'Raporlar giderken',
        [
          `İstek süreleri (ms): ${baseline.join(', ')}  → ortanca ${median(baseline)}`,
          `Sunucuya gelen kayıt: ${reports.length} (${reports.map((e) => e.status).join(', ')})`,
        ].join('\n'),
      );
    });

    await test.step(`Terminal: raporların gittiği port (Config API, ${env.REPORT_PORT}) kapatılır (iptables DROP: paketler sessizce atılır)`, async () => {
      device.blockTcp(env.LAN_IP, env.REPORT_PORT, 'drop');
      const rules = device.describeNetRules('filter');
      await attachText(
        testInfo,
        `iptables: ${env.LAN_IP}:${env.REPORT_PORT} DROP`,
        [
          '$ iptables -A OUTPUT -p tcp -d ' + env.LAN_IP + ' --dport ' + env.REPORT_PORT + ' -j DROP',
          '',
          rules.trim(),
          '',
          'DROP: paketler sessizce atılır; rapor isteği (POST) "bağlantı reddedildi"',
          `yanıtını (RST) bile almaz ve 5 saniyelik bağlantı zaman aşımını bekler.`,
          'Raporlar config ile aynı porttan gittiği için config yenileme de bu sürede',
          'sunucuya ulaşamaz; hedef host açık kalır.',
        ].join('\n'),
      );
      expect(rules).toContain(`--dport ${env.REPORT_PORT}`);
    });

    await test.step('Mobil: rapor adresi yanıt vermezken istekler yine hızlı tamamlanıyor', async () => {
      const marker = Date.now();
      blocked = await timedRequests(app);
      await app.snap('raporlar gidemiyor: istekler yine başarılı');
      const eventLog = app.eventLog();
      // Telemetri POST'ları 5 sn'lik zaman aşımına takılırken uygulama içi
      // olay listesi dolmaya devam ediyor.
      const reports = await reportsSince(run.model, marker);
      await attachText(
        testInfo,
        'Rapor adresi kapalıyken',
        [
          `İstek süreleri (ms): ${blocked.join(', ')}  → ortanca ${median(blocked)}`,
          `Raporlar giderken  : ${baseline.join(', ')}  → ortanca ${median(baseline)}`,
          `Fark (ortanca)     : ${median(blocked) - median(baseline)} ms`,
          '',
          `Sunucuya gelen yeni kayıt: ${reports.length} (beklenen 0 — port kapalı)`,
          '',
          'Telefonun olay listesi (uygulama içi listener çalışmaya devam ediyor):',
          eventLog.split('\n').slice(0, 5).join('\n'),
          '',
          'DynamicSSLManager: listener\'lar tek bir daemon thread\'de (PinVault-Listener)',
          'çalışır, kuyruk sınırlıdır (LISTENER_QUEUE_CAPACITY) ve taşan iş',
          'DiscardPolicy ile atılır. Bu yüzden rapor gönderimindeki 5 saniyelik zaman',
          'aşımları TLS bağlantısını hiç geciktirmiyor.',
        ].join('\n'),
      );
      expect(eventLog).toContain(`[✓] ${TARGET_HOST}`);
      expect(reports.length, 'port kesikken sunucuya kayıt düşmemeli').toBe(0);
      // Telemetri istek yoluna karışsaydı her istek en az 5 sn uzardı.
      expect(median(blocked) - median(baseline)).toBeLessThan(4000);
    });

    await test.step('Mobil: aynı port config\'i de sunuyor — yenileme başarısız, uygulama saklı config\'le çalışmaya devam ediyor', async () => {
      const startedAt = Date.now();
      const status = await app.refreshConfig();
      const elapsed = Date.now() - startedAt;
      await app.snap('Config API portu kapalı: config yenilenemedi');
      // Yenileme başarısız oldu ama saklı config yerinde: pinli istek yine geçer.
      const after = await app.testLibraryClient();
      await app.snap('Config API portu kapalı: pinli istek saklı config ile geçiyor');
      await attachText(
        testInfo,
        'Config API portu kapalıyken config yenileme ve ardından pinli istek',
        [
          `Yenileme süresi: ${elapsed} ms`,
          '',
          status.split('\n').slice(0, 2).join('\n'),
          '',
          'Ardından pinli istek:',
          after.split('\n').slice(0, 2).join('\n'),
        ].join('\n'),
      );
      expect(status).toMatch(/Config yenilenemedi|zaman aşımına uğradı/);
      expect(after).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Terminal: kural kaldırılır → raporlar yeniden sunucuya gidiyor', async () => {
      device.clearNetRules();
      const marker = Date.now();
      await sleep(1000);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await expect
        .poll(async () => (await reportsSince(run.model, marker)).length, { timeout: 40_000 })
        .toBeGreaterThan(0);
      const reports = await reportsSince(run.model, marker);
      await app.snap('kural kaldırıldı: raporlar yeniden gidiyor');
      await attachText(
        testInfo,
        'Kural kaldırıldıktan sonra',
        [
          `$ iptables -D OUTPUT -p tcp -d ${env.LAN_IP} --dport ${env.REPORT_PORT} -j DROP`,
          '',
          `Sunucuya gelen yeni kayıt: ${reports.length} (${reports.map((e) => e.status).join(', ')})`,
        ].join('\n'),
      );
      expect(reports.length).toBeGreaterThan(0);
    });
  } finally {
    device.clearNetRules();
  }
});
