// F03: telemetri ucu erişilemezken uygulama akıcı kalmalı. Bağlantı olayları
// TLS el sıkışma thread'inde değil, tek başına bir dispatcher thread'inde
// (PinVault-Listener) işleniyor ve kuyruk sınırlı; taşan iş sessizce atılıyor.
// Böylece yanıt vermeyen bir telemetri backend'i istekleri geciktiremiyor.
//
// Emülatörde yönetim portuna (telemetri) giden TCP iptables ile DROP edilir:
// paketler sessizce düşer, yani her rapor 5 saniyelik bağlantı zaman aşımına
// takılır. Pinli istekler bu sırada da normal hızında tamamlanmalı.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/android');
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

test('Mobil+Sunucu: telemetri ucu kapalıyken pinli istekler akıcı kalıyor, uygulama donmuyor', async ({
  app,
  device,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables kuralı yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  let baseline;
  let blocked;

  try {
    await test.step('Mobil+Sunucu: telemetri açıkken üç istek — süre ve sunucu kayıtları', async () => {
      const marker = Date.now();
      await sleep(2000);
      baseline = await timedRequests(app);
      await app.snap('telemetri açık: üç başarılı istek');
      await expect
        .poll(async () => (await reportsSince(run.model, marker)).length, { timeout: 30_000 })
        .toBeGreaterThan(0);
      const reports = await reportsSince(run.model, marker);
      await attachText(
        testInfo,
        'Telemetri açıkken',
        [
          `İstek süreleri (ms): ${baseline.join(', ')}  → ortanca ${median(baseline)}`,
          `Sunucuya düşen kayıt: ${reports.length} (${reports.map((e) => e.status).join(', ')})`,
        ].join('\n'),
      );
    });

    await test.step(`Terminal: yönetim portu (${env.HTTP_PORT}) DROP ile kesilir`, async () => {
      device.blockTcp(env.LAN_IP, env.HTTP_PORT, 'drop');
      const rules = device.rootShell('iptables -S OUTPUT');
      await attachText(
        testInfo,
        `iptables: ${env.LAN_IP}:${env.HTTP_PORT} DROP`,
        [
          '$ iptables -A OUTPUT -p tcp -d ' + env.LAN_IP + ' --dport ' + env.HTTP_PORT + ' -j DROP',
          '',
          rules.trim(),
          '',
          'DROP: paketler sessizce düşer, yani telemetri POST\'u RST almaz ve',
          `istemcinin 5 saniyelik bağlantı zaman aşımını bekler. Config API portu`,
          `(${env.CONFIG_API_PORT}) ve hedef host açık kalır.`,
        ].join('\n'),
      );
      expect(rules).toContain(`--dport ${env.HTTP_PORT}`);
    });

    await test.step('Mobil: telemetri ucu yanıt vermezken istekler yine hızlı tamamlanıyor', async () => {
      const marker = Date.now();
      blocked = await timedRequests(app);
      await app.snap('telemetri kesik: istekler yine başarılı');
      const eventLog = app.eventLog();
      // Telemetri POST'ları 5 sn'lik zaman aşımına takılırken uygulama içi
      // olay listesi dolmaya devam ediyor.
      const reports = await reportsSince(run.model, marker);
      await attachText(
        testInfo,
        'Telemetri ucu kapalıyken',
        [
          `İstek süreleri (ms): ${blocked.join(', ')}  → ortanca ${median(blocked)}`,
          `Telemetri açıkken  : ${baseline.join(', ')}  → ortanca ${median(baseline)}`,
          `Fark (ortanca)     : ${median(blocked) - median(baseline)} ms`,
          '',
          `Sunucuya düşen yeni kayıt: ${reports.length} (beklenen 0 — port kesik)`,
          '',
          'Telefonun olay listesi (uygulama içi listener çalışmaya devam ediyor):',
          eventLog.split('\n').slice(0, 5).join('\n'),
          '',
          'DynamicSSLManager: listener\'lar tek bir daemon thread\'de (PinVault-Listener)',
          'çalışır, kuyruk sınırlıdır (LISTENER_QUEUE_CAPACITY) ve taşan iş',
          'DiscardPolicy ile atılır. Bu yüzden 5 saniyelik telemetri zaman aşımları',
          'TLS el sıkışma yoluna hiç yansımıyor.',
        ].join('\n'),
      );
      expect(eventLog).toContain(`[✓] ${TARGET_HOST}`);
      expect(reports.length, 'port kesikken sunucuya kayıt düşmemeli').toBe(0);
      // Telemetri istek yoluna karışsaydı her istek en az 5 sn uzardı.
      expect(median(blocked) - median(baseline)).toBeLessThan(4000);
    });

    await test.step('Mobil: config yenileme de akıcı (kesinti telemetriye özel)', async () => {
      const startedAt = Date.now();
      const status = await app.refreshConfig();
      const elapsed = Date.now() - startedAt;
      await app.snap('telemetri kesik: config yenileme çalışıyor');
      await attachText(
        testInfo,
        'Telemetri kesikken config yenileme',
        [`Süre: ${elapsed} ms`, '', status.split('\n').slice(0, 2).join('\n')].join('\n'),
      );
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
    });

    await test.step('Terminal: kural kaldırılır → telemetri yeniden akıyor', async () => {
      device.clearNetRules();
      const marker = Date.now();
      await sleep(1000);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
      await expect
        .poll(async () => (await reportsSince(run.model, marker)).length, { timeout: 40_000 })
        .toBeGreaterThan(0);
      const reports = await reportsSince(run.model, marker);
      await app.snap('kural kaldırıldı: telemetri yeniden akıyor');
      await attachText(
        testInfo,
        'Kural kaldırıldıktan sonra',
        [
          `$ iptables -D OUTPUT -p tcp -d ${env.LAN_IP} --dport ${env.HTTP_PORT} -j DROP`,
          '',
          `Sunucuya düşen yeni kayıt: ${reports.length} (${reports.map((e) => e.status).join(', ')})`,
        ].join('\n'),
      );
      expect(reports.length).toBeGreaterThan(0);
    });
  } finally {
    device.clearNetRules();
  }
});
