// G01 — Gerçek araya girme: telefonun konuştuğu sunucu başkası.
//
// Saldırgan proxy KENDİ ürettiği anahtarla (identity: 'rogue') dinler ve
// telefonun Config API trafiği emülatördeki iptables DNAT ile ona yönlendirilir.
// Sertifika geçerli bir X.509'dur, SAN'ında host'un IP'si vardır, tek eksiği
// pin'lerin tutmamasıdır. Pinleme çalışıyorsa:
//
//   • TLS el sıkışması yarıda kesilir — saldırgana tek bir HTTP isteği bile
//     ulaşmaz (proxy'nin istek sayacı 0'da kalır, karşılığında fatal alert
//     gelir),
//   • saklı config'i olan uygulama config'i yenileyemez ama eski pin'lerle
//     çalışmaya devam eder (fail-safe),
//   • saklı config'i olmayan uygulama hiç başlayamaz (şüphede bağlantıya izin
//     vermez),
//   • uyuşmazlık telefonun kendi olay listesine düşer. Cihaz raporları
//     (telemetri) da Config API portundan gittiği için saldırı sürerken
//     sunucuya ULAŞAMAZ: araya giren, o yoldaki her şeyi düşürebilir. Raporlar
//     da pinli olduğundan saldırgan onları okuyamaz ve sahtesini üretemez.
//     (Hedef host'lardaki uyuşmazlığın dashboard'a düşmesi: senaryo 03.)
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { sleep } = require('../lib/android');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

test('Saldırı: araya sahte sertifikalı bir sunucu girer → telefon ona hiç istek göndermiyor, uyuşmazlığı kaydediyor; saldırgan raporları da göremiyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  const startedAt = Date.now() - 5000;
  let mitm;

  try {
    await test.step('Saldırgan: kendi anahtarıyla dinlemeye başlar (sunduğu pin ≠ telefonun beklediği pin)', async () => {
      mitm = await proxy.start({ identity: 'rogue' });
      const rogue = proxy.certSummary('rogue');
      const expected = hostApi.hostPins();
      await attachText(
        testInfo,
        `Saldırganın sunduğu sertifika ve telefonun beklediği pin'ler (${env.LAN_IP}:${env.CONFIG_API_PORT})`,
        [
          'SALDIRGANIN SUNDUĞU SERTİFİKA',
          `  konu      : ${rogue.subject}`,
          `  veren     : ${rogue.issuer}`,
          `  geçerlilik: ${rogue.validFrom} → ${rogue.validTo}`,
          `  SPKI pin  : ${rogue.pin}`,
          '',
          "TELEFONUN BEKLEDİĞİ: uygulamaya gömülü ilk pin'ler (bootstrap), host'un demo-server.pins dosyasından",
          ...expected.map((p, i) => `  pin ${i + 1}     : ${p}`),
          '',
          `eşleşme: ${expected.includes(rogue.pin) ? 'VAR ✗' : 'yok ✓ (pinleme bu sertifikayı kabul etmemeli)'}`,
          '',
          'Sertifika teknik olarak kusursuz: SAN\'ında host\'un IP\'si var, süresi',
          'geçmemiş, kendinden imzalı. Pinleme yalnızca sertifikanın public key\'ine',
          '(SPKI) baktığı için geçerli bir sertifika üretebilmek saldırganı kurtarmıyor.',
        ].join('\n'),
      );
      expect(expected).not.toContain(rogue.pin);
    });

    await test.step(`Terminal: telefonun ${env.CONFIG_API_PORT} portuna giden trafiği saldırgana yönlendirilir (iptables DNAT)`, async () => {
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      const rules = device.rootShell('iptables -t nat -S OUTPUT');
      await attachText(
        testInfo,
        `Yönlendirme kuralı (iptables DNAT): ${env.LAN_IP}:${env.CONFIG_API_PORT} → ${env.LAN_IP}:${env.PROXY_PORT}`,
        [
          `$ iptables -t nat -A OUTPUT -p tcp -d ${env.LAN_IP} --dport ${env.CONFIG_API_PORT} ` +
            `-j DNAT --to-destination ${env.LAN_IP}:${env.PROXY_PORT}`,
          '',
          rules.trim(),
          '',
          'Telefon hâlâ https://' + env.LAN_IP + ':' + env.CONFIG_API_PORT + '/ adresine',
          'bağlandığını sanıyor; paketler saldırgana gidiyor. Hedef host\'a (' + TARGET_HOST + ')',
          'dokunulmadı. Cihaz raporları (telemetri) da bu porttan gittiği için onlar da saldırgana yönleniyor.',
        ].join('\n'),
      );
      expect(rules).toContain(`--dport ${env.CONFIG_API_PORT}`);
    });

    await test.step('Mobil: saklı config\'i olan uygulama config\'i yenileyemiyor, eski pin\'lerle çalışmaya devam ediyor', async () => {
      // Uygulama yeniden açılır: DNAT yalnızca YENİ bağlantıları yakalar,
      // OkHttp'nin havuzundaki canlı bağlantı gerçek host'a gitmeye devam
      // ederdi. Saklı config korunuyor (pm clear değil, force-stop).
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('araya girme: saklı config ile Hazır');
      expect(ready).toContain('Hazır — config v');

      const refresh = await app.refreshConfig();
      await app.snap('araya girme: config yenilenemedi');
      expect(refresh).toContain('Config yenilenemedi');
      // Hedefe giden trafik yönlendirilmedi: saklı (doğrulanmış) pin'lerle
      // yapılan istek çalışmaya devam ediyor.
      const request = await app.testLibraryClient();
      await app.snap('araya girme: saklı config ile hedefe bağlantı sürüyor');
      expect(request).toContain('Pinned bağlantı başarılı');
      await attachText(
        testInfo,
        'Telefonun ekranı (özet)',
        [
          'Yeniden açılış (saklı config var, trafik saldırgana yönlendirilmiş):',
          ready.split('\n').slice(0, 3).join('\n'),
          '',
          'Config yenileme denemesi:',
          refresh.split('\n').slice(0, 3).join('\n'),
          '',
          "Hedef host'a pinli istek (bu trafik saldırgana yönlendirilmedi):",
          request.split('\n').slice(0, 3).join('\n'),
        ].join('\n'),
      );
    });

    await test.step('Mobil: uygulama sıfırdan açılınca hiç başlayamıyor (şüphede bağlantıya izin vermez)', async () => {
      app.launchFresh();
      const failed = await app.waitInitFailed();
      await app.snap('araya girme: PinVault başlatılamadı');
      await attachText(
        testInfo,
        'Sıfırdan açılış (uygulama verisi silinmiş, saklı config yok)',
        [
          failed,
          '',
          'Kütüphane yedek yol olarak Android\'in sistem sertifika deposuna BAŞVURMUYOR:',
          'pin tutmayınca config hiç alınamıyor, config olmayınca da pinli istemci',
          'TLS bağlantısı kurmayı reddediyor.',
        ].join('\n'),
      );
      expect(failed).toContain('başlatılamadı');
    });

    await test.step('Saldırgan: eline tek bir HTTP isteği bile geçmedi (telefon bağlantıyı TLS aşamasında kesti)', async () => {
      // El sıkışma sertifika doğrulamasında kesildiği için vekil istek
      // göremiyor; gördüğü tek şey telefonun gönderdiği fatal TLS alert'i.
      const logcat = device.logcat({ match: /Pin mismatch|pinning failure|PinVault/ , lines: 3000 })
        .split('\n')
        .filter((row) => /Pin mismatch|pinning failure|Init failed|Config update failed/.test(row))
        .slice(-8)
        .join('\n');
      await attachText(
        testInfo,
        'Saldırganın gördüğü (ulaşan istek sayısı ve TLS el sıkışma hataları)',
        [
          `geçen HTTP isteği : ${mitm.requests.length} (${mitm.requests.join(', ') || 'yok ✓'})`,
          `el sıkışma hatası : ${mitm.handshakeErrors.length}`,
          ...mitm.handshakeErrors.slice(0, 5).map((e) => `  • ${e}`),
          '',
          'Telefonun günlüğü:',
          logcat || '(ilgili satır yok)',
        ].join('\n'),
      );
      expect(mitm.requests.length, 'sahte sunucuya ulaşan istek olmamalı').toBe(0);
      expect(mitm.handshakeErrors.length, 'telefon el sıkışmayı kesmeli').toBeGreaterThan(0);
      expect(logcat).toMatch(/Pin mismatch|pinning failure/);
    });

    await test.step('Mobil+Sunucu: uyuşmazlık telefonun olay listesinde; raporlar saldırgana da sunucuya da ulaşmadı', async () => {
      // Raporlar (telemetri) Config API portundan, config'le aynı pin'lerle
      // gider. O port saldırgana yönlendiği için rapor isteği de aynı TLS
      // kontrolüne takılır: saldırgan içeriğini göremez, sunucuya da ulaşmaz.
      await app.backToMain();
      const eventLog = app.eventLog();
      await app.snap('araya girme: olay listesinde uyuşmazlık');
      const rows = (await hostApi.connectionHistory(env.LAN_IP)).filter(
        (e) => e.deviceModel === run.model && e.status === 'pin_mismatch' && Date.parse(e.timestamp) >= startedAt,
      );
      await attachText(
        testInfo,
        'Uyuşmazlığın kaydı: telefonda var, sunucuya ulaşmadı',
        [
          'Telefonun olay listesi:',
          eventLog.split('\n').slice(0, 5).join('\n'),
          '',
          `Sunucuda bu süreye ait, bu cihazdan gelen pin_mismatch kaydı (host ${env.LAN_IP}): ${rows.length}`,
          `Saldırgana ulaşan HTTP isteği (rapor POST'ları dahil): ${mitm.requests.length}`,
          `saldırganın sertifikasının pin'i: ${proxy.certPin('rogue')}`,
          '',
          'Cihaz raporları Config API portundan gider; telefon yönetim portuna hiç',
          'bağlanmaz. Araya giren biri o yoldaki raporu düşürebilir, ama okuyamaz ve',
          'sahtesini üretemez (rapor istemcisi de pinli). Uyuşmazlığı fark etmenin yolu',
          'telefonun kendi kaydı ve cihazın sunucuya hiç ulaşamamasıdır.',
        ].join('\n'),
      );
      expect(eventLog).toContain('UYUŞMAZLIK');
      expect(rows.length, 'saldırı sürerken uyuşmazlık raporu sunucuya ulaşamaz (aynı port saldırganda)').toBe(0);
      expect(mitm.requests.length, 'rapor istekleri de saldırgana ulaşmamalı').toBe(0);
    });

    await test.step('Terminal: yönlendirme kaldırılır → uygulama normale dönüyor', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      const rules = device.rootShell('iptables -t nat -S OUTPUT');
      await sleep(1000);
      app.launchFresh();
      const ready = await app.waitReady();
      const request = await app.testLibraryClient();
      await app.snap('yönlendirme kalktı: Hazır ve bağlantı başarılı');
      await attachText(
        testInfo,
        'Kural kaldırıldıktan sonra',
        [
          `$ iptables -t nat -D OUTPUT -p tcp -d ${env.LAN_IP} --dport ${env.CONFIG_API_PORT} ` +
            `-j DNAT --to-destination ${env.LAN_IP}:${env.PROXY_PORT}`,
          '',
          rules.trim(),
          '',
          ready.split('\n').slice(0, 3).join('\n'),
        ].join('\n'),
      );
      expect(rules).not.toContain(`--dport ${env.CONFIG_API_PORT}`);
      expect(ready).toContain('Hazır — config v');
      expect(request).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
