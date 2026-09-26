// G08 — Güncelleme sonrası sağlık doğrulaması ve geri alma.
//
// Yeni pin'ler uygulandıktan hemen sonra kütüphane bir sağlık isteği atıyor
// (SSLCertificateUpdater.verifyPinnedConnection): "bu config yürürlükteyken
// Config API'ye hâlâ ulaşabiliyor muyum?" Saldırgan proxy bu senaryoda config'i
// olduğu gibi geçirip yalnızca /health yanıtını 500'e çeviriyor.
//
// Beklenen davranış (bulgu düzeltildikten sonra):
//   • init "başlatılamadı" diyor (kontrol çalışıyor),
//   • uygulanan config GERİ ALINIYOR: önceki config varsa geri yazılıyor,
//     yoksa depo temizleniyor,
//   • bu yüzden sağlık hâlâ bozukken yapılan ikinci açılış da başlatılamıyor —
//     kontrolü atlatan "saklı config'le sessizce Hazır" yolu kapandı.
//
// Bulgu neydi: verifyPinnedConnection temizleme/sıfırlama işini yalnızca
// istisna dalında yapıyordu, DefaultCertificateConfigApi.healthCheck() ise
// bütün istisnaları yutup false döndürdüğü için o dal hiç çalışmıyordu. Sonuç:
// init başarısız derken config diskte kalıyor, ikinci açılış AlreadyCurrent
// yolundan geçtiği için sağlık kontrolü hiç işlemiyor ve uygulama "Hazır" diyordu.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const proxy = require('../lib/proxy');
const env = require('../lib/env');

const prefsOf = (listing) =>
  listing.split('\n').map((l) => l.trim()).filter((l) => l.endsWith('.xml')).map((l) => l.split(/\s+/).pop());

test("Saldırı: config indikten sonra /health 500 döner → telefon başlatılamıyor ve uyguladığı config'i geri alıyor", async ({
  app,
  device,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(8 * 60 * 1000);

  let mitm;

  try {
    await test.step("Saldırgan: config'e dokunmaz, yalnızca /health yanıtını 500 hatasına çevirir", async () => {
      mitm = await proxy.start({ identity: 'trusted', mutate: proxy.failHealth });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      await attachText(
        testInfo,
        'Saldırganın değiştirdiği tek şey: sağlık kontrolü ucu (/health)',
        [
          `saldırgan proxy ${env.LAN_IP}:${env.PROXY_PORT} üzerinde sunucunun kendi TLS anahtarıyla dinliyor (pin tutuyor)`,
          `iptables DNAT: ${env.LAN_IP}:${env.CONFIG_API_PORT} → saldırgan proxy`,
          '',
          'GET /health  → HTTP 500 {"status":"down"}   (saldırgan üretiyor)',
          'diğer uçlar  → sunucudan geldiği gibi, bayt bayt aynı',
          '',
          'Yani pin config\'i kusursuz iniyor; yalnızca "yeni pin\'lerle sunucuya',
          'ulaşabiliyor muyum" sorusunun cevabı olumsuz.',
        ].join('\n'),
      );
    });

    await test.step('Mobil: sıfırdan açılış → config uygulanıyor ama sağlık kontrolü düşünce PinVault başlatılamıyor', async () => {
      device.clearLogcat();
      app.launchFresh();
      const failed = await app.waitInitFailed();
      await app.snap('sağlık 500: PinVault başlatılamadı');
      const seen = mitm.requests.join('\n');
      const logcat = device
        .logcat({ match: /Health check|health check|Config updated|Pinned connection|Init failed/, lines: 4000 })
        .split('\n')
        .slice(-10)
        .join('\n');
      await attachText(
        testInfo,
        'İlk açılış: ağ trafiğinde ve telefonda',
        [
          'SALDIRGANIN GÖRDÜĞÜ İSTEKLER (sırayla)',
          seen || '(yok)',
          '',
          'TELEFONUN EKRANI',
          failed.split('\n').slice(0, 3).join('\n'),
          '',
          'CİHAZIN GÜNLÜĞÜ',
          logcat || '(ilgili satır yok)',
          '',
          'Sıra önemli: önce config indi ve UYGULANDI (Config updated), sonra',
          'pinlenmiş istemciyle sağlık kontrolü yapıldı ve düştü.',
        ].join('\n'),
      );
      expect(failed).toContain('başlatılamadı');
      expect(failed).toMatch(/unhealthy/i);
      expect(seen).toContain('/api/v1/certificate-config');
      expect(seen).toContain('/health');
    });

    await test.step('Mobil: uygulanan config geri alındı — şifreli depo boş', async () => {
      const listing = device.appFiles(env.APP_ID, 'shared_prefs');
      const files = prefsOf(listing);
      const configFile = files.find((f) => f === 'pinvault_secure_config.xml');
      const contents = configFile ? device.appFileText(env.APP_ID, `shared_prefs/${configFile}`) : '';
      // Uygulama bu açılışta tek blokla (sample-host) çalışıyor: dosyadaki
      // her kayıt onun.
      const entryCount = (contents.match(/<string name="([^"]*)"/g) || []).length;
      await attachText(
        testInfo,
        `Cihazdaki tercih dosyaları (adb shell run-as ${env.APP_ID})`,
        [
          `$ run-as ${env.APP_ID} ls -la shared_prefs`,
          listing.trim(),
          '',
          `config deposu: ${configFile || '(yok)'}`,
          `kayıt sayısı : ${entryCount}`,
          '',
          'Bu açılış "pm clear" sonrası yapıldı: geri dönülecek ÖNCEKİ config yok.',
          'Sağlık kontrolü geçmeyince kütüphane uygulanan config\'i geri alıyor —',
          'önceki kopya olmadığı için depoyu temizliyor (configStore.clear) ve',
          'istemciyi, şüphede bağlantıya izin vermeyen duruma döndürüyor (httpClientProvider.reset).',
          'Dosya diskte kalsa bile içinde tek bir kayıt yok.',
          '',
          'Önceki davranış: config olduğu gibi depoda kalıyordu; healthCheck()',
          'istisnaları yuttuğu için "temizle ve sıfırla" dalı hiç çalışmıyordu.',
        ].join('\n'),
      );
      expect(entryCount, 'geri alınan config depoda kayıt bırakmamalı').toBe(0);
    });

    await test.step('Mobil: sağlık hâlâ bozukken ikinci açılış da başlatılamıyor', async () => {
      app.relaunch();
      const status = await app.waitFor(
        'statusView',
        (n) => /Hazır — config v\d+/.test(n.text) || n.text.includes('başlatılamadı'),
        { timeout: 90_000, what: 'ikinci açılış sonucu' },
      );
      await app.snap('sağlık hâlâ 500: ikinci açılış da başlatılamadı');
      const ready = /Hazır — config v\d+/.test(status.text);
      await attachText(
        testInfo,
        "İkinci açılış (saldırgan /health'i hâlâ bozarken)",
        [
          status.text.split('\n').slice(0, 3).join('\n'),
          '',
          `library client düğmesi: ${app.node('testButton').enabled ? 'açık' : 'kilitli'}`,
          '',
          'Geri alma sayesinde ikinci açılış da aynı kontrole takılıyor: saklı config',
          'olmadığı için config yeniden iniyor, uygulanıyor, sağlık düşüyor ve yine',
          'geri alınıyor. "Sunucuya ulaşılamaz hale getiren config diskte kalıp',
          'sonraki açılışta sessizce Hazır oluyor" yolu kapandı.',
          '',
          'Önceki davranış bu adımda "Hazır — config vN" diyordu: saklı config',
          'yükleniyor, sunucu aynı sürümü döndürdüğü için sonuç AlreadyCurrent',
          'oluyor ve sağlık kontrolü hiç çalışmıyordu (kontrol yalnızca config',
          'güncellendiğinde, yani Updated sonucunda işliyor).',
        ].join('\n'),
      );
      expect(ready, 'geri alınan config ikinci açılışta yürürlüğe girmemeli').toBe(false);
      expect(status.text).toContain('başlatılamadı');
      expect(app.node('testButton').enabled, 'library client düğmesi').toBe(false);
    });

    await test.step('Saldırgan: /health yanıtını bozmayı bırakınca uygulama normale dönüyor', async () => {
      mitm.setMutate(null);
      app.launchFresh();
      const ready = await app.waitReady();
      const request = await app.testLibraryClient();
      await app.snap('sağlık düzeldi: Hazır ve bağlantı başarılı');
      await attachText(
        testInfo,
        'Sağlık ucu düzeldikten sonra',
        [ready.split('\n').slice(0, 3).join('\n'), '', request.split('\n').slice(0, 2).join('\n')].join('\n'),
      );
      expect(ready).toContain('Hazır — config v');
      expect(request).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      expect(await app.waitReady()).toContain('Hazır — config v');
      await app.snap('saldırgan proxy kapandı: doğrudan sunucuyla Hazır');
      expect(device.rootShell('iptables -t nat -S OUTPUT')).not.toContain(`--dport ${env.CONFIG_API_PORT}`);
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
  }
});
