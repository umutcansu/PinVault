// H02 — Config kaynağı uygulamanın içinde: özel CertificateConfigApi.
//
// PinVault'un HTTP istemcisi zorunlu değil. `PinVault.init(context, config,
// api)` ile kütüphaneye kendi [CertificateConfigApi] uygulaman verilebilir;
// pin'ler remote-config SDK'sından, imzalı bir asset'ten ya da (bu örnekte)
// doğrudan derlemeden gelir. Doğrulama, sürümleme, depolama ve periyodik
// yenileme aynen çalışmaya devam eder.
//
// Kanıtın belkemiği: Config API portu emülatörde TAMAMEN KESİLİRKEN (iptables
// REJECT) uygulama sıfırdan açılıp "Hazır" oluyor ve hedefe pinli bağlanıyor.
// Aynı koşulda TLS moduna geçirilen uygulama ise açılamıyor — yani kesinti
// gerçek, gömülü modun ağa ihtiyacı yok.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

function logMark() {
  const lines = hostControl.logs(5).trim().split('\n');
  return lines[lines.length - 1] || '';
}

function logsSince(mark) {
  const all = hostControl.logs(800);
  const idx = mark ? all.lastIndexOf(mark) : -1;
  return idx >= 0 ? all.slice(idx + mark.length) : all;
}

test('Uygulama içi config kaynağı: gömülü CertificateConfigApi ile kütüphane config için ağa hiç çıkmıyor', async ({
  app,
  device,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables kuralı yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  let mark;

  try {
    await test.step(`Terminal: Config API portu (${env.CONFIG_API_PORT}) tamamen kesilir`, async () => {
      mark = logMark();
      device.blockTcp(env.LAN_IP, env.CONFIG_API_PORT, 'reject');
      const rules = device.describeNetRules('filter');
      await attachText(
        testInfo,
        `iptables REJECT: ${env.LAN_IP}:${env.CONFIG_API_PORT}`,
        [
          `$ iptables -A OUTPUT -p tcp -d ${env.LAN_IP} --dport ${env.CONFIG_API_PORT} -j REJECT`,
          '',
          rules.trim(),
          '',
          'Hedef host açık kalıyor; kesilen, kütüphanenin pin config\'ini çektiği (ve cihaz',
          'raporlarının gittiği) port. Bu sürede raporlar da sunucuya ulaşamaz.',
        ].join('\n'),
      );
      expect(rules).toContain(`--dport ${env.CONFIG_API_PORT}`);
    });

    await test.step('Mobil: karşılaştırma için TLS modunda sıfırdan açılış — port kesikken başlatılamıyor', async () => {
      // Uygulama verisi silinir: saklı config yok, mod varsayılan (TLS).
      app.launchFresh();
      const failed = await app.waitInitFailed();
      await app.snap('port kesik + TLS modu: başlatılamadı');
      await attachText(
        testInfo,
        'Karşılaştırma: aynı koşulda TLS modu',
        [
          failed.split('\n').slice(0, 4).join('\n'),
          '',
          'Kesinti gerçek: varsayılan modda kütüphane config\'i HTTP ile çekmek zorunda;',
          'saklı config de olmadığı için başlamayı reddediyor (şüphede bağlantıya izin vermez).',
        ].join('\n'),
      );
      expect(failed).toContain('başlatılamadı');
    });

    await test.step('Mobil: aynı boş kurulumda gömülü API moduna geçilir, uygulama "Hazır" oluyor', async () => {
      // Saklı config hâlâ yok (TLS denemesi hiçbir şey kaydedemedi); mod
      // Ayarlar'dan değiştiriliyor, yani init sırası deterministik.
      device.clearLogcat();
      await app.openSettings();
      const applied = await app.applyMode('EMBEDDED_API');
      expect(applied).toContain('Hazır — config v');
      await app.backToMain();
      const ready = await app.waitReady();
      await app.snap('port kesik + gömülü API: Hazır');
      const status = app.status();
      await attachText(
        testInfo,
        'Telefonun ekranı (gömülü API modu, Config API portu kesik)',
        [
          status.split('\n').slice(0, 8).join('\n'),
          '',
          `hedef host sürümü: v${SampleApp.hostVersion(status, TARGET_HOST)}`,
          "pin'ler APK'ya gömülü (BuildConfig.TARGET_PINS), sürüm sabit v1.",
        ].join('\n'),
      );
      expect(ready).toContain('Hazır — config v');
      expect(SampleApp.modeOf(status)).toBe('gömülü API');
      expect(status).toContain('uygulama içi EmbeddedConfigApi (HTTP yok)');
    });

    await test.step('Mobil: gömülü config\'in pin\'leriyle hedefe bağlanılıyor', async () => {
      const request = await app.testLibraryClient();
      await app.snap('gömülü API: hedefe pinli bağlantı');
      expect(request).toContain('Pinned bağlantı başarılı');
      const eventLog = app.eventLog();
      await attachText(
        testInfo,
        'Uygulamanın olay listesi (TLS bağlantıları)',
        [
          eventLog.split('\n').slice(0, 6).join('\n'),
          '',
          `config'teki pin sayısı: ${run.goodPins.length} (APK'ya gömülü olanlar)`,
        ].join('\n'),
      );
      expect(eventLog).toContain(`[✓] ${TARGET_HOST}`);
    });

    await test.step('Mobil: cihaz günlüğünde config akışı var, HTTP yok', async () => {
      const logcat = device.logcat({ match: /Config updated|Pin verified|Health check|Static pin|Init ready/, lines: 4000 })
        .split('\n')
        .slice(-12)
        .join('\n');
      await attachText(
        testInfo,
        'Cihazın günlüğü (gömülü API modunda init)',
        [
          logcat || '(ilgili satır yok)',
          '',
          'Kütüphane normal akışı izliyor: config alındı → biçimi denetlendi →',
          'şifreli depoya yazıldı → pinlenmiş istemci kuruldu → sağlık kontrolü.',
          'Farkı, bu adımların hiçbirinin ağa çıkmaması: fetchConfig ve',
          'healthCheck uygulamanın kendi sınıfından geliyor.',
          '',
          'Bu modda İMZA DOĞRULANMAZ ve uygulama bunu kodda açıkça söyler: blok',
          'allowUnsigned() ile kurulur (App.startEmbeddedApi). fetchConfig hazır bir',
          'config döndürdüğü için doğrulanacak imzalı bir zarf yoktur; pin\'ler APK\'nın',
          'içinden geldiğinden güven APK\'ya dayanır. Pin\'leri uzaktan getiren bir özel',
          'API SignedConfigSource uygulamak zorundadır; aksi hâlde init hata verir.',
        ].join('\n'),
      );
      expect(logcat).toMatch(/Config updated|Init ready/);
    });

    await test.step('Sunucu: ana host günlüğünde bu süreye ait config isteği yok', async () => {
      const window = logsSince(mark);
      const requestLines = window
        .split('\n')
        .filter((line) => /io\.ktor\.server\.Application - \d{3}/.test(line))
        .map((line) => line.replace(/^.*Application - /, '').trim());
      const configLines = requestLines.filter((l) => /certificate-config/.test(l));
      await attachText(
        testInfo,
        'Ana host (demo-server) günlüğü — gömülü API modundayken',
        [
          `bu sürede ${requestLines.length} istek satırı var:`,
          ...requestLines.slice(-15).map((l) => `  ${l}`),
          '',
          `config isteği: ${configLines.length} (${configLines.join(' | ') || 'yok ✓'})`,
          '',
          'Kalanlar docker\'ın sağlık kontrolü (cihaz raporları Config API portundan gider; o port kesik).',
        ].join('\n'),
      );
      expect(configLines, 'gömülü modda sunucuya config isteği gitmemeli').toHaveLength(0);
    });

    await test.step('Terminal: iptables kuralı kaldırılır, uygulama TLS modunda yeniden "Hazır"', async () => {
      device.clearNetRules();
      await app.openSettings();
      const applied = await app.applyMode('TLS');
      expect(applied).toContain('Hazır — config v');
      await app.backToMain();
      const ready = await app.waitReady();
      await app.snap('kural kalktı: TLS modunda Hazır');
      expect(SampleApp.modeOf(ready)).toBe('TLS config');
      expect(ready).toContain(`https://${env.LAN_IP}:${env.CONFIG_API_PORT}/`);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    device.clearNetRules();
  }
});
