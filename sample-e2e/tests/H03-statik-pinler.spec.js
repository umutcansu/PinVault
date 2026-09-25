// H03 — Sunucusuz çalışma: statik pin'ler.
//
// `PinVaultConfig.static(HostPin(...))` ile kurulan PinVault hiçbir Config API
// bloğu içermez: pin'ler APK'ya gömülüdür, kütüphane hiçbir sunucuya bağlanmaz.
// Uzaktan yönetim, vault ve kayıt bu modda yoktur — karşılığında hiçbir
// altyapı gerekmez.
//
// Kanıt için host container'ı tamamen DURDURULUYOR: uygulama o haldeyken
// sıfırdan açılıp hedefe pinli bağlanıyor. Aynı adımlar TLS modunda mümkün
// olmazdı (bkz. 06-host-down-first-launch).
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText, attachCommand } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostControl = require('../lib/hostControl');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;

test('Sunucusuz kullanım: statik pin\'lerle host kapalıyken bile pinli bağlantı kuruluyor', async ({
  app,
  device,
  run,
}, testInfo) => {
  test.setTimeout(10 * 60 * 1000);

  let hostStopped = false;

  try {
    await test.step('Mobil: Ayarlar\'dan "Statik pin\'ler" moduna geçilir', async () => {
      device.clearLogcat();
      await app.openSettings();
      const applied = await app.applyMode('STATIC');
      await app.snap('statik mod uygulandı');
      expect(applied).toContain('Hazır — config v');
      await app.backToMain();
      const status = app.status();
      await attachText(
        testInfo,
        'Telefonun ekranı (statik mod)',
        [
          status.split('\n').slice(0, 8).join('\n'),
          '',
          `APK'ya gömülü pin sayısı: ${run.goodPins.length}`,
          ...run.goodPins.map((p, i) => `  pin ${i + 1}: ${p}`),
          '',
          'Bu pin\'ler derleme sırasında sample-host.properties\'ten BuildConfig\'e',
          'gömüldü; kütüphane için pin\'lerin kaynağı APK, sunucu değil.',
        ].join('\n'),
      );
      expect(SampleApp.modeOf(status)).toBe("statik pin'ler");
      expect(status).toContain("APK'ya gömülü statik pin'ler (sunucu yok)");
      expect(SampleApp.hostVersion(status, TARGET_HOST)).not.toBeNull();
    });

    await test.step('Mobil: hedefe pinli bağlantı çalışıyor', async () => {
      const request = await app.testLibraryClient();
      await app.snap('statik mod: hedefe pinli bağlantı');
      expect(request).toContain('Pinned bağlantı başarılı');
      const logcat = device.logcat({ match: /Static pin mode|Pin verified|Init ready/, lines: 4000 })
        .split('\n')
        .slice(-8)
        .join('\n');
      await attachText(
        testInfo,
        'Cihazın günlüğü (statik modda init)',
        [
          logcat || '(ilgili satır yok)',
          '',
          'PinVault.executeInit statik config\'i doğrudan uyguluyor: hiçbir',
          'CertificateConfigApi çağrılmıyor, HTTP istemcisi hiç kurulmuyor.',
        ].join('\n'),
      );
      expect(logcat).toMatch(/Static pin mode/);
    });

    await test.step('Sunucu: host container\'ı tamamen durdurulur', async () => {
      await hostControl.stop();
      hostStopped = true;
      await attachCommand(testInfo, 'docker ps — host kapalı', 'docker', [
        'ps', '-a', '--filter', `name=${env.CONTAINER}`, '--format', '{{.Names}}\t{{.Status}}',
      ]);
      expect(await hostApi.isHealthy()).toBe(false);
    });

    await test.step('Mobil: host kapalıyken uygulama kapatılıp yeniden açılıyor ve bağlanıyor', async () => {
      // Uygulama verisi silinmiyor (mod ayarı korunsun) ama süreç öldürülüyor:
      // init baştan çalışıyor ve yine hiçbir sunucuya gitmiyor.
      app.relaunch();
      const ready = await app.waitReady();
      const request = await app.testLibraryClient();
      await app.snap('host kapalı + statik mod: Hazır ve bağlantı başarılı');
      await attachText(
        testInfo,
        'Host kapalıyken açılış',
        [
          ready.split('\n').slice(0, 6).join('\n'),
          '',
          request.split('\n').slice(0, 2).join('\n'),
          '',
          `host sağlıklı mı: ${(await hostApi.isHealthy()) ? 'evet' : 'hayır (container durduruldu)'}`,
          '',
          'Aynı adım TLS modunda "başlatılamadı" ile biterdi (senaryo 06).',
        ].join('\n'),
      );
      expect(ready).toContain('Hazır — config v');
      expect(request).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Mobil: vault bu modda kullanılamıyor (dosya tanımlı değil)', async () => {
      await app.openVault();
      const status = await app.fetchVault(KEY);
      await app.snap('statik mod: vault kullanılamıyor');
      await attachText(
        testInfo,
        'Statik modda vault',
        [
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'PinVaultConfig.static hiçbir vaultFile tanımlamıyor; kütüphane tanımlı',
          'olmayan dosyayı fetchFile\'da reddediyor. Vault için bir Config API',
          'bloğu (ve onu sunan bir backend) gerekir.',
        ].join('\n'),
      );
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toMatch(/not registered in config/i);
      await app.backToMain();
    });

    await test.step('Mobil: kayıt (enrollment) bu modda kullanılamıyor', async () => {
      await app.openMtls();
      expect(app.enrollState()).toContain('Kayıtlı değil');
      const status = await app.enroll('statik-mod-denemesi');
      await app.snap('statik mod: kayıt kullanılamıyor');
      await attachText(
        testInfo,
        'Statik modda kayıt',
        [
          status.split('\n').slice(0, 3).join('\n'),
          '',
          'PinVault.enroll ilk iş olarak varsayılan Config API bloğunu arıyor;',
          'statik modda blok olmadığı için istek hiç kurulmuyor (ağa çıkılmıyor).',
        ].join('\n'),
      );
      expect(status).toContain('Kayıt başarısız');
      await app.backToMain();
    });

    await test.step('Sunucu: host geri açılır', async () => {
      await hostControl.start();
      hostStopped = false;
      await attachCommand(testInfo, 'docker ps — host yeniden ayakta', 'docker', [
        'ps', '--filter', `name=${env.CONTAINER}`, '--format', '{{.Names}}\t{{.Status}}',
      ]);
      expect(await hostApi.isHealthy()).toBe(true);
    });

    await test.step('Mobil: TLS moduna dönülür, uzaktan yönetim geri geliyor', async () => {
      await app.openSettings();
      const applied = await app.applyMode('TLS');
      await app.backToMain();
      const status = app.status();
      await app.snap('TLS moduna dönüldü');
      expect(applied).toContain('Hazır — config v');
      expect(SampleApp.modeOf(status)).toBe('TLS config');
      expect(status).toContain(`https://${env.LAN_IP}:${env.CONFIG_API_PORT}/`);
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });
  } finally {
    if (hostStopped) await hostControl.ensureUp();
  }
});
