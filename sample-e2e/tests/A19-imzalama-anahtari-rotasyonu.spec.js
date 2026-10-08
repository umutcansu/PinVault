// A19: imzalama anahtarı rotasyonu. Sunucu her config yanıtını ECDSA P-256 ile
// imzalar; istemci imzayı APK'ya gömülü public key ile doğrular. Anahtar
// dashboard'dan yenilenince eski anahtarla derlenmiş uygulama yeni config'i
// kabul etmez — imza doğrulanamaz, eski (daha önce doğrulanmış) config yerinde
// kalır ve verisi silinmiş bir kurulum hiç açılamaz. Uygulama yeni public key
// ile yeniden derlenince akış normale döner.
//
// Geçici test sunucusunda çalışır: ana host'un imzalama anahtarı değişirse
// telefondaki APK'ya gömülü public key eskir ve diğer bütün senaryolar
// çöker. Senaryo sonunda uygulama MUTLAKA ana host değerleriyle yeniden
// derlenip kurulur (finally).
const fs = require('fs');
const path = require('path');
const { test, expect } = require('../lib/fixtures');
const { attachText, redact } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const clientBuild = require('../lib/clientBuild');
const fresh = require('../lib/freshHost');
const env = require('../lib/env');

const FRESH_PROPS = path.join(env.LOCAL_DIR, 'host-fresh.properties');

/** Taze host'un güncel değerlerini istemci derlemesi için dosyaya yazar. */
function writeFreshProps() {
  const out = fresh.run('./scripts/client-config.sh', env.CLIENT_CONFIG_ARGS);
  fs.writeFileSync(FRESH_PROPS, out);
  return out;
}

function propLine(props, key) {
  return (props.split('\n').find((l) => l.startsWith(`${key}=`)) || '').slice(key.length + 1).trim();
}

test('Web+Mobil: imzalama anahtarı yenilenince eski APK config\'i reddediyor, yeni anahtarla derlenen APK kabul ediyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(30 * 60 * 1000);
  await fresh.ensure();

  const app = new SampleApp(device, testInfo);
  const dashboard = await fresh.openDashboard(browser, testInfo);
  let oldKey;
  let newKey;

  try {
    await test.step('Terminal: uygulama geçici test sunucusunun şu anki imzalama anahtarıyla derlenip kurulur', async () => {
      const props = writeFreshProps();
      oldKey = propLine(props, 'host.signingPublicKey');
      clientBuild.buildAndInstall(device, FRESH_PROPS);
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('geçici test sunucusu: imzalı config kabul edildi');
      await attachText(
        testInfo,
        'Derlemeye gömülen imzalama public key\'i',
        [
          `host.signingPublicKey=${redact(oldKey, 24)}`,
          `(uzunluk ${oldKey.length} karakter, X.509 SPKI / Base64)`,
          '',
          `Telefon: ${status.split('\n')[0]}`,
        ].join('\n'),
      );
      expect(status).toMatch(/Hazır — config v\d+/);
    });

    await test.step('Web: İmzalama sekmesindeki public key (anahtar değişmeden önce)', async () => {
      const shown = await dashboard.signingPublicKey('default-tls');
      await dashboard.snap('İmzalama sekmesi (anahtar değişmeden önce)');
      expect(shown.replace(/\s/g, '')).toContain(oldKey.slice(0, 40));
    });

    await test.step('Web: "Anahtarı Yenile" → çalışan sunucu anında yeni anahtarla imzalamaya başlıyor', async () => {
      const toast = await dashboard.regenerateSigningKey('default-tls');
      await dashboard.snap('İmzalama sekmesi (yenileme sonrası)');
      newKey = fresh.signingKeyRaw().split('\n')[1].trim();
      const servedAfterClick = ((await fresh.api('/api/v1/signing-key', { withKey: false })).json || {}).publicKey;
      const shownAfterClick = (await dashboard.signingPublicKey('default-tls')).replace(/\s/g, '');
      await attachText(
        testInfo,
        'Anahtar değişti (rotasyon) — dosya, sunucu ve dashboard aynı anahtarı gösteriyor',
        [
          `onay  : ${dashboard.lastDialog()}`,
          `toast : ${toast}`,
          '',
          `data/signing-key.pem (public yarısı): ${redact(newKey, 24)}`,
          `GET /api/v1/signing-key              : ${redact(servedAfterClick, 24)}`,
          `Dashboard'da görünen                 : ${redact(shownAfterClick, 24)}`,
          `Değişmeden önceki anahtar            : ${redact(oldKey, 24)}`,
          '',
          'Yeni anahtar sunucu yeniden başlatılmadan devreye giriyor: imza servisi',
          'anahtar çiftini yerinde değiştiriyor (ConfigSigningService.regenerate) ve',
          'API uçları aynı servis nesnesini kullandığı için sonraki imza yeni',
          'anahtarla atılıyor. Eskiden uçlar servisin açılıştaki halini tutuyordu:',
          'dashboard "yenilendi" derken sunucu eski anahtarla imzalamaya devam',
          'ediyordu. Yeni anahtar ancak ilk yeniden başlatmada devreye giriyordu ve',
          'o anda sahadaki bütün APK\'lar birden config kabul edemez oluyordu.',
        ].join('\n'),
      );
      expect(newKey, 'diskteki anahtar yenilenmeli').not.toBe(oldKey);
      expect(servedAfterClick, 'çalışan sunucu yeni anahtarı veriyor').toBe(newKey);
      expect(shownAfterClick).toContain(newKey.slice(0, 40));
    });

    await test.step('Mobil: imza doğrulanamadığı için yenileme başarısız, eski config yerinde kalıyor', async () => {
      const status = await app.refreshConfig();
      await app.snap('imza doğrulanamadı: config reddedildi');
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toContain('Config yenilenemedi');
      expect(status).toContain('Config signature verification failed');
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
    });

    await test.step('Mobil: uygulama saklı config ile yine açılıyor (imzası daha önce doğrulanmıştı)', async () => {
      app.relaunch();
      const status = await app.waitReady();
      await app.snap('saklı config ile hazır');
      expect(status).toMatch(/Hazır — config v\d+/);
    });

    await test.step('Mobil: verisi silinmiş uygulama hiç başlatılamıyor (imzası doğrulanan config yok)', async () => {
      app.launchFresh();
      const status = await app.waitInitFailed();
      await app.snap('eski public key ile: başlatılamadı');
      await attachText(
        testInfo,
        'Sıfırdan açılış — imzası doğrulanamayan config',
        [
          status,
          '',
          'Saklı config yok + sunucudan gelen imzalı config doğrulanamıyor →',
          'InitResult.Failed. Kütüphane imzasız/şüpheli config\'i ASLA uygulamıyor,',
          'telefonun sistem sertifikalarına güvenmeye de geri dönmüyor.',
        ].join('\n'),
      );
      expect(status).toContain('PinVault başlatılamadı');
      expect(app.node('testButton').enabled, 'library client düğmesi').toBe(false);
    });

    await test.step('Terminal: client-config.sh yeni public key\'i veriyor, uygulama yeniden derleniyor', async () => {
      const props = writeFreshProps();
      const rebuiltKey = propLine(props, 'host.signingPublicKey');
      await attachText(
        testInfo,
        'scripts/client-config.sh --properties (anahtar değiştikten sonra)',
        [
          `host.signingPublicKey=${redact(rebuiltKey, 24)}`,
          `dashboard\'daki yeni anahtarla aynı mı: ${rebuiltKey === newKey}`,
          `eski anahtarla aynı mı               : ${rebuiltKey === oldKey}`,
        ].join('\n'),
      );
      expect(rebuiltKey).toBe(newKey);
      expect(rebuiltKey).not.toBe(oldKey);
      clientBuild.buildAndInstall(device, FRESH_PROPS);
    });

    await test.step('Mobil: yeni public key ile config yeniden kabul ediliyor', async () => {
      app.launchFresh();
      const status = await app.waitReady();
      await app.snap('yeni imzalama anahtarı: config kabul edildi');
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(status).toMatch(/Hazır — config v\d+/);
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
      const refreshed = await app.refreshConfig();
      expect(refreshed).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(refreshed).not.toContain('Config yenilenemedi');
    });
  } finally {
    // Ana host'un değerlerine dönüş: bundan sonraki senaryolar ana host'la çalışır.
    const restore = clientBuild.buildAndInstall(device, env.PROPS_FILE);
    await attachText(
      testInfo,
      'Ana host değerleriyle yeniden derleme ve kurulum',
      `$ ${env.buildCommandFor(env.PROPS_FILE)}\n${restore}`,
    );
    app.launchFresh();
    const status = await app.waitReady();
    await app.snap('ana host değerleriyle geri yüklendi');
    expect(status).toMatch(/Hazır — config v\d+/);
    expect(SampleApp.hostVersion(status, env.TARGET_HOST)).not.toBeNull();
    await dashboard.page.close();
  }
});
