// E12: cihaz bazlı pin kapsamı. Uygulamanın Ayarlar ekranındaki "yalnızca
// hedef host'un pin'lerini iste" anahtarı kütüphanenin wantPinsFor yolunu
// açar: config isteğine ?hosts=<hedef> ve X-Device-Id eklenir. Sunucu cihazın
// host ACL'iyle kesiştirir — ACL boşken sıfır pin döner, kütüphane boş
// config'i reddeder ve başlatma hiç açılmaz (fail-closed); dashboard'dan izin
// verilince telefon yalnızca izinli host'un pin'lerini alır.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const API = env.VAULT_API;

/** Cihaz gibi kapsamlı config isteği (yalnızca kanıt paneli için). */
async function scopedFetch(deviceId, hosts) {
  const res = await fetch(
    `${env.WEB_URL}/api/v1/certificate-config?signed=false&hosts=${encodeURIComponent(hosts.join(','))}`,
    { headers: { 'X-Device-Id': deviceId } },
  );
  const json = await res.json();
  return { status: res.status, hosts: (json.pins || []).map((p) => p.hostname) };
}

async function setDeviceAcl(deviceId, hosts) {
  return hostApi.api(`/api/v1/config-apis/${API}/devices/${encodeURIComponent(deviceId)}/host-acl`, {
    method: 'PUT',
    body: { hostnames: hosts },
  });
}

test('Mobil+Web: wantPinsFor ile cihaz yalnızca ACL\'de izinli host\'un pin\'lerini alır', async ({
  app,
  dashboard,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  let deviceId;

  try {
    await test.step('Mobil: cihaz kimliği okunur (X-Device-Id)', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      await app.snap('cihaz kimliği');
      await app.backToMain();
      expect(deviceId.length).toBeGreaterThan(4);
    });

    await test.step('Mobil: "yalnızca hedef host\'un pin\'leri" anahtarı açılır', async () => {
      await app.openSettings();
      const status = await app.setScopedPins(true);
      await app.snap('pin kapsamı açık');
      expect(status).toContain('Pin kapsamı: yalnızca');
      expect(status).toContain(env.TARGET_HOST);
      await app.backToMain();
    });

    await test.step('Mobil: ACL boşken cihaz hiç pin alamıyor, başlatma fail-closed düşüyor', async () => {
      // Anahtar uygulanırken PinVault sıfırlanıp yeniden kuruluyor: saklı
      // config de siliniyor, yani cihaz pin'lerini yalnızca kapsamlı istekten
      // alabilir. ACL boş olduğu için sunucu sıfır pin dönüyor.
      const status = await app.waitInitFailed();
      await app.snap('ACL yok: boş config reddedildi, başlatma düştü');
      await attachText(
        testInfo,
        'Telefondaki sonuç',
        [
          status,
          '',
          `Hedef pin sürümü: ${SampleApp.hostVersion(status, env.TARGET_HOST)}`,
          '',
          'Kütüphane boş pin listesini "değişiklik yok" saymıyor: doğrulama çalışıyor,',
          'UpdateResult.Failed / InvalidPinFormatException dönüyor, birincil blok',
          'düştüğü için init de düşüyor. Pinli istek düğmeleri hiç açılmıyor, yani',
          'sıfır pin ile tek bir istek bile denenemiyor.',
        ].join('\n'),
      );
      expect(status).toContain('at least one pin');
      expect(SampleApp.hostVersion(status, env.TARGET_HOST)).toBeNull();
      expect(app.node('testButton').enabled).toBe(false);
    });

    await test.step('Sunucu: kapsamlı istek ve ACL reddi logu', async () => {
      const empty = await scopedFetch(deviceId, [env.TARGET_HOST]);
      const logs = hostControl
        .logs(300)
        .split('\n')
        .filter((l) => l.includes('Unauthorized host request'))
        .slice(-3)
        .join('\n');
      await attachText(
        testInfo,
        'GET /api/v1/certificate-config?hosts=… + X-Device-Id',
        [
          `X-Device-Id: ${deviceId}`,
          `?hosts=${env.TARGET_HOST}`,
          `→ HTTP ${empty.status}, dönen host'lar: ${empty.hosts.length ? empty.hosts.join(', ') : '(boş)'}`,
          '',
          'Sunucu logu:',
          logs || '(log satırı bulunamadı)',
        ].join('\n'),
      );
      expect(empty.hosts).toEqual([]);
      expect(logs).toContain('Unauthorized host request');
    });

    await test.step('Web: ACL yöneticisinden varsayılan ACL verilir', async () => {
      await dashboard.openAclManager(API);
      await dashboard.snap('cihaz ACL yöneticisi (izin öncesi)');
      const toast = await dashboard.setDefaultAcl(API, [env.TARGET_HOST]);
      await dashboard.snap(`varsayılan ACL: ${env.TARGET_HOST}`);
      const current = await hostApi.api(`/api/v1/config-apis/${API}/default-host-acl`);
      await attachText(
        testInfo,
        `PUT /api/v1/config-apis/${API}/default-host-acl`,
        `toast: ${toast}\nGET → HTTP ${current.status} ${current.text.trim()}`,
      );
      expect(current.text).toContain(env.TARGET_HOST);
    });

    await test.step('Mobil: yalnızca izinli host\'un pin\'leri geliyor', async () => {
      // Başlatma boş config yüzünden düşmüştü; bu durumda ana ekrandaki düğme
      // "Tekrar dene" olur ve init'i baştan çalıştırır.
      await app.tapButton('refreshButton');
      const status = await app.waitReady();
      await app.snap('yalnızca hedef host\'un pin\'leri');
      await attachText(testInfo, 'Telefondaki durum kutusu', status);
      expect(SampleApp.hostVersion(status, env.TARGET_HOST)).not.toBeNull();
      // Diğer host'lar (host'un kendi IP'si, mock host'lar) artık gelmiyor.
      expect(SampleApp.hostVersion(status, env.LAN_IP)).toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).toBeNull();
      expect(await app.testLibraryClient()).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Web+Sunucu: cihaza özel ACL (X-Device-Id ile) ve arayüzdeki kimlik farkı', async () => {
      // Varsayılan ACL kaldırılır, izin yalnızca bu cihaza verilir.
      await dashboard.setDefaultAcl(API, []);
      const granted = await setDeviceAcl(deviceId, [env.TARGET_HOST]);
      const scoped = await scopedFetch(deviceId, [env.TARGET_HOST, env.LAN_IP]);
      const other = await scopedFetch('baska-cihaz', [env.TARGET_HOST]);

      await dashboard.openAclManager(API);
      const listed = await dashboard.aclDeviceIds();
      await dashboard.snap('ACL yöneticisi: cihaz listesi');
      await attachText(
        testInfo,
        'Cihaza özel ACL',
        [
          `PUT …/devices/${deviceId}/host-acl → HTTP ${granted.status}`,
          `bu cihaz  ?hosts=${env.TARGET_HOST},${env.LAN_IP} → ${scoped.hosts.join(', ') || '(boş)'}`,
          `başka cihaz ?hosts=${env.TARGET_HOST}          → ${other.hosts.join(', ') || '(boş)'}`,
          '',
          `Arayüzdeki cihaz listesi: ${listed.join(', ') || '(boş)'}`,
          `Telefonun gönderdiği X-Device-Id: ${deviceId}`,
          '',
          'NOT: ACL yöneticisindeki liste /api/v1/client-devices\'tan geliyor ve orada',
          'cihaz kimliği "üretici_model" olarak üretiliyor; telefon ise ANDROID_ID',
          'gönderiyor. İki kimlik uzayı farklı olduğu için satırdaki "Düzenle" düğmesi',
          'yanlış anahtara ACL yazar — cihaza özel izin şimdilik ANDROID_ID ile',
          'API üzerinden verilmeli (bulgu).',
        ].join('\n'),
      );
      expect(granted.status).toBe(200);
      expect(scoped.hosts).toEqual([env.TARGET_HOST]);
      expect(other.hosts).toEqual([]);

      const status = await app.refreshConfig();
      await app.snap('cihaza özel ACL ile yalnızca hedef host');
      expect(status).toMatch(/Yeni config uygulandı|Config güncel/);
      expect(SampleApp.hostVersion(status, env.TARGET_HOST)).not.toBeNull();
    });

    await test.step('Mobil: anahtar kapatılınca bütün pin\'ler geri geliyor', async () => {
      await app.openSettings();
      const applied = await app.setScopedPins(false);
      expect(applied).toContain("Pin kapsamı: bütün host'lar");
      await app.backToMain();
      const status = await app.refreshConfig();
      await app.snap('pin kapsamı kapalı: bütün host\'lar');
      expect(SampleApp.hostVersion(status, env.TARGET_HOST)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.LAN_IP)).not.toBeNull();
      expect(SampleApp.hostVersion(status, env.MOCK_TLS_HOST)).not.toBeNull();
    });
  } finally {
    await hostApi.api(`/api/v1/config-apis/${API}/default-host-acl`, { method: 'PUT', body: { hostnames: [] } });
    if (deviceId) await setDeviceAcl(deviceId, []);
  }
});
