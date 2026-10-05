// C09 — Config API'nin "vault aktif" anahtarı gerçekten kapatıyor.
//
// Anahtar kapatılınca o Config API'nin indirme yolu 403 dönüyor: hem telefon
// hem de ağ trafiğindeki ham istek. Yönetim uçları (yükleme, listeleme, silme) kasten
// etkilenmiyor — operatörün bu düğmeye basmasının nedeni genellikle "yanlışlıkla
// yayılan bir dosya", ve hemen ardından onu incelemesi ve silmesi gerekiyor.
//
// Senaryo iki katmanı da kanıtlıyor, çünkü bulgu ikisinde birden vardı:
//   1. Uygulamanın kullandığı varsayılan Config API (`default-tls`) artık
//      config_apis tablosunda bir satır: anahtar orada da yazılabiliyor.
//      (Önceden Main.kt bu dinleyiciyi doğrudan kuruyor, satır oluşmuyordu ve
//      PUT 404 dönüyordu; dashboard ise kutuyu kapalı gösteriyordu.)
//   2. İndirme yolu bayrağı okuyor. (Önceden yalnızca iki yönetim ucu
//      bayrağa dokunuyordu; dosya 200 ile inmeye devam ediyordu.)
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, describeResponse } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.flags;
const WORK_DIR = path.join(env.LOCAL_DIR, 'c09');
const P12 = path.join(WORK_DIR, 'client.p12');
const CERT_PEM = path.join(WORK_DIR, 'client-cert.pem');
const KEY_PEM = path.join(WORK_DIR, 'client-key.pem');
const PINVAULT_DIR = process.env.E2E_PINVAULT_DIR || path.resolve(env.ROOT, '..');

function splitP12(p12, password = 'changeit') {
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nokeys', '-out', CERT_PEM]);
  execFileSync('openssl', ['pkcs12', '-in', p12, '-passin', `pass:${password}`, '-nocerts', '-nodes', '-out', KEY_PEM]);
}

/** mTLS dinleyicisi sertifika üretiminden sonra yeniden başladığı için kısa yeniden deneme. */
async function mtlsDownload(key, deviceId, attempts = 8) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      return await hostApi.rawVaultDownload(key, deviceId, {
        port: env.MTLS_API_PORT,
        certFile: CERT_PEM,
        keyFile: KEY_PEM,
      });
    } catch (e) {
      last = e;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw last;
}

test('Vault\'u kapatma ayarı: "vault aktif" kapatılınca indirme gerçekten duruyor', async ({ app, dashboard }, testInfo) => {
  test.setTimeout(10 * 60 * 1000);
  const stamp = Date.now();
  const body = `kapali-vault-denemesi-${stamp}`;
  const mtlsBody = `mtls-kapsam-${stamp}`;
  const certId = `c09-${stamp}`;
  let version;
  let deviceId;
  let defaultFlagChanged = false;
  let mtlsFlagChanged = false;
  fs.mkdirSync(WORK_DIR, { recursive: true });

  try {
    await test.step('Web: dosya yüklenir, telefon indiriyor (temel durum)', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, body, { policy: 'public' });
      await app.openVault();
      deviceId = app.deviceId();
      expect(await app.fetchVault(KEY)).toContain(`${KEY} v${version} indirildi`);
      await app.snap('vault açık: dosya indi');
    });

    await test.step('Web: varsayılan Config API\'de "vault aktif" ayarı kapatılıp kaydedilebiliyor', async () => {
      const result = await dashboard.setVaultEnabled(env.VAULT_API, false);
      defaultFlagChanged = true;
      await dashboard.snap(`"vault aktif" kapatıldı — ${env.VAULT_API} Genel sekmesi`);
      const read = await hostApi.api(`/api/v1/config-apis/${env.VAULT_API}/vault-enabled`);
      await attachText(
        testInfo,
        `PUT /api/v1/config-apis/${env.VAULT_API}/vault-enabled {"enabled": false}`,
        [
          `HTTP ${result.status} ${result.body}`,
          `toast: ${result.toast}`,
          '',
          `GET …/vault-enabled → HTTP ${read.status} ${read.text.trim()}`,
          '',
          hostApi.dbQuery('SELECT id, port, mode, vault_enabled FROM config_apis;'),
          '',
          `Sunucu açılışta sunduğu her Config API için config_apis tablosuna bir satır`,
          `yazıyor (ConfigApiRegistry.ensureRegistered); Main.kt'nin doğrudan kurduğu`,
          `${env.VAULT_API} de dahil. Önceden bu satır yoktu: UPDATE hiçbir satır`,
          'bulamıyor, uç 404 dönüyordu; yani ayar, uygulamanın gerçekten kullandığı',
          'Config API\'de hiç çalışmıyordu. Var olan bir satırın vault_enabled değeri',
          'sunucu yeniden başlatılınca korunuyor (INSERT OR IGNORE + port/mode UPDATE).',
        ].join('\n'),
      );
      expect(result.status).toBe(200);
      expect(read.status).toBe(200);
      expect(await hostApi.vaultEnabled(env.VAULT_API)).toBe(false);
    });

    await test.step('Mobil: vault kapalıyken dosya inmiyor (403)', async () => {
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('vault kapalı: indirme reddedildi');
      const raw = await hostApi.rawVaultDownload(KEY, deviceId);
      await attachText(
        testInfo,
        `Telefon ve ağ trafiği — ${env.VAULT_API} vault_enabled = false`,
        [
          'TELEFONUN EKRANI',
          status.split('\n').slice(0, 3).join('\n'),
          '',
          `GET https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/vault/${KEY}`,
          describeResponse(raw, { maxBody: 200 }),
          '',
          'Dosya `public` politikalı ve yerinde duruyor; isteği reddeden şey bu Config',
          'API\'nin vault_enabled ayarı. Bu kontrol, erişim politikası kontrolünden ÖNCE',
          'çalışıyor.',
        ].join('\n'),
      );
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('403');
      expect(raw.status).toBe(403);
      expect(raw.body.toString('utf8')).toContain('disabled');
    });

    await test.step('Ağ trafiği: vault kapalıyken hangi dosyaların var olduğu anlaşılmıyor', async () => {
      const present = await hostApi.rawVaultDownload(KEY, deviceId);
      const absent = await hostApi.rawVaultDownload(`yok-${stamp}`, deviceId);
      await attachText(
        testInfo,
        'Var olan ve olmayan dosya — vault kapalı',
        [
          `GET /api/v1/vault/${KEY}        → HTTP ${present.status}`,
          `GET /api/v1/vault/yok-${stamp}  → HTTP ${absent.status}`,
          '',
          'İkisi de 403: vault kapalıyken 403/404 farkına bakarak hangi dosyaların',
          'bulunduğu anlaşılamıyor.',
        ].join('\n'),
      );
      expect(present.status).toBe(403);
      expect(absent.status).toBe(403);
    });

    await test.step('Web: yönetim uçları çalışmaya devam ediyor (temizlik yapılabilsin)', async () => {
      const list = await hostApi.api(`/api/v1/config-apis/${env.VAULT_API}/vault`);
      const upload = await dashboard.uploadVaultText(env.VAULT_API, KEY, `${body}-duzeltildi`, {
        policy: 'public',
      });
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault kapalıyken yönetim açık');
      await attachText(
        testInfo,
        'Vault kapalıyken yönetim uçları',
        [
          `GET …/vault (listeleme) → HTTP ${list.status}, ${list.json ? list.json.length : 0} dosya`,
          `PUT …/vault/${KEY} (yükleme) → yeni sürüm v${upload}`,
          '',
          'Bu ayar dağıtımı durduran bir düğme; ama operatörün yanlışlıkla yayılan',
          'dosyayı inceleyip silebilmesi gerekiyor. Yönetim uçları bu yüzden bilerek',
          'ayarın dışında bırakıldı.',
        ].join('\n'),
      );
      expect(list.status).toBe(200);
      expect(upload).toBeGreaterThan(version);
      version = upload;
    });

    await test.step('Web: "vault aktif" geri açılıyor, telefon yine indiriyor', async () => {
      const result = await dashboard.setVaultEnabled(env.VAULT_API, true);
      defaultFlagChanged = false;
      await dashboard.snap(`"vault aktif" açıldı — ${env.VAULT_API} Genel sekmesi`);
      expect(result.status).toBe(200);
      expect(await hostApi.vaultEnabled(env.VAULT_API)).toBe(true);
      await app.vaultClear(KEY);
      const status = await app.fetchVault(KEY);
      await app.snap('vault açık: indirme çalışıyor');
      expect(status).toContain(`${KEY} v${version} indirildi`);
    });

    await test.step('Web: ikinci Config API\'de (sample-mtls) vault ayrıca kapatılıyor, varsayılan açık kalıyor', async () => {
      await dashboard.uploadVaultText(env.MTLS_API, KEY, mtlsBody, { policy: 'public' });
      const result = await dashboard.setVaultEnabled(env.MTLS_API, false);
      mtlsFlagChanged = true;
      await dashboard.snap(`"vault aktif" kapatıldı — ${env.MTLS_API} Genel sekmesi`);
      const flag = await hostApi.vaultEnabled(env.MTLS_API);
      await attachText(
        testInfo,
        `PUT /api/v1/config-apis/${env.MTLS_API}/vault-enabled {"enabled": false}`,
        [
          `HTTP ${result.status} ${result.body}`,
          `toast: ${result.toast}`,
          `GET …/vault-enabled → vault_enabled = ${flag}`,
          '',
          hostApi.dbQuery('SELECT id, mode, vault_enabled FROM config_apis;'),
        ].join('\n'),
      );
      expect(result.status).toBe(200);
      expect(flag).toBe(false);
      // Varsayılan kapsam açık kaldı: bayrak kapsam başına.
      expect(await hostApi.vaultEnabled(env.VAULT_API)).toBe(true);
    });

    await test.step('Ağ trafiği: mTLS portunda da indirme 403', async () => {
      await dashboard.generateClientCert(env.MTLS_API, certId, { saveTo: P12 });
      splitP12(P12);
      // Cihaz kimliği sertifikaya ait olmalı (DeviceIdBinding): sertifikanın kendi id'si gönderilir.
      const res = await mtlsDownload(KEY, certId);
      await attachText(
        testInfo,
        `GET https://${env.LAN_IP}:${env.MTLS_API_PORT}/api/v1/vault/${KEY} — vault_enabled = false`,
        [
          describeResponse(res, { maxBody: 200 }),
          '',
          'Aynı kontrol mTLS portunda da çalışıyor; ayar Config API\'nin kendisine ait,',
          'portun TLS ya da mTLS olmasına bağlı değil.',
        ].join('\n'),
      );
      expect(res.status).toBe(403);
      expect(res.body.toString('utf8')).toContain('disabled');
    });

    await test.step('Sunucu: vault_enabled ayarı kodda nerede okunuyor', async () => {
      const grep = await attachCommand(
        testInfo,
        'Sunucu kaynak kodunda vault_enabled / vaultEnabled araması',
        'sh',
        ['-c', `cd ${JSON.stringify(PINVAULT_DIR)} && grep -rnE "vault_enabled|vaultEnabledProvider" demo-server/src/main/kotlin || true`],
      );
      await attachText(
        testInfo,
        'Ayar artık indirmeyi gerçekten durduruyor',
        [
          'Ayarı artık yalnızca yönetim uçları okumuyor: VaultRoutes\'taki indirme',
          'yolu her istekte `vaultEnabledProvider()` çağırıyor, Main.kt de bunu Config',
          'API\'nin ConfigApiRegistry kaydına bağlıyor. Ayar her istekte okunduğu için',
          'dashboard\'daki değişiklik, o port yeniden başlatılmadan hemen geçerli oluyor.',
          '',
          'Etkilediği yer: yalnızca GET /api/v1/vault/{key}. Yükleme, listeleme, silme,',
          'token yönetimi ve dağıtım geçmişi bilerek dışarıda. Bu ayar bir kimlik',
          'doğrulama kuralı değil, dağıtımı durduran bir operatör düğmesi. İçeriği',
          'koruyan şey yine her dosyanın kendi access_policy değeri.',
          '',
          grep.split('\n').filter((l) => l.includes('kotlin')).join('\n') || '(kaynak taraması yapılamadı)',
        ].join('\n'),
      );
      expect(grep).toContain('/VaultRoutes.kt');
      expect(grep).toContain('/AdminVaultRoutes.kt');
      expect(grep).toContain('/ConfigApiRegistry.kt');
    });

    await test.step('Web: ikinci Config API\'de de vault geri açılıyor', async () => {
      const result = await dashboard.setVaultEnabled(env.MTLS_API, true);
      mtlsFlagChanged = false;
      await dashboard.snap(`"vault aktif" açıldı — ${env.MTLS_API} Genel sekmesi`);
      expect(result.status).toBe(200);
      expect(await hostApi.vaultEnabled(env.MTLS_API)).toBe(true);
    });
  } finally {
    if (mtlsFlagChanged) await hostApi.setVaultEnabled(env.MTLS_API, true).catch(() => {});
    if (defaultFlagChanged) await hostApi.setVaultEnabled(env.VAULT_API, true).catch(() => {});
    await hostApi.deleteVaultFile(env.VAULT_API, KEY).catch(() => {});
    await hostApi.deleteVaultFile(env.MTLS_API, KEY).catch(() => {});
    await hostApi.revokeClientCertIfActive(certId).catch(() => {});
  }
});
