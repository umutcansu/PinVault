// C02 — Vault `api_key` politikası: cihaz bu dosyayı asla indiremez.
//
// Kütüphane cihazdan yönetim anahtarı göndermez (göndermemeli de: anahtar
// APK'ya gömülmüş olurdu). Sunucu bu politikayı Config API dinleyicisinde
// zorluyor, dolayısıyla telefon her zaman 401 alıyor; aynı dosya yönetim
// anahtarıyla (sunucu-sunucu çağrısı) 200 iniyor.
const { test, expect } = require('../lib/fixtures');
const { attachText, attachCommand, describeResponse, redact } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const env = require('../lib/env');

const KEY = env.VAULT_KEYS.admin;

test('Vault api_key: telefon 401 alıyor, yönetim anahtarıyla 200 iniyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  const secret = `yalnizca-yonetim-${Date.now()}`;
  let version;
  let deviceId;

  try {
    await test.step('Web: dosya api_key politikasıyla yüklenir', async () => {
      version = await dashboard.uploadVaultText(env.VAULT_API, KEY, secret, { policy: 'api_key' });
      const cells = await dashboard.vaultRowCells(KEY);
      await dashboard.snapCard('.card:has(#vault-upload-key) ~ .card', 'vault dosyaları — api_key');
      expect(cells.policy).toContain('api_key');
    });

    await test.step('Mobil: indirme 401 ile reddediliyor', async () => {
      await app.openVault();
      deviceId = app.deviceId();
      const status = await app.fetchVault(KEY);
      await app.snap('api_key dosyası reddedildi (401)');
      expect(status).toContain(`${KEY} indirilemedi`);
      expect(status).toContain('401');
    });

    await test.step('Kablo: anahtarsız istek 401, yönetim anahtarıyla 200', async () => {
      const without = await hostApi.rawVaultDownload(KEY, deviceId);
      await attachText(
        testInfo,
        `GET /api/v1/vault/${KEY} — X-API-Key YOK (cihazın gönderdiği istek)`,
        describeResponse(without, { maxBody: 256 }),
      );
      expect(without.status).toBe(401);
      expect(without.body.toString('utf8')).toContain('X-API-Key header required');

      // Anahtar komut satırına yazılmasın diye ortam değişkeninden geçiriliyor.
      const withKey = await attachCommand(
        testInfo,
        `curl — aynı dosya yönetim anahtarıyla (X-API-Key: ${redact(env.API_KEY)})`,
        'sh',
        ['-c',
          `curl -sS -k --max-time 15 -H "X-API-Key: $PV_API_KEY" -D - ` +
          `https://${env.LAN_IP}:${env.CONFIG_API_PORT}/api/v1/vault/${KEY}`],
        { env: { ...process.env, PV_API_KEY: env.API_KEY } },
      );
      expect(withKey).toContain('200');
      expect(withKey).toContain(secret);

      const viaLibrary = await hostApi.rawVaultDownload(KEY, deviceId, { apiKey: env.API_KEY });
      expect(viaLibrary.status).toBe(200);
      expect(viaLibrary.body.toString('utf8')).toBe(secret);
    });

    await test.step('Web: dağıtım geçmişinde failed kaydı ve nedeni', async () => {
      await dashboard.expectDistribution(env.VAULT_API, {
        key: KEY,
        deviceModel: run.model,
        status: 'failed',
      });
      await dashboard.snap('dağıtım geçmişi — failed (api_key)');
      const dists = await hostApi.vaultDistributions(env.VAULT_API, KEY);
      const mine = dists.find((d) => d.deviceId === deviceId);
      await attachText(
        testInfo,
        'Sunucudaki başarısız dağıtım kaydı',
        [
          `key=${mine.vaultKey} version=${mine.version} status=${mine.status}`,
          `authMethod=${mine.authMethod}`,
          `failureReason=${mine.failureReason}`,
          `cihaz: ${mine.deviceManufacturer} ${mine.deviceModel} (${mine.deviceId})`,
          '',
          'Kütüphane başarısız indirmeyi de raporluyor: hangi yetkilendirmeyle',
          'denendiği (authMethod) ve sunucunun verdiği yanıt geçmişte duruyor.',
        ].join('\n'),
      );
      expect(mine.status).toBe('failed');
      expect(mine.authMethod).toBe('api_key');
      expect(mine.failureReason).toContain('401');
      expect(mine.version).toBe(0);
    });

    await test.step('Sunucu: api_key politikasının cihaz tarafındaki anlamı — değerlendirme', async () => {
      await attachText(
        testInfo,
        'api_key politikası cihazdan kullanılamaz (tasarım)',
        [
          'VaultRoutes: "api_key" dalında X-API-Key başlığı ApiKeyPolicy.matches ile',
          'kontrol ediliyor; başlık yoksa 401, sunucuda API_KEY hiç ayarlı değilse 403',
          '(fail-closed — "yönetim dosyası" sessizce herkese açık hale gelmiyor).',
          '',
          'Kütüphane tarafında bu başlığı gönderecek bir yol YOK: VaultFileConfig',
          'yalnızca accessToken sağlayıcısı taşıyor. Doğru karar — yönetim anahtarının',
          'APK\'ya gömülmesi anahtarı herkese açardı.',
          '',
          'Eksik: VaultFileAccessPolicy.API_KEY kütüphanenin genel API\'sinde seçilebilir',
          'bir değer ve hiçbir uyarı vermiyor; bu politikayla tanımlanan her dosya',
          'sessizce her seferinde 401 alıyor (yalnızca dağıtım geçmişinden görülüyor).',
          'Öneri: (a) kütüphane init sırasında API_KEY politikalı dosya için uyarı',
          'loglasın, (b) dashboard yükleme formunda "cihazdan inmez, yalnızca',
          'sunucu-sunucu" açıklaması dursun.',
        ].join('\n'),
      );
    });
  } finally {
    await hostApi.deleteVaultFile(env.VAULT_API, KEY);
  }
});
