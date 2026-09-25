// S01 — Çevrimdışı yedek imzalama anahtarı: birincil anahtar kaybolunca (ya da
// çalınınca) sunucu yedeğe geçer, sahadaki uygulama GÜNCELLENMEDEN config
// almaya devam eder.
//
// Uygulama tek bir anahtara değil bir anahtar listesine güveniyor
// (ConfigApiBlock.signaturePublicKeys): sunucunun birincil anahtarı + özel
// yarısı hiç sunucuya girmemiş çevrimdışı bir yedek. Yedek, operatörün kendi
// makinesinde `signing-keys.sh gen` ile üretilir; public yarısı APK'ya gömülür.
// Birincil kaybolduğunda operatör yedeği `signing-keys.sh install` ile
// sunucunun imzalayıcısı yapar ve container'ı yeniden başlatır — telefon
// imzalayanın değiştiğini görür ama config'i kabul etmeye devam eder.
//
// Geçici test sunucusunda çalışır (ana host'un anahtarı ana APK'ya gömülü;
// değişirse bütün suite çöker). Sonunda geçici test sunucusunun özgün anahtarı
// geri konur ve ana APK geri kurulur.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const fresh = require('../lib/freshHost');
const lab = require('../lib/signingLab');

test('Sunucu+Mobil: birincil imza anahtarı kaybolunca sunucu çevrimdışı saklanan yedek anahtara geçiyor; telefon uygulama güncellemesi olmadan config almaya devam ediyor', async ({
  device,
  browser,
}, testInfo) => {
  test.setTimeout(30 * 60 * 1000);
  const app = new SampleApp(device, testInfo);
  let dashboard;
  let setup;
  let backup;
  let apkBefore;
  let swapped = false;

  try {
    await test.step('Terminal: operatör yedek imza anahtarını (lab-backup) kendi makinesinde üretir; anahtar çevrimdışı kalır', async () => {
      await lab.ensureFresh();
      backup = await lab.showKey(testInfo, lab.KEYS.backup, 'signing-keys.sh: çevrimdışı yedek anahtar (private key sunucuya hiç gitmez)');
      expect(backup.keyId).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    });

    await test.step('Terminal+Mobil: bu test için derlenen uygulama (birincil ve yedek anahtar gömülü) Hazır; config geçici test sunucusunun BİRİNCİL anahtarıyla imzalı', async () => {
      setup = await lab.setup(device, testInfo);
      apkBefore = lab.installedApk(device);
      app.launchFresh();
      await app.waitReady();
      const refreshed = await app.refreshConfig();
      await app.snap('bu test için derlenen uygulama: config birincil anahtarla imzalı');
      const info = await lab.signingKeyInfo();
      const sig = SampleApp.signingOf(refreshed);
      await attachText(
        testInfo,
        'Telefon ↔ sunucu: config\'i imzalayan anahtar',
        [
          'TELEFON (config yenile)',
          refreshed.split('\n').filter((l) => /Config|İmza|imzalayan/.test(l)).join('\n'),
          '',
          'SUNUCU (GET /api/v1/signing-key)',
          `birincil keyId : ${info.keyId}`,
          `imzalayıcılar  : ${info.signers.length}`,
          '',
          `telefondaki "Son config'i imzalayan" = sunucunun birincil anahtarının ilk 12 karakteri: ${sig && sig.signedBy[0] === info.keyId.slice(0, 12) ? 'evet ✓' : 'HAYIR'}`,
          `yedek anahtar (${lab.KEYS.backup}) henüz imza atmıyor: ${backup.keyId.slice(0, 12)}…`,
          '',
          `kurulu APK: ${apkBefore.sha256} (sha256, cihazdaki base.apk)`,
        ].join('\n'),
      );
      expect(refreshed).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(info.keyId).toBe(setup.primary.keyId);
      expect(sig).not.toBeNull();
      expect(sig.trusted).toBe(3);
      expect(sig.keySetVersion).toBe(0);
      expect(sig.signedBy).toEqual([info.keyId.slice(0, 12)]);
    });

    await test.step('Sunucu: birincil anahtar "kayboldu"; operatör yedek anahtarı signing-keys.sh install ile kurar ve container yeniden başlatılır', async () => {
      lab.savePrimaryKeyFile();
      swapped = true;
      await lab.op(testInfo, 'Operatör: yedek anahtarı sunucunun imzalayıcısı yap', {
        display: `OFFLINE_KEYS_DIR=${lab.REL_KEYS} ./scripts/signing-keys.sh install ${lab.KEYS.backup}`,
        file: './scripts/signing-keys.sh',
        args: ['install', lab.KEYS.backup],
        note: '(test için: özgün data/signing-key.pem, senaryo sonunda geri konmak üzere .local/signing-lab altında saklandı)',
      });
      const restartOut = await lab.restart();
      const after = await lab.signingKeyInfo();
      await attachText(
        testInfo,
        'docker compose restart → GET /api/v1/signing-key',
        [
          '$ docker compose restart pinvault-host',
          restartOut,
          '',
          `$ curl -s ${fresh.WEB_URL}/api/v1/signing-key | jq '{keyId, signers: [.signers[].keyId]}'`,
          JSON.stringify({ keyId: after.keyId, signers: after.signers.map((s) => s.keyId) }, null, 2),
          '',
          `önceki birincil (kayıp) : ${setup.primary.keyId}`,
          `şimdiki birincil        : ${after.keyId}`,
          `${lab.KEYS.backup} anahtar kimliği: ${backup.keyId}  → ${after.keyId === backup.keyId ? 'aynı ✓' : 'FARKLI'}`,
        ].join('\n'),
      );
      expect(after.keyId).toBe(backup.keyId);
      expect(after.signers).toHaveLength(1);
    });

    await test.step('Web: İmzalama sekmesinde tek imzalayıcı artık yedek anahtar', async () => {
      dashboard = await fresh.openDashboard(browser, testInfo);
      await dashboard.openSigning('default-tls');
      const rows = await dashboard.signerRows();
      await dashboard.snapCard('#signers-card', 'İmzalayıcılar: birincil artık lab-backup');
      await attachText(
        testInfo,
        'Dashboard → İmzalama → İmzalayıcılar',
        rows.map((r) => `${r.name} (${r.type}${r.primary ? ', birincil' : ''}) — ${r.keyId} — ${r.description}`).join('\n'),
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].primary).toBe(true);
      expect(rows[0].keyId).toBe(backup.keyId);
    });

    await test.step('Mobil: config yenile → yedek anahtarın imzası kabul ediliyor; APK değişmedi', async () => {
      const status = await app.refreshConfig();
      await app.snap('config yedek anahtarla imzalı: kabul edildi');
      const sig = SampleApp.signingOf(status);
      const apkAfter = lab.installedApk(device);
      await attachText(
        testInfo,
        'Uygulama güncellemesi olmadan imzalayan değişti',
        [
          'TELEFON (config yenile)',
          status.split('\n').filter((l) => /Config|İmza|imzalayan|yenilenemedi/.test(l)).join('\n'),
          '',
          `imzalayan (telefon) : ${sig ? sig.signedBy.join(', ') : '?'}`,
          `${lab.KEYS.backup} kimliği  : ${backup.keyId.slice(0, 12)}…`,
          '',
          `kurulu APK önce : ${apkBefore.sha256}`,
          `kurulu APK şimdi: ${apkAfter.sha256}  → ${apkAfter.sha256 === apkBefore.sha256 ? 'aynı APK ✓' : 'DEĞİŞTİ'}`,
          '',
          'Yedek anahtar APK\'ya baştan gömülü (signaturePublicKeys) olduğu için imzası',
          'geçerli sayılıyor; sunucunun eski anahtarına artık ihtiyaç yok.',
        ].join('\n'),
      );
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(status).not.toContain('Config yenilenemedi');
      expect(sig.signedBy).toEqual([backup.keyId.slice(0, 12)]);
      expect(apkAfter.sha256).toBe(apkBefore.sha256);
    });

    await test.step('Mobil: uygulama verisi silinip sıfırdan açılınca da aynı APK, yedek anahtarın imzasıyla Hazır oluyor', async () => {
      app.launchFresh();
      const ready = await app.waitReady();
      await app.snap('sıfırdan açılış: yedek anahtarla Hazır');
      const sig = SampleApp.signingOf(ready);
      await attachText(testInfo, 'Sıfırdan açılış (pm clear) — durum kutusu', ready);
      expect(sig.signedBy).toEqual([backup.keyId.slice(0, 12)]);
      expect(sig.keySetVersion).toBe(0);
    });
  } finally {
    await test.step('Sunucu+Terminal: geçici test sunucusunun özgün anahtarı geri konur; telefona ana host için derlenen APK geri kurulur', async () => {
      const lines = [];
      if (swapped && lab.restorePrimaryKeyFile()) {
        lines.push('$ cp .local/signing-lab/fresh-signing-key.orig.pem data/signing-key.pem   (özgün anahtar, 0600)');
        lines.push('$ docker compose restart pinvault-host', await lab.restart());
      }
      const info = await lab.signingKeyInfo();
      lines.push('', `geçici test sunucusunun birincil anahtarı: ${info.keyId}${setup ? ` (özgün: ${info.keyId === setup.primary.keyId ? 'evet' : 'HAYIR'})` : ''}`);
      await attachText(testInfo, 'Geri dönüş: geçici test sunucusunun imza anahtarı', lines.join('\n'));
      await lab.restoreMain(device, app, testInfo);
      if (setup) expect(info.keyId).toBe(setup.primary.keyId);
    });
    if (dashboard) await dashboard.page.close();
  }
});
