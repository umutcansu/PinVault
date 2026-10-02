// G09 — Ağ trafiğine eklenen sahte imzalama anahtarı seti.
//
// Anahtar setleri (hangi imzalama anahtarlarına güvenileceği) yalnızca
// uygulamaya gömülü KURTARMA anahtarıyla imzalanabilir. Burada saldırgan
// sunucunun imzalama anahtarını ele geçirmiş kabul edilir: saldırgan proxy
// pin'i tutan host kimliğiyle araya girer ve imzalı config yanıtına kendi
// anahtarını "tek güvenilir anahtar" ilan eden bir set ekler — seti imzalama
// anahtarıyla imzalayarak. Config'in kendi imzası geçerli; yine de:
//
//   • telefon bütün yanıtı reddediyor ("Signing-key set rejected — 0 of 1
//     required recovery signature(s) valid"), config uygulanmıyor,
//   • güvenilen anahtarlar ve saklı config değişmiyor, pinli istek sürüyor,
//   • aynı yolla gelen, kurtarma anahtarıyla (recovery-1) imzalı GEÇERLİ set
//     ise uygulanıyor: cihaz tam olarak kurtarma anahtarının izin verdiğini
//     kabul ediyor.
//
// Emülatörde koşar (iptables DNAT). Ana host'a dokunmaz; setin kalıcı kopyası
// senaryo sonunda uygulama verisiyle birlikte silinir.
const crypto = require('crypto');
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const proxy = require('../lib/proxy');
const hostApi = require('../lib/hostApi');
const offlineKeys = require('../lib/offlineKeys');
const env = require('../lib/env');

test('Saldırı: çalınmış imzalama anahtarıyla imzalı sahte anahtar seti eklenir → telefon bütün yanıtı reddediyor; kurtarma anahtarıyla imzalı set uygulanıyor', async ({
  app,
  device,
  run,
}, testInfo) => {
  test.skip(!device.isEmulator(), 'iptables DNAT yalnızca emülatörde (root) kurulabilir');
  test.setTimeout(10 * 60 * 1000);

  const backup = offlineKeys.ensure('backup-1');
  const recovery = offlineKeys.ensure('recovery-1');
  const seen = [];
  let mitm;
  let primary;
  let names;

  try {
    await test.step('Saldırgan: sunucunun kendi TLS anahtarıyla araya girer, henüz bir şey değiştirmiyor → telefon uygulamaya gömülü imza anahtarlarıyla (anahtar seti v0) Hazır', async () => {
      primary = await hostApi.signingKeyInfo();
      names = {
        [primary.keyId]: 'ana host birincil',
        [backup.keyId]: 'backup-1 (çevrimdışı yedek)',
        [recovery.keyId]: 'recovery-1 (kurtarma)',
      };
      mitm = await proxy.start({ identity: 'trusted' });
      device.redirectTcp(env.LAN_IP, env.CONFIG_API_PORT, env.PROXY_PORT);
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan henüz bir şey değiştirmiyor: anahtar seti v0, iki güvenilen anahtar');
      const sig = SampleApp.signingOf(ready);
      await attachText(
        testInfo,
        'Saldırganın kimliği ve telefonun imza durumu',
        [
          `saldırganın pin'i   : ${proxy.certPin('trusted')}`,
          `host'un pin dosyası : ${hostApi.hostPins().join(', ')}`,
          'eşleşme             : var ✓ — TLS katmanı itiraz etmiyor (test gereği sunucunun gerçek TLS anahtarı kullanılıyor)',
          '',
          ready.split('\n').filter((l) => /Hazır|İmza|imzalayan/.test(l)).join('\n'),
          '',
          `APK'nın güvendiği: ${primary.keyId.slice(0, 16)}… (ana host birincil), ${backup.keyId.slice(0, 16)}… (backup-1)`,
          `kurtarma anahtarı: ${recovery.keyId.slice(0, 16)}… (recovery-1) — yalnızca anahtar setini (telefonun güvendiği imza anahtarlarının listesi) imzalar`,
        ].join('\n'),
      );
      expect(sig.keySetVersion).toBe(0);
      expect(sig.trusted).toBe(2);
      expect(run.signing.recoveryKeyId).toBe(recovery.keyId);
    });

    await test.step('Saldırgan: yanıta, kurtarma anahtarıyla DEĞİL imzalama anahtarıyla imzaladığı sahte bir anahtar seti ekler → telefon bütün yanıtı reddediyor', async () => {
      const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const attackerPub = attacker.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
      const attackerKeyId = offlineKeys.keyIdOf(attackerPub);
      names[attackerKeyId] = 'saldırganın anahtarı';
      const payload = JSON.stringify({ type: 'pinvault-signing-keys', version: 1, keys: [attackerPub] });
      const forged = { payload, signatures: [{ keyId: primary.keyId, signature: proxy.hostSigner()(payload) }] };
      mitm.setMutate(proxy.injectKeySet(forged, seen));
      const status = await app.refreshConfig();
      await app.snap('sahte anahtar seti: config yenilenemedi');
      const wire = seen[seen.length - 1];
      await attachText(
        testInfo,
        'Saldırganın yaptığı değişiklik (GET /api/v1/certificate-config)',
        [
          'SUNUCUNUN GÖNDERDİĞİ',
          `  signingKeys : ${JSON.parse(wire.before).signingKeys ? 'var' : 'yok (ana host anahtar seti dağıtmıyor)'}`,
          `  signature   : ${JSON.parse(wire.before).signature.slice(0, 20)}… (config imzası, geçerli)`,
          '',
          'TELEFONUN ALDIĞI (saldırgan signingKeys alanını ekledi)',
          `  payload     : ${payload.slice(0, 60)}…`,
          `  set sürümü  : v1, listelenen: ${attackerKeyId.slice(0, 16)}… (saldırganın anahtarı — tek güvenilir anahtar ilan ediliyor)`,
          `  set imzası  : keyId ${primary.keyId.slice(0, 16)}… (ana host'un İMZALAMA anahtarı — test gereği çalındığı varsayılıyor)`,
          `  config imzası değişmedi: ${JSON.parse(wire.after).signature === JSON.parse(wire.before).signature ? 'evet' : 'HAYIR'}`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').slice(0, 2).join('\n'),
        ].join('\n'),
      );
      expect(status).toContain('Config yenilenemedi');
      expect(status).toContain('Signing-key set rejected — 0 of 1 required recovery signature(s) valid');
    });

    await test.step('Mobil: Depolama — anahtar seti v0, güvenilen anahtarlar değişmedi; saklı config ile pinli istek sürüyor', async () => {
      await app.openStorage();
      const detail = SampleApp.signingDetailOf(await app.storageText());
      await app.snap('sahte set reddedildikten sonra Depolama: anahtar seti v0, iki gömülü anahtar');
      await app.backToMain();
      const pinned = await app.testLibraryClient();
      await app.snap(`sahte set sonrası: ${TARGET_HOST} pinli istek başarılı`);
      await attachText(
        testInfo,
        'Depolama (PinVault.signingStatus) + pinli istek',
        [
          detail.text,
          '',
          ...detail.trusted.map((id) => `güvenilen ${id} = ${names[id] || '?'}`),
          '',
          pinned.split('\n').slice(0, 2).join('\n'),
        ].join('\n'),
      );
      expect(detail.keySetVersion).toBe(0);
      expect(new Set(detail.trusted)).toEqual(new Set([primary.keyId, backup.keyId]));
      expect(pinned).toContain('Pinned bağlantı başarılı');
    });

    await test.step('Saldırgan: aynı yoldan bu kez kurtarma anahtarıyla (recovery-1) imzalı GEÇERLİ bir set ekler {ana birincil, backup-1} → telefon uyguluyor', async () => {
      const valid = offlineKeys.keySet({ version: 1, keys: [primary.publicKey, backup.pub], signers: [recovery] });
      mitm.setMutate(proxy.injectKeySet(valid, seen));
      const status = await app.refreshConfig();
      await app.snap('kurtarma anahtarıyla imzalı set uygulandı: v1');
      const sig = SampleApp.signingOf(status);
      await attachText(
        testInfo,
        'Geçerli anahtar seti (kurtarma anahtarıyla imzalı)',
        [
          `payload     : ${valid.payload.slice(0, 60)}…`,
          `set sürümü  : v1, listelenen: ${JSON.parse(valid.payload).keys.map((k) => names[offlineKeys.keyIdOf(k)] || '?').join(', ')}`,
          `set imzası  : keyId ${valid.signatures[0].keyId.slice(0, 16)}… (recovery-1)`,
          '',
          'TELEFONUN CEVABI',
          status.split('\n').filter((l) => /Config|İmza|imzalayan/.test(l)).join('\n'),
        ].join('\n'),
      );
      expect(status).toMatch(/Config güncel|Yeni config uygulandı/);
      expect(sig.keySetVersion).toBe(1);
      expect(sig.trusted).toBe(2);
      expect(sig.signedBy).toEqual([primary.keyId.slice(0, 12)]);
    });

    await test.step('Mobil: Depolama — anahtar seti v1 (sunucudan gelen, kurtarma anahtarıyla imzalı); telefon yalnızca setteki iki anahtara güveniyor', async () => {
      await app.openStorage();
      const detail = SampleApp.signingDetailOf(await app.storageText());
      await app.snap('Depolama: anahtar seti v1, kurtarma anahtarının izin verdiği iki anahtar');
      await attachText(
        testInfo,
        'Depolama (PinVault.signingStatus)',
        [detail.text, '', ...detail.trusted.map((id) => `güvenilen ${id} = ${names[id] || '?'}`)].join('\n'),
      );
      expect(detail.keySetVersion).toBe(1);
      expect(detail.fromServer).toBe(true);
      expect(new Set(detail.trusted)).toEqual(new Set([primary.keyId, backup.keyId]));
      await app.backToMain();
    });

    await test.step('Terminal: yönlendirme kaldırılır → doğrudan sunucuyla Hazır; uygulanan anahtar seti v1 kalıcı', async () => {
      device.clearNetRules();
      await mitm.stop();
      mitm = null;
      app.relaunch();
      const ready = await app.waitReady();
      await app.snap('saldırgan proxy kapandı: doğrudan sunucuyla Hazır, anahtar seti v1');
      const rules = device.rootShell('iptables -t nat -S OUTPUT');
      await attachText(
        testInfo,
        'iptables + telefonun durumu',
        [
          '$ adb shell su 0 iptables -t nat -S OUTPUT',
          rules.trim(),
          '',
          ready.split('\n').filter((l) => /Hazır|İmza|imzalayan/.test(l)).join('\n'),
        ].join('\n'),
      );
      expect(rules).not.toContain(`--dport ${env.CONFIG_API_PORT}`);
      expect(SampleApp.signingOf(ready).keySetVersion).toBe(1);
    });
  } finally {
    device.clearNetRules();
    if (mitm) await mitm.stop();
    // Uygulanan set cihazda kalıcı (pinvault_secure_signing_keys.xml); verisi
    // silinmiş açılış onu da siler, telefon temel durumda kalır. Asıl hatayı
    // gölgelemesin diye burada düşülmez.
    try {
      app.launchFresh();
      await app.waitReady();
    } catch (e) {
      console.warn(`[G09] temizlikte uygulama açılamadı: ${e.message}`);
    }
  }
});
