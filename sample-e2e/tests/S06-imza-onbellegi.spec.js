// S06 — İmza önbelleği: her yayında tek imza (CONFIG_SIGNATURE_CACHE=true).
//
// Varsayılan olarak sunucu her config isteğini ayrıca imzalar (yeni issuedAt,
// yeni imza). İmzalayıcı bir HSM/KMS ise bu hem yavaş hem pahalıdır; her
// cihaz sorgusu bir imza çağrısı demektir. Önbellek açıkken aynı içerik BİR KEZ
// imzalanır ve birebir aynı imzalı yanıt tekrar verilir; pin değişikliği
// kaydedilir kaydedilmez imzalanır (prewarm), yani imzalayıcı cihazlar
// sorduğunda değil operatör yayımladığında çağrılır.
//
// Aynı imzalı yanıtın ikinci kez gelmesi eski kütüphaneler için "eski yanıtı
// tekrar gönderme" sayılırdı; bu yüzden önbellekteki yanıtı yalnızca
// `X-PinVault-Features: redelivery` ile aynı yanıtı tekrar kabul edebildiğini
// bildiren (yeni sürüm, kütüphane 2.1+) uygulamalar alır, bildirmeyenlere her
// istekte yeni imza gider. Telefon aynı imzalı yanıtı "Config güncel" sayar.
//
// Ana host üzerinde çalışır (önbellekteki yanıtı yalnızca bunu bildiren
// uygulamalar alır; anahtarlar değişmez). Sonunda ortam .env değerlerine döner.
const crypto = require('crypto');
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

/** Kütüphanenin her config isteğinde gönderdiği başlık (DefaultCertificateConfigApi.FEATURES_HEADER). */
const FEATURES = 'redelivery,multisig,keyset';
const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

function counters(status) {
  const c = status.cache;
  return { produced: c.signaturesProduced, hits: c.cacheHits, cached: c.cachedEnvelopes };
}

function row(label, c) {
  return `${label.padEnd(44)} üretilen imza ${String(c.produced).padStart(4)}   önbellek isabeti ${String(c.hits).padStart(4)}   önbellekteki imzalı yanıt ${c.cached}`;
}

test('Sunucu+Web+Mobil: imza önbelleği — her yayında tek imza; aynı yanıtı tekrar kabul edebildiğini bildiren uygulamaya birebir aynı imzalı yanıt gidiyor, telefon bunu "güncel" sayıyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  const backupPin = hostApi.randomPin();
  let overridden = false;
  let v0;
  let beforePublish;
  let afterPublish;

  try {
    await test.step('Sunucu: imza önbelleği açılır (CONFIG_SIGNATURE_CACHE=true)', async () => {
      await hostControl.setEnv({ CONFIG_SIGNATURE_CACHE: 'true' });
      overridden = true;
      const status = await hostApi.signingStatus();
      await attachText(
        testInfo,
        'env-override.sh + GET /api/v1/signing/status → cache',
        [
          '$ ./scripts/env-override.sh set CONFIG_SIGNATURE_CACHE=true',
          'Host hazır: http://localhost:6650 (set)',
          '',
          JSON.stringify(status.cache, null, 2),
          '',
          `imzalayıcılar: ${status.signers.map((s) => `${s.name} ${s.keyId.slice(0, 16)}…`).join(', ')} (değişmedi)`,
        ].join('\n'),
      );
      expect(status.cache.cacheEnabled).toBe(true);
      expect(status.signers[0].keyId).toBe(run.signing.primaryKeyId);
    });

    await test.step('Terminal: "X-PinVault-Features: redelivery" başlıklı iki istek birebir aynı imzalı yanıtı alıyor; başlıksız istek yeni imzalı yanıt alıyor', async () => {
      const get = (features) =>
        hostApi.api('/api/v1/certificate-config', { withKey: false, headers: features ? { 'X-PinVault-Features': features } : {} });
      const a = await get(FEATURES);
      const b = await get(FEATURES);
      const c = await get();
      const info = (r) => {
        const j = JSON.parse(r.text);
        const p = JSON.parse(j.payload);
        return { sha: sha(r.text), issuedAt: p.issuedAt, signature: j.signature };
      };
      const [ia, ib, ic] = [info(a), info(b), info(c)];
      const line = (label, i) => `${label}  sha256(gövde) ${i.sha.slice(0, 16)}…  issuedAt ${i.issuedAt}  imza ${i.signature.slice(0, 16)}…`;
      await attachText(
        testInfo,
        'Aynı içerik: önbellekteki imzalı yanıt ve yeni imza',
        [
          `$ curl -s -H 'X-PinVault-Features: ${FEATURES}' ${env.WEB_URL}/api/v1/certificate-config | shasum -a 256   # iki kez`,
          `$ curl -s ${env.WEB_URL}/api/v1/certificate-config | shasum -a 256                                            # başlıksız`,
          '',
          line('1. redelivery', ia),
          line('2. redelivery', ib),
          line('3. başlıksız ', ic),
          '',
          `1 ve 2 bayt bayt aynı: ${a.text === b.text ? 'evet ✓' : 'HAYIR'} — aynı issuedAt, aynı imza (önbellekten)`,
          `3 farklı            : ${c.text !== a.text ? 'evet ✓' : 'HAYIR'} — yeni issuedAt, yeni imza (eski sürüm uygulama bunu tekrar gönderilmiş eski yanıt sanmasın)`,
        ].join('\n'),
      );
      expect(a.text).toBe(b.text);
      expect(c.text).not.toBe(a.text);
      expect(ic.issuedAt).toBeGreaterThan(ia.issuedAt);
      expect(ic.signature).not.toBe(ia.signature);
    });

    await test.step('Web: İmzalama sekmesi — imza önbelleği açık; üretilen imza ve önbellek isabeti sayaçları', async () => {
      await dashboard.reload();
      await dashboard.openSigning(env.VAULT_API);
      const stats = await dashboard.sigCacheStats();
      await dashboard.snapCard('#sig-cache-card', 'İmza önbelleği kartı: açık, isabet sayacı');
      await attachText(testInfo, 'Dashboard → İmza Önbelleği', JSON.stringify(stats, null, 2));
      expect(stats.enabled).toBe(true);
      expect(stats.hits).toBeGreaterThanOrEqual(1);
    });

    await test.step('Mobil: sıfırdan açılan uygulama önbellekteki imzalı yanıtı uygular; iki kez yenile → ikisi de "Config güncel" (birebir aynı yanıt, eski yanıtın tekrar gönderilmesi sayılmıyor)', async () => {
      const s0 = counters(await hostApi.signingStatus());
      app.launchFresh();
      await app.waitReady();
      const r1 = await app.refreshConfig();
      await app.snap('önbellekteki imzalı yanıt 1. kez yeniden geldi: Config güncel');
      const r2 = await app.refreshConfig();
      await app.snap('önbellekteki imzalı yanıt 2. kez yeniden geldi: Config güncel');
      const s1 = counters(await hostApi.signingStatus());
      await attachText(
        testInfo,
        'Telefonun iki yenilemesi ve sunucunun sayaçları',
        [
          row('telefon açılmadan önce', s0),
          row('açılış + iki yenilemeden sonra', s1),
          '',
          `1. yenileme: ${r1.split('\n')[0]}`,
          `2. yenileme: ${r2.split('\n')[0]}`,
          '',
          'Telefon açılışta önbellekteki imzalı yanıtı uyguladı (issuedAt değerini sakladı); sonraki',
          'yenilemelerde birebir AYNI yanıt geldi. Kütüphane aynı issuedAt + aynı pin\'leri "zaten güncel"',
          'sayıyor; "eski yanıt tekrar gönderildi" diye reddetmesi yalnızca DAHA ESKİ bir issuedAt için.',
          'Sunucu bu sürede hiç imza atmadı.',
        ].join('\n'),
      );
      expect(r1).toContain('Config güncel');
      expect(r2).toContain('Config güncel');
      expect(`${r1}\n${r2}`).not.toMatch(/replay/i);
      expect(s1.produced).toBe(s0.produced);
      expect(s1.hits).toBeGreaterThanOrEqual(s0.hits + 3);
    });

    await test.step('Web: hedef host\'a yedek pin eklenir (yayın) — config, değişiklik kaydedilir kaydedilmez imzalanıyor; cihaz sormadan önce', async () => {
      // İmzalama sekmesini açan tıklama API ağacını kapatmış olabilir: host,
      // ağacı açık tutan yoldan açılır.
      await dashboard.openHostIn(env.VAULT_API, TARGET_HOST);
      v0 = await dashboard.version();
      beforePublish = counters(await hostApi.signingStatus());
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, backupPin]);
      await expect.poll(() => dashboard.version()).toBe(v0 + 1);
      afterPublish = counters(await hostApi.signingStatus());
      await dashboard.snapHostSummary(`yayımlandı: ${TARGET_HOST} v${v0 + 1}`);
      await attachText(
        testInfo,
        'Değişiklik kaydedilir kaydedilmez imza (prewarm)',
        [
          row('yayından önce', beforePublish),
          row(`yayından hemen sonra (telefon henüz sormadı)`, afterPublish),
          '',
          `imza sayacı: +${afterPublish.produced - beforePublish.produced} — pin yazımı config'i o anda imzaladı ve önbelleğe koydu.`,
          'İmzalayıcı (HSM/KMS) operatörün yayınıyla çağrılıyor, cihazların sorgusuyla değil.',
        ].join('\n'),
      );
      expect(afterPublish.produced).toBeGreaterThan(beforePublish.produced);
      expect(afterPublish.cached).toBeGreaterThanOrEqual(1);
    });

    await test.step('Mobil: config yenile → yeni sürüm geldi (kayıt anında atılan imzayla); tekrar yenile → "Config güncel"; imza sayacı artmadı', async () => {
      const r3 = await app.refreshConfig();
      await app.snap(`yeni sürüm v${v0 + 1}: kayıt anında atılmış imza`);
      const s3 = counters(await hostApi.signingStatus());
      const r4 = await app.refreshConfig();
      await app.snap(`aynı imzalı yanıt yeniden: Config güncel (v${v0 + 1})`);
      const s4 = counters(await hostApi.signingStatus());
      await attachText(
        testInfo,
        'Cihazın sorgularına önbellekten yanıt',
        [
          row('yayından hemen sonra', afterPublish),
          row('telefon yeni sürümü aldı', s3),
          row('telefon tekrar sordu', s4),
          '',
          `yenileme 1: ${r3.split('\n')[0]}  → ${TARGET_HOST} v${SampleApp.hostVersion(r3, TARGET_HOST)}`,
          `yenileme 2: ${r4.split('\n')[0]}`,
          '',
          'Yayından sonra hiç yeni imza yok: telefonun iki sorgusu da kayıt anında atılan imzayı aldı.',
        ].join('\n'),
      );
      expect(r3).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(r3, TARGET_HOST)).toBe(v0 + 1);
      expect(r4).toContain('Config güncel');
      expect(s3.produced).toBe(afterPublish.produced);
      expect(s4.produced).toBe(afterPublish.produced);
      expect(s4.hits).toBeGreaterThan(afterPublish.hits);
    });
  } finally {
    // Fixture'ın temizliği (temel pin'ler) ortam sıfırlandıktan sonra çalışır.
    if (overridden) {
      await test.step('Sunucu: ortam .env değerlerine döner (imza önbelleği kapalı)', async () => {
        await hostControl.resetEnv();
        const status = await hostApi.signingStatus();
        await attachText(
          testInfo,
          'env-override.sh reset → GET /api/v1/signing/status → cache',
          ['$ ./scripts/env-override.sh reset', 'Host hazır: http://localhost:6650 (reset)', '', JSON.stringify(status.cache, null, 2)].join('\n'),
        );
        expect(status.cache.cacheEnabled).toBe(false);
      });
    }
  }
});
