// D04 — forceUpdate bayrağı saklı config'te kalıcı; kapanması da cihaza ulaşıyor.
//
// Sunucu force açıkken servis ettiği config'i `forceUpdate: true` ile
// damgalıyor; CertificateConfigStore bunu şifreli depoya yazıyor ve uygulama
// yeniden açıldığında ağdan bir şey gelmeden önce depodan okuyor
// (PinVault.isForceUpdate → Depolama ekranı).
//
// Kapanma yönü de artık ulaşıyor: bayrak sunucuda kapatılınca kütüphane sürüm
// değişmese bile saklı kopyadaki bayrağı siliyor. Sonuç yine "Config güncel"
// (pin'lerle ilgili hiçbir şey değişmedi, yeni bir config uygulanmadı) ama
// diskteki bayrak kapanıyor.
//
// Bulgu neydi: değişiklik tespiti (hasChanges) bayrağın AÇILMASINI değişiklik
// sayıyor, KAPANMASINI saymıyordu; gelen config AlreadyCurrent olarak elenip
// diske hiç yazılmıyordu. Etkisi kozmetik değildi: force açık saklı config,
// sunucuya ulaşılamayan bir açılışta init'i düşürüyor (F01), yani operatör
// force'u kapatsa bile cihaz çevrimdışı açılışta başlatılamaz kalıyordu.
const { test, expect, TARGET_HOST } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');

test('Depolama: forceUpdate saklı config\'te kalıcı; kapatılınca saklı kopyadan siliniyor', async ({
  app,
  device,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(8 * 60 * 1000);

  const storageForce = async () => {
    await app.openStorage();
    const text = await app.refreshStorage();
    const line = text.split('\n').find((l) => l.startsWith('forceUpdate')) || '';
    await app.backToMain();
    return { line, text };
  };

  try {
    await test.step('Mobil: başlangıçta forceUpdate kapalı', async () => {
      const { line } = await storageForce();
      await app.openStorage();
      await app.snap('Depolama ekranı — forceUpdate kapalı');
      await app.backToMain();
      expect(line).toContain('kapalı');
    });

    await test.step('Web: host için force update açılır', async () => {
      await dashboard.openHost(TARGET_HOST);
      await dashboard.setForce(TARGET_HOST, true);
      await dashboard.snap('force update aktif');
      expect(await dashboard.forceActive(TARGET_HOST)).toBe(true);
    });

    await test.step('Mobil: config yenilenince Depolama "açık" diyor', async () => {
      expect(await app.refreshConfig()).toContain('Yeni config uygulandı');
      const { line } = await storageForce();
      await app.openStorage();
      await app.snap('Depolama ekranı — forceUpdate açık');
      await app.backToMain();
      await attachText(
        testInfo,
        'Depolama ekranı — force açıkken',
        [
          line,
          '',
          'Sunucu servis ettiği config\'i hasAnyForceUpdate() ile damgalıyor; kütüphane',
          'bayrağı config nesnesiyle birlikte şifreli depoya yazıyor.',
        ].join('\n'),
      );
      expect(line).toContain('açık');
    });

    await test.step('Mobil: uygulama yeniden açılınca bayrak saklı config\'ten geliyor', async () => {
      device.clearLogcat();
      app.relaunch();
      await app.waitReady();
      const { line } = await storageForce();
      await app.openStorage();
      await app.snap('yeniden açılış sonrası — forceUpdate açık');
      await app.backToMain();
      const log = device.logcat({ tags: ['CertificateConfigStore'] });
      await attachText(
        testInfo,
        'logcat — açılışta saklı config okuması',
        [
          log || '(ilgili satır yok)',
          '',
          'Bu satır ağ isteğinden ÖNCE basılıyor: bayrak sunucudan değil diskten geliyor.',
          '',
          `Depolama ekranı: ${line}`,
        ].join('\n'),
      );
      expect(log).toMatch(/Certificate config loaded.*forceUpdate: true/);
      expect(line).toContain('açık');
    });

    await test.step('Web: force update kapatılır', async () => {
      await dashboard.openHost(TARGET_HOST);
      await dashboard.setForce(TARGET_HOST, false);
      await dashboard.snap('force update pasif');
      expect(await dashboard.forceActive(TARGET_HOST)).toBe(false);
    });

    await test.step('Mobil: sürüm değişmese de bayrak cihazda kapanıyor', async () => {
      const refresh = await app.refreshConfig();
      const { line } = await storageForce();
      await app.openStorage();
      await app.snap('force kapatıldı — cihazda da kapandı');
      await app.backToMain();
      await attachText(
        testInfo,
        'Force bayrağının KAPANMASI da cihaza ulaşıyor',
        [
          `Telefon yenileme sonucu: ${refresh.split('\n')[0]}`,
          `Depolama ekranı: ${line}`,
          '',
          'İki sonuç aynı anda doğru ve kasıtlı:',
          '  • "Config güncel" — pin\'lerle ilgili hiçbir şey değişmedi, yeni bir',
          '    config uygulanmadı, sonuç hâlâ UpdateResult.AlreadyCurrent.',
          '  • Depolama "kapalı" — kütüphane bayraklar farklıysa saklı (ve daha önce',
          '    doğrulanmış) config\'i bayrakları güncelleyerek diske geri yazıyor.',
          '    Uzaktan gelen ham config diske yazılmıyor; canlı istemci de',
          '    değiştirilmiyor, çünkü pin\'ler aynı.',
          '',
          'Bu yalnızca kozmetik bir düzeltme değil: forceUpdate açık bir saklı config,',
          'açılışta başarılı bir güncelleme ZORUNLU kılıyor (F01: sunucuya ulaşılamazsa',
          'ForceUpdateFailedException ile init düşüyor). Bayrak diske ulaşmasaydı,',
          'operatör force\'u kapatsa bile o cihaz sürüm değişene kadar çevrimdışı',
          'açılışlarda başlatılamaz kalırdı.',
          '',
          'Önceki davranış: hasChanges bayrağın yalnızca AÇILMASINI değişiklik sayıyor,',
          'gelen config AlreadyCurrent olarak elenip diske hiç yazılmıyordu; Depolama',
          'ekranı bu adımda "açık" diyordu.',
        ].join('\n'),
      );
      expect(refresh).toContain('Config güncel');
      expect(line).toContain('kapalı');
    });

    await test.step('Mobil: yeniden açılışta da kapalı (diske gerçekten yazıldı)', async () => {
      device.clearLogcat();
      app.relaunch();
      await app.waitReady();
      const { line } = await storageForce();
      const log = device.logcat({ tags: ['CertificateConfigStore'] });
      await attachText(
        testInfo,
        'logcat — bayrak kapandıktan sonraki açılış',
        [
          log || '(ilgili satır yok)',
          '',
          `Depolama ekranı: ${line}`,
          '',
          'Bu satır ağ isteğinden ÖNCE basılıyor: bayrağın kapalı geldiği yer disk.',
          'F01\'deki "force açıkken host kapalıysa init düşer" kapısı artık operatör',
          'bayrağı kapatınca gerçekten kapanıyor.',
        ].join('\n'),
      );
      expect(log).toMatch(/Certificate config loaded.*forceUpdate: false/);
      expect(line).toContain('kapalı');
    });

    await test.step('Web: sürümü değiştiren bir işlem yapılır (yedek pin eklenir)', async () => {
      await dashboard.openHost(TARGET_HOST);
      const before = await dashboard.version();
      await dashboard.setPins(TARGET_HOST, [...run.goodPins, hostApi.randomPin()]);
      await expect.poll(() => dashboard.version()).toBe(before + 1);
      await dashboard.snap('pin sürümü artırıldı');
    });

    await test.step('Mobil: gerçek bir sürüm değişiminde de bayrak kapalı kalıyor', async () => {
      expect(await app.refreshConfig()).toContain('Yeni config uygulandı');
      let result = await storageForce();
      expect(result.line).toContain('kapalı');
      device.clearLogcat();
      app.relaunch();
      await app.waitReady();
      result = await storageForce();
      await app.openStorage();
      await app.snap('sürüm değişti, force kapalı kaldı');
      await app.backToMain();
      const log = device.logcat({ tags: ['CertificateConfigStore'] });
      await attachText(
        testInfo,
        'logcat — sürüm değişiminden sonraki açılış',
        [
          log || '(ilgili satır yok)',
          '',
          `Depolama ekranı: ${result.line}`,
          '',
          'Config gerçekten yeniden yazıldığında (yeni sürüm) bayrak yine kapalı',
          'geliyor: iki yol da aynı sonuca varıyor, biri "yeni config uygulandı",',
          'diğeri "config güncel ama bayrak diske yazıldı".',
        ].join('\n'),
      );
      expect(log).toMatch(/Certificate config loaded.*forceUpdate: false/);
      expect(result.line).toContain('kapalı');
    });

    await test.step('Web: pin\'ler temel duruma döndürülür', async () => {
      await dashboard.openHost(TARGET_HOST);
      await dashboard.setPins(TARGET_HOST, run.goodPins);
      await dashboard.snap('pin\'ler temel durumda');
      expect(await dashboard.viewedPins(TARGET_HOST)).toEqual(run.goodPins);
    });
  } finally {
    await dashboard.setForce(TARGET_HOST, false).catch(() => {});
  }
});
