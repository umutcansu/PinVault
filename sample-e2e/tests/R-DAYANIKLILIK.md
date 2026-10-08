# R grubu — Dayanıklılık (root / hooking / debugger / kurcalama)

Bu senaryolar PinVault'un **kendi** tespit kodunun (`pinvault/.../integrity/Probes.kt`)
ve atestasyon zincirinin, ele geçirilmiş bir cihazda gerçekten devreye girdiğini
uçtan uca kanıtlar: ilgili sinyal yükselir, host politikası onu reddedince telefon
`PinVault-Token` alamaz ve token isteyen mock host isteği `401` ile geri çevirir.
Tehdit kalkınca aynı telefon yeniden geçer ve token alır.

Hepsi **tek kullanımlık emülatörde** yapılır. Gerçek telefon root'lanmaz; root,
hooking ve debugger gerektiren senaryolar `device.isEmulator()` önkoşuluyla yalnızca
emülatörde koşar.

## Senaryolar

| # | Dosya | Ne kanıtlar | Mekanizma |
|---|---|---|---|
| R01 | `R01-root-tespiti.spec.js` | Kök yöneticisi paketi kuruluyken `rooted` yükselir; reject → token yok + mock host 401; kaldırılınca geçer | Magisk paket adlı stub APK |
| R02 | `R02-frida-hooking.spec.js` | Gerçek frida-gadget yüklüyken `hooking_framework` yükselir; reject → 401; kaldırılınca geçer | frida-gadget + LD_PRELOAD |
| R03 | `R03-frida-yeniden-adlandirilmis.spec.js` | Gadget .so'su `libhelper.so`'ya yeniden adlandırılsa (maps adı frida içermez) bile thread izleriyle yakalanır | adı değişik gadget |
| R04 | `R04-sunucu-verdisi-sahtelenemez.spec.js` | İstemci bütün kendi sinyallerini gizlese (hepsi `ignore`) bile sunucunun yargıladığı `key_unattested` reddeder | Android Key Attestation (sunucu) |
| R05 | `R05-debugger-tespiti.spec.js` | Bağlı JDWP (ham handshake) oturumunda `debugger` yükselir; reject → 401; ayrılınca geçer | ham JDWP soketi |
| R06 | `R06-yeniden-paketleme.spec.js` | Farklı anahtarla imzalanmış APK `app_integrity` yükseltir; reject → 401; doğru imza geçer | APK yeniden imzalama |
| R07 | `R07-environment-guard.spec.js` | "Ortam kontrolü" açıkken hata ayıklayıcı bağlı telefonda `environmentGuard` (DeviceShield) dosya indirmeyi ağdan ÖNCE reddeder; ayrılınca iner | environmentGuard + ham JDWP soketi |
| R08 | `R08-temiz-cihaz-temeli.spec.js` | Tehdit sinyalleri `reject` iken temiz cihaz yine geçer: yanlış alarm yok | sıkı politika, tehdit yok |

Hepsi API 33 emülatöründe (google_apis, arm64) geçti (2026-10-09, 8/8).

## Çalıştırma

```bash
cd sample-e2e
ANDROID_SERIAL=<emülatör, ör. emulator-5554> E2E_SKIP_BUILD=1 \
  JAVA_HOME=<JDK 17 yolu> \
  npx playwright test tests/R0 --reporter=line
```

- `ANDROID_SERIAL` **şart**: birden çok cihaz bağlıyken harness ilk cihazı seçer;
  yanlışlıkla fiziksel telefona kurulum/ayar yapmamak için emülatörü sabitleyin.
- `JAVA_HOME` geçerli bir JDK 17'yi göstermeli (global-setup uygulamayı yeniden
  derlerken ve R06 imza anahtarını üretirken gerekir).
- Emülatörde animasyonlar kapalı olmalı (global-setup `disableAnimationsIfEmulator`
  ile kapatır; yoksa soğuk başlangıçta `uiautomator dump` idle'a giremeyip düşebilir).
- R02/R03 için `frida-gadget` .so'su `sample-e2e/.local/frida/` altında olmalı (git
  dışı). Yoksa R02/R03 **skip** olur (test başarısız saymaz).

## Yardımcı: `lib/resilience.js`

Atestasyon politikası okuma/yazma (`getPolicy`/`setPolicy`/`LENIENT`), cihaz kaydı
(`deviceRecord`/`reasonsOf`), ve tehdit iliştirme: `plantRootManager`/`removeRootManager`
(R01), `plantFridaGadget`/`removeFridaGadget` (R02/R03), `attachDebugger` (R05 ve R07, ham
JDWP — jdb DEĞİL), `repackageApk` (R06). Gereken stub/anahtar/APK'ları SDK ile kendisi
üretir (`.local/stubs`).

## Bulgular (üretim için değerlendirilmeli)

1. **SELinux enforcing'de dosya tabanlı root tespiti büyük ölçüde kör.** Bu emülatör
   imajında `/system/xbin/su` var ve `ro.debuggable=1`, ama enforcing altında
   untrusted uygulama su ikililerini `stat` edemiyor; `ro.debuggable` da
   `android.os.SystemProperties` üzerinden okunuyor. Sonuç: salt ambient root tek
   başına `rooted`'ı yükseltmiyordu. R01 bu yüzden uygulamanın SELinux'tan bağımsız
   gerçekten görebildiği bir sinyalle (kök yöneticisi paketi, `<queries>` ile görünür)
   gösteriliyor. Üretimde prop/paket tabanlı ve `Runtime.exec("su")` gibi yollar daha
   güvenilir.

2. **frida-server (ptrace enjeksiyonu) bu Apple Silicon arm64 emülatörlerinde çalışmaz**
   ("need Gadget to attach on jailed Android"); iki imaj (google_apis API 33, AOSP API
   28), iki frida sürümü (16.7.19, 17.22.2) denendi. Bu bir ortam kısıtı. Çözüm:
   **frida-gadget**'i `LD_PRELOAD` (`wrap.<pkg>`) ile debuggable uygulamaya yüklemek —
   ptrace gerektirmez, gerçek frida çalışma zamanını (gum-js-loop, gmain, gdbus,
   pool-frida thread'leri) sürece sokar ve HookingProbe tam da bunu yakalar.
   - `wrap.<pkg>` değeri **tırnaksız** olmalı (`LD_PRELOAD=/data/.../lib.so`); literal
     tırnak zygote'ta `exit 127` yapar.
   - API 31+'ta `wrap.<pkg>` özelliği shell'den reddedilir; `su 0 setprop` gerekir.

Araçlar `sample-e2e/.local/frida/` altına indirildi (git dışı): `frida-server-*` (ptrace
yolu için; bu emülatörlerde çalışmıyor), `frida-gadget-*-android-arm64.so` (kullanılan).
