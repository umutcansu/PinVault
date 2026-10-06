# Release derlemesini DexProtector ile korumak

Bu belge, sample-client gibi kurulmuş bir uygulamanın release derlemesi DexProtector'dan geçirilirken PinVault açısından nelere dikkat edileceğini anlatır.

> **Bu belgedeki hiçbir şey DexProtector ile denenmedi.** Aşağıdakiler PinVault'un nasıl çalıştığından çıkarılan gereksinimlerdir. DexProtector'ın ayar dosyasının biçimi burada **bilerek verilmedi**: emin olmadığımız bir biçimi yazıp yanlış yönlendirmek istemedik. Her madde bir **yeteneği** tarif eder; o yeteneğin DexProtector'daki adını ve ayarını kendi sürümünün belgesinden ya da Licel desteğinden öğren. Sondaki kontrol listesi, korunan derlemenin gerçekten çalıştığını gerçek bir telefonda göstermek içindir.

---

## 1. Neden gerekli, neyi çözer

PinVault ağdaki saldırganı durdurur: sahte sertifika, araya giren proxy, kullanıcının kurduğu CA. Telefonun **kendisi** ele geçirildiğinde (root, Frida, Xposed, yeniden paketlenmiş uygulama) durum değişir: uygulamanın içinde çalışan kod pin kontrolünü kapatabilir, uygulama adına dosya indirebilir, kayıt olabilir. Bu senaryoda ana savunma DexProtector'dır; PinVault tek başına root'a karşı koruma sağlamaz.

## 2. Yayın hattında yeri

Sıra önemli. DexProtector, **R8'den sonra ve imzadan önce** çalışır:

```
kaynak → R8 (assembleRelease) → DexProtector → imza → (Play'e yüklenirse Google yeniden imzalar)
```

1. `./gradlew :app:assembleRelease` küçültülmüş APK/AAB'yi üretir. Bu adım test bayraklarıyla çalışmaz ve gerçek imza anahtarı ister ([README → Yayın derlemesi](README.md#yayın-derlemesi)).
2. DexProtector bu çıktıyı korur. Dosyanın içeriği değiştiği için Gradle'ın attığı imza geçersiz olur.
3. Korunan dosya **yayın anahtarıyla yeniden imzalanır** (DexProtector'ın kendi imzalama adımı ya da `apksigner`).
4. Mağazaya ya da dağıtım kanalına giden dosya bu son dosyadır. Testler de bu dosyayla yapılır, Gradle'ın çıktısıyla değil.

DexProtector'ın Gradle eklentisi kullanılıyorsa aynı sıra eklentinin içinde gerçekleşir; yine de 7. bölümdeki kontrolleri **son dosya** üzerinde yap.

`e2e` ve `debug` derlemeleri korunmaz: uçtan uca testler uygulamaya adb ile dokunur, emülatörde ve root yetkisiyle çalışır; koruma açıkken bu testlerin çoğu (bilerek) çalışmaz.

## 3. Açık olması gerekenler

### Ortam kontrolleri: PinVault'tan ÖNCE tepki vermeli

Aşağıdaki tespitler açık olmalı ve sonuçları `PinVault.init` çağrılmadan **önce** değerlendirilmeli:

| Tespit | Neden |
|---|---|
| Root (Magisk, Zygisk dahil) | Root'lu telefonda uygulama adına çalışan kod, Keystore anahtarlarını **kullanabilir** (dışarı çıkaramaz ama imza attırabilir) ve uygulamanın dosyalarını okuyabilir |
| Kanca araçları (Frida, Xposed/LSPosed ve benzerleri) | Pin kontrolünü çalışma anında kapatmanın bilinen yolu |
| Hata ayıklayıcı (debugger) bağlı | Bellekten token ve açılmış dosya içeriği okunur |
| Emülatör | Toplu sahte kayıt ve otomasyonla saldırı; gerçek güvenli donanım yok |

Tepki uygulamanın kendi kodundadır. Örnek uygulamada yeri `App.onCreate` içinde `startPinVault()` çağrısından hemen öncesi ve şu üç işlemin başıdır:

- **Kayıt** (`PinVault.enrollForResult`, `MtlsActivity`): riskli ortamda kayıt başlatılmaz. Aksi hâlde saldırganın kontrolündeki bir ortam geçerli bir cihaz kimliği alır.
- **Dosya indirme** (`PinVault.fetchFile`, `syncAllFiles`, `VaultActivity`): riskli ortamda gizli dosya indirilmez.
- **Dosya açma** (`PinVault.unlockFile`): riskli ortamda kilitli dosya açılmaz; içerik uygulamanın belleğine hiç gelmez.

Tespitin sonucunu PinVault'a `environmentGuard` ile ver: kütüphane bu kararı `init`, kayıt, dosya indirme ve dosya açma işlemlerinin her birinden hemen önce sorar ve `false` gelirse o işlemi başlatmaz (sonuç `Failed`, nedeni `UntrustedEnvironmentException`; hiçbir şey gönderilmez, token harcanmaz). Böylece kontrolün bir kod yolunda unutulması mümkün olmaz:

```kotlin
PinVaultConfig.Builder()
    .environmentGuard { operation ->
        // DexProtector'ın kararı; INIT açık kalırsa pinlenmiş trafik çalışmaya devam eder.
        operation == GuardedOperation.INIT || !dexProtectorSaysCompromised()
    }
```

Ne yapılacağı ürüne göre değişir (uygulamayı kapatmak, kullanıcıya nedenini söylemek, sunucuya bildirmek). Değişmeyen kural: **tespit olumsuzsa bu üç işlem çalışmaz** ve kontrol yalnızca açılışta değil, bu işlemlerden hemen önce de yapılır (araç uygulama açıldıktan sonra da takılabilir). Mümkünse sonucu sunucuya da taşı: DexProtector'ın ürettiği cihaz/uygulama doğrulama bilgisi kayıt isteğinde sunucuda kontrol edilirse, uygulamadaki kontrolü atlatan biri yine de kayıt olamaz. Bunun yolu `integrityTokenProvider`'dır: verdiği token (Play Integrity ya da DexProtector'ın doğrulama bilgisi) kayıt isteğine `integrityToken` olarak, istekteki CSR'a ve cihaz kimliğine bağlı gider; sunucu onu `INTEGRITY_VERIFIER_COMMAND` ile çözer ve `INTEGRITY_VERIFICATION=enforce` altında geçmeyen cihaza sertifika vermez. DexProtector'ın doğrulama bilgisini çözen bir komut yazmak gerekir; Play Integrity için hazır olanı `demo-server/scripts/play-integrity-verify.sh`.

### Bütünlük ve yeniden paketlemeye karşı koruma

- Uygulamanın bütünlük kontrolü açık olmalı ve **yayın imza sertifikasına** bağlanmalı: başka bir anahtarla yeniden imzalanmış kopya çalışmamalı.
- Uygulamayı Google Play imzalıyorsa (Play App Signing) bağlanacak sertifika, yükleme anahtarının değil **Google'ın tuttuğu uygulama imzalama anahtarının** sertifikasıdır. Yanlışı seçilirse mağazadan inen uygulama kendi bütünlük kontrolüne takılır. Bkz. 5. bölüm.

### Şifreleme

- **Metin (string) şifreleme:** host adresleri, başlangıç (bootstrap) pin'leri, imza ve kurtarma public key'leri `BuildConfig` içinde düz metindir. Bunlar gizli değildir (APK'yı açan herkes görür), ama şifrelenmeleri uygulamayı inceleyip hedef çıkarmayı ve yeniden paketleyip değerleri değiştirmeyi zorlaştırır. En azından `com.example.sampleclient.BuildConfig` ve `App` sınıfı kapsanmalı.
- **Sınıf şifreleme:** uygulamanın kendi paketi (`com.example.sampleclient.**`) ve PinVault'un iç sınıfları (`io.github.umutcansu.pinvault.**`; istisna için 4. bölüme bak).
- **Kaynak (resource) şifreleme:** `res/xml/network_security_config.xml` ve yedek kuralları gibi dosyalar uygulamanın ağ ve yedek davranışını anlatır. Dikkat: bu dosyaları **Android'in kendisi** okur; şifrelenmeleri işletim sisteminin onları okumasını bozmamalıdır. Korunan derlemede düz HTTP'nin hâlâ kapalı ve yedeğin hâlâ dışarıda olduğunu kontrol et (7. bölüm).

### Log'lar

Release derlemesi `Log.d/v/i` ve kütüphanenin teşhis log çağrılarını zaten R8 ile siler (`app/proguard-release.pro`) ve kütüphanenin debug log'unu hiç açmaz. DexProtector'da log temizleme ayrıca varsa açık kalsın; korunan derlemede `adb logcat` çıktısında host adı, pin öneki, kimlik görünmemeli.

## 4. KAPALI olması ya da dışarıda tutulması gerekenler

| Ne | Neden |
|---|---|
| **DexProtector'ın kendi sertifika pinlemesi**, PinVault'un yönettiği host'lar için | Aynı host iki ayrı yerden pinlenirse biri güncellenip diğeri güncellenmediğinde bağlantı kesilir. PinVault'un pin'leri sunucudan, imzalı olarak ve uygulama güncellemesi olmadan değişir; DexProtector'ın pin'leri derlemeye gömülüdür. Sunucu sertifikası döndüğünde uygulama kendi kendini kilitler. PinVault'un pinlediği bütün host'lar (Config API adresleri, kurtarma kapısı, config'ten gelen hedef host'lar) DexProtector'ın pinlemesinin **dışında** kalmalı. PinVault'un yönetmediği başka host'ların varsa onlar için kullanılabilir |
| **Certificate Transparency (CT) zorunluluğu**, özel CA'lı host'lar için | Kurum içi CA'dan ya da kendinden imzalı sertifikalar CT kayıtlarında yer almaz. Config API'yi sunan sunucunun sertifikası (bu örnekte sunucunun kendi CA'sı) ve kurtarma kapısı böyledir; CT zorunlu tutulursa uygulama ilk açılışta Config API'ye bağlanamaz |
| **`io.github.umutcansu.pinvault.model.**` için ad değiştirme ve alan kaldırma** | Bu paketteki sınıflar Gson ile JSON'dan okunur (config, imzalı zarf, anahtar seti, kayıt yanıtı). Alan adları değişirse ya da alanlar silinirse imzalı config **ayrıştırılamaz** ve uygulama pin alamaz. Kütüphanenin R8 kuralları bunları korur; DexProtector bu kuralları kendiliğinden bilmeyebilir. Bu paket ad değiştirmeden ve küçültmeden muaf tutulmalı; sınıf şifrelemesi uygulanacaksa yansıma (reflection) ile erişimin çalıştığı doğrulanmalı |
| `io.github.umutcansu.pinvault.PinVault` ve `…api.CertificateConfigApi` adları | Kütüphanenin dışa açık yüzü; kütüphane kuralları bunları da korur |
| WorkManager'ın bulduğu sınıflar | Periyodik güncelleme işi sınıf adıyla kayıtlıdır; ad değişirse arka plan güncellemesi sessizce durur |

Kural olarak: R8'in `consumer-rules.pro` ile koruduğu her şey DexProtector'da da korunmalı. Kütüphanenin kuralları: depodaki `pinvault/consumer-rules.pro`.

## 5. `ATTESTATION_SIGNER_SHA256` son imza sertifikası olmalı

Sunucu, ekran kilidiyle açılan dosyaların anahtarını (ve açıksa kayıt anahtarını) Android'in donanım belgesiyle doğrular; belgede uygulamanın **imza sertifikasının SHA-256'sı** yazar. Sunucudaki `ATTESTATION_SIGNER_SHA256` buna eşit olmalı.

Bu değer, telefona **kurulan** dosyayı imzalayan sertifikanınkidir:

- DexProtector'dan sonra kendi anahtarınla imzalayıp kendin dağıtıyorsan: o yayın anahtarının sertifikası.
- Google Play imzalıyorsa (Play App Signing): Play Console → Uygulama bütünlüğü → **Uygulama imzalama anahtarı sertifikası** → SHA-256. Yükleme anahtarının sertifikası değil.

Kontrol: mağazadan (ya da gerçek dağıtım kanalından) telefona inen APK üzerinde `apksigner verify --print-certs <apk> | grep SHA-256`. Koruma öncesi Gradle çıktısına ya da debug anahtarına bakma.

## 6. Neyi çözmez

- **Kilit meşru yoldan açıldıktan sonraki düz metin.** Kullanıcı ekran kilidiyle bir dosyayı açtığında içerik uygulamanın belleğinde ve ekranındadır. O anda uygulamanın içinde çalışan kod (tespiti atlatmış bir araç) içeriği okuyabilir. Uygulama içeriği kısa tutar (ekrandan ayrılınca ve 1 dakika sonra siler, ekran görüntüsüne kapalıdır), ama bu bir azaltmadır, engel değil.
- **Root'lu telefonda Keystore'un "imza aracı" olarak kullanılması.** Özel anahtarlar telefondan çıkarılamaz, ama root yetkisiyle uygulama adına çalışan kod onlara **imza attırabilir**: mTLS bağlantısı kurar, dosya ister. DexProtector bunu zorlaştırır (root ve kanca tespiti), yok etmez. Kalıcı çözüm sunucudadır: cihazı iptal etmek ve kayıtta/anahtarda donanım belgesi istemek.
- **Sunucu tarafındaki sorunlar.** Yönetim panelinin korunması, imza anahtarlarının nerede durduğu, iki kişi onayı, iptalin her yere ulaşması, hız sınırları: bunların hiçbiri uygulamayı korumakla çözülmez. Bkz. `sample-host/README.md` → "Üretim profili".
- **Çalınmış, kilidi açık telefon.** Uygulama o anda meşru kullanıcının elindeymiş gibi çalışır.
- **Tespitin kendisi.** Root ve kanca gizleme araçları sürekli gelişir; tespit bir yarıştır. Bu yüzden kritik kararlar (kayıt, dosya dağıtımı) sunucuda da doğrulanmalıdır.

## 7. Korunan derlemeyi gerçek telefonda doğrulama

Emülatör değil, **gerçek bir telefon** (bootloader'ı kilitli, root'suz) ve dağıtılacak **son dosya** ile. Her satır bir kez "beklenen oldu" diye işaretlenmeli.

**Temel akış (koruma bir şeyi bozmadı mı?)**

- [ ] Uygulama açılıyor, "Hazır — config vN" yazıyor (Config API'ye bağlandı, imzalı config ayrıştırıldı: `model.**` kuralları doğru).
- [ ] Hedefe pinli istek iki istemciyle de geçiyor.
- [ ] Sunucuda bir pin değiştirilince telefon yeni sürümü alıyor (elle yenileme ve 15 dakikalık arka plan işi: WorkManager sınıfları korunmuş).
- [ ] Token ile kayıt oluyor; sunucu `ATTESTATION_SIGNER_SHA256` ile belgeyi kabul ediyor (5. bölüm).
- [ ] Gizli dosya iniyor, "Aç" ekran kilidini soruyor, içerik görünüyor, ekrandan ayrılınca siliniyor.
- [ ] Sunucu cihazı iptal edince bir sonraki istekte dosyalar siliniyor ve yeniden kayıt isteniyor.
- [ ] Süresi dolmaya yakın sertifika kendiliğinden yenileniyor (kurtarma kapısı dahil; CT ve çifte pinleme kapalı olduğunun göstergesi).
- [ ] Sunucu sertifikası döndürülünce (yedek pin'e geçiş) uygulama güncelleme istemeden bağlanmaya devam ediyor.

**Koruma gerçekten çalışıyor mu?**

- [ ] Root'lu (Magisk) bir test telefonunda: uygulama PinVault'u başlatmıyor; kayıt, indirme ve açma çalışmıyor.
- [ ] Frida sunucusu çalışırken ve bir kanca takılmaya çalışılırken: aynı sonuç.
- [ ] Hata ayıklayıcı bağlanmaya çalışılınca: aynı sonuç.
- [ ] Emülatörde: aynı sonuç.
- [ ] APK açılıp başka bir anahtarla yeniden imzalanınca: uygulama çalışmıyor.
- [ ] APK'nın içinde host adresi, pin ve public key düz metin olarak aranınca bulunmuyor.
- [ ] `adb logcat` çıktısında uygulamadan host adı, pin öneki, token, kimlik geçmiyor.
- [ ] Ekran görüntüsü ve ekran kaydı siyah çıkıyor; "son uygulamalar"da içerik görünmüyor.
- [ ] Ayarlar ve Depolama ekranları yok; `adb shell am start -n com.example.sampleclient/.MainActivity --es mode STATIC` modu değiştirmiyor.
- [ ] Düz HTTP hâlâ kapalı, uygulama verisi yedeğe ve cihaz taşımaya girmiyor (kaynak şifreleme bu dosyaları bozmadı).

**Araya girme (pinleme hâlâ PinVault'ta mı?)**

- [ ] Telefona kullanıcı CA'sı kurulup trafiği bir proxy'den geçirince: Config API ve hedef bağlantıları reddediliyor.
- [ ] Proxy kaldırılınca uygulama kendiliğinden toparlanıyor.

Listenin tamamı geçmeden korunan derleme yayınlanmamalı. Bir satır geçmiyorsa önce 4. bölümdeki dışarıda tutma kurallarına bak: en sık görülen iki neden `model.**` sınıflarının değiştirilmesi ve çifte pinlemedir.
