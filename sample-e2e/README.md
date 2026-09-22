# SamplePinVaultE2E

[SamplePinVaultHost](../SamplePinVaultHost) ile [SamplePinVaultClient](../SamplePinVaultClient) arasında uçtan uca testler. Her senaryo web dashboard'unda gerçek bir tarayıcıyla işlem yapar ve sonucunu Android uygulamasının ekranında doğrular, ya da tersini yapar.

- **Web tarafı:** Playwright, dashboard'u (`http://localhost:6650`) başsız Chromium'da sürer. Seçiciler arayüz dilinden bağımsız `data-action` özniteliklerine dayanır.
- **Mobil tarafı:** adb, uygulamaya bir kullanıcı gibi dokunur, yazı yazar ve ekrandaki metni UI Automator dökümünden okur. Uygulamaya test kodu gömülmez.
- **Kablo ve cihaz:** kurcalama vekili (`lib/proxy.js`) telefon ile host arasına girer; `run-as` ile uygulamanın şifreli depoları okunur. Bu kanıtlar rapora metin paneli olarak girer.
- **Kanıt:** Her adımda web ve telefon ekran görüntüleri rapora ve tek dosyalık kanıt sayfasına eklenir; sayfanın başında kapsam matrisi (özellik → senaryo → durum) durur.

Kapsam planı ve senaryo listesi: [PLAN.md](PLAN.md).

## Senaryolar

| # | Ne doğrulanır |
|---|---|
| 1 | Telefondaki pinli istek, dashboard'da "Bağlı Cihazlar" ve "Bağlantı Geçmişi" kartlarında aynı pin sürümüyle görünür. |
| 2 | Web'de yedek pin eklenince sürüm artar, telefon yeni sürümü alır ve iki client da bağlanır. Pin kaldırılınca döngü tekrar eder. |
| 3 | Web'de yanlış pin girilince telefon bağlantıyı reddeder, uyuşmazlık dashboard'a düşer. Pin'ler düzeltilince telefon elle yenilemeden toparlanır. |
| 4 | Force update açıkken telefon config'i sürüm değişmese de yeniden uygular; kapatılınca normale döner. |
| 5 | PinVault'u import etmeyen production-style client da yanlış pin'i reddeder ve kendi interceptor'ıyla toparlanır. |
| 6 | Host kapalıyken ilk açılışta uygulama başlatılamadığını söyler ve istek yapılmasına izin vermez. Host dönünce "Tekrar dene" ile toparlanır. |
| 7 | Host kapalıyken sonraki açılışta uygulama saklı config ile açılır ve hedefe pinli bağlanır. |
| 8 | Web'de host silinince telefon o host'a bağlanmaz. Geri eklenince sürüm kaldığı yerden devam eder ve bağlantı döner. |
| 9 | Web'de bütün host'lar silinince sunucu boş config yayınlar; telefon bunu reddedip eski config'le çalışır. |
| 10 | Web'de hatalı biçimli pin reddedilir, başarı mesajı çıkmaz, telefon etkilenmez. |
| 11 | Web'deki değişiklik, uygulamada hiçbir şeye dokunmadan WorkManager'ın periyodik göreviyle telefona ulaşır. Yalnızca emülatör. |
| 12 | Web'de kayıt token'ı üretilir, telefon onunla kayıt olur, sertifika dashboard'da görünür, mTLS bağlantısı geçer. Web'de iptal edilince aynı bağlantı reddedilir. |
| 13 | Web'de yüklenen dosya telefonda iner, içerik imzası doğrulanır, indirme dağıtım geçmişinde görünür. Güncellenince yeni sürüm gelir. |
| 14 | Token politikalı dosya token olmadan inmez; web'de bu cihaz için üretilen token'la iner, iptal edilince yine reddedilir. |
| 15 | Uçtan uca şifreli dosya kabloda cihazın RSA anahtarıyla sarılı gider; yalnızca telefon çözer. |

Yeni senaryolar PLAN.md'deki gruplara göre eklenir: kurulum (K), pin yönetimi (A), mTLS (B), vault (C), cihaz depolama (D), sunucu operasyonları (E), dayanıklılık (F), kurcalama (G), sunucu bağımsızlığı (H). Dosya adı grup harfiyle başlar (`K01-…`, `E03-…`); kanıt sayfası grubu buradan okur.

| Grup | Ne doğrulanır |
|---|---|
| K01–K07 | Sıfırdan kurulum: gereksinimler, `setup.sh`, compose + Flyway + smoke-test, dashboard'un ilk açılışı ve API anahtarı istemi, Config API sekmeleri, host ekleme üç yolla, mTLS API ve mock host'lar, vault yükleme, istemci değerleri + derleme + telefonun ilk bağlantısı, Swagger/TR-EN/sayfalama. Adım adım anlatım: [SETUP.md](SETUP.md). |
| E01–E09 | Sunucu operasyonları: imzalama anahtarının diskte şifrelenmesi, yetkilendirme ve anonim mod, sunucu sertifikası rotasyonu, sertifika süre izleme, Config API yaşam döngüsü, pin geçmişi ve watermark, telemetri ve cihaz listeleri, Docker down/up kalıcılığı, `wantPinsFor` + cihaz host ACL'i. |
| A16–A31 | Pin yönetimi ve imzalı config: tek pin'li host reddi (≥2 pin kuralı), wildcard eşleşmesi (`*.example.com` geçer, `*.com` yok sayılır), config tazeliği (kısa TTL + cihaz saati ileri → "expired"), imzalama anahtarı rotasyonu, mock host'ta gerçek sertifika rotasyonu, özel bağlantı ayarlı istemci (kurtarma yok), `reset()` + çift init koruması, telemetri seçenekleri. |
| F01–F03 | Dayanıklılık: zorunlu güncelleme işaretliyken sunucuya ulaşılamazsa açılış başarısız, kurtarma devre kesicisi (3 hata → 10 dk soğuma), telemetri ucu kesikken uygulamanın akıcı kalması. |

**İkinci host örneği:** K ve E'nin yıkıcı adımları (sıfırdan kurulum, sertifika yenileme, Config API silme, down/up) ana host'u bozmasın diye `lib/freshHost.js` SamplePinVaultHost'un bir kopyasını `.local/host-fresh` altında, 6650–6654 yerine **6750–6754** portlarında ve `pinvault-host-fresh` container'ıyla kurar. Koşu sonunda `docker compose down -v` ile tamamen silinir. Telefon yalnızca K06 ve E03'te bu örneğe bakar; iki senaryo da sonunda uygulamayı ana host'un değerleriyle yeniden derleyip kurar.

## Gereksinimler

- Host ayakta ve hazırlanmış: `cd ../SamplePinVaultHost && docker compose up -d && ./scripts/provision.sh`. Kurulum aşaması provision'ı zaten çağırır.
- Bir Android cihaz: USB ile bağlı telefon ya da bir emülatör AVD'si. Saat, iptables ve root gerektiren senaryolar yalnızca emülatörde koşar.
- Node 18+ ve Docker CLI (bazı senaryolar host container'ını durdurup başlatır ya da ortam değişkenlerini geçici değiştirir).
- İstemciyi derlemek için JDK 17 (JAVA_HOME yoksa Android Studio'nun ya da `~/Library/Java` altındaki JDK aranır).
- Kurcalama vekili için host'un anahtarı: `cd ../SamplePinVaultHost && ./scripts/export-server-key.sh`.

## Çalıştırma

```bash
npm install
npm test                    # bağlı cihazda
npm run test:emulator       # cihaz yoksa AVD'yi başsız açar, bitince kapatır
npm run report              # Playwright'ın HTML raporu
npm run evidence            # tek dosyalık kanıt sayfası
npm run check-evidence      # kanıt sayfası denetimi (kanıtsız adım, tekrar görüntü, gizli değer)
```

Tek bir senaryo için: `npx playwright test tests/12-mtls-enroll-and-revoke.spec.js`.

Kurulum aşaması şunları yapar:

1. Host'un sağlığını ve `.env`'deki API anahtarını kontrol eder, `scripts/provision.sh` ile mTLS Config API'sini, host'un kendi pin kaydını ve mock hedef host'ları açar.
2. Cihaz yoksa ve `E2E_AVD` verilmişse emülatörü salt-okunur açar. AVD'ye kalıcı hiçbir şey yazılmaz.
3. Host değerlerini `.local/sample-host.properties` dosyasına yazar (IP, portlar, bootstrap pin'leri, imzalama public key'i, hedefin canlı pin'leri, özel backend anahtarları) ve istemciyi bu dosyayla derleyip kurar.
4. Sunucuyu temel duruma getirir.

Her test host'u ayağa kaldırıp sunucuyu temel duruma döndürerek ve uygulamanın verisini silerek başlar; bitince yine temel duruma döndürür. Vault senaryoları yükledikleri dosyaları siler. Pin değişiklikleri host sürümünü her seferinde artırır; istemciler sürüm düşüşünü reddettiği için geri alma da her zaman ileri doğrudur.

## Kanıt sayfası

Her koşu `evidence/index.html` dosyasını yeniden üretir. En üstte kapsam matrisi, sonra gruplara ayrılmış senaryolar; senaryo başına adımlar, web ve telefon ekran görüntüleri, metin panelleri (terminal çıktısı, kablodaki bayt, cihaz dosyaları) ve süreler. Görüntüler dosyanın içine gömülüdür; tek başına açılır ve paylaşılabilir. Görüntüye tıklayınca büyür. Başarısız bir senaryoda tarayıcının yanında telefonun hata anındaki ekranı da eklenir. Sayfanın başındaki "Nasıl okunur" notu rozetleri, 📱/🌐/📄 işaretlerini ve matrisi açıklar.

`npm run check-evidence` sayfayı ayrıştırıp kanıtsız adımları (ne görüntü ne panel), görüntüsüz senaryoları, bayt bayt aynı görüntünün birden fazla yerde kullanılmasını ve tam uzunlukta token/anahtar dizilerini (bilinen gizli değerler dahil) listeler; sıfır bulguda 0 ile çıkar.

## Ayarlar

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `ANDROID_SERIAL` | ilk bağlı cihaz | Birden fazla cihaz varsa hangisi |
| `E2E_AVD` | yok | Cihaz yoksa açılacak AVD |
| `E2E_KEEP_EMULATOR` | yok | `1` ise açılan emülatör test sonunda kapatılmaz |
| `E2E_SKIP_BUILD` | yok | `1` ise istemci derlenmez (host değerleri değişmediyse) |
| `E2E_TARGET_HOST` | `www.example.com` | Pin'leri değiştirilen hedef |
| `E2E_CONTAINER` | `pinvault-host` | Durdurulup başlatılan host container'ı |
| `E2E_PROXY_PORT` | `6661` | Kurcalama vekilinin dinlediği port |
| `E2E_CUSTOM_BACKEND_PORT` | `6660` | Özel backend'in dinlediği port |
| `E2E_HOST_DIR`, `E2E_CLIENT_DIR` | kardeş klasörler | Host ve istemci projelerinin yolu |

## Bilinmesi gerekenler

- Testler host'un gerçek pin config'ini ve vault dosyalarını değiştirir; sonunda temel duruma döndürür. Yarıda kesilirse bir sonraki koşunun kurulumu düzeltir.
- Bazı senaryolar host container'ını birkaç saniyeliğine durdurur ya da sunucu ortam değişkenlerini geçici değiştirir (`scripts/env-override.sh`).
- Arka plan senaryosu emülatörün saatini bir WorkManager periyodu kadar ileri alır ve sonunda geri alır; bunun için emülatör imajındaki `su` kullanılır. WorkManager periyodik görevi zamanı gelmeden, zorlansa bile çalıştırmaz.
- Kurcalama senaryoları emülatörde `iptables` ile trafiği vekile yönlendirir; kurallar test sonunda silinir.
- mTLS senaryoları dashboard'da her koşuda yeni bir istemci sertifikası oluşturur ve iptal eder.
- Telefonda testler uygulamanın verisini siler. Telefonun genel ayarlarına dokunulmaz; animasyonlar yalnızca emülatörde kapatılır.
- Telefon, host'a `.local/sample-host.properties` içindeki IP'den ulaşabilmeli.
- Uygulama her işlem sonucunun altına `#<sıra> · <saat>` yazar. Testler yeni sonucu eskisinden bununla ayırır.

## Yapı

```
PLAN.md                                kapsam planı, özellik matrisi, yürütme
global-setup.js / global-teardown.js   host, cihaz, host değerleri, APK, sunucu durumu
lib/env.js          yollar, portlar, API anahtarı (host .env'den), vault anahtarları, modlar
lib/hostApi.js      hazırlık/temizlik, tazelik kontrolü, kablodaki vault içeriği
lib/hostControl.js  host container'ı: durdur/başlat, ortam değişkeni ezme, log
lib/freshHost.js    ikinci (tek kullanımlık) host örneği: kur, hazırla, dashboard'unu aç, sil
lib/clientBuild.js  istemciyi verilen host değerleriyle derle ve cihaza kur
lib/android.js      adb: cihaz, emülatör, UI dökümü, dokunma, yazma, klavye, saat, iptables, run-as
lib/sampleApp.js    uygulama ekranları: ana, mTLS, Vault, Depolama, Ayarlar
lib/dashboard.js    web dashboard: host'lar, pin'ler, force, vault, mTLS
lib/proxy.js        kurcalama vekili (sahte anahtar / host anahtarı) ve hazır kurcalamalar
lib/custom-backend.js  özel uç yollu, kendi anahtarıyla imzalayan örnek backend
lib/evidence.js     metin panelleri: terminal çıktısı, kablo hex dökümü, cihaz dosyaları
lib/coverage.js     kapsam matrisi (özellik → senaryo)
lib/evidence-reporter.js   koşu sonunda evidence/index.html kanıt sayfası
lib/fixtures.js     her test için ayakta host + temel durum + temiz uygulama + açık dashboard
tests/              senaryolar
```
