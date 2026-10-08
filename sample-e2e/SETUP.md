# Sıfırdan kurulum

PinVault'u hiç görmemiş birinin, boş bir Mac'te (ya da Linux'ta) host'u ayağa
kaldırıp örnek uygulamayı telefona kurmasına kadar olan adımlar. Her adımın
karşılığı kanıt sayfasındadır (`evidence/index.html` → **Sıfırdan kurulum**
bölümü); parantez içindeki senaryo ve adım başlığı orada aranabilir.

Kanıtları üreten senaryolar **geçici bir test sunucusunda** çalışır (host'un
ikinci bir örneği: `.local/host-fresh`, portlar 6750–6756). Aşağıdaki komutlar gerçek kurulum
içindir: `sample-host` dizininde, 6650–6656 portlarıyla.

## 0. Gereksinimler

| Araç | Niçin |
|---|---|
| Docker Desktop (compose v2) | host container'ı |
| JDK 17 | Android derlemesi (`JAVA_HOME`) |
| Android SDK + platform-tools | `adb`, emülatör ya da USB telefon |
| Node 18+ | uçtan uca testler (isteğe bağlı) |
| `openssl`, `curl`, `jq` | kurulum betikleri ve smoke test |

```bash
docker --version && docker compose version
java -version && node --version
adb --version && openssl version && jq --version
```

*(Kanıt: **K01 → Terminal: gereksinim sürümleri (K0)**)*

## 1. Depo

Her şey tek depoda: kütüphane, sunucu ve örnekler PinVault'un ana dizininde.
Betikler birbirini bu dizinlerin göreli yolundan bulur.

```bash
cd ~/Programming
git clone <PinVault>   # pinvault/, demo-server/, sample-host/, sample-client/, sample-e2e/
cd PinVault
```

*(Kanıt: **K01 → Terminal: depo ve geçici test sunucusu için host kopyası (K1)**)*

## 2. Host ayarları: `.env`, API anahtarı, imzalama anahtarı

```bash
cd sample-host
./scripts/setup.sh
```

Yaptıkları:

- `.env` yoksa `.env.example`'dan üretir (izin 600),
- `API_KEY` boşsa rastgele üretir — dashboard bunu ister,
- `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD` ve `SIGNING_KEY_PASSWORD` boşsa
  rastgele üretir — sunucu bu üçü olmadan açılmaz,
- `FETCH_ALLOW_PRIVATE_TARGETS=true` yazar (demo: sunucu "URL'den sertifika al" ile
  bu makineye ve yerel ağa bağlanabilsin),
- `HOST_LAN_IP` boşsa makinenin LAN IP'sini bulur (telefon bu adrese bağlanır;
  sunucu sertifikası bu adresi de kapsar, yani adres SAN listesine girer),
- `data/signing-key.pem` yoksa ECDSA P-256 anahtar çifti üretir (izin 600).
  Dosyanın ilk satırı private (PKCS8, Base64), ikinci satırı public (X.509 SPKI).
  Sunucu dosyayı ilk açılışta `SIGNING_KEY_PASSWORD` ile şifreler (`ENCv1:`); testler
  onu `.env`'deki parolayla açar (`lib/signingKeyFile.js`).

Yerel PinVault kaynağından derlemek için `.env`'e ekle:

```
PINVAULT_SERVER_SRC=../demo-server
```

`API_KEY` boşken compose başlamayı reddeder — sunucu anahtarsız (anonim)
yönetimle asla açılmaz:

```bash
docker compose config    # "API_KEY bos. Once ./scripts/setup.sh calistir."
```

*(Kanıt: **K01 → Terminal: API anahtarı yokken compose başlamayı reddeder (K2)**
ve **Terminal: scripts/setup.sh — .env, API anahtarı, imzalama anahtarı (K2)**;
ayrıca **E02 → Sunucu: API_KEY verilmemişse açılmayı reddediyor**)*

## 3. Çalıştırma

```bash
docker compose up -d --build
docker compose ps                 # healthy olmalı
docker compose logs | grep -i flyway   # migration'lar
./scripts/provision.sh            # mTLS Config API + mock hedef host'lar
./scripts/smoke-test.sh           # hepsi PASS olmalı
```

`provision.sh` şunları açar: `sample-mtls` (mTLS Config API, dışarıda 6652),
host'un kendi LAN IP'si için pin kaydı ve test için kurulan iki hedef sunucu
(mock host): `mock-tls.sample` (6653) ve `mock-mtls.sample` (6654).

`smoke-test.sh` sağlığı, imzalı config'i (ECDSA doğrulaması, `issuedAt`/
`expiresAt`), sunucu sertifikasının pin'ini ve geçerli olduğu adresleri (SAN), yetkilendirmeyi,
`ping-remote` enjeksiyon korumasını ve mTLS dinleyicisini kontrol eder.

*(Kanıt: **K01 → Terminal: docker compose up -d --build (K3)**, **Sunucu:
Flyway migration logları (K3)**, **Terminal: smoke-test.sh bütün kontroller
PASS (K3)**)*

## 4. Dashboard

`http://localhost:6650` → ilk açılışta API anahtarı sorar (`.env`'deki
`API_KEY`). Yanlış anahtar girilirse sunucu 403 döner ve istem tekrarlanır.

Bakılacak yerler:

- **Genel**: port, mod, host sayısı, sürüm, global force update, vault'u açıp
  kapatan anahtar, cihaz bazlı host izin listesi (ACL) yöneticisi.
- **Bootstrap**: sunucu TLS pin'leri (birincil/yedek) ve Android kod parçası.
  Bu pin'ler APK'ya gömülür.
- **İmzalama**: config imzalama public key'i — APK'ya gömülen ikinci değer.
- **Vault**: dosya yükleme (metin/dosya × politika × şifreleme), dağıtım geçmişi.
- **Bağlantı Geçmişi**: telefonların raporları + sertifika süre kartı.

*(Kanıt: **K02**, tüm adımlar; vault için **K05**)*

## 5. Host ekleme

Dört yol (Config API satırındaki **+**, "Yeni Host Ekle" penceresinin sekmeleri):

1. **Elle Gir** — pin'leri elde hesaplayıp yapıştır (44 karakter Base64, host
   başına en az iki tane).
2. **Sertifika Üret** — sunucu o ad için sertifika üretir, pin kaydını açar;
   test için kurulan hedef sunucular (mock host) böyle kurulur.
3. **URL'den Çek** — sunucu adrese bağlanıp host'un şu an sunduğu sertifika
   zincirinden pin'leri çeker (`POST /api/v1/hosts/fetch-from-url`).
4. **Dosya Yükle** — host'un JKS/P12 dosyası yüklenir, pin'ler bu sertifikadan
   hesaplanır (`POST /api/v1/hosts/upload-cert`).

Hatalı biçimli pin kaydedilmez.

*(Kanıt: **K03**; mock host başlatma ve "Bağlantıyı Test Et" için **K04**)*

## 6. İstemci değerleri ve derleme

```bash
./scripts/client-config.sh --properties > ../sample-client/sample-host.properties
cd ../sample-client
./gradlew installDebug           # ya da assembleDebug + adb install -r -t
```

`sample-host.properties` → `BuildConfig`: IP, portlar, APK'ya gömülen ilk
pin'ler (bootstrap), imzalama public key'i, hedef host ve mock host adları. Başka bir dosya vermek
için `-PsampleHostProps=<yol>`.

Cihaz raporları (telemetri) düz HTTP ile gittiği için
`app/src/main/res/xml/network_security_config.xml` yalnızca host IP'si için
şifresiz HTTP (cleartext) izni verir; IP değişirse bu dosya da güncellenmeli.

*(Kanıt: **K06 → Terminal: client-config.sh --properties — istemci değerleri (K10)**,
**Terminal: derleme ve kurulum (K11)**)*

## 7. İlk açılış

Uygulama açılınca durum kutusunda `Hazır — config vN` ve pin'li host listesi
görünür. Dashboard'da host detayında **Bağlı Cihazlar** ve **Bağlantı Geçmişi**
kartlarında cihaz belirir.

*(Kanıt: **K06 → Mobil: ilk açılış — "Hazır — config vN" (K12)** ve
**Web: geçici test sunucusunun dashboard'unda Bağlı Cihazlar ve Bağlantı Geçmişi (K12)**)*

## 8. API belgeleri, dil, sayfalama

- `http://localhost:6650/docs` → Swagger UI (varlıklar aynı origin'den gelir;
  CSP gevşetilmez), şema `/static/openapi.yaml`.
- Sol altta TR/EN; bütün geçmiş tabloları sayfalanır (10/25/50/100).

*(Kanıt: **K07**)*

## Sık karşılaşılan hatalar

| Belirti | Sebep / çözüm |
|---|---|
| `API_KEY bos. Once ./scripts/setup.sh calistir.` | `.env` yok ya da `API_KEY` boş → `./scripts/setup.sh` |
| Sunucu açılmıyor: `KEYSTORE_PASSWORD, … not set. Refusing to start with the demo values` | `.env`'de parolalar eksik (eski kurulum) → `./scripts/setup.sh` yeniden çalıştır, sonra `docker compose up -d` |
| Sunucu açılmıyor: `API_KEY env var is not set. Refusing to start…` | container'a `API_KEY` geçilmemiş; yalnızca bilinçli olarak `ALLOW_ANONYMOUS_ADMIN=true` ile açılır (E02) |
| Telefon: `başlatılamadı` / pin uyuşmazlığı | APK'ya gömülü ilk pin (bootstrap) sunucunun sertifikasıyla uyuşmuyor (sertifika yenilendi mi?) → `client-config.sh --properties` ile yeniden derle (E03) |
| smoke-test: `SAN <ip> içermiyor` | sertifika LAN IP'si `.env`'e girmeden üretilmiş → `data/certs/demo-server.jks` ve `.pins` silinip container yeniden başlatılmalı |
| Dashboard boş, sürekli anahtar soruyor | yanlış API anahtarı (403). `.env`'deki değeri gir; anahtar yalnızca o sekmede (`sessionStorage.pinvault_api_key`) saklanır, sekme kapanınca yeniden sorulur |
| mTLS Config API açılmıyor: `mTLS için önce client sertifika oluşturun` | truststore (sunucunun güvendiği istemci sertifikaları) yok → mTLS sekmesinden bir istemci sertifikası üret (K04) |
| Telefon host'a ulaşamıyor | telefon ve Mac aynı ağda değil ya da `HOST_LAN_IP` yanlış; emülatörde 10.0.2.2 yerine LAN IP kullanılır |
| `Signing key file is encrypted but SIGNING_KEY_PASSWORD is not set` ya da şifre çözme hatası | `.env`'deki `SIGNING_KEY_PASSWORD` dosyayı şifreleyen parola değil (silinmiş ya da değiştirilmiş) → eski parolayı geri yaz; anahtar dosyası `./data` dizin mount'u içinde olmalı (tek dosyalık mount'a yazılamıyor) |
| `docker compose down` sonrası Config API'ler kayıp sanılıyor | veriler `./data` altında kalıcıdır; `up -d` sonrası kendiliğinden yeniden başlar (E08) |

## iOS koşusu (`E2E_PLATFORM=ios`)

Aynı senaryolar iPhone simülatöründeki iOS örnek uygulamasına
(`sample-client-ios`, paket kimliği yine `com.example.sampleclient`) karşı da
koşar. Web tarafı aynı; telefon tarafında adb'nin yerini simülatör araçları
(`xcrun simctl`) ve küçük bir UI sürücüsü alır. Uygulamayla harness arasındaki
anlaşma: [`pinvault-ios/PORTING.md`](../pinvault-ios/PORTING.md) §7 (örnek
uygulama) ve §8 (test denetim kanalı).

### Gereksinimler

| Araç | Niçin |
|---|---|
| Xcode 27 (komut satırı araçlarıyla) ve iOS 26.5 simülatörü | uygulamayı ve UI sürücüsünü derlemek, simülatör |
| XcodeGen (`brew install xcodegen`) | `project.yml`'dan Xcode projesi |
| Docker, Node 18+, `openssl`, `curl`, `jq` | Android koşusundaki gibi |

```bash
xcodebuild -version && xcodegen --version && xcrun simctl list runtimes | grep iOS
```

### Simülatör

Koşu simülatördeki uygulamanın verisini ve **simülatörün bütün Keychain'ini**
siler. Bu yüzden yalnızca bu koşuya ayrılmış bir simülatör kullanılır:

```bash
xcrun simctl create PinVault-iOS-E2E com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro \
  com.apple.CoreSimulator.SimRuntime.iOS-26-5     # çıkan UDID → E2E_IOS_UDID
```

Kapalıysa global setup açar (bitince yalnızca kendi açtığını kapatır;
`E2E_KEEP_EMULATOR=1` ile açık kalır). Uygulama her test başında silinmez,
yalnızca verisi temizlenir: uygulama silinip yeniden kurulursa cihaz kimliği
(`identifierForVendor`) değişir.

### UI sürücüsü (`ios-driver/`)

Simülatörde ekrana dokunmak ve ekrandaki metni okumak için Xcode'un UI test
altyapısıyla (XCUITest) yazılmış küçük bir sunucu: bir UI test paketinin tek
testi `127.0.0.1:6870`'te (`E2E_IOS_DRIVER_PORT`) HTTP isteklerini bekler;
`lib/iosDriver.js` onu derler (`.local/ios-driver-derived`), arka planda
başlatır, ölürse yeniden başlatır, koşu sonunda durdurur. Günlüğü
`.local/ios-driver.log`. (idb'nin dokunma yolu Xcode 27'de çalışmadığı için.)

Elle denemek için:

```bash
cd ios-driver && xcodegen generate
xcodebuild build-for-testing -project PinVaultDriver.xcodeproj -scheme PinVaultDriver \
  -sdk iphonesimulator -destination "platform=iOS Simulator,id=$E2E_IOS_UDID" -derivedDataPath ../.local/ios-driver-derived
TEST_RUNNER_DRIVER_PORT=6870 xcodebuild test-without-building \
  -xctestrun ../.local/ios-driver-derived/Build/Products/PinVaultDriver_*.xctestrun \
  -destination "platform=iOS Simulator,id=$E2E_IOS_UDID" &
curl -s localhost:6870/health
curl -s "localhost:6870/tree?bundle=com.example.sampleclient" | head -c 400
curl -s -X POST localhost:6870/stop
```

Uçlar: `GET /health`, `GET /tree?bundle=`, `POST /tap {x,y}`,
`POST /tapElement {id}` (gerekirse kaydırarak; ekran dışındaki SwiftUI
öğeleri ağaçta durur ama dokunulamaz), `POST /type {text}`,
`POST /clearAndType {id,text}`, `POST /swipe {x1,y1,x2,y2,duration}`,
`POST /scrollTo {id}`, `GET /alerts` ve `POST /tapAlertButton {id|label}`
(sistem pencereleri: Face ID), `POST /pressHome`, `GET /keyboard`,
`POST /dismissKeyboard`, `POST /stop`.

### Ayrı bir host örneği

Aynı Mac'te başka bir Android koşusu varsa (host 6650–6656, `pinvault-host`)
iOS koşusu kendi host'unu kullanır: bu çalışma kopyasının `sample-host`'u, kendi
compose projesi, container adı ve portlarıyla. `docker-compose.yml` container
adını `.env`'deki `HOST_CONTAINER_NAME`'den alır (boşsa `pinvault-host`).

```bash
cd ../sample-host
./scripts/setup.sh                 # demo profili: .env, API anahtarı, parolalar, imzalama anahtarı
```

`.env`'de şunlar değiştirilir (ya da eklenir):

```
COMPOSE_PROJECT_NAME=pinvault-ios
HOST_CONTAINER_NAME=pinvault-host-ios
HOST_HTTP_PORT=6850
HOST_HTTPS_PORT=6851
HOST_MTLS_PORT=6852
HOST_MOCK_TLS_PORT=6853
HOST_MOCK_MTLS_PORT=6854
HOST_MANAGEMENT_TLS_PORT=6855
HOST_RECOVERY_PORT=6856
PINVAULT_SERVER_SRC=../demo-server
TARGET_HOST=<Android host'unun hedefiyle aynı>
```

```bash
docker compose up -d --build
./scripts/provision.sh
./scripts/smoke-test.sh            # hepsi PASS
./scripts/export-server-key.sh     # saldırgan proxy için (G senaryoları)
```

Mock host'lar (`mock-tls.sample`, `mock-mtls.sample`) sertifikayı porta göre
seçer; iOS uygulaması bu adları kütüphanenin `resolve(host:to:)` ayarıyla host
IP'sine yönlendirir, `/etc/hosts` değişmez.

### Ortam değişkenleri

`sample-e2e/.env.ios.example` → `.env.ios` (git dışı). `lib/env.js` iOS
koşusunda bu dosyayı okur; ortamda zaten verilmiş değişkenleri ezmez.

| Değişken | iOS değeri | Açıklama |
|---|---|---|
| `E2E_PLATFORM` | `ios` | `npm run test:ios` verir |
| `E2E_IOS_UDID` | simülatörün UDID'si | yalnızca bu koşunun simülatörü |
| `E2E_IOS_DRIVER_PORT` | `6870` | UI sürücüsü |
| `E2E_HOST_DIR`, `E2E_CONTAINER` | `../sample-host`, `pinvault-host-ios` | host örneği (container adı verilmezse host `.env`'indeki `HOST_CONTAINER_NAME`) |
| `E2E_CUSTOM_BACKEND_PORT`, `E2E_PROXY_PORT`, `E2E_WEBHOOK_PORT` | `6860`, `6861`, `6862` | harness'ın Mac'te açtığı servisler |
| `E2E_BLACKHOLE_PORT` | `6863` | "paketleri düşür" kuralının karşılığı (bağlantıyı kabul edip yanıt vermeyen sunucu) |
| `E2E_FRESH_PORT_BASE`, `E2E_FRESH_PROJECT`, `E2E_FRESH_CONTAINER` | `6950`, `pinvault-ios-fresh`, `pinvault-host-ios-fresh` | geçici test sunucusu (taban … taban+6) |
| `E2E_FRESH_SUBNET` | boş = `10.213.<taban/100>.0/24` | geçici test sunucusunun Docker ağı. Docker'a bırakılınca `192.168.0.0/20` verebiliyor; bu ev ağını örter ve Jenkins gibi container'lar `192.168.1.x` adreslerine (GitLab, modem) ulaşamaz |
| `E2E_VARIANT` | `debug` / `e2e` | `Debug` ya da `E2E` derleme yapılandırması |
| `E2E_IOS_CLIENT_DIR`, `E2E_IOS_APP_NAME` | `../sample-client-ios`, `SampleClient` | uygulama projesi ve `.app` adı |
| `E2E_IOS_DEVICE_ID` | — | uygulamanın cihaz kimliği elle (normalde `report.json`'dan) |

### Çalıştırma

```bash
npm run test:ios
E2E_PLATFORM=ios npx playwright test tests/12-mtls-enroll-and-revoke.spec.js
```

Global setup simülatörü açar, UI sürücüsünü derleyip başlatır, uygulamayı
`SAMPLE_HOST_PROPS=.local/sample-host.properties xcodebuild … build` ile derler
(`.local/ios-derived`) ve `xcrun simctl install` ile kurar.

### Android'den farklar

| Android | iOS |
|---|---|
| `am start --es mode`, `date -s`, iptables | uygulamanın test denetim dosyası `Library/Caches/pinvault-e2e/control.json` (`mode`, `clockOffsetSeconds`, `redirects`) + `com.example.sampleclient.e2e.control` bildirimi. REJECT → kapalı yerel port, DROP → yanıt vermeyen yerel sunucu |
| `cmd jobscheduler run -f`, `dumpsys jobscheduler` | `…e2e.runScheduledWork` bildirimi; planlı işler `report.json`'da (BGTaskScheduler simülatörde yok) |
| `run-as` | veri kabı Mac'ten okunur: `shared_prefs/<ad>.xml` → `Library/Application Support/pinvault/<ad>.plist`, `files/vault_files/…` → `Library/Application Support/pinvault/vault_files/…` |
| `pm clear` | uygulama kapatılır, `Documents`, `Library`, `tmp` boşaltılır, simülatörün Keychain'i sıfırlanır |
| logcat | `log show` (`io.github.umutcansu.pinvault` ve uygulamanın satırları) |
| ekran kilidi PIN'i | Face ID kaydı; "PIN'i yaz" = eşleşme, "vazgeç" = eşleşmeme + Vazgeç düğmesi. Simülatörde cihaz şifresi hep var: "ekran kilidi yok" kurulamaz |
| GERİ tuşu | her ekranın `backButton`'u |

Yalnızca Android'de koşan senaryolar (`lib/env.js` → `ANDROID_ONLY_TESTS`,
iOS'ta atlanır): D05 (yedekleme, `bmgr`), U01 (2.0.9 APK'sından sürüm
yükseltme). iOS'a özgü kanıtlar kapsam matrisinde **I** grubunda.
