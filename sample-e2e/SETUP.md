# Sıfırdan kurulum

PinVault'u hiç görmemiş birinin, boş bir Mac'te (ya da Linux'ta) host'u ayağa
kaldırıp örnek uygulamayı telefona kurmasına kadar olan adımlar. Her adımın
karşılığı kanıt sayfasındadır (`evidence/index.html` → **Sıfırdan kurulum**
bölümü); parantez içindeki senaryo ve adım başlığı orada aranabilir.

Kanıtları üreten senaryolar **geçici bir test sunucusunda** çalışır (host'un
ikinci bir örneği: `.local/host-fresh`, portlar 6750–6754). Aşağıdaki komutlar gerçek kurulum
içindir: `SamplePinVaultHost` dizininde, 6650–6654 portlarıyla.

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

## 1. Depolar

Dördü kardeş dizin olmalı; betikler birbirini göreli yoldan bulur.

```bash
cd ~/Programming
git clone <PinVault>              # kütüphane + demo-server kaynağı
git clone <SamplePinVaultHost>    # Docker'da çalışan host paketi
git clone <SamplePinVaultClient>  # örnek Android uygulaması
git clone <SamplePinVaultE2E>     # uçtan uca testler (isteğe bağlı)
```

*(Kanıt: **K01 → Terminal: dört depo ve geçici test sunucusu için host kopyası (K1)**)*

## 2. Host ayarları: `.env`, API anahtarı, imzalama anahtarı

```bash
cd SamplePinVaultHost
./scripts/setup.sh
```

Yaptıkları:

- `.env` yoksa `.env.example`'dan üretir (izin 600),
- `API_KEY` boşsa rastgele üretir — dashboard bunu ister,
- `HOST_LAN_IP` boşsa makinenin LAN IP'sini bulur (telefon bu adrese bağlanır;
  sunucu sertifikası bu adresi de kapsar, yani adres SAN listesine girer),
- `data/signing-key.pem` yoksa ECDSA P-256 anahtar çifti üretir (izin 600).
  Dosyanın ilk satırı private (PKCS8, Base64), ikinci satırı public (X.509 SPKI).

Yerel PinVault kaynağından derlemek için `.env`'e ekle:

```
PINVAULT_SERVER_SRC=../PinVault/demo-server
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
./scripts/client-config.sh --properties > ../SamplePinVaultClient/sample-host.properties
cd ../SamplePinVaultClient
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
| Sunucu açılmıyor: `API_KEY env var is not set. Refusing to start…` | container'a `API_KEY` geçilmemiş; yalnızca bilinçli olarak `ALLOW_ANONYMOUS_ADMIN=true` ile açılır (E02) |
| Telefon: `başlatılamadı` / pin uyuşmazlığı | APK'ya gömülü ilk pin (bootstrap) sunucunun sertifikasıyla uyuşmuyor (sertifika yenilendi mi?) → `client-config.sh --properties` ile yeniden derle (E03) |
| smoke-test: `SAN <ip> içermiyor` | sertifika LAN IP'si `.env`'e girmeden üretilmiş → `data/certs/demo-server.jks` ve `.pins` silinip container yeniden başlatılmalı |
| Dashboard boş, sürekli anahtar soruyor | yanlış API anahtarı (403). `.env`'deki değeri gir; tarayıcıda `localStorage.pinvault_api_key` saklanır |
| mTLS Config API açılmıyor: `mTLS için önce client sertifika oluşturun` | truststore (sunucunun güvendiği istemci sertifikaları) yok → mTLS sekmesinden bir istemci sertifikası üret (K04) |
| Telefon host'a ulaşamıyor | telefon ve Mac aynı ağda değil ya da `HOST_LAN_IP` yanlış; emülatörde 10.0.2.2 yerine LAN IP kullanılır |
| `SIGNING_KEY_PASSWORD` ayarlayınca sunucu açılmıyor | anahtar dosyası şifreli kaldıysa parolayı geri ver ya da düz metin yedeği koy; anahtar dosyası `./data` dizin mount'u içinde olmalı (tek dosyalık mount'a yazılamıyor) |
| `docker compose down` sonrası Config API'ler kayıp sanılıyor | veriler `./data` altında kalıcıdır; `up -d` sonrası kendiliğinden yeniden başlar (E08) |
