# sample-host

Bu deponun `demo-server`'ını ([../demo-server](../demo-server)) tek komutla Docker'da çalıştıran referans host. Android tarafı için [sample-client](../sample-client) bu host'a bağlanır.

Host iki şey sunar: pinlenmiş ve ECDSA ile imzalanmış bir pin config API'si (TLS) ve yönetim API'si ile web dashboard (HTTP).

---

## Gereksinimler

- Docker 24+ ve Docker Compose v2.17+ (`build.additional_contexts` için); üretim profili Compose 2.24.4+ ister
- `openssl`, `curl`, `jq`
- İlk build için internet (Gradle bağımlılıkları; upstream kaynak seçiliyse git clone)

## Hızlı başlangıç

```bash
./scripts/setup.sh              # .env, API anahtarı, parolalar, LAN IP, signing key (DEMO profili)
docker compose up -d --build    # ilk build 3-5 dk
./scripts/provision.sh          # mTLS Config API + host'un kendi pin kaydı
./scripts/smoke-test.sh         # hepsi PASS olmalı
./scripts/seed-vault.sh         # isteğe bağlı: örnek uygulamanın vault dosyaları
./scripts/client-config.sh      # Android client'a girilecek değerler
```

> **Bu kurulum demo profilidir.** Tek paylaşılan yönetim anahtarı var, iki kişi onayı ve canlı sertifika kontrolü kapalı, imza anahtarı sunucunun diskinde, yedek ve kurtarma anahtarı yok. `setup.sh` ve `client-config.sh` bunu her çalıştığında hatırlatır; cihazlara uygulanan ret sınırı da kapalıdır (`DEVICE_REFUSAL_RATE_LIMIT=0`). Uçtan uca testler bu profille çalışır (üretim profilli bir host'a karşı başlamayı reddeder). Gerçek kullanım için aşağıdaki [Üretim profili](#üretim-profili).

> **Uçtan uca testlerin APK'sı (`e2e` derlemesi) gerçek kullanıcı telefonuna kurulmaz.** Test kontrollerini taşır, herkesin bildiği debug anahtarıyla imzalıdır ve demo değerleriyle derlenir. Telefonlara yalnızca `release` derlemesi gider; o da demo değerleriyle derlenmez ([sample-client → Yayın derlemesi](../sample-client/README.md#yayın-derlemesi)).

`provision.sh` tekrar çalıştırılabilir; yalnızca eksik olanı ekler. mTLS Config API'si veritabanına kaydedilir ve container yeniden başladığında kendiliğinden açılır.

`seed-vault.sh` örnek uygulamanın Vault ekranındaki dosyaları, uygulamanın beklediği kurallarla yükler (var olanlara dokunmaz, `--force` yeniler):

| Dosya | Nerede | Politika | Şifreleme | Ne için |
|---|---|---|---|---|
| `sample-flags` | default-tls | public | plain | herkese açık demo dosyası |
| `sample-atrest` | default-tls | public | at_rest | sunucu diskinde şifreli ama **herkese açık**; gizli bilgi için değil |
| `sample-admin` | default-tls | api_key | plain | cihazdan inmez (yalnızca sunucu araçları) |
| `sample-model` | default-tls | public | plain | dosya deposu, config ile eşitlenir |
| `sample-secret`, `sample-mtls-secret` | **sample-mtls** | token_mtls | **user_auth** | gizli: sunucu dosyayı telefonun ekran kilidi anahtarına kilitler |
| `sample-e2e` | **sample-mtls** | token_mtls | end_to_end | gizli: cihazın RSA anahtarıyla gelir, telefon ekran kilidiyle saklar |

Gizli dosyalar için telefonun mTLS'e kayıtlı olması, ekran kilidinin olması ve her dosya için o cihaza üretilmiş bir token gerekir (dashboard → sample-mtls → Vault → dosya → Token). Ayrıntı: [sample-client](../sample-client/README.md#gizli-dosyalar).

Dashboard: `http://localhost:6650/`. İlk istekte API anahtarını sorar; anahtar `.env` içindeki `API_KEY`. Anahtar yalnızca o tarayıcı sekmesinde (sessionStorage) tutulur; sekme kapanınca yeniden sorulur.

`client-config.sh` iki değeri sunucudan kendisi çıkarır:

- `host.clientCaPin`: cihaz sertifikalarını imzalayan istemci CA'sının pin'i. Sunucu bu CA'yı bir uçta yayımlamaz; betik onu container içinde `data/certs/client-ca.jks`'ten `keytool` ile okur, olmazsa sunucunun açılış log'undaki `client CA — SPKI …` satırından alır. Uygulama kayıtta ve her yenilemede gelen zincirin bu CA'nın imzasını taşımasını ister: kayıt yanıtını yolda değiştiren biri kendi CA'sıyla imzaladığı sertifikayı kurduramaz.
- `host.tlsScope` / `host.mtlsScope` (serverScope): yalnızca sunucu imzalı config'e `configApiId` yazıyorsa doldurulur. Yazmayan bir sunucu sürümüyle bu bağlama açık olsaydı uygulama hiçbir config'i kabul etmezdi; betik bu durumda iki değeri boş bırakır ve uyarır. Sunucu `configApiId` ve `X-Vault-Signature-V2` yazmaya başlayınca betiği yeniden çalıştır.

Dashboard'da işlem yapıp sonucunu telefonda doğrulayan uçtan uca testler [sample-e2e](../sample-e2e)'de.

---

## Sunucu kaynağı

Image, `demo-server` kaynağını `pinvault-server` adlı build context'inden alır. `.env` ile seçilir:

| Ayar | Kaynak |
|---|---|
| `PINVAULT_SERVER_SRC` boş (varsayılan) | Upstream git: `PINVAULT_REPO` @ `PINVAULT_REF` |
| `PINVAULT_SERVER_SRC=../demo-server` | Bu depodaki `demo-server/`, yayınlanmamış değişiklikler dahil |

Kaynak değiştikten sonra `docker compose up -d --build` yeterli. Yerel dizindeki çalışma verisi (`pinvault.db`, `certs/`, `signing-key.pem`, `build/`) image'a girmez; yalnızca `settings.gradle.kts`, `build.gradle.kts` ve `src/` kopyalanır.

## Portlar

| Dış port | Container | Protokol | İçerik |
|---|---|---|---|
| `6650` | `8080` | HTTP, **yalnızca bu makine** | Yönetim API'si ve web dashboard (`HOST_HTTP_BIND=127.0.0.1`) |
| `6655` | `8082` | HTTPS, sunucu sertifikası, **varsayılan olarak yalnızca bu makine** | Yönetim API'si şifreli (`HOST_MANAGEMENT_TLS_BIND=127.0.0.1`). Telefonlar ve uçtan uca testler bu porta ağdan bağlanmaz. Demo profilinde başka makineden dashboard için `HOST_MANAGEMENT_TLS_BIND=0.0.0.0`; üretim profilinde her durumda yalnızca bu makine |
| `6651` | `8081` | HTTPS, self-signed | Config API: `/api/v1/certificate-config`, enrollment, vault ve cihaz raporları (telemetri) |
| `6652` | `8092` | HTTPS + istemci sertifikası | mTLS Config API (`provision.sh` açar) |
| `6653` | `8443` | HTTPS, sunucu üretimi sertifika | Mock TLS hedef host `mock-tls.sample` (`provision.sh` açar). Üretim profilinde yayımlanmaz |
| `6654` | `8444` | HTTPS + istemci sertifikası | Mock mTLS hedef host `mock-mtls.sample` (`provision.sh` açar). Üretim profilinde yayımlanmaz |
| `6656` | `8083` | HTTPS, sunucu CA'sının imzaladığı sertifika | Kurtarma kapısı: istemci sertifikası istemez, yalnızca sertifika yenileme. Süresi dolmuş sertifikalı telefon buradan yeniler; uygulama bu porta sunucu CA'sının pin'iyle bağlanır |

`.env` içinde `HOST_HTTP_PORT` / `HOST_MANAGEMENT_TLS_PORT` / `HOST_HTTPS_PORT` / `HOST_MTLS_PORT` / `HOST_MOCK_TLS_PORT` / `HOST_MOCK_MTLS_PORT` / `HOST_RECOVERY_PORT` ile değişir. Düz HTTP yönetim portu ağa kapalıdır; API anahtarı ağda şifresiz dolaşmaz. Şifreli yönetim portu da varsayılan olarak yalnızca bu makineye açıktır. Demo profilinde başka bir makineden yönetmek için `.env`'e `HOST_MANAGEMENT_TLS_BIND=0.0.0.0` yazılıp `docker compose up -d` çalıştırılır, sonra `https://<host>:6655` (tarayıcı kendinden imzalı sertifika uyarısı verir); ya da SSH tüneli. Üretim profilinde iki yönetim portu da yalnızca `127.0.0.1`'e açılır; uzaktan yönetim VPN ya da SSH tüneliyle yapılır (`ssh -L 6655:127.0.0.1:6655 kullanici`, sonra `https://localhost:6655`). Telefonların yönetim portuna ihtiyacı yoktur: raporları da Config API portuna gider. Mock host adları gerçek DNS'te yoktur; örnek uygulama onları `host.ip`'ye çözümler.

---

## Güvenlik modeli

- **API anahtarı zorunlu.** Anonim admin kapalı; `API_KEY` boşsa compose başlamaz. Yönetim uçları iki portta da `X-API-Key` ister. Yönetim işlemleri yalnızca yönetim portlarında: vault yönetimi (yükleme, silme, politika, token, dağıtım listesi) `/api/v1/config-apis/<kimlik>/vault/…` altındadır, Config API portları (`6651`, `6652`) yalnızca cihazın indirmesini, raporunu ve anahtar kaydını sunar. Tarayıcıdan gelen yönetim yazımları ancak sunucunun kendi sayfasından (aynı köken) ve JSON ya da `X-API-Key` / `X-PinVault-Admin` başlığıyla kabul edilir; dashboard anahtarı tarayıcı sekmesi kapanınca silinen oturum belleğinde (sessionStorage) tutar.
- **Parolalar zorunlu.** Sunucu `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD` ve (sunucuda yerel imzalayıcı varsa) `SIGNING_KEY_PASSWORD` olmadan açılmaz; `setup.sh` üçünü de demo profilinde de üretir. `ALLOW_DEMO_SECRETS=true` sunucuyu kaynak koddaki demo parolalarıyla açar: yalnızca kullan-at denemeler içindir, sample-host kullanmaz, üretim profili `false` sabitler. Cihazların çağırdığı uçlar (config indirme, enrollment, vault indirme, telemetri) anahtarsız açıktır; hepsi TLS üzerinden ve pinli.
- **Config imzalı.** Her config cevabı `data/signing-key.pem` ile imzalanır ve `issuedAt/expiresAt` taşır. Client imzasız, süresi geçmiş ya da eski bir config'i uygulamaz.
- **Signing key (demo) host'ta durur, diskte şifreli.** `setup.sh` anahtarı `0600` izinle üretir; sunucu ilk açılışta `SIGNING_KEY_PASSWORD` ile şifreler (dosya `ENCv1:` ile başlar; host'taki araçlar public yarısını `GET /api/v1/signing-key`'den okur); `data/` ile birlikte container'a bağlanır ve git'e girmez. Public yarısı client'a gömülür. Üretim profili tek ve diskteki bir anahtarı kabul etmez: en az iki imzalayıcı, en az biri HSM ya da KMS ([Üretim profili](#üretim-profili)).
- **Enrollment token ile.** `ENROLLMENT_MODE=token`: mTLS sertifikası yalnızca admin'in ürettiği tek kullanımlık token'la alınır. Çok cihaz için panelden bir **kayıt politikası** açılabilir: tek kod, en fazla N cihaz, gün sınırı ve istenirse her cihaz için yönetici onayı (Client Sertifikaları → Kayıt politikaları; onay bekleyenler aynı sekmede). Kod verilemeyen cihazlar için aynı sekmedeki **Kodsuz başvurular** anahtarı açılabilir: cihaz hiçbir şey girmeden başvurur, her başvuru onay bekler; telefon ve panel aynı doğrulama kodunu gösterir. İptal edilen bir kimlik iptal edilmiş kalır; aynı kimlikle yeniden kayıt için listede **Kimliği unut**'a basılır (eski sertifikası ve anahtarı reddedilmeye devam eder).
- **TLS sertifikası LAN IP'yi içerir.** Container, Mac'in LAN IP'sini göremez; `HOST_LAN_IP` sunucuya `EXTRA_CERT_SANS` olarak geçer ve sertifika üretilirken SAN listesine eklenir. Yoksa telefon hostname doğrulamasında bağlantıyı reddeder.
- **Telemetri şifreli ve pinlidir, Config API portundan gider.** Client'ın bağlantı olayları `6651`'deki rapor uçlarına (`POST /api/v1/connection-history/client-report` ve `…/config-update-report`) config sunucusunun pin'leriyle gönderilir; telefon yönetim portuna hiç bağlanmaz. Bu uçlar anahtarsızdır (cihazlar yönetim anahtarı taşımaz): sunucu alanları doğrular ve adres/cihaz başına sınırlar (`REPORT_RATE_LIMIT`, `REPORT_DEVICE_RATE_LIMIT`), yine de raporlar bir güvenlik kanıtı değil, işletim bilgisidir.
- **Dosya izinleri.** `data/` altındaki anahtar depoları (`*.jks`), veritabanı ve imza anahtarı yalnızca servis kullanıcısına açıktır (container `umask 077` ile çalışır, açılışta izinler düzeltilir). Tek istisna, içinde yalnızca herkese açık pin'ler olan `data/certs/demo-server.pins`. Betikler yönetim anahtarını ve PIN'leri komut satırına yazmaz (komut satırı makinedeki herkese görünür).

`smoke-test.sh` bunların hepsini çalışan container'a karşı doğrular: imzayı `openssl` ile kontrol eder, sertifika pin'ini ve SAN'ı okur, yönetim uçlarının anahtarsız 401 döndüğünü ve `ping-remote` enjeksiyon denemesinin 400 aldığını görür.

---

## Konfigürasyon (`.env`)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SAMPLE_PROFILE` | `demo` | `demo` ya da `production`; `setup.sh` ve `client-config.sh` buna göre davranır (sunucu okumaz). [Üretim profili](#üretim-profili) |
| `HOST_HTTP_PORT` | `6650` | Yönetim portunun host tarafı |
| `HOST_MANAGEMENT_TLS_BIND` | `127.0.0.1` | Şifreli yönetim portunun (6655) açıldığı adres. `0.0.0.0`: başka makineden dashboard (yalnızca demo; üretim profili yok sayar) |
| `HOST_HTTPS_PORT` | `6651` | Config API portunun host tarafı |
| `HOST_LAN_IP` | `setup.sh` bulur | Telefonların bu makineye ulaştığı IP; sertifika SAN'ına girer |
| `TARGET_HOST` | `www.example.com` | Örnek uygulamanın pin'lediği ve bağlandığı gerçek HTTPS sitesi; `client-config.sh` ve uçtan uca testler buradan okur. En az üç parçalı bir ad (joker alan adı testi için) |
| `API_KEY` | `setup.sh` üretir | Yönetim API'si ve dashboard anahtarı |
| `PINVAULT_REPO` / `PINVAULT_REF` | upstream / `main` | Upstream kaynak ve sürüm. Üretim profili dal ya da etiket adını kabul etmez: 40 haneli commit SHA'sı ya da `PINVAULT_SERVER_SRC` |
| `PINVAULT_SERVER_SRC` | boş | Yerel `demo-server` dizini (bu depoda `../demo-server`); doluysa upstream yerine kullanılır |
| `ENROLLMENT_MODE` | `token` | `token` önerilir; `open` deviceId ile kayda izin verir (yalnızca demo) |
| `CLIENT_CERT_TTL_DAYS` | `90` | CSR ile kayıt olan cihazların sertifika ömrü (gün); ömrünün son üçte birinde kendiliğinden yenilenir |
| `ALLOW_TEST_HOOKS` | boş | `true`: kısa ömürlü sertifika kancası açılır (`POST /api/v1/test-hooks/client-cert-ttl`). Yalnızca testler; uçtan uca testler `env-override.sh` ile geçici açar. Üretim profilinde açılamaz (`ALLOW_ANONYMOUS_ADMIN` da): compose `false` sabitler, sunucu `true` ile açılmaz |
| `DEVICE_REFUSAL_RATE_LIMIT` | demo `0`, üretim sunucu varsayılanı (300) | Bir adresin 10 dakikada toplayabileceği reddedilen istek sayısı. Demo profilinde sınır yoktur: Docker Desktop arkasında bütün cihazlar tek adresten görünür ve uçtan uca testler bilerek çok sayıda reddedilen istek yapar. Üretimde `0` yazma |
| `REPORT_RATE_LIMIT`, `REPORT_DEVICE_RATE_LIMIT`, `DEVICE_KEY_RATE_LIMIT`, `DEVICE_KEY_LIMIT`, `VAULT_MAX_FILE_BYTES`, `MTLS_RESTART_MIN_INTERVAL_SECONDS` | sunucu varsayılanı | Kötüye kullanım sınırları: cihaz raporları, cihaz anahtarı kaydı, vault dosya boyutu, mTLS dinleyicilerinin yeniden başlatılma aralığı |
| `ENROLLMENT_ATTESTATION`, `ENROLLMENT_P12`, `USER_AUTH_REQUIRE_PER_USE` | boş (üretim: `enforce`, `off`, `true`) | Kayıtta donanım belgesi, P12 ile kaydın kapatılması, ekran kilitli dosyada her kullanımda onay. Bu adları tanımayan bir sunucu sürümü onları yok sayar; derlediğin sürümde geçtiklerini doğrula |
| `INTEGRITY_VERIFICATION`, `INTEGRITY_VERIFIER_COMMAND` | boş (`off`) | Kayıtta cihaz bütünlüğü: uygulama `integrityTokenProvider` ile bir Play Integrity token'ı gönderir, sunucu komutla çözer. Doğrulayıcı imajda: `/opt/pinvault/scripts/play-integrity-verify.sh`; `INTEGRITY_PLAY_PACKAGE` ve `INTEGRITY_PLAY_SERVICE_ACCOUNT_FILE` (servis hesabı JSON'u, `data/` altında, izinler 600) ister. Önce `warn` ile gerçek bir telefonda dene, sonra `enforce` |
| `CONFIG_TTL_SECONDS` | `86400` | İmzalı config'in geçerlilik süresi |
| `SIGNING_KEY_PASSWORD` | `setup.sh` üretir | İmzalama anahtarı diskte AES-256-GCM ile şifrelenir; düz metin bir anahtar dosyası (eski kurulum, `signing-keys.sh install`) ilk açılışta şifrelenir. Sunucuda yerel imzalayıcı varken boşsa sunucu açılmaz |
| `ALLOW_DEMO_SECRETS` | boş | `true`: parolalar boşken sunucu kaynak koddaki demo değerleriyle açılır. Yalnızca kullan-at denemeler; üretim profilinde sabit `false` |
| `FETCH_ALLOW_PRIVATE_TARGETS` | demo `true` (`setup.sh` yazar), üretim boş | "URL'den sertifika al" (host ekleme, sertifikayı URL'den yenileme) yalnızca `true` iken bu makineye (loopback) ve yerel ağ adreslerine bağlanır; bulut meta veri adreslerine hiçbir zaman. Demo profili bu makinedeki ve LAN'daki deneme host'larını pinlediği için açar |
| `MANAGEMENT_BIND`, `MANAGEMENT_ALLOWED_HOSTS` | `0.0.0.0`, `localhost:<HOST_HTTP_PORT>,127.0.0.1:<HOST_HTTP_PORT>` | Yönetim dinleyicisi container içinde her arayüzü dinler (dışarıya açılışı `HOST_HTTP_BIND` belirler). Yalnızca anahtarsız modda (`ALLOW_ANONYMOUS_ADMIN`, testler) önemli: sunucu istekleri yalnızca bu adreslerle gelirse cevaplar |
| `ADMIN_ALLOWED_ORIGINS` | boş | Dashboard `Host` başlığını değiştiren bir ters vekilin arkasındaysa onun adresi (yoksa yönetim yazımları 403) |
| `PINVAULT_UID`, `PINVAULT_GID` | `10001` | Sunucunun çalıştığı kullanıcı. Aşağıya bak: [Container kullanıcısı](#container-kullanıcısı) |
| `ENROLLMENT_TOKEN_TTL_SECONDS` | `86400` | Kayıt token'ının geçerlilik süresi |
| `ENROLLMENT_REQUEST_TTL_HOURS` | `24` | Onay bekleyen başvurunun ömrü (saat); cevaplanmayan başvuru düşer, telefon yeniden başvurur |
| `OPEN_ENROLLMENT_RATE_LIMIT` | `20` | Kodsuz başvurularda bir IP adresinden 10 dakikada en fazla yeni başvuru; `0` sınırı kaldırır |
| `OPEN_ENROLLMENT_MAX_PENDING` | `50` | Aynı anda onay bekleyebilecek en fazla kodsuz başvuru |
| `VAULT_AT_REST_PASSWORD` | `setup.sh` üretir | Sunucu diskindeki vault dosyalarının (at_rest ve cihaza özel) parolası. **Boşsa şifreleme yalnızca etikettir**, aşağıya bak |
| `VAULT_AT_REST_PASSWORD_PREVIOUS` | boş | Parolayı değiştirirken eskisi: sunucu açılışta dosyaları yeni parolaya geçirir, sonra silinir |
| `CERT_EXPIRY_WARN_DAYS` | `30` | Sertifika süre uyarısı eşiği |
| `KEYSTORE_PASSWORD` | `setup.sh` üretir | Sunucunun kendi anahtar depolarının parolası (TLS anahtarları, yedek anahtarlar, istemci güven listesi, host istemci sertifikaları). Hiçbir cihaza gitmez; eski kurulumlarda depolar açılışta bu parolaya geçirilir |
| `KEYSTORE_PASSWORD_PREVIOUS` | boş | Parolayı değiştirirken eskisi: sunucu açılışta depoları yeni parolaya geçirir, sonra silinir |
| `CLIENT_P12_PASSWORD` | `changeit` (üretim profili rastgele üretir) | Cihaza giden mTLS sertifika paketinin parolası; yalnızca eski kütüphane sürümleri ve elle kurulan P12 dosyaları için. Güncel kütüphane her indirmede tek kullanımlık parola alır. Örnek uygulama elle kurulan P12'nin parolasını kullanıcıdan bir kez ister, dosyayı telefonun anahtar deposuyla şifreleyip düz kopyayı siler |
| `USER_AUTH_ATTESTATION` | `warn` | Ekran kilidiyle açılan dosyaların (`user_auth`) anahtarı için Google imzalı donanım belgesi (Android Key Attestation): `off` bakmaz; `warn` ilk anahtarı belgesiz de kabul eder, değiştirmek için cihazın sertifikası ya da token'ı **ve** geçerli belge ister; `enforce` her anahtarda belge ister. Emülatör yazılım belgesi üretir, `enforce`'ta reddedilir. Paket adı `ATTESTATION_PACKAGE_NAMES`, imza sertifikası `ATTESTATION_SIGNER_SHA256`: ikisi birden dolu değilse hiçbir belge sayılmaz (`warn` uyarır, `enforce` açılmaz) |
| `ATTESTATION_REQUIRE_VERIFIED_BOOT` | boş (= `true`; üretim `true` yazar) | `false`: kilidi açılmış (bootloader) ya da doğrulanmamış açılışlı test telefonunun belgesi de geçer |
| `ATTESTATION_REVOKED_SERIALS_FILE`, `ATTESTATION_STATUS_MAX_AGE_HOURS` | boş (üretim: `/data/attestation-status.json`, `48`) | Google'ın donanım belgesi iptal listesi (container içindeki yol) ve en fazla kaç saatlik olabileceği; eskiyse hiçbir belge geçmez. Dosya yoksa sunucu açılmaz. Aşağıya bak: [Donanım belgesi iptal listesi](#donanım-belgesi-iptal-listesi) |
| `ATTESTATION_MIN_PATCH_LEVEL` | boş | Bu tarihten eski güvenlik yamalı telefonun belgesi geçmez (`YYYYAA`, ör. `202401`) |

> ### ⚠️ `VAULT_AT_REST_PASSWORD` boş bırakılmamalı
>
> `at_rest` ve cihaza özel vault dosyaları diskte AES-256-GCM ile tutulur;
> anahtar bu değişkenden PBKDF2-SHA256 ile türetilir. Değişken boşsa sunucu
> **kaynak kodundaki sabit demo anahtarını** kullanır ve log'a uyarı basar.
>
> Sonuç: dosyalar `pinvault.db` içinde şifreli *görünür*, ama anahtar
> kütüphanenin kaynağında herkese açık olduğu için veritabanını ele geçiren
> biri içeriği aynen çözebilir. Yani boşken bu şifreleme bir güvenlik sınırı
> değil, yalnızca bir etikettir. Cihaza özel mod da diskte aynı parolayı
> kullanır; telefona giderken ayrıca cihazın anahtarıyla şifrelenir.
>
> `setup.sh` bu yüzden rastgele bir parola üretir; demo parolasıyla yazılmış
> dosyalar sunucu ilk açıldığında yeni parolaya geçirilir. Parolayı
> değiştirirken eskisini `VAULT_AT_REST_PASSWORD_PREVIOUS`'a yaz, sunucuyu
> yeniden başlat, sonra sil. Hiçbir parolanın açmadığı bir dosya cihaza
> gönderilmez (sunucu hata verir ve açılışta log'a yazar); onu yeniden yükle.

### Kurulum sihirbazı

Dashboard → **Kurulum Sihirbazı**. Üç adım:

1. **Sunucu**: üretim için eksik olanları sıralar (yönetici anahtarları, iki kişi onayı, imzalayıcılar, donanım belgesi, cihaz bütünlüğü, demo parolaları…) ve her biri için `.env`'e yazılacak satırı verir. `.env`'i değiştirmez, hiçbir gizli değeri göstermez; satırları ekleyip `docker compose up -d` ile yeniden başlat.
2. **Uygulama**: Config API'yi, telefonun sunucuya ulaştığı adresi ve açılacak korumaları seç.
3. **Kod**: uygulamanın PinVault ayarı, Kotlin ya da Java, bu sunucunun pin'leri, imza anahtarları, istemci CA pin'i ve portlarıyla. Sertifika ya da imza anahtarı değişince sihirbazı yeniden çalıştır.

`client-config.sh` örnek uygulamanın `sample-host.properties` dosyasını yazmaya devam eder; sihirbaz kendi uygulaman içindir.

## Kalıcı veri

| Yol | İçerik |
|---|---|
| `data/db/pinvault.db` | SQLite; Flyway migration'ları açılışta otomatik uygulanır |
| `data/certs/demo-server.jks`, `demo-server.pins` | Sunucu TLS anahtarı ve pin'leri; ilk açılışta üretilir |
| `data/signing-key.pem` | Config imzalama anahtarı; `setup.sh` üretir, sunucu ilk açılışta `SIGNING_KEY_PASSWORD` ile şifreler (`ENCv1:`) |
| `data/certs/client-ca.jks` | Cihaz sertifikalarını (CSR ile kayıt ve yenileme) imzalayan istemci CA'sı; ilk açılışta üretilir. Pin'ini `client-config.sh` `host.clientCaPin` olarak yazar |
| `data/attestation-status.json` | Google'ın donanım belgesi iptal listesi (üretim profili; `fetch-attestation-status.sh` indirir) |
| `data/signing-key*.pem.<tarih>.bak` | `signing-keys.sh install`'ın üzerine yazmadan önce sakladığı eski imza anahtarı; gerekmiyorsa sil |

`data/` altındaki her şey git dışıdır (`.gitignore`; yalnızca iki `.gitkeep` izlenir).

### Mac'in IP'si değişirse

```bash
# .env içinde HOST_LAN_IP'yi güncelle (ya da satırı boşaltıp ./scripts/setup.sh)
docker compose down
rm data/certs/demo-server.jks data/certs/demo-server.pins   # yeni SAN ile yeniden üretilsin
docker compose up -d
./scripts/client-config.sh     # yeni IP ve pin'leri client'a gir
```

### Sıfırlama

```bash
docker compose down
rm -rf data/db/* data/certs/*
rm data/signing-key.pem && ./scripts/setup.sh   # imza anahtarını da yenilemek istersen
docker compose up -d
./scripts/client-config.sh
```

Signing key ya da sunucu sertifikası yenilenirse client'taki sabitler de değişmelidir; eski APK yeni host'a bağlanamaz.

**Sertifikayı yenilemek yerine yedek anahtara geçmek.** Sunucu sertifikayı üretirken bir de yedek anahtar üretip `data/certs/demo-server.backup.jks` dosyasında saklar; yedeğin pin'i APK'ya ikinci başlangıç pin'i olarak girer. Dashboard → Bootstrap Pin → "Yedek Anahtara Geç" ve ardından `docker compose restart`: sunucu artık yedek anahtarı sunar, eski APK bağlanmaya devam eder. Sunucu yeni bir yedek hazırlar; onu bir sonraki sürüme almak için `./scripts/client-config.sh` yeniden çalıştırılır. Hedef host'larda aynı düğme host detayında; telefonlar config yenilemeden bağlanmaya devam eder. Bu özellikten önce üretilmiş sertifikaların saklı yedeği yoktur: bir kez yeniden üretmek gerekir (sunucu sertifikası için bu bir kez daha APK güncellemesi demek). Yedek, birincil anahtarla aynı dizinde durur: `data/certs` başkasının eline geçtiyse yedeğe geçmek yetmez, sertifika yeniden üretilmelidir.

---

## Sorun giderme

**`API_KEY bos. Once ./scripts/setup.sh calistir.`** Compose `.env`'de anahtar bulamadı. `./scripts/setup.sh` çalıştır.

**Port çakışması.** `lsof -iTCP:6650 -sTCP:LISTEN` ile süreci bul ya da `.env`'de portları değiştir.

**Healthcheck başarısız.** `docker compose logs -f pinvault-host`. İlk açılışta migration birkaç saniye sürer.

**Telefon bağlanamıyor.** Sırayla bak:
1. `./scripts/smoke-test.sh` içindeki SAN kontrolü PASS mı? Değilse yukarıdaki "IP değişirse" adımları.
2. Telefon aynı ağda mı, `https://<HOST_LAN_IP>:6651/health` açılıyor mu?
3. macOS güvenlik duvarı Docker'a gelen bağlantıya izin veriyor mu?

**Upstream değişikliği gelmiyor.** Git context'i cache'lenmiş olabilir: `docker compose build --no-cache && docker compose up -d`.

**Derleme `load metadata for docker.io/library/…` adımında `DeadlineExceeded` ile düşüyor.** Ağ sağlamsa (`curl -I https://registry-1.docker.io/v2/` hızlı dönüyorsa) sorun genellikle Docker Desktop'ın kimlik yardımcısıdır: `echo https://index.docker.io/v1/ | docker-credential-desktop get` yanıt vermiyorsa takılmıştır. Kalıcı çözüm Docker Desktop'ı yeniden başlatmak. Diğer container'ları durdurmadan geçmek için temel imajları kimlik yardımcısı olmadan bir kez çek; sonraki derlemeler onları yerelden çözer:

```bash
mkdir -p /tmp/docker-anon && echo '{"auths":{},"currentContext":"desktop-linux"}' > /tmp/docker-anon/config.json
ln -sf ~/.docker/contexts ~/.docker/cli-plugins /tmp/docker-anon/
DOCKER_CONFIG=/tmp/docker-anon docker pull gradle:8.7-jdk17
DOCKER_CONFIG=/tmp/docker-anon docker pull eclipse-temurin:17-jre-noble
```

## Komut özeti

```bash
docker compose up -d --build                 # başlat / yeniden derle
docker compose logs -f pinvault-host         # log
docker compose ps                            # durum
./scripts/smoke-test.sh                      # doğrulama
./scripts/client-config.sh --properties      # client'ın sample-host.properties dosyası
./scripts/seed-vault.sh [--force]            # örnek uygulamanın vault dosyaları (gizliler sample-mtls'te)
./scripts/setup.sh --production …            # üretim profili (aşağıdaki "Üretim profili")
./scripts/offline-keygen.sh keys <ad>…       # BAŞKA makinede: çevrimdışı kurtarma/yedek anahtarı (parolayla şifreli)
./scripts/check-secrets.sh [--all]           # depoya anahtar girmesin (pre-commit kancası)
./scripts/env-override.sh set KEY=VALUE ...  # geçici sunucu ayarı (container yeniden oluşturulur)
./scripts/env-override.sh reset              # .env değerlerine dön
./scripts/export-server-key.sh               # TLS anahtarını PEM olarak dışa aktar (E2E'deki saldırgan proxy için)
./scripts/signing-keys.sh …                 # anahtar seti imzalama/yükleme; demo için yedek/kurtarma anahtarı
./scripts/add-admin.sh <ad> --apply         # kişisel yönetici anahtarı (ADMIN_KEYS)
./scripts/softhsm-init.sh [enable|show]      # PKCS#11 yolunu denemek için SoftHSM (gerçek HSM değil)
docker compose down                          # durdur
```

---

## İsteğe bağlı güvenlik katmanları

Demo profilinde hiçbiri açık değildir ve host eskisi gibi çalışır; her biri ayrı açılıp denenebilir. Aşağıdaki örnekler demo profili içindir (anahtarlar bu makinede, şifresiz üretilir). [Üretim profili](#üretim-profili) bunları kendisi açar ve çevrimdışı anahtarları bu makinede üretmez. Değişkenler `.env`'e yazılır (kalıcı) ya da `./scripts/env-override.sh set …` ile geçici denenir.

**Yedek imza anahtarı (uygulama güncellemesi gerektirmeden anahtar değiştirme).** Çevrimdışı bir anahtar üret, public key'ini APK'ya ikinci anahtar olarak göm. Sunucunun anahtarı kaybolur ya da çalınırsa sunucuyu yedek anahtarla başlatmak yeter:

```bash
./scripts/signing-keys.sh gen backup-1                  # offline-keys/backup-1.{pem,pub}
./scripts/client-config.sh --properties > …             # host.signingPublicKeys yedeği de içerir
# acil durumda:
./scripts/signing-keys.sh install backup-1 && docker compose restart pinvault-host
```

**İmzalama anahtarı seti (döndürme ve iptal).** Kurtarma anahtarı yalnızca "cihazlar artık şu imza anahtarlarına güvensin" listesini imzalar; çevrimdışı durur, sunucuya hiç gelmez. Uygulama kurtarma public key'ini gömer, sunucu `RECOVERY_PUBLIC_KEYS` ile yüklenen seti cihazın yapacağı gibi doğrular ve her config'le taşır. Çalınan bir anahtar, onu listelemeyen yeni bir setle bütün cihazlarda iptal olur:

```bash
./scripts/signing-keys.sh gen recovery-1                # APK'ya ve RECOVERY_PUBLIC_KEYS'e girer
./scripts/signing-keys.sh gen next
./scripts/signing-keys.sh install next next             # data/signing-key-next.pem
./scripts/env-override.sh set CONFIG_SIGNERS=local,local:next RECOVERY_PUBLIC_KEYS="$(cat offline-keys/recovery-1.pub)"
./scripts/signing-keys.sh keyset -v 1 -k next -s recovery-1 -o keyset-v1.json   # eski anahtar artık listede yok
./scripts/signing-keys.sh upload keyset-v1.json
```

Sunucu, etkin imzalayıcılarından yeterince anahtar içermeyen bir seti reddeder (aksi hâlde onu uygulayan her cihaz sonraki bütün config'leri reddederdi). Anahtar seti etkinken dashboard'daki "anahtarı yenile" kapanır; döndürme set üzerinden yapılır.

**HSM'de imzalama.** SoftHSM gerçek bir HSM değildir: PKCS#11 arayüzünü taklit eden bir yazılımdır, anahtarı yine sunucunun diskinde tutar ve yalnızca bu yolu donanımsız denemek içindir (üretim profilinde çalışmaz ve sayılmaz). `./scripts/softhsm-init.sh` imajdaki SoftHSM'de bir token hazırlar (128 bit rastgele PIN), `./scripts/softhsm-init.sh enable` sunucuyu `CONFIG_SIGNERS=pkcs11` ile açar: anahtar token'ın içinde üretilir, dışarı çıkarılamaz ve yalnızca imza için kullanılabilir (şifre çözme, anahtar sarma yok; `./scripts/softhsm-init.sh show` öznitelikleri gösterir: "Usage: sign", "never extractable"). Gerçek bir HSM'de yalnızca `PKCS11_LIBRARY` değişir. Bulut KMS ya da ayrı bir imza servisi için `CONFIG_SIGNERS=command` + `SIGNER_COMMAND` (stdin'den gelen baytları imzalayıp stdout'a imza basan komut) + `SIGNER_PUBLIC_KEY`; özet imzalayan KMS'ler için `SIGNER_INPUT=digest`. `CONFIG_SIGNATURE_CACHE=true` aynı içeriği bir kez, yayın anında imzalar; HSM/KMS'e her cihaz isteğinde gidilmez.

**m-of-n imza.** `CONFIG_SIGNERS=local,command` gibi iki imzalayıcı her config'e iki imza koyar; uygulama `requiredSignatures(2)` ile ikisini birden ister. Anahtarlar farklı kişilerde ya da sistemlerde durdukça ne tek bir yönetici ne de bu sunucunun kendisi tek başına pin yayımlayabilir.

**Kişisel yönetici anahtarları, denetim kaydı, bildirim.** `./scripts/add-admin.sh alice --apply` bir anahtar üretir ve `.env`'deki `ADMIN_KEYS`'e yalnızca SHA-256'sını yazar. Denetim kaydı (dashboard → Denetim Kaydı) her yönetim değişikliğini kimin yaptığıyla ve pin farkıyla tutar; kayıtlar silinemez ve hash zinciriyle bağlıdır ("Zinciri doğrula"). `NOTIFY_WEBHOOK_URL` güvenlik olaylarını anında bir webhook'a (Slack uyumlu) gönderir; `NOTIFY_WEBHOOK_SECRET` ile her istek `X-PinVault-Timestamp` (Unix saniye) ve `X-PinVault-Signature: sha256=<HMAC-SHA256("<zaman damgası>.<gövde>")>` taşır; alıcı imzayı zaman damgasıyla birlikte doğrulamalı ve birkaç dakikadan eski bildirimleri reddetmeli (yakalanan bir bildirim yeniden gönderilemesin). Yalnızca gövdeyi imzalayan eski alıcılar bu sürümle doğrulayamaz.

**İki kişi onayı.** `PIN_CHANGE_APPROVALS=2`: pin, force, sertifika ve imza anahtarı değişiklikleri hemen uygulanmaz; başka bir yönetici dashboard'daki "Onaylar" bölümünden onaylayınca uygulanır. Kimse kendi isteğini onaylayamaz, paylaşılan `API_KEY` onay veremez. Bu modda cihazlara açık Config API portları pin yazmalarını reddeder.

**Canlı sertifika kontrolü.** `PIN_LIVE_CHECK=enforce`: yeni ya da değişen bir pin seti, host'un şu an sunduğu sertifikayı telefonun kabul edeceği bir pin içermiyorsa (sertifikanın kendi pin'i ya da sertifikanın gerçekten bağlandığı CA'nın pin'i; yazım hatası, yanlış host) kaydedilmez; `warn` kaydeder ama uyarır. Sunucunun doğrudan çözemediği adlar için `LIVE_CHECK_HOST_MAP="mock-tls.sample=127.0.0.1:8443"`. Acil durumda gerekçe yazılarak yine de kaydedilebilir; gerekçe denetim kaydına düşer.

---

## Üretim profili

Demo profili her güvenlik katmanını kapalı bırakır ve yalnızca denemek içindir. Üretim profili onları açılmış olarak kurar ve kurallara uymayan bir kurulumu **başlatmaz**. Üç şey demo profilinden temelden farklıdır:

1. **Çevrimdışı özel anahtarlar bu makinede üretilmez ve bu makineye hiç gelmez.** Kurtarma ve yedek imza anahtarları, sunucunun imza anahtarı çalındığında onu iptal eden anahtarlardır; sunucuda dururlarsa sunucuyu ele geçiren hepsini birden alır. Başka bir makinede üretilir, buraya yalnızca public yarıları verilir.
2. **Tek imzalayıcı kabul edilmez.** En az iki imzalayıcı ve en az biri sunucunun diskinde düz dosya olmayan (HSM ya da KMS); uygulama her config'te en az 2 imza ister.
3. **Demo kurulumunun üstüne kurulmaz.** Demo `.env`'i, imza anahtarı, sunucu sertifikası ve veritabanı (açık kayıt ayarı dahil) üretime taşınmaz.

### Adım adım

**1. Başka bir makinede (internete kapalı): çevrimdışı anahtarlar.** Yalnızca `scripts/offline-keygen.sh` dosyasını kopyala; `openssl`'den başka bir şeye ihtiyacı yok.

```bash
./offline-keygen.sh keys recovery-1 backup-1    # parola sorar; özel yarılar şifreli yazılır
```

Ekrana yazdığı iki `public key` satırını not al. `*.pem` dosyaları o makinede (iki ayrı yerde yedekli) kalır; sunucuya, e-postaya, depoya konmaz.

**2. Her yönetici kendi makinesinde: kişisel anahtar.**

```bash
./offline-keygen.sh admin ayse      # anahtarı bir kez gösterir; sunucuya verilecek olan: ayse:<sha256>
```

**3. Uygulamanın yayın imzası.** Telefona kurulan son dosyanın imza sertifikasının SHA-256'sı ([sample-client → Yayın derlemesi](../sample-client/README.md#yayın-derlemesi)).

**4. Sunucuda: kurulum.** İmzalayıcıların ayarları (`PKCS11_LIBRARY`, `PKCS11_PIN`, `SIGNER_COMMAND`, `SIGNER_PUBLIC_KEY`) ortam değişkeni olarak ya da önceden `.env`'e yazılarak verilir; PIN komut satırına yazılmaz.

```bash
docker compose down                       # çalışan bir demo varsa
export SIGNER_COMMAND='…KMS imza komutu…' SIGNER_PUBLIC_KEY='<KMS anahtarının public yarısı>'
export PKCS11_LIBRARY=/yol/hsm-pkcs11.so PKCS11_PIN='…'
./scripts/setup.sh --production --fresh \
    --server-ref <demo-server'ın 40 haneli commit SHA'sı> \
    --signers pkcs11,command \
    --recovery-public-key <recovery-1 public key> \
    --backup-public-key <backup-1 public key> \
    --admins ayse:<sha256>,mehmet:<sha256> \
    --attestation-signer <yayın imza sertifikasının SHA-256'sı>
docker compose up -d --build
ADMIN_KEY=<kişisel anahtar> ./scripts/provision.sh    # pin yazmaları ikinci yöneticinin onayını bekler (dashboard → Onaylar)
./scripts/smoke-test.sh
./scripts/client-config.sh --properties > ../sample-client/sample-host.properties
```

`--fresh` yalnızca demo kurulumunun üstüne kurarken gerekir: eski `.env`, `data/` ve `offline-keys/` zaman damgalı bir dizine (`backup-before-production-<tarih>/`) taşınır ve kurulum boş veriyle başlar. O dizinde demo'nun gizli değerleri vardır; ihtiyacın kalmayınca sil. Boş bir dizinde `--fresh` gerekmez. Betik tekrar çalıştırılabilir; eksik bir değerde ne gerektiğini söyleyip durur.

### `setup.sh --production` neyi reddeder

| Durum | Neden |
|---|---|
| Demo `.env` ya da dolu `data/` var ve `--fresh` verilmemiş | Demo anahtarları ve ayarları üretime taşınırdı |
| Bu dizinde çevrimdışı özel anahtar dosyası var (`offline-keys/` altında public yarı dışında bir dosya; `recovery*.pem`, `backup*.pem` …) | Bu anahtarlar sunucuda durmamalı |
| `PINVAULT_REF` bir dal ya da etiket adı (`main`, `v2.1.1`) | Aynı ad zamanla başka bir kodu gösterebilir; 40 haneli commit SHA'sı ya da `--server-src <yerel dizin>` gerekir |
| Tek imzalayıcı, ya da hepsi `local` (diskteki dosya); SoftHSM sayılmaz | Sunucuyu ele geçiren tek başına pin yayımlayabilirdi |
| Kurtarma anahtarının public yarısı yok ya da geçerli bir EC P-256 anahtarı değil | Çalınan bir imza anahtarı iptal edilemezdi |
| Yedek imza anahtarının public yarısı yok | Uygulama 2 imza ister; bir imzalayıcı kaybolunca bütün telefonlar dururdu (release derlemesi de yedeksiz değerlerle derlenmez) |
| `SIGNER_COMMAND` ya da `--server-src` içinde `$( )` ya da `` ` `` var | `.env` kabukla okunurken komut çalışırdı |
| İkiden az yönetici | İki kişi onayı çalışmaz |
| `ATTESTATION_SIGNER_SHA256` yok ya da biçimi yanlış | Herhangi bir uygulama herhangi bir cihaz adına geçerli belge üretebilirdi |

`data/proxy` (uçtan uca testlerin dışa aktardığı sunucu TLS özel anahtarı) varsa silinir.

**Yalnızca değerlendirme için** tek imzalayıcıyla kurmak mümkündür: `--evaluation-single-signer-NOT-FOR-PRODUCTION`. Betik ve `client-config.sh` her çalıştığında bu kurulumun **üretim olmadığını** yazar; uygulama 1 imza ister. Gerçek kullanıcıya açılmaz.

### Ne kurulur

| Ne | Nasıl |
|---|---|
| İmzalayıcılar | `CONFIG_SIGNERS` (en az iki, en az biri `pkcs11` ya da `command`); `CLIENT_REQUIRED_SIGNATURES=2`. `local` varsa `data/signing-key.pem` üretilir ve `SIGNING_KEY_PASSWORD` ile diskte şifrelenir |
| Kurtarma ve yedek anahtarı | Yalnızca public yarıları: `RECOVERY_PUBLIC_KEYS` (sunucu anahtar setini bununla doğrular), `BACKUP_PUBLIC_KEYS` (yalnızca uygulamaya gömülür) |
| Kişisel yöneticiler, iki kişi onayı | `ADMIN_KEYS` (yalnızca SHA-256'lar), `PIN_CHANGE_APPROVALS=2`: pin, force, sertifika ve imza anahtarı değişikliği başka bir yöneticinin onayıyla uygulanır; paylaşılan `API_KEY` onay veremez |
| Canlı sertifika kontrolü | `PIN_LIVE_CHECK=enforce`; host'un kendi IP'si için `LIVE_CHECK_HOST_MAP` |
| Kayıt | `ENROLLMENT_MODE=token`, `ENROLLMENT_ATTESTATION=enforce`, `ENROLLMENT_P12=off` |
| Ekran kilidiyle açılan dosyalar | `USER_AUTH_ATTESTATION=enforce`, `ATTESTATION_PACKAGE_NAMES`, `ATTESTATION_SIGNER_SHA256`, `USER_AUTH_REQUIRE_PER_USE=true` (emülatörle denenmez) |
| Donanım belgesi | `ATTESTATION_REQUIRE_VERIFIED_BOOT=true`; Google'ın iptal listesi `data/attestation-status.json` (ilk kopyayı `setup.sh` indirir, sonrası cron), `ATTESTATION_STATUS_MAX_AGE_HOURS=48` |
| Sunucu kaynağı | Sabit commit ya da yerel dizin; Dockerfile'daki temel imajlar özetleriyle (digest) sabit |
| Ağ | Yönetim portları (6650, 6655) yalnızca `127.0.0.1`; mock host portları yayımlanmaz; cihaz portları (6651, 6652, 6656) açık |
| Container | `no-new-privileges`, Linux yetkileri düşürülmüş, kök dosya sistemi salt okunur, bellek ve süreç sınırı (`docker-compose.production.yml`) |
| Test anahtarları | `ALLOW_TEST_HOOKS` ve `ALLOW_ANONYMOUS_ADMIN` sabit `false`; `env-override.sh`, `softhsm-init.sh` ve `export-server-key.sh` bu profilde çalışmaz; `signing-keys.sh install` yalnızca `--emergency` ile |
| Sabit ayarlar | `docker-compose.production.yml` iki kişi onayını (`2`), canlı sertifika kontrolünü ve iki donanım belgesi ayarını (`enforce`), `ENROLLMENT_P12=off` ve `USER_AUTH_REQUIRE_PER_USE=true`'yu sabitler: `.env`'den gevşetilemez |
| Parolalar | `API_KEY`, `KEYSTORE_PASSWORD`, `VAULT_AT_REST_PASSWORD`, `SIGNING_KEY_PASSWORD`, `CLIENT_P12_PASSWORD` rastgele üretilir (`.env`, 0600) |

Sunucunun kendisi de her açılışta kontrol eder (`entrypoint.sh`); `.env` kurulumdan sonra elle değiştirilse bile şu durumlarda container başlamaz ve nedenini log'a yazar (`docker compose logs pinvault-host`):

- `/data` altında çevrimdışı özel anahtar ya da `data/proxy` var,
- test anahtarları açık, kayıt modu `token` değil ya da parolalardan biri boş,
- iki kişi onayı, canlı sertifika kontrolü ya da donanım belgesi ayarları yukarıdaki üretim değerlerinde değil,
- ikiden az kişisel yönetici var (`ADMIN_KEYS` ve `ADMIN_KEYS_FILE` birlikte sayılır) ya da `RECOVERY_PUBLIC_KEYS` boş,
- ikiden az imzalayıcı var ya da hiçbiri sunucunun diski dışında değil (SoftHSM sayılmaz). Değerlendirme kurulumu (`SAMPLE_EVALUATION=single-signer`) açılır ama her açılışta "ÜRETİM DEĞİLDİR" yazar,
- sunucu kaynağı sabit değil (`PINVAULT_REF` 40 haneli SHA değil ve `PINVAULT_SERVER_SRC` boş),
- `ATTESTATION_REVOKED_SERIALS_FILE` dolu ama dosya yok.

`smoke-test.sh` aynı değerleri çalışan container'dan okuyup denetler, iptal listesinin yaşını da gösterir.

> `ENROLLMENT_ATTESTATION`, `ENROLLMENT_P12` ve `USER_AUTH_REQUIRE_PER_USE` sunucuya eklenmekte olan ayarlardır. Bu adları tanımayan bir sunucu sürümü onları sessizce yok sayar. Derlediğin commit'in notlarında geçtiklerini ve açılış log'unda etkin göründüklerini doğrula; geçmiyorlarsa bu üç koruma o sürümde yoktur.

### HSM ve KMS imzalayıcıları

- `pkcs11`: `PKCS11_LIBRARY`, HSM üreticisinin PKCS#11 kitaplığının **container içindeki** yoludur; kitaplığı imaja eklemen (Dockerfile) ve gerekiyorsa aygıtı container'a tanıtman gerekir. `PKCS11_PIN` `.env`'de durur.
- `command`: `SIGNER_COMMAND` stdin'den gelen baytları imzalayıp stdout'a imza basan komuttur (KMS istemcisi imajda olmalı, kimlik bilgisi container'a güvenli bir yoldan verilmeli); `SIGNER_PUBLIC_KEY` o anahtarın public yarısı; özet imzalayan KMS'ler için `SIGNER_INPUT=digest`.
- Kök dosya sistemi salt okunur olduğu için bu araçların yazdığı yerler `/tmp` ya da `/data` altında olmalı.
- **SoftHSM bir HSM değildir.** `softhsm-init.sh` yalnızca sunucunun PKCS#11 yolunu donanımsız denemek içindir: anahtar yine sunucunun diskinde, PIN'i de aynı makinededir. Üretim profili onu saymaz.

### İşletim

- Ayar değişikliği `.env`'de yapılır ve `docker compose up -d` ile uygulanır. `.env`'i kimin değiştirebildiği, sunucuyu kimin yönetebildiği demektir.
- Değişiklikler kişisel anahtarla yapılır; ikinci bir yönetici dashboard'daki **Onaylar** bölümünden onaylar. Bir pin seti host'un o an sunduğu sertifikayı tutmuyorsa kaydedilmez.
- Dashboard'a uzaktan erişim: VPN ya da `ssh -L 6655:127.0.0.1:6655 kullanici@sunucu`, sonra `https://localhost:6655`.
- **İmza anahtarı değiştirmek ya da çalınan birini iptal etmek:** çevrimdışı makinede kurtarma anahtarıyla bir anahtar seti imzalanır (`signing-keys.sh keyset -v N -k <public key'ler> -s /yol/recovery-1.pem -o keyset-vN.json`; openssl parolayı sorar), dosya sunucuya getirilir ve `ADMIN_KEY=… ./scripts/signing-keys.sh upload keyset-vN.json` ile yüklenir. Sunucuya gelen yalnızca imzalı settir.
- **Bir imzalayıcı kaybolursa:** yedek anahtarın public yarısı uygulamada zaten güvenilen anahtarlar arasındadır. Yedek anahtar yeni imzalayıcı olarak devreye alınır (tercihen HSM/KMS'e aktarılarak); son çare olarak `signing-keys.sh install --emergency /takili-disk/backup-1.pem` onu sunucunun yerel imzalayıcısı yapar (`--emergency` olmadan üretim profilinde çalışmaz; yerindeki anahtarın kopyası `data/signing-key.pem.<tarih>.bak` olarak kalır). O andan sonra o anahtar artık çevrimdışı değildir: yeni bir yedek üretip bir anahtar setiyle duyur.
- Yedekle: `data/` (veritabanı, sunucu ve istemci CA anahtarları) ve `.env`. İkisi de gizlidir.
- **Ortam değişkenleri `docker` grubuna açıktır.** `.env`'deki parolalar, `API_KEY`, `PKCS11_PIN` container'a ortam değişkeni olarak geçer; makinede `docker inspect pinvault-host` çalıştırabilen herkes (root ve `docker` grubundaki her kullanıcı) hepsini düz metin görür. `docker` grubu root yetkisi demektir: oraya yalnızca sunucuyu yönetenleri ekle. Sonraki adım olarak gizli değerler dosyadan okunmalı (`*_FILE` değişkenleri ya da Docker/Compose secrets); sunucu şu an bunu yalnızca `ADMIN_KEYS_FILE` için destekler.

### Donanım belgesi iptal listesi

Google, ele geçirildiği ya da sızdığı anlaşılan donanım belgesi anahtarlarını herkese açık bir listede iptal eder. Sunucu internete çıkmaz; listeyi `ATTESTATION_REVOKED_SERIALS_FILE`'ın gösterdiği dosyadan okur (üretim: `/data/attestation-status.json`, host'ta `data/attestation-status.json`) ve dosya değişince kendiliğinden yeniden okur. Dosya yoksa sunucu açılmaz; `ATTESTATION_STATUS_MAX_AGE_HOURS=48` olduğu için liste 48 saatten eskiyse hiçbir belge geçmez (o arada iptal edilen bir telefon fark edilmeden geçerdi).

`setup.sh --production` ilk kopyayı indirir. Listeyi güncel tutmak için betiği cron'a koy (6 saatte bir):

```bash
./scripts/fetch-attestation-status.sh        # elle bir kez
crontab -e
# 0 */6 * * *  cd /yol/sample-host && PATH=/usr/local/bin:/usr/bin:/bin ./scripts/fetch-attestation-status.sh 2>&1 | logger -t pinvault-attestation
```

Betik listeyi önce geçici bir dosyaya indirir, gerçekten iptal listesi olduğuna bakar ve tek adımda eskisinin yerine koyar; indirme başarısızsa eski dosya kalır. Linux'ta `data/` servis kullanıcısına aittir: betik o zaman dosyayı çalışan container'ın içinden, o kullanıcıyla yazar. `smoke-test.sh` listenin kaç saatlik olduğunu gösterir.

### Bu profil neyi çözmez

- Sunucu self-signed sertifika ve SQLite kullanır; tek makinedir.
- `local` imzalayıcı seçildiyse anahtarlardan biri hâlâ sunucunun diskindedir (şifreli; parolası aynı makinedeki `.env`'de). İkinci imza olmadan işe yaramaz, ama en sağlamı iki imzalayıcının da sunucu dışında olmasıdır (`pkcs11,command`).
- Sunucu, cihaza özel şifrelenen dosyaların içeriğini görür.
- Uygulama, sertifikası herkesin güvendiği bir CA'dan olan hedefler için `requireCaTrust` ister (`target.requireCaTrust`): imza anahtarları çalınsa bile o hedef için sahte sertifika pinlenemez. `client-config.sh` hedefin zincirini doğrulamadan pin almaz; kurum içi CA'lı hedef için `--target-private-ca` gerekir ve release derlemesi o değerle derlenmez.

## Üretim için

Bu host bir örnektir. [Üretim profili](#üretim-profili) örneğin sağlayabildiği en sıkı kurulumu yapar; gerçek bir ürün ayrıca:

- Self-signed sertifika yerine gerçek bir CA kullanır, TLS'i bir reverse proxy'de sonlandırır.
- İki imzalayıcıyı da sunucunun dışında tutar (`CONFIG_SIGNERS=pkcs11,command`).
- `.env`'deki gizli değerleri (API anahtarı, parolalar, HSM PIN'i) bir secret yöneticisinden verir.
- `VAULT_AT_REST_PASSWORD`'ü bir KMS'ten alır.
- SQLite yerine PostgreSQL gibi bir veritabanı kullanır.
- Güvenlik olaylarını bir kanala düşürür (`NOTIFY_WEBHOOK_URL`) ve denetim kaydını izler.

### Container kullanıcısı

Sunucu root olarak çalışmaz. demo-server'ın kendi imajı uid 10001 ile çalışır; bu dizinin imajı aynı kullanıcıyı (`pinvault`, uid/gid 10001) kendisi oluşturur ve `entrypoint.sh` kısa bir root adımıyla `data/` bağlamasının sahipliğini ona verip yetkileri bırakır (`setpriv`). Bu yüzden `data/`'yı elle `chown` etmek gerekmez, ne macOS'ta ne Linux'ta.

- **macOS (Docker Desktop):** dosyalar host'ta senin kullanıcına ait görünmeye devam eder; betikler ve uçtan uca testler `data/` altını doğrudan okur.
- **Linux:** `data/` ilk açılıştan sonra host'ta uid 10001'e ait olur ve yalnızca ona açıktır (`umask 077`). Betikler herkese açık pin dosyasını okuyamazsa container'ın içinden okur (`docker compose exec -u 10001:10001 …`). Dosyaları kendi kullanıcınla okumak istersen `.env`'e `PINVAULT_UID=$(id -u)` ve `PINVAULT_GID=$(id -g)` yaz ve `docker compose up -d`: entrypoint sahipliği o kullanıcıya verir ve sunucuyu onunla çalıştırır (root, yani 0, kabul edilmez).
- `data/`'yı taşırken ya da silerken Linux'ta `sudo` gerekebilir (`setup.sh --production --fresh` bunu söyler).

### Temel imajlar

`Dockerfile`'daki iki temel imaj (`gradle:8.7-jdk17`, `eclipse-temurin:17-jre-noble`) özetleriyle (`@sha256:…`) sabittir: etiket Hub'da başka bir imaja taşınsa da derleme değişmez. Özetler bu deponun derlendiği makinedeki imajlardan alındı (`docker image inspect --format '{{index .RepoDigests 0}}' <imaj>`). Güncellemek için yeni imajı çek, gözden geçir, aynı komutla özetini al ve Dockerfile'daki iki satırı değiştir.

### Depoya anahtar girmesin

Bu depo herkese açık bir depoya yansır. Kök `.gitignore` anahtar depolarını, PEM dosyalarını, veritabanlarını, `.env` dosyalarını ve `demo-server/data/` dizinini dışarıda tutar; `scripts/check-secrets.sh` ikinci engeldir:

```bash
./sample-host/scripts/check-secrets.sh          # commit'e eklenmiş dosyalar
./sample-host/scripts/check-secrets.sh --all    # izlenen bütün dosyalar (CI)
# pre-commit kancası (depo kökünde, bir kez):
printf '#!/bin/sh\nexec sample-host/scripts/check-secrets.sh\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Adıyla ya da içeriğiyle anahtar gibi görünen bir dosya commit'e girmeye çalışırsa commit durur. Serbest biçimli gizli değerleri (token, API anahtarı) aramaz; onlar için gitleaks gibi bir tarayıcı ekle.

## Yapı

```
.
├── Dockerfile                     # iki aşama: gradle build + JRE runtime; temel imajlar özetle sabit
├── docker-compose.yml             # demo profili: tek servis, port, volume, build context seçimi
├── docker-compose.production.yml  # üretim profili: demo dosyasının üstüne biner (portlar, sıkılaştırma)
├── entrypoint.sh                  # dosya izinleri, üretim açılış kontrolleri, yetkileri bırakma
├── .env.example                   # ayar şablonu, demo profili (.env git'e girmez)
├── .env.production.example        # ayar şablonu, üretim profili (setup.sh --production)
├── scripts/
│   ├── setup.sh             # .env + API_KEY + HOST_LAN_IP + signing key (--production: üretim profili)
│   ├── offline-keygen.sh    # BAŞKA makinede: çevrimdışı kurtarma/yedek anahtarı, kişisel yönetici anahtarı
│   ├── provision.sh         # mTLS Config API, host'un kendi pin kaydı, (demo) mock host'lar
│   ├── seed-vault.sh        # örnek uygulamanın vault dosyaları, beklediği politikalarla
│   ├── generate-signing-key.sh
│   ├── smoke-test.sh        # sağlık, imza, sertifika, yetki, port ve rapor ucu kontrolleri
│   ├── fetch-attestation-status.sh # Google'ın donanım belgesi iptal listesi (üretim; cron)
│   ├── client-config.sh     # Android client değerleri (--properties ile dosya); hedef pin'ini doğrulayarak alır
│   ├── signing-keys.sh      # anahtar seti imzalama ve yükleme; demo için yedek/kurtarma anahtarı
│   ├── add-admin.sh         # kişisel yönetici anahtarı (demo; üretimde offline-keygen.sh admin)
│   ├── softhsm-init.sh      # PKCS#11 yolunu denemek için SoftHSM (gerçek HSM değil; yalnızca demo)
│   ├── env-override.sh      # geçici ortam değişkeni değişikliği ve geri alma (yalnızca demo)
│   ├── export-server-key.sh # TLS anahtar/sertifikasını PEM olarak dışa aktarır (yalnızca demo, E2E için)
│   ├── check-secrets.sh     # depoya anahtar girmesini engelleyen denetim (pre-commit)
│   └── lib.sh               # betiklerin ortak yardımcıları
├── offline-keys/            # yalnızca demo ve testler (signing-keys.sh gen); üretimde bu makinede YOKTUR
└── data/                    # kalıcı çalışma verisi (git'e girmez)
```
