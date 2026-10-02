# SamplePinVaultHost

[PinVault](https://github.com/umutcansu/PinVault) `demo-server`'ını tek komutla Docker'da çalıştıran referans host. Android tarafı için [SamplePinVaultClient](../SamplePinVaultClient) bu host'a bağlanır.

Host iki şey sunar: pinlenmiş ve ECDSA ile imzalanmış bir pin config API'si (TLS) ve yönetim API'si ile web dashboard (HTTP).

---

## Gereksinimler

- Docker 24+ ve Docker Compose v2.17+ (`build.additional_contexts` için)
- `openssl`, `curl`, `jq`
- İlk build için internet (Gradle bağımlılıkları; upstream kaynak seçiliyse git clone)

## Hızlı başlangıç

```bash
./scripts/setup.sh              # .env, API anahtarı, LAN IP, signing key
docker compose up -d --build    # ilk build 3-5 dk
./scripts/provision.sh          # mTLS Config API + host'un kendi pin kaydı
./scripts/smoke-test.sh         # hepsi PASS olmalı
./scripts/client-config.sh      # Android client'a girilecek değerler
```

`provision.sh` tekrar çalıştırılabilir; yalnızca eksik olanı ekler. mTLS Config API'si veritabanına kaydedilir ve container yeniden başladığında kendiliğinden açılır.

Dashboard: `http://localhost:6650/`. İlk istekte API anahtarını sorar; anahtar `.env` içindeki `API_KEY`.

Dashboard'da işlem yapıp sonucunu telefonda doğrulayan uçtan uca testler [SamplePinVaultE2E](../SamplePinVaultE2E)'de.

---

## Sunucu kaynağı

Image, `demo-server` kaynağını `pinvault-server` adlı build context'inden alır. `.env` ile seçilir:

| Ayar | Kaynak |
|---|---|
| `PINVAULT_SERVER_SRC` boş (varsayılan) | Upstream git: `PINVAULT_REPO` @ `PINVAULT_REF` |
| `PINVAULT_SERVER_SRC=../PinVault/demo-server` | Yerel PinVault checkout'u, yayınlanmamış değişiklikler dahil |

Kaynak değiştikten sonra `docker compose up -d --build` yeterli. Yerel dizindeki çalışma verisi (`pinvault.db`, `certs/`, `signing-key.pem`, `build/`) image'a girmez; yalnızca `settings.gradle.kts`, `build.gradle.kts` ve `src/` kopyalanır.

## Portlar

| Dış port | Container | Protokol | İçerik |
|---|---|---|---|
| `6650` | `8080` | HTTP, **yalnızca bu makine** | Yönetim API'si ve web dashboard (`HOST_HTTP_BIND=127.0.0.1`) |
| `6655` | `8082` | HTTPS, sunucu sertifikası | Yönetim API'si ağa şifreli: telefonların raporları (telemetri, pinli) ve başka makineden dashboard |
| `6651` | `8081` | HTTPS, self-signed | Config API: `/api/v1/certificate-config`, enrollment, vault |
| `6652` | `8092` | HTTPS + istemci sertifikası | mTLS Config API (`provision.sh` açar) |
| `6653` | `8443` | HTTPS, sunucu üretimi sertifika | Mock TLS hedef host `mock-tls.sample` (`provision.sh` açar) |
| `6654` | `8444` | HTTPS + istemci sertifikası | Mock mTLS hedef host `mock-mtls.sample` (`provision.sh` açar) |
| `6656` | `8083` | HTTPS, sunucu CA'sının imzaladığı sertifika | Kurtarma kapısı: istemci sertifikası istemez, yalnızca sertifika yenileme. Süresi dolmuş sertifikalı telefon buradan yeniler; uygulama bu porta sunucu CA'sının pin'iyle bağlanır |

`.env` içinde `HOST_HTTP_PORT` / `HOST_MANAGEMENT_TLS_PORT` / `HOST_HTTPS_PORT` / `HOST_MTLS_PORT` / `HOST_MOCK_TLS_PORT` / `HOST_MOCK_MTLS_PORT` / `HOST_RECOVERY_PORT` ile değişir. Düz HTTP yönetim portu ağa kapalıdır; API anahtarı ağda şifresiz dolaşmaz. Başka bir makineden yönetmek için `https://<host>:6655` (tarayıcı kendinden imzalı sertifika uyarısı verir) ya da SSH tüneli kullanılır. Mock host adları gerçek DNS'te yoktur; örnek uygulama onları `host.ip`'ye çözümler.

---

## Güvenlik modeli

- **API anahtarı zorunlu.** Anonim admin kapalı; `API_KEY` boşsa compose başlamaz. Yönetim uçları iki portta da `X-API-Key` ister. Cihazların çağırdığı uçlar (config indirme, enrollment, vault indirme, telemetri) anahtarsız açıktır; hepsi TLS üzerinden ve pinli.
- **Config imzalı.** Her config cevabı `data/signing-key.pem` ile imzalanır ve `issuedAt/expiresAt` taşır. Client imzasız, süresi geçmiş ya da eski bir config'i uygulamaz.
- **Signing key host'ta kalır.** `setup.sh` anahtarı `0600` izinle üretir, container'a salt-okunur bağlanır ve git'e girmez. Public yarısı client'a gömülür.
- **Enrollment token ile.** `ENROLLMENT_MODE=token`: mTLS sertifikası yalnızca admin'in ürettiği tek kullanımlık token'la alınır. Çok cihaz için panelden bir **kayıt politikası** açılabilir: tek kod, en fazla N cihaz, gün sınırı ve istenirse her cihaz için yönetici onayı (Client Sertifikaları → Kayıt politikaları; onay bekleyenler aynı sekmede).
- **TLS sertifikası LAN IP'yi içerir.** Container, Mac'in LAN IP'sini göremez; `HOST_LAN_IP` sunucuya `EXTRA_CERT_SANS` olarak geçer ve sertifika üretilirken SAN listesine eklenir. Yoksa telefon hostname doğrulamasında bağlantıyı reddeder.
- **Telemetri düz HTTP'dir.** Client'ın bağlantı olayları `6650`'ye gider. LAN'daki biri bu kayıtları okuyabilir ya da sahte kayıt ekleyebilir; pinlemeyi etkileyemez. Üretimde telemetriyi HTTPS ve pinli bir client ile gönder.

`smoke-test.sh` bunların hepsini çalışan container'a karşı doğrular: imzayı `openssl` ile kontrol eder, sertifika pin'ini ve SAN'ı okur, yönetim uçlarının anahtarsız 401 döndüğünü ve `ping-remote` enjeksiyon denemesinin 400 aldığını görür.

---

## Konfigürasyon (`.env`)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `HOST_HTTP_PORT` | `6650` | Yönetim portunun host tarafı |
| `HOST_HTTPS_PORT` | `6651` | Config API portunun host tarafı |
| `HOST_LAN_IP` | `setup.sh` bulur | Telefonların bu makineye ulaştığı IP; sertifika SAN'ına girer |
| `API_KEY` | `setup.sh` üretir | Yönetim API'si ve dashboard anahtarı |
| `PINVAULT_REPO` / `PINVAULT_REF` | upstream / `main` | Upstream kaynak ve sürüm |
| `PINVAULT_SERVER_SRC` | boş | Yerel `demo-server` dizini; doluysa upstream yerine kullanılır |
| `ENROLLMENT_MODE` | `token` | `token` önerilir; `open` deviceId ile kayda izin verir (yalnızca demo) |
| `CLIENT_CERT_TTL_DAYS` | `90` | CSR ile kayıt olan cihazların sertifika ömrü (gün); ömrünün son üçte birinde kendiliğinden yenilenir |
| `ALLOW_TEST_HOOKS` | boş | `true`: kısa ömürlü sertifika kancası açılır (`POST /api/v1/test-hooks/client-cert-ttl`). Yalnızca testler; uçtan uca testler `env-override.sh` ile geçici açar |
| `CONFIG_TTL_SECONDS` | `86400` | İmzalı config'in geçerlilik süresi |
| `SIGNING_KEY_PASSWORD` | boş | Doluysa imzalama anahtarı diskte AES-256-GCM ile şifrelenir |
| `ENROLLMENT_TOKEN_TTL_SECONDS` | `86400` | Kayıt token'ının geçerlilik süresi |
| `VAULT_AT_REST_PASSWORD` | `setup.sh` üretir | Sunucu diskindeki vault dosyalarının (at_rest ve cihaza özel) parolası. **Boşsa şifreleme yalnızca etikettir**, aşağıya bak |
| `VAULT_AT_REST_PASSWORD_PREVIOUS` | boş | Parolayı değiştirirken eskisi: sunucu açılışta dosyaları yeni parolaya geçirir, sonra silinir |
| `CERT_EXPIRY_WARN_DAYS` | `30` | Sertifika süre uyarısı eşiği |
| `KEYSTORE_PASSWORD` | `setup.sh` üretir | Sunucunun kendi anahtar depolarının parolası (TLS anahtarları, yedek anahtarlar, istemci güven listesi, host istemci sertifikaları). Hiçbir cihaza gitmez; eski kurulumlarda depolar açılışta bu parolaya geçirilir |
| `KEYSTORE_PASSWORD_PREVIOUS` | boş | Parolayı değiştirirken eskisi: sunucu açılışta depoları yeni parolaya geçirir, sonra silinir |
| `CLIENT_P12_PASSWORD` | `changeit` | Cihaza giden mTLS sertifika paketinin parolası; yalnızca eski kütüphane sürümleri ve elle kurulan P12 dosyaları için. Güncel kütüphane her indirmede tek kullanımlık parola alır |

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

## Kalıcı veri

| Yol | İçerik |
|---|---|
| `data/db/pinvault.db` | SQLite; Flyway migration'ları açılışta otomatik uygulanır |
| `data/certs/demo-server.jks`, `demo-server.pins` | Sunucu TLS anahtarı ve pin'leri; ilk açılışta üretilir |
| `data/signing-key.pem` | Config imzalama anahtarı; `setup.sh` üretir |

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
./scripts/env-override.sh set KEY=VALUE ...  # geçici sunucu ayarı (container yeniden oluşturulur)
./scripts/env-override.sh reset              # .env değerlerine dön
./scripts/export-server-key.sh               # TLS anahtarını PEM olarak dışa aktar (E2E'deki saldırgan proxy için)
./scripts/signing-keys.sh …                 # çevrimdışı yedek/kurtarma anahtarları, anahtar seti
./scripts/add-admin.sh <ad> --apply         # kişisel yönetici anahtarı (ADMIN_KEYS)
./scripts/softhsm-init.sh [enable|show]      # HSM imzalayıcısı (SoftHSM)
docker compose down                          # durdur
```

---

## İsteğe bağlı güvenlik katmanları

Hiçbiri açık olmadan host eskisi gibi çalışır. Her biri ayrı açılır; ekip ne kadarını taşıyabiliyorsa o kadarını seçer. Değişkenler `.env`'e yazılır (kalıcı) ya da `./scripts/env-override.sh set …` ile geçici denenir.

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

**HSM'de imzalama.** `./scripts/softhsm-init.sh` imajdaki SoftHSM'de bir token hazırlar, `./scripts/softhsm-init.sh enable` sunucuyu `CONFIG_SIGNERS=pkcs11` ile açar: anahtar token'ın içinde üretilir, dışarı çıkarılamaz ve yalnızca imza için kullanılabilir (şifre çözme, anahtar sarma yok; `./scripts/softhsm-init.sh show` öznitelikleri gösterir: "Usage: sign", "never extractable"). Gerçek bir HSM'de yalnızca `PKCS11_LIBRARY` değişir. Bulut KMS ya da ayrı bir imza servisi için `CONFIG_SIGNERS=command` + `SIGNER_COMMAND` (stdin'den gelen baytları imzalayıp stdout'a imza basan komut) + `SIGNER_PUBLIC_KEY`; özet imzalayan KMS'ler için `SIGNER_INPUT=digest`. `CONFIG_SIGNATURE_CACHE=true` aynı içeriği bir kez, yayın anında imzalar; HSM/KMS'e her cihaz isteğinde gidilmez.

**m-of-n imza.** `CONFIG_SIGNERS=local,command` gibi iki imzalayıcı her config'e iki imza koyar; uygulama `requiredSignatures(2)` ile ikisini birden ister. Anahtarlar farklı kişilerde ya da sistemlerde durdukça ne tek bir yönetici ne de bu sunucunun kendisi tek başına pin yayımlayabilir.

**Kişisel yönetici anahtarları, denetim kaydı, bildirim.** `./scripts/add-admin.sh alice --apply` bir anahtar üretir ve `.env`'deki `ADMIN_KEYS`'e yalnızca SHA-256'sını yazar. Denetim kaydı (dashboard → Denetim Kaydı) her yönetim değişikliğini kimin yaptığıyla ve pin farkıyla tutar; kayıtlar silinemez ve hash zinciriyle bağlıdır ("Zinciri doğrula"). `NOTIFY_WEBHOOK_URL` güvenlik olaylarını anında bir webhook'a (Slack uyumlu) gönderir; `NOTIFY_WEBHOOK_SECRET` ile her istek HMAC imzası taşır.

**İki kişi onayı.** `PIN_CHANGE_APPROVALS=2`: pin, force, sertifika ve imza anahtarı değişiklikleri hemen uygulanmaz; başka bir yönetici dashboard'daki "Onaylar" bölümünden onaylayınca uygulanır. Kimse kendi isteğini onaylayamaz, paylaşılan `API_KEY` onay veremez. Bu modda cihazlara açık Config API portları pin yazmalarını reddeder.

**Canlı sertifika kontrolü.** `PIN_LIVE_CHECK=enforce`: yeni ya da değişen bir pin seti, host'un şu an sunduğu sertifikayı telefonun kabul edeceği bir pin içermiyorsa (sertifikanın kendi pin'i ya da sertifikanın gerçekten bağlandığı CA'nın pin'i; yazım hatası, yanlış host) kaydedilmez; `warn` kaydeder ama uyarır. Sunucunun doğrudan çözemediği adlar için `LIVE_CHECK_HOST_MAP="mock-tls.sample=127.0.0.1:8443"`. Acil durumda gerekçe yazılarak yine de kaydedilebilir; gerekçe denetim kaydına düşer.

---

## Üretim için

Bu host bir örnektir. Üretimde:

- Self-signed sertifika yerine gerçek bir CA kullan, TLS'i bir reverse proxy'de sonlandır.
- Signing key'i HSM/KMS'te tut (`CONFIG_SIGNERS=pkcs11|command`); en azından `SIGNING_KEY_PASSWORD` ile diskte şifrele. Yedek ve kurtarma anahtarlarını çevrimdışı sakla (yukarıdaki bölüm).
- `API_KEY`'i bir secret yöneticisinden oku; yönetim portunu dış ağa açma.
- `KEYSTORE_PASSWORD`'ü `setup.sh` üretir ve hiçbir cihaza gitmez; elle kurulan P12 dosyaları için `CLIENT_P12_PASSWORD`'ü de değiştir (varsayılanı `changeit`).
- `VAULT_AT_REST_PASSWORD` dolu olsun (`setup.sh` üretir; yukarıdaki uyarı), daha iyisi bir KMS'ten gelsin.
- SQLite yerine PostgreSQL gibi bir veritabanı düşün.
- Container root olarak çalışmaz: `entrypoint.sh` `data/` bağlamasının sahipliğini `pinvault` kullanıcısına (uid 10001) verip yetkileri bırakır. Linux'ta bu, `data/` dizininin host'ta da uid 10001'e ait olması demektir.

## Yapı

```
.
├── Dockerfile               # iki aşama: gradle build + JRE runtime
├── docker-compose.yml       # tek servis, port, volume, build context seçimi
├── .env.example             # ayar şablonu (.env git'e girmez)
├── scripts/
│   ├── setup.sh             # .env + API_KEY + HOST_LAN_IP + signing key
│   ├── generate-signing-key.sh
│   ├── smoke-test.sh        # sağlık, imza, sertifika, yetki kontrolleri
│   ├── client-config.sh     # Android client değerleri (--properties ile dosya)
│   ├── env-override.sh      # geçici ortam değişkeni değişikliği ve geri alma
│   └── export-server-key.sh # TLS anahtar/sertifikasını PEM olarak dışa aktarır
└── data/                    # kalıcı çalışma verisi (git'e girmez)
```
