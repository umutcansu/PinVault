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
| `6650` | `8080` | HTTP | Yönetim API'si, web dashboard, telemetri uçları |
| `6651` | `8081` | HTTPS, self-signed | Config API: `/api/v1/certificate-config`, enrollment, vault |
| `6652` | `8092` | HTTPS + istemci sertifikası | mTLS Config API (`provision.sh` açar) |
| `6653` | `8443` | HTTPS, sunucu üretimi sertifika | Mock TLS hedef host `mock-tls.sample` (`provision.sh` açar) |
| `6654` | `8444` | HTTPS + istemci sertifikası | Mock mTLS hedef host `mock-mtls.sample` (`provision.sh` açar) |

`.env` içinde `HOST_HTTP_PORT` / `HOST_HTTPS_PORT` / `HOST_MTLS_PORT` / `HOST_MOCK_TLS_PORT` / `HOST_MOCK_MTLS_PORT` ile değişir. Mock host adları gerçek DNS'te yoktur; örnek uygulama onları `host.ip`'ye çözümler.

---

## Güvenlik modeli

- **API anahtarı zorunlu.** Anonim admin kapalı; `API_KEY` boşsa compose başlamaz. Yönetim uçları iki portta da `X-API-Key` ister. Cihazların çağırdığı uçlar (config indirme, enrollment, vault indirme, telemetri) anahtarsız açıktır.
- **Config imzalı.** Her config cevabı `data/signing-key.pem` ile imzalanır ve `issuedAt/expiresAt` taşır. Client imzasız, süresi geçmiş ya da eski bir config'i uygulamaz.
- **Signing key host'ta kalır.** `setup.sh` anahtarı `0600` izinle üretir, container'a salt-okunur bağlanır ve git'e girmez. Public yarısı client'a gömülür.
- **Enrollment token ile.** `ENROLLMENT_MODE=token`: mTLS sertifikası yalnızca admin'in ürettiği tek kullanımlık token'la alınır.
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
| `CONFIG_TTL_SECONDS` | `86400` | İmzalı config'in geçerlilik süresi |
| `SIGNING_KEY_PASSWORD` | boş | Doluysa imzalama anahtarı diskte AES-256-GCM ile şifrelenir |
| `ENROLLMENT_TOKEN_TTL_SECONDS` | `86400` | Kayıt token'ının geçerlilik süresi |
| `VAULT_AT_REST_PASSWORD` | demo anahtarı | `at_rest` vault dosyalarının anahtarı; boşsa şifreleme yalnızca etikettir, üretimde mutlaka ayarla |
| `CERT_EXPIRY_WARN_DAYS` | `30` | Sertifika süre uyarısı eşiği |
| `KEYSTORE_PASSWORD` | `changeit` | JKS/P12 parolası |
| `VAULT_AT_REST_PASSWORD` | boş | **Boşken `at_rest` şifrelemesi bir güvenlik sınırı değildir** — aşağıya bak |

> ### ⚠️ `VAULT_AT_REST_PASSWORD` boş bırakılmamalı
>
> `at_rest` şifrelemeli vault dosyaları diskte AES-256-GCM ile tutulur; anahtar
> bu değişkenden PBKDF2-SHA256 ile türetilir. Değişken boşsa sunucu **kaynak
> kodundaki sabit demo anahtarını** kullanır ve log'a uyarı basar.
>
> Sonuç: dosyalar `pinvault.db` içinde şifreli *görünür*, ama anahtar
> kütüphanenin kaynağında herkese açık olduğu için veritabanını ele geçiren
> biri içeriği aynen çözebilir. Yani boşken `at_rest` bir güvenlik sınırı
> değil, yalnızca bir etikettir — gerçek gizlilik isteyen dosyalar için
> `end_to_end` (cihazın kendi anahtarı) ya da ayarlanmış bir
> `VAULT_AT_REST_PASSWORD` gerekir.
>
> Bu örnek host'ta bilinçli olarak boş bırakılabilir (laboratuvar verisi).
> Üretimde mutlaka ayarla ya da bir KMS kullan. Değeri sonradan değiştirirsen
> eski anahtarla yazılmış dosyalar okunamaz hale gelir; onları yeniden yükle.

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
./scripts/export-server-key.sh               # TLS anahtarını PEM olarak dışa aktar (E2E kurcalama vekili)
docker compose down                          # durdur
```

---

## Üretim için

Bu host bir örnektir. Üretimde:

- Self-signed sertifika yerine gerçek bir CA kullan, TLS'i bir reverse proxy'de sonlandır.
- Signing key'i HSM/KMS'te tut; en azından `SIGNING_KEY_PASSWORD` ile diskte şifrele.
- `API_KEY`'i bir secret yöneticisinden oku; yönetim portunu dış ağa açma.
- `KEYSTORE_PASSWORD`'ü ayarla (varsayılanı `changeit`).
- `VAULT_AT_REST_PASSWORD`'ü ayarla (aşağıdaki uyarı).
- SQLite yerine PostgreSQL gibi bir veritabanı düşün.
- Container'ı root olmayan bir kullanıcıyla çalıştır. Bu örnek, bind mount izinleriyle uğraşmamak için root kalır.

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
