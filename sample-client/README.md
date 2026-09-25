# SamplePinVaultClient

PinVault'u bir Android uygulamasına uçtan uca bağlayan örnek (Java). Pin config'ini Docker'da çalışan [SamplePinVaultHost](../SamplePinVaultHost)'tan alır ve kütüphanenin bütün özelliklerini ekranlarda gösterir.

Uygulama şunları gösterir:

1. APK'ya gömülü **bootstrap pin**'lerle host'a bağlanıp pin config'ini çekmek.
2. Config'in **ECDSA imzasını** ve `issuedAt/expiresAt` tazeliğini doğrulamak; tutmayan config uygulanmaz.
3. Gelen pin'lerle gerçek bir hedefe iki farklı yoldan pinli istek atmak: kütüphaneyi kullanan client (`PinVault.applyTo`) ve PinVault'u import etmeyen **production-style** client (kendi `CertificatePinner`'ı).
4. Config'i elle ya da 15 dakikada bir arka planda yenilemek.
5. Her TLS el sıkışmasını ve config güncellemesini uygulama içinde listelemek ve host dashboard'una telemetri olarak göndermek.
6. **mTLS:** token ya da cihaz kimliğiyle kayıt, elle P12 içe aktarma, mTLS Config API'ye ve host'taki mock mTLS hedefine bağlanma, kaydı silme.
7. **Vault:** yedi farklı dosya (herkese açık, token, uçtan uca şifreli, sunucuda şifreli, yalnızca yönetim anahtarıyla, şifreli dosya deposu, mTLS + token) indirme, eşitleme, okuma ve silme.
8. **Depolama:** cihazda ne saklandığı ve nasıl saklandığı; şifreli tercihler, vault blob'ları, Android Keystore anahtarları.
9. **Ayarlar:** PinVault'un çalışma modu, telemetri seçenekleri ve kütüphanenin nadir yolları (özel bağlantı ayarlı istemci, sıfırlama, planlı iş).

---

## Ekranlar

| Ekran | Ne var |
|---|---|
| Ana | Durum (mod, config sürümü, host başına pin sürümü), iki client ile pinli istek, config yenileme, bağlantı olayları |
| mTLS | Kayıt (token / otomatik), P12 içe aktarma, mTLS Config API ve mock host testleri, kaydı silme |
| Vault | Yedi dosya, "Tümünü eşitle", dosya bilgisi (sunucuya gitmeden), silme, cihaz kimliği, erişim token'ı |
| Depolama | Şifreli tercih dosyaları ve düz metin sızıntısı kontrolü, `files/vault_files/*.enc`, Keystore anahtarları (algoritma, bit, donanım), istemci sertifikası kaydı |
| Ayarlar | Mod seçimi, telemetri (başarıları raporla, tekrar bastırma), özel ayarlı istemci, reset / init tekrar / yeniden başlat, WorkManager işleri |

## Modlar

Ayarlar ekranından seçilir; her seçim PinVault'u sıfırlayıp yeni yapılandırmayla kurar. Açılışta `--es mode <MOD>` intent ekiyle de verilebilir.

| Mod | Ne gösterir |
|---|---|
| `TLS` (varsayılan) | Config TLS Config API'den; cihaz kayıtlıysa ikinci blok olarak mTLS Config API de eklenir |
| `MTLS_CONFIG` | Config'in kendisi mTLS üzerinden, istemci sertifikasıyla çekilir |
| `CUSTOM_BACKEND` | Kütüphanenin varsayılan yolları yerine özel uçlar (`ssl/pins`, `ping`, `auth/register`, `certs/client`, `analytics/vault`) |
| `EMBEDDED_API` | Config uygulama içindeki `CertificateConfigApi` uygulamasından; kütüphaneden hiç HTTP çıkmaz |
| `STATIC` | Sunucusuz: pin'ler APK'ya gömülü |

Son iki mod `sample-host.properties` içindeki `target.pins`, özel backend modu ise `custom.*` değerleri doluysa çalışır.

---

## Kütüphane nereden geliyor?

`gradle.properties`:

```properties
pinvault.version=2.0.9          # Maven Central sürümü
pinvault.localPath=../PinVault  # doluysa kütüphane bu checkout'tan derlenir
```

`pinvault.localPath` bir PinVault checkout'unu gösterdiği sürece `settings.gradle.kts` bir composite build kurar ve kütüphaneyi kaynaktan derler; henüz yayınlanmamış değişiklikler dahil olur. Maven Central sürümüyle derlemek için yolu boşalt ya da tek seferlik `./gradlew assembleDebug -Ppinvault.localPath=`.

## Host değerleri

IP, portlar, bootstrap pin'leri ve imzalama public key'i `sample-host.properties` dosyasından `BuildConfig`'e gömülür:

```bash
cd ../SamplePinVaultHost
./scripts/client-config.sh --properties > ../SamplePinVaultClient/sample-host.properties
```

Başka bir dosya kullanmak için `./gradlew installDebug -PsampleHostProps=/yol/dosya.properties` (uçtan uca testler kendi dosyasını böyle verir). Sunucu sertifikası ya da imzalama anahtarı değişirse bu dosyayı yenile ve yeniden derle.

## Kurulum

1. Host'u ayağa kaldır ve hazırla:
   ```bash
   cd ../SamplePinVaultHost && ./scripts/setup.sh && docker compose up -d --build && ./scripts/provision.sh && ./scripts/smoke-test.sh
   ```
   `provision.sh` mTLS Config API'sini (`:6652`), host'un kendi pin kaydını ve mock hedef host'ları (`:6653` TLS, `:6654` mTLS) açar.
2. Host değerlerini al (yukarıdaki `client-config.sh --properties`).
3. Derle ve kur:
   ```bash
   ./gradlew installDebug
   ```

Telefon Mac ile aynı ağda olmalı. Emülatör de host IP'sine erişebiliyor.

## Beklenen akış

| Adım | Ekranda |
|---|---|
| Açılış | "PinVault başlatılıyor…", düğmeler kilitli |
| Config geldi | "✅ Hazır — config v29", mod ve pin'li host'lar |
| Library client ile test | "✅ Pinned bağlantı başarılı, HTTP 403" |
| Production-style client ile test | "✅ Production-style bağlantı başarılı, HTTP 403" |
| Config'i şimdi yenile | "✅ Config güncel" ya da "✅ Yeni config uygulandı: vN" |
| Host kapalıyken açılış | "❌ PinVault başlatılamadı" ve "Tekrar dene" |
| mTLS → token gir → Kayıt ol | "✅ Kayıt başarılı — CN=PinVault Client: …" |
| mTLS → Mock mTLS host | Kayıtlıysa "✅ Mock mTLS host bağlantısı başarılı, HTTP 200" |
| Vault → flags | "✅ sample-flags v1 indirildi (imza doğrulandı)" ve içerik |
| Vault → admin | "❌ sample-admin indirilemedi … 401" (kütüphane yönetim anahtarı göndermez) |
| Depolama | Şifreli dosyalar, "düz metin sızıntısı: yok ✓", Keystore anahtarları |

Vault dosyaları dashboard'da **Config API default-tls → Vault** sekmesinden bu anahtarlarla yüklenir: `sample-flags` (public), `sample-secret` (token), `sample-e2e` (public + end_to_end), `sample-atrest` (public + at_rest), `sample-admin` (api_key), `sample-model` (public). `sample-mtls-secret` ise **sample-mtls → Vault** altına token politikasıyla yüklenir. Token'lar dosya detayında Vault ekranındaki "Cihaz ID" değeriyle üretilir ve ekrana girilir; yalnızca bellekte tutulur.

Hedef sunucu kök adrese `403` döndürür; önemli olan TLS el sıkışmasının ve pin doğrulamasının geçmesidir.

Log:

```bash
adb logcat -s PinVault DynamicSSLManager SSLCertificateUpdater ConfigSignatureVerifier VaultFileRouter
```

## Uçtan uca testler

Dashboard'da işlem yapıp sonucunu bu uygulamada doğrulayan senaryolar [SamplePinVaultE2E](../SamplePinVaultE2E)'de:

```bash
cd ../SamplePinVaultE2E && npm install && npm run test:emulator
```

Uygulama her işlem sonucunun altına `#<sıra> · <saat>` yazar; testler yeni sonucu eskisinden bununla ayırır.

---

## Yapı

```
sample-host.properties      host IP/port/pin/imza anahtarı → BuildConfig
App.java                    PinVault init (beş mod), vault dosyaları, telemetri
AppSettings.java            mod ve telemetri tercihleri (düz SharedPreferences)
InitState.java              başlatma durumu (ekranlar için)
ActionActivity.java         ekranların ortak iskeleti: arka planda işlem, sıra numaralı sonuç
MainActivity.java           durum, iki client, config yenileme, olay listesi
MtlsActivity.java           kayıt, otomatik kayıt, P12 içe aktarma, mTLS ve mock testleri
VaultActivity.java          yedi dosya, eşitleme, bilgi, silme, token
StorageActivity.java        cihazdaki şifreli depolar ve Keystore anahtarları
SettingsActivity.java       mod, telemetri, gelişmiş kütüphane yolları
MockDns.java                mock host adlarını host IP'sine çözümler
EmbeddedConfigApi.kt        HTTP yapmayan örnek CertificateConfigApi
VaultTokens.java            vault erişim token'ları (yalnızca bellekte)
ConnectionEventLog.java     PinVaultConnectionListener → uygulama içi liste
ProductionStyleClient.java  PinVault import etmeyen network katmanı (CertificatePinner)
PinManagerLite.kt           suspend API'ler için senkron köprü, pin aktarımı
res/xml/network_security_config.xml   düz HTTP hiçbir yere yok (raporlar da şifreli porttan)
```

## Pin'ler nasıl hesaplanır?

`client-config.sh` bunları host'un dosyalarından okur. Elle doğrulamak için:

```bash
openssl s_client -connect 192.168.1.80:6651 -servername 192.168.1.80 < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl base64
```

`HostPin`'e verirken başına `sha256/` ekleme; kütüphane yalnızca Base64 bekler.
