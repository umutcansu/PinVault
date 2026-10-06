# sample-client

PinVault'u bir Android uygulamasına uçtan uca bağlayan örnek (Java). Pin config'ini Docker'da çalışan [sample-host](../sample-host)'tan alır ve kütüphanenin bütün özelliklerini ekranlarda gösterir.

Uygulama şunları gösterir:

1. APK'ya gömülü **bootstrap pin**'lerle host'a bağlanıp pin config'ini çekmek.
2. Config'in **ECDSA imzasını** ve `issuedAt/expiresAt` tazeliğini doğrulamak; tutmayan config uygulanmaz.
3. Gelen pin'lerle gerçek bir hedefe iki farklı yoldan pinli istek atmak: kütüphaneyi kullanan client (`PinVault.applyTo`) ve PinVault'u import etmeyen **production-style** client (kendi `OkHttpClient`'ı; pinlemeyi uygulama katmanının verdiği `PinVault::applyTo` geri çağrısı takar — önceki sürümdeki `CertificatePinner` kopyası, hazır Frida/objection bypass betiklerinin doğrudan hedefi olduğu için kaldırıldı).
4. Config'i elle ya da 15 dakikada bir arka planda yenilemek.
5. Her TLS el sıkışmasını ve config güncellemesini uygulama içinde listelemek ve host dashboard'una telemetri olarak göndermek (Config API portundan, pinli; telefon yönetim portuna hiç bağlanmaz).
6. **mTLS:** telefonun cihaz kimliği (ANDROID_ID) ekranda yazar; panelde token üretirken bu kimlik "Cihaz kimliği" alanına yazılırsa token yalnızca bu telefonda geçer ve gizli dosyalar sertifikaya bağlanabilir (başka telefon "bu token başka bir telefon için üretilmiş" uyarısı alır, token harcanmaz). Token ya da kayıt koduyla kayıt; yönetici onayı gerekiyorsa doğrulama koduyla bekleme (panelde aynı kod görünür, onaylanınca kayıt kendiliğinden tamamlanır); reddedilen kaydın nedeni; mTLS Config API'ye ve host'taki mock mTLS hedefine bağlanma; süresi dolan sertifikanın kurtarma kapısından yenilenmesi; kaydı silme.
7. **Vault:** herkese açık dosyalar (TLS) ve ekran kilidi arkasındaki gizli dosyalar (mTLS + token + ekran kilidi): indirme, "Aç" ile ekran kilidi sorularak açma, eşitleme, bilgi ve silme. Sunucu cihazın kaydını iptal edince gizli dosyalar ve token'lar silinir.
8. **Yalnızca test derlemelerinde** (debug ve e2e; [Derleme türleri](#derleme-türleri)): Depolama ekranı (cihazda ne saklandığı ve nasıl saklandığı), Ayarlar ekranı (çalışma modu, telemetri seçenekleri, özel bağlantı ayarlı istemci, sıfırlama, planlı iş), token'sız otomatik kayıt ve elle P12 içe aktarma. Telefona kurulacak release derlemesinde bunların hiçbiri yoktur.

---

## Ekranlar

| Ekran | Ne var |
|---|---|
| Ana | Durum (mod, config sürümü, host başına pin sürümü), iki client ile pinli istek, config yenileme, bağlantı olayları |
| mTLS | Cihaz kimliği (panelde token'ı bu telefona bağlamak için), kayıt (token / kayıt kodu), onay bekleme ve doğrulama kodu, ret nedeni, mTLS Config API ve mock host testleri, kaydı silme. Test derlemelerinde ayrıca otomatik kayıt ve P12 içe aktarma (parolayla) |
| Vault | Yedi dosya (dördü herkese açık, üçü gizli ve kilitli), "Aç" (ekran kilidi sorulur), "Tümünü eşitle", dosya bilgisi (sunucuya gitmeden; kilitli dosyanın içeriği gösterilmez), silme, cihaz kimliği, erişim token'ı |
| Depolama (yalnızca test derlemeleri) | Şifreli tercih dosyaları ve düz metin sızıntısı kontrolü, `files/vault_files/*.enc`, Keystore anahtarları (algoritma, bit, donanım), istemci sertifikası kaydı |
| Ayarlar (yalnızca test derlemeleri) | Mod seçimi, telemetri (başarıları raporla, tekrar bastırma), özel ayarlı istemci, reset / init tekrar / yeniden başlat, WorkManager işleri |

## Modlar

Mod seçimi bir test kontrolüdür: yalnızca debug ve e2e derlemelerinde, Ayarlar ekranından ya da açılışta `--es mode <MOD>` intent ekiyle yapılır; her seçim PinVault'u sıfırlayıp yeni yapılandırmayla kurar. **Release derlemesi her zaman `TLS` modunda çalışır** ve dışarıdan gelen hiçbir intent ekini okumaz: ana ekran dışa açık olduğu için bu ek release'te kalsaydı telefondaki herhangi bir uygulama modu kalıcı olarak değiştirip uygulamayı pin güncellemelerinden ve iptalden koparabilirdi.

| Mod | Ne gösterir |
|---|---|
| `TLS` (varsayılan) | Config TLS Config API'den; cihaz kayıtlıysa ikinci blok olarak mTLS Config API de eklenir |
| `MTLS_CONFIG` | Config'in kendisi mTLS üzerinden, istemci sertifikasıyla çekilir |
| `CUSTOM_BACKEND` | Kütüphanenin varsayılan yolları yerine özel uçlar (`ssl/pins`, `ping`, `auth/register`, `certs/client`, `analytics/vault`). İstekleri yine kütüphanenin kendi istemcisi yapar; imza, tazelik ve replay kontrolleri aynen çalışır |
| `EMBEDDED_API` | Config uygulama içindeki `CertificateConfigApi` uygulamasından; kütüphaneden hiç HTTP çıkmaz. **İmza doğrulanmaz** (blok `allowUnsigned()` ile kurulur): pin'ler APK'nın içinden geldiği için güven APK'ya dayanır |
| `STATIC` | Sunucusuz: pin'ler APK'ya gömülü |

Son iki mod `sample-host.properties` içindeki `target.pins`, özel backend modu ise `custom.*` değerleri doluysa çalışır.

**Kendi `CertificateConfigApi`'ni yazıyorsan.** `fetchConfig` hazır bir config döndürür; kütüphanenin doğrulayabileceği bir imza kalmaz. Pin'leri uzaktan getiren bir API bu yüzden `SignedConfigSource`'u da uygulamalı (imzalı zarfı kütüphaneye verir, kütüphane kendi istemcisinde yaptığı gibi doğrular) ve blok `signaturePublicKey(...)` taşımalıdır. İmza anahtarı olan bir blok, bunu uygulamayan özel bir API ile kurulursa `PinVault.init` hata verir; tek çıkış `allowUnsigned()` demek, yani doğrulama olmadığını kodda açıkça yazmaktır. Ayrıntı: `EmbeddedConfigApi.kt`.

---

## Kütüphane nereden geliyor?

`gradle.properties`:

```properties
pinvault.version=2.1.1          # Maven Central sürümü
pinvault.localPath=..  # doluysa kütüphane bu checkout'tan derlenir
```

`pinvault.localPath` bir PinVault checkout'unu gösterdiği sürece `settings.gradle.kts` bir composite build kurar ve kütüphaneyi kaynaktan derler; henüz yayınlanmamış değişiklikler dahil olur. Maven Central sürümüyle derlemek için yolu boşalt ya da tek seferlik `./gradlew assembleDebug -Ppinvault.localPath=`.

## Host değerleri

IP, portlar, bootstrap pin'leri ve imzalama public key'i `sample-host.properties` dosyasından `BuildConfig`'e gömülür:

```bash
cd ../sample-host
./scripts/client-config.sh --properties > ../sample-client/sample-host.properties
```

Başka bir dosya kullanmak için `./gradlew installDebug -PsampleHostProps=/yol/dosya.properties` (uçtan uca testler kendi dosyasını böyle verir). Sunucu sertifikası ya da imzalama anahtarı değişirse bu dosyayı yenile ve yeniden derle.

İmza katmanları da bu dosyadan gelir: `host.signingPublicKeys` (sunucunun imzalayıcıları + çevrimdışı yedek anahtar), `host.recoveryPublicKeys` (anahtar setini imzalayan kurtarma anahtarı) ve `host.requiredSignatures` (config başına gereken imza sayısı). Uygulama bu sayının altına inmez: test derlemelerindeki "iki imza iste" ayarı yalnızca yükseltebilir, release'te ayar hiç yoktur. Host'un üretim profili (`setup.sh --production`) bunları doldurur ve `requiredSignatures`'ı en az 2 yazar; demo profilinde yedek ve kurtarma anahtarı yoktur.

`host.tlsScope` ve `host.mtlsScope` sunucudaki Config API kimlikleridir (`default-tls`, `sample-mtls`). Uygulama her bloğu kendi kimliğine bağlar (`serverScope`): aynı imza anahtarıyla başka bir Config API için imzalanmış bir config, imzası geçerli olsa da kabul edilmez. Bunun için sunucu imzalı config'e `configApiId`, vault dosyalarına `X-Vault-Signature-V2` yazmalı; yazmayan bir sunucuda `client-config.sh` (ve uçtan uca testlerin kurulumu) bu iki değeri boş bırakır ve uyarır, boşken bağlama yapılmaz.

`host.clientCaPin` cihaz sertifikalarını imzalayan sunucu CA'sının SPKI pin'idir (`client-config.sh` sunucudan okur; CA değişecekse yenisi virgülle eklenir). Uygulama onu kayıt yapan bloğa ve mTLS bloğuna `clientCaPins(...)` olarak verir: kayıtta ve her yenilemede gelen zincir en az iki sertifika olmalı, yaprak telefonun kendi anahtarı için kesilmiş ve bu CA tarafından imzalanmış olmalı. Kayıt yanıtını yolda değiştiren biri (başka anahtar için ya da kendi CA'sıyla imzaladığı bir sertifika) telefona kimlik kurduramaz. Boşsa ilk kayıtta gelen zincire güvenilir. Sunucunun ürettiği anahtar (P12 ile kayıt) kabul edilmez: örnek uygulama `allowServerGeneratedKey()` çağırmaz; elle yüklenen P12 (yalnızca test derlemeleri) kayıt değil, `clientKeystore(...)` ile verilir.

Dosyadaki her değer derlemede biçimine göre denetlenir (IP, port, Base64 pin, public key) ve `BuildConfig`'e kaçışlanarak yazılır; biçime uymayan bir değer derlemeyi durdurur.

`target.requireCaTrust=true` (varsayılan; `client-config.sh` hedefin zincirine bakıp yazar): hedefin (`www.example.com`) sertifikası pin'i tutmakla kalmamalı, telefonun güvendiği CA'lardan da geçmeli (`PinVaultConfig.Builder.requireCaTrust`). Config imza anahtarı çalınsa bile saldırgan bu hedef için kendi sertifikasını pinleyemez. Sertifikası self-signed ya da kurum içi CA'lı bir hedef için `false` yazılır; bunu `client-config.sh` yalnızca açıkça `--target-private-ca` verilince yapar ve **release derlemesi `false` ile derlenmez**. Host'un kendi portları ve mock host'lar bu listede değildir (sunucunun kendi CA'sı).

## Kurulum

1. Host'u ayağa kaldır ve hazırla:
   ```bash
   cd ../sample-host && ./scripts/setup.sh && docker compose up -d --build && ./scripts/provision.sh && ./scripts/smoke-test.sh
   ```
   `provision.sh` mTLS Config API'sini (`:6652`), host'un kendi pin kaydını ve mock hedef host'ları (`:6653` TLS, `:6654` mTLS) açar. İsteğe bağlı `./scripts/seed-vault.sh` Vault ekranının dosyalarını uygulamanın beklediği kurallarla yükler ([Gizli dosyalar](#gizli-dosyalar)). Bu kurulum host'un **demo profili**dir; gerçek kullanım için host'ta `./scripts/setup.sh --production` (sample-host README → "Üretim profili").
2. Host değerlerini al (yukarıdaki `client-config.sh --properties`).
3. Derle ve kur:
   ```bash
   ./gradlew installDebug
   ```

Telefon Mac ile aynı ağda olmalı. Emülatör de host IP'sine erişebiliyor.

## Derleme türleri

| Tür | Komut | Ne için | Test kontrolleri | İmza |
|---|---|---|---|---|
| `debug` | `./gradlew installDebug` | Geliştirme | var | debug anahtarı |
| `e2e` | `./gradlew :app:assembleE2e` | Uçtan uca testler: release ile aynı küçültülmüş kod (R8, aynı keep kuralları, aynı paket adı) | var | debug anahtarı |
| `release` | `./gradlew :app:assembleRelease` | Telefona ve mağazaya giden derleme | **yok** | **senin yayın anahtarın** |

"Test kontrolleri" `app/src/testControls` klasöründedir ve yalnızca debug ile e2e derlemelerine girer: Ayarlar ve Depolama ekranları (mod değiştirme, gereken imza sayısı, sıfırlama, planlı işi iptal etme, Keystore anahtar listesi), `mode` intent eki, otomatik kayıt, elle P12. Release derlemesi onların yerine `app/src/release` altındaki boş karşılığı alır; o ekranlar APK'da ve manifest'te yoktur (`BuildConfig.TEST_CONTROLS = false`). Önceki bir sürümden kalmış elle P12 dosyası varsa release açılışta siler.

Release ayrıca:

- Bütün ekranlarda `FLAG_SECURE` (ekran görüntüsü, ekran kaydı, "son uygulamalar" önizlemesi kapalı).
- `Log.d/v/i` ve kütüphanenin teşhis log çağrıları R8 ile koddan silinir (`app/proguard-release.pro`); kütüphanenin debug log'u hiç açılmaz.
- Test bayraklarıyla derlenmez: `-Psample.diagnosticLogs=true`, `-Psample.e2eScreenshots=true` ya da `target.requireCaTrust=false` verilirse derleme durur. Bu bayraklar yalnızca debug ve e2e içindir.
- Demo host değerleriyle derlenmez. Depodaki `sample-host.properties` bir demo dosyasıdır; release şunları ister, biri eksikse ne gerektiğini yazıp durur: `host.requiredSignatures` en az 2, gereken imzadan en az bir fazla güvenilen anahtar (`host.signingPublicKey` + `host.signingPublicKeys`, yani yedek anahtar), dolu `host.recoveryPublicKeys`, `host.clientCaPin`, `host.tlsScope` ve `host.mtlsScope`. Bu değerleri host'un üretim profili üretir: `../sample-host/scripts/client-config.sh --properties > sample-host.properties` (README → [Üretim profili](../sample-host/README.md#üretim-profili)).

> **e2e APK'sı gerçek telefona kurulmaz.** Test kontrollerini (mod değiştirme, otomatik kayıt, elle P12, gereken imza sayısını değiştiren Ayarlar ekranı) taşır, herkesin bildiği debug anahtarıyla imzalıdır ve demo host değerleriyle derlenir. Yalnızca test telefonu ve emülatör içindir; kullanıcılara yalnızca `release` gider.

### Yayın derlemesi

Release, debug anahtarıyla **imzalanmaz**. Debug anahtarı her geliştirici makinesinde ve çoğu CI'da bulunur, parolası herkesçe bilinir; onunla imzalı bir uygulamanın üstüne aynı anahtarla imzalanmış sahte bir güncelleme kurulabilir ve uygulamanın bütün verisini, Keystore anahtarlarını devralır.

İmza bilgisi depoda durmaz. Gradle özelliği (`~/.gradle/gradle.properties` ya da `-P…`) ya da ortam değişkeni olarak verilir:

| Gradle özelliği | Ortam değişkeni | |
|---|---|---|
| `sample.release.storeFile` | `SAMPLE_RELEASE_STORE_FILE` | anahtar deposunun yolu |
| `sample.release.storePassword` | `SAMPLE_RELEASE_STORE_PASSWORD` | |
| `sample.release.keyAlias` | `SAMPLE_RELEASE_KEY_ALIAS` | |
| `sample.release.keyPassword` | `SAMPLE_RELEASE_KEY_PASSWORD` | |

```bash
export SAMPLE_RELEASE_STORE_FILE=/guvenli/yer/yayin.jks
export SAMPLE_RELEASE_STORE_PASSWORD=…  SAMPLE_RELEASE_KEY_ALIAS=…  SAMPLE_RELEASE_KEY_PASSWORD=…
./gradlew :app:assembleRelease
```

Biri eksikse (ya da `sample-host.properties` üretim değerlerini taşımıyorsa, yukarıda) `assembleRelease` ne gerektiğini yazıp durur. Parolaları komut satırına yazmak yerine ortam değişkeni ya da CI'ın gizli değer deposunu kullan.

**Sunucuya verilecek imza parmak izi (`ATTESTATION_SIGNER_SHA256`).** Host'un üretim profili, uygulamanın yayın imza sertifikasının SHA-256'sını ister (`setup.sh --production --attestation-signer …`). İmzalı APK'dan:

```bash
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk | grep "SHA-256"
# ya da anahtar deposundan:
keytool -list -v -keystore /guvenli/yer/yayin.jks -alias <alias> | grep "SHA256:"
```

Uygulamayı Google Play imzalıyorsa (Play App Signing) telefona giden APK'yı senin yükleme anahtarın değil Google'ın tuttuğu **uygulama imzalama anahtarı** imzalar: değer Play Console → Uygulama bütünlüğü → Uygulama imzalama anahtarı sertifikası → SHA-256'dan alınır. Yanlış sertifika verilirse gerçek telefonların anahtar belgeleri reddedilir.

Release'i DexProtector ile korumak için: [DEXPROTECTOR.md](DEXPROTECTOR.md).


## Beklenen akış

| Adım | Ekranda |
|---|---|
| Açılış | "PinVault başlatılıyor…", düğmeler kilitli |
| Config geldi | "✅ Hazır — config v29", mod ve pin'li host'lar |
| Library client ile test | "✅ Pinned bağlantı başarılı, HTTP 403" |
| Production-style client ile test | "✅ Production-style bağlantı başarılı, HTTP 403" |
| Config'i şimdi yenile | "✅ Config güncel" ya da "✅ Yeni config uygulandı: vN" |
| Atestasyon: şimdi ölç, token al, mock host'a git | Temiz telefonda "✅ Atestasyon geçti · arc … · PinVault-Token … · HTTP 200"; rootlu/emülatör/hooklu cihazda "⛔ Atestasyon KALDI · neden: rooted,…" ve mock host `MOCK_HOST_REQUIRE_TOKEN=true` ise HTTP 401. Durum satırı ("🛡 Atestasyon: …") her 5 dakikada kendiliğinden yenilenir |
| Host kapalıyken açılış | "❌ PinVault başlatılamadı" ve "Tekrar dene" |
| mTLS → token gir → Kayıt ol | "✅ Kayıt başarılı — CN=PinVault Client: …" |
| mTLS → başka telefon için üretilmiş token gir → Kayıt ol | "bu token başka bir telefon için üretilmiş" uyarısı; token harcanmaz |
| mTLS → onaylı kayıt kodu gir → Kayıt ol | "⏳ Onay bekleniyor — kimlik: … doğrulama kodu: XXXX-XXXX"; panelde onaylanınca "✅ Kayıt başarılı" |
| mTLS → Otomatik kayıt (test derlemesi; kodsuz başvurular açıkken) | Aynı bekleme ekranı; panelde satırda "kodsuz başvuru" ve aynı doğrulama kodu |
| mTLS → Mock mTLS host | Kayıtlıysa "✅ Mock mTLS host bağlantısı başarılı, HTTP 200" |
| mTLS → P12 parolasını gir → P12 içe aktar (test derlemesi) | "✅ P12 içe aktarıldı — CN=…"; `files/manual-client.p12` silinir, Depolama'da "düz P12 dosyası: yok ✓" |
| Vault → flags | "✅ sample-flags v1 indirildi (imza doğrulandı)" ve içerik |
| Vault → admin | "❌ sample-admin indirilemedi … 401" (kütüphane yönetim anahtarı göndermez) |
| Vault → secret (kayıtlı değilken) | "❌ sample-secret indirilemedi — bu gizli bir dosya: önce mTLS ekranından kayıt ol" |
| Vault → secret (kayıtlı, token girilmiş) | "✅ sample-secret v1 indirildi … 🔒 Kilitli: içerik burada gösterilmez" |
| Vault → anahtar `sample-secret` → Aç | Telefon ekran kilidini sorar; sonra "🔓 sample-secret v1 açıldı" ve içerik. Vazgeçilirse "✋ … açılmadı" |
| Vault → secret (telefonda ekran kilidi yok) | "❌ … indirilemedi — bu dosya telefonda ekran kilidi olmadan saklanmaz" |
| Depolama (test derlemesi) | Şifreli dosyalar, "düz metin sızıntısı: yok ✓", Keystore anahtarları |

## Atestasyon (Approov'un çalışma mantığı)

`host.attestation=true` (varsayılan) ile TLS ve mTLS blokları `attestation()`
açar. Kütüphane açılışta ve sonra 5 dakikada bir uygulamayı ve cihazı ölçer
(root, emülatör, hata ayıklayıcı, debuggable, hooking çerçevesi, imza
sertifikası, klon uygulama, kurulum kaynağı, ADB, anahtarın yeri), raporu
Keystore'daki kimlik anahtarıyla imzalayıp `POST /api/v1/attest`'e gönderir.
Host, Config API'nin **atestasyon politikasına** göre karar verir (panel →
Config API → Atestasyon): geçen cihaz 5 dakikalık bir **PinVault-Token** alır
ve kütüphane bunu bloğun pinli host'larına giden her isteğe `PinVault-Token`
başlığı olarak ekler; yeni bir pin config'i varsa aynı yanıtta gelir. Kalan
cihaz token da pin güncellemesi de almaz. Host'un mock TLS hedefi
`MOCK_HOST_REQUIRE_TOKEN=true` ile token'sız ya da geçersiz token'lı isteği
401 ile reddeder; gerçek bir backend aynı doğrulamayı
`SERVER_IMPLEMENTATION_GUIDE.md`'deki örneklerle yapar. Ayrıntı:
[ATTESTATION.md](../ATTESTATION.md).

**Play Integrity (isteğe bağlı).** `host.playIntegrityProjectNumber` dolu
derlenirse uygulama `pinvault-play-integrity` modülünün
`PlayIntegrityVerdictProvider`'ını kurar: rapor, Google'ın bu turun
nonce'una bağlı kararını da taşır (`verdictProvider`). Host, Play
Console'dan indirilen yanıt anahtarlarıyla (`PLAY_INTEGRITY_DECRYPTION_KEY`,
`PLAY_INTEGRITY_VERIFICATION_KEY`) token'ı kendisi çözüp doğrular ve
politikadaki `play_integrity` / `play_integrity_missing` bayraklarını
kaldırır; panelde cihaz sayfasında Google'ın özeti görünür. Üç yerden ayrı
ayrı açılıp kapanır: uygulamada proje numarası, host'ta anahtarlar,
politikada bayrağın eylemi. Boş bırakılırsa uygulama Google'ın istemcisini
hiç çağırmaz; Play Servisleri olmayan telefonda da atestasyon aynen çalışır.
Sağlayıcı Google'a en çok 6 saatte bir sorar (klasik istek kotası günde
10 000); host son doğrulanmış kararı 24 saat sayar.

Uygulama kodunda token'a dokunulmaz: `PinVault.getClient()` ve `applyTo`
istemcileri başlığı kendileri ekler. Ana ekrandaki düğme akışın tamamını
gösterir; `PinManagerLite.attestNowBlocking()` / `fetchTokenBlocking()`
suspend API'lerin Java köprüleridir. Olay listesinde her tur `[atestasyon]`
satırıyla görünür. Panelde cihaz başına son karar, ARC, anahtar seviyesi ve
"geçir / düşür" ek açıklamaları vardır; ARC, nedenleri telefona açıklamayan
bir politika altında bile panelden çözülebilir.

## Gizli dosyalar

Vault ekranında iki tür dosya var.

**Herkese açık olanlar** (dashboard → Config API **default-tls** → Vault): `sample-flags` (public), `sample-atrest` (public + at_rest), `sample-admin` (api_key), `sample-model` (public). `sample-atrest` sunucunun diskinde şifreli durur ama isteyen herkes indirebilir; gizli bilgi için değildir.

**Gizli olanlar** (dashboard → **sample-mtls** → Vault, politika **token_mtls**): `sample-secret` ve `sample-mtls-secret` şifreleme **user_auth**, `sample-e2e` şifreleme **end_to_end** ile yüklenir. `../sample-host/scripts/seed-vault.sh` hepsini doğru kurallarla yükler. Uygulamada üçü de aynı kuralla tanımlı (`App.java`):

```java
.vaultFile("sample-secret", file -> {
    file.configApi("sample-mtls");                         // mTLS bloğu
    file.accessPolicy(VaultFileAccessPolicy.TOKEN_MTLS);   // token + bu cihazın sertifikası
    file.accessToken(() -> VaultTokens.get("sample-secret"));
    file.userAuth(UserAuth.REQUIRED);                      // ekran kilidi olmadan açılmaz
    file.encryption(VaultFileEncryption.USER_AUTH);        // sunucu telefonun kilit anahtarına kilitler
    ...
})
```

Telefonda ne olur:

1. Önce mTLS ekranından kayıt olunur (gizli dosyalar mTLS bloğunda; kayıtsız cihazda tanımlanmazlar), sonra uygulama kapatılıp yeniden açılır (test derlemelerinde Ayarlar → "Uygula ve yeniden başlat" da olur).
2. Telefonda ekran kilidi (PIN, desen, şifre) olmalı. Yoksa dosya saklanmaz ve ekran bunu söyler.
3. Dashboard'da dosya detayında bu cihaz için token üretilir ("Cihaz ID" Vault ekranında yazar) ve Vault ekranında anahtar + token girilip "Token'ı kaydet"e basılır. Token yalnızca bellekte durur.
4. Dosyanın düğmesi dosyayı indirir ama içeriği göstermez: "🔒 Kilitli".
5. Anahtar alanına dosya adı yazılıp **Aç**'a basılınca telefon ekran kilidini (ya da parmak izini) sorar; doğru girilince içerik görünür. Ekrandan ayrılınca (başka bir pencere öne gelince) ya da 1 dakika sonra silinir; metin seçilip kopyalanamaz. "Bilgi" kilitli dosyanın içeriğini göstermez.
6. Kilit anahtarı geçersiz olduysa (ekran kilidi kaldırılıp yeniden konduysa ya da parmak izi eklendiyse) ya da telefonda kopya yoksa, "Aç" dosyayı yeniden indirir; tekrar "Aç" ile açılır.

`sample-secret` ve `sample-mtls-secret`'ta (user_auth) içerik telefona kilitli gelir; uygulama ekran kilidi sorulmadan okuyamaz. Root'lu telefonda uygulama adına çalışan kod da yalnızca kilitli kopyayı alır, ama bu ancak sunucu anahtar doğrulamasını (attestation) zorunlu tuttuğunda geçerli (`USER_AUTH_ATTESTATION=enforce` ve uygulamanın paket adı; bootloader'ı kilitli telefon). Zorunlu değilken sunucu cihazın ilk kaydettiği anahtara güvenir: uygulamanın kimlik bilgilerini ele geçiren kod, ilk kayıtta kendi anahtarını kaydettirebilir. Kayıtlı anahtarı değiştirmek doğrulama ya da yönetici sıfırlaması ister. Android 7–10'da parmak izi yoksa ekran kilidi anahtarı 10 saniyeliğine açar (telefonun kilidini açmak da sayılır). `sample-e2e`'de (end_to_end) sunucu cihazın RSA anahtarıyla şifreler, telefon çözüp hemen ekran kilidi anahtarıyla yeniden kilitler; indirme anında içerik uygulamanın belleğinden geçtiği için user_auth daha sıkıdır.

**Çevrimdışı süre sınırı (öneri: 7 gün).** Gizli dosyalarda `maxOfflineAge(7, TimeUnit.DAYS)` açık (`App.SECRET_MAX_OFFLINE_DAYS`): sunucu kopyayı en son 7 günden önce onayladıysa (indirme ya da "değişmedi" cevabı) "Aç" kopyayı açmaz, önce yeniden indirir. Kaydı iptal edilmiş ama hiç ağa çıkmayan bir telefon gizli dosyayı böylece en fazla bu süre okuyabilir (iptali öğrenince zaten siler). Süre telefonun saatiyle değil kütüphanenin güvenilen saatiyle ölçülür; saati geri almak süreyi uzatmaz. Kendi uygulamanda bu süreyi kullanıcıların ne kadar süre çevrimdışı kalabileceğine göre seç; kopyanın o an silinmesi istenirse `wipeWhenStale()` de eklenir. Gizli olmayan dosyalarda sınır yoktur.

**Kayıt iptal edilince.** Sunucu cihazın kaydını iptal ettiğinde (dashboard → istemci sertifikası → iptal) uygulama bir sonraki istekte bunu öğrenir: kütüphane mTLS bloğunun vault dosyalarını, kilitli kopyalar dahil, siler (`wipeVaultFilesOnRevocation()`), uygulama da bellekteki bütün token'ları unutur. mTLS ekranındaki "Kaydı sil" de aynı dosyaları siler (`unenroll(…, wipeVaultFiles = true)`). Olay listesinde "[kimlik] … kaydını iptal etti" satırı görünür.

**Ekran görüntüsü ve üst pencere.** Uygulamanın bütün ekranları ekran görüntüsüne, ekran kaydına ve "son uygulamalar" önizlemesine kapalıdır (`FLAG_SECURE`, `App.java`'da tek yerden). Yalnızca test derlemeleri `-Psample.e2eScreenshots=true` ile bunu kapatabilir (kanıt görüntüleri); release bu bayrakla derlenmez. Token ve parola alanları ile onları gönderen düğmeler, üstlerinde başka bir uygulamanın penceresi varken dokunuşu kabul etmez (`filterTouchesWhenObscured`): sahte bir üst pencereyle kullanıcıya düğme bastırılamaz.

**Elle yüklenen sertifika (yalnızca test derlemeleri).** `files/manual-client.p12` (adb ile konur) "P12 içe aktar"a basılınca, mTLS ekranındaki alana girilen parolayla açılır, rastgele bir parolayla yeniden paketlenir, Android Keystore'da üretilen ve dışarı çıkarılamayan bir anahtarla şifrelenip `files/manual-client.sealed` olarak saklanır; düz dosya silinir. Parola saklanmaz. "Elle P12'yi bırak" şifreli kopyayı ve anahtarını da siler. Bu dosyalar yedeğe ve yeni telefona taşımaya girmez (`res/xml/sample_data_extraction_rules.xml`). Bu yalnızca diskteki kopyayı korur: uygulama paketi her açılışta çözdüğü için root'lu telefonda uygulama adına çalışan kod da onu açıp özel anahtarı alabilir; düz dosyanın üstünü sıfırlayıp silmek de flash bellekte güvenilir değildir. Gerçek bir üründe elle P12 yüklenmez, cihaz kayıt (enroll) olur: özel anahtar telefonun Keystore'unda üretilir, dışarı çıkarılamaz, hiç dosyaya düşmez. Release derlemesinde bu özellik yoktur; önceki bir derlemeden kalmış `manual-client.p12` / `manual-client.sealed` dosyası ve anahtarı açılışta silinir.

Hedef sunucu kök adrese `403` döndürür; önemli olan TLS el sıkışmasının ve pin doğrulamasının geçmesidir.

Log:

```bash
adb logcat -s PinVault DynamicSSLManager SSLCertificateUpdater ConfigSignatureVerifier VaultFileRouter
```

## Uçtan uca testler

Dashboard'da işlem yapıp sonucunu bu uygulamada doğrulayan senaryolar [sample-e2e](../sample-e2e)'de:

```bash
cd ../sample-e2e && npm install && npm run test:emulator
```

Uygulama her işlem sonucunun altına `#<sıra> · <saat>` yazar; testler yeni sonucu eskisinden bununla ayırır.

---

## Yapı

```
sample-host.properties      host IP/port/pin/imza anahtarı → BuildConfig (derlemede denetlenir)
app/build.gradle.kts        üç derleme türü, release kapısı (imza, test bayrakları), değer denetimi
app/proguard-rules.pro      release ve e2e'nin ortak R8 kuralları
app/proguard-release.pro    yalnızca release: log çağrılarını siler
DEXPROTECTOR.md             release'i DexProtector ile koruma rehberi

app/src/main — her derlemede
App.java                    PinVault init (modlar), vault dosyaları, telemetri, FLAG_SECURE
AppSettings.java            mod ve telemetri tercihleri; release'te güvenliği etkileyenler sabit
InitState.java              başlatma durumu (ekranlar için)
ActionActivity.java         ekranların ortak iskeleti: arka planda işlem, sıra numaralı sonuç
MainActivity.java           durum, iki client, config yenileme, olay listesi
MtlsActivity.java           kayıt, onay bekleme, mTLS ve mock testleri, kaydı silme
VaultActivity.java          yedi dosya, "Aç" (unlockFile), eşitleme, bilgi, silme, token
MockDns.java                mock host adlarını host IP'sine çözümler
EmbeddedConfigApi.kt        HTTP yapmayan örnek CertificateConfigApi (imza doğrulanmaz; nedeni ve doğrusu içinde)
VaultTokens.java            vault erişim token'ları (yalnızca bellekte; kayıt iptal edilince silinir)
ConnectionEventLog.java     PinVaultConnectionListener → uygulama içi liste
ProductionStyleClient.java  PinVault import etmeyen network katmanı (pinlemeyi geri çağrıyla takar)
PinManagerLite.kt           suspend API'ler için senkron köprü (yenileme, kayıt, vault, atestasyon)
res/xml/network_security_config.xml   düz HTTP hiçbir yere yok (raporlar da şifreli porttan)
res/xml/sample_*_rules.xml  yedek ve cihaz taşıma kuralları: kütüphanenin kuralları + elle yüklenen P12

app/src/testControls — yalnızca debug ve e2e
TestControls.java           test kontrollerinin girişi: ekranlar, mode intent eki, otomatik kayıt, elle P12
StorageActivity.java        cihazdaki şifreli depolar ve Keystore anahtarları
SettingsActivity.java       mod, telemetri, gereken imza, sıfırlama, planlı iş
ManualP12Store.java         elle yüklenen P12: Keystore anahtarıyla şifreli kopya, düz dosya silinir
TestEnrollment.kt           token'sız otomatik kayıt köprüsü

app/src/release — yalnızca release
TestControls.java           boş karşılık: test kontrolü yok; elle P12 kalıntısını siler
```

## Pin'ler nasıl hesaplanır?

`client-config.sh` bunları host'un dosyalarından okur. Elle doğrulamak için:

```bash
openssl s_client -connect 192.168.1.80:6651 -servername 192.168.1.80 < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl base64
```

`HostPin`'e verirken başına `sha256/` ekleme; kütüphane yalnızca Base64 bekler.
