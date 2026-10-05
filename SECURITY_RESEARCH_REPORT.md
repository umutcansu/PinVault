# PinVault Güvenlik Araştırması Raporu ve Approov Dynamic Cert Pinning Karşılaştırması

_Tarih: 2026-10-05 · İncelenen commit: `a5204d5` (dal `claude/sharp-euler-uf519f`, `main` ile aynı) · Yöntem: beyaz kutu kaynak kod incelemesi (kütüphane, referans sunucu, örnek uygulamalar, dağıtım dosyaları, git geçmişi); beş paralel inceleme kolu, her bulgu kaynak satırıyla doğrulandı. Hiçbir şey çalıştırılarak sömürülmedi; bulgular kod okumasına dayanır._

---

## 1. Yönetici özeti

**Soru 1 — Projede açık var mı?**

Uzaktan, yalnızca ağ üzerinden (MITM konumundan) sömürülebilen **Kritik veya Yüksek** seviye bir açık **bulunamadı**. Kütüphanenin TLS çekirdeği gerçekten "fail-closed" çalışıyor: config yoksa, süresi dolmuşsa, host tanınmıyorsa ya da pin eşleşmiyorsa el sıkışma reddediliyor; sistem CA'larına sessiz geri dönüş yok. İmza doğrulama, tekrar (replay) koruması, m-of-n imza ve anahtar seti rotasyonu doğru yazılmış. Daha önceki iki iç inceleme turunun kapattığı klasik hatalar (kimlik doğrulamasız yönetim yüzeyi, düz metin token, HTML enjeksiyonu, `changeit`) gerçekten kapanmış.

Bulunanlar **Orta** seviyede tasarım boşlukları ve bir dizi **Düşük** seviye savunma-derinliği eksiği:

| # | Bulgu | Bileşen | Seviye |
|---|---|---|---|
| L-1 | Güvenilir saat (TrustedClock) geri sarılabiliyor: cihazın hiç görmediği, yakalanmış imzalı bir config + sahte SNTP/NITZ ile duvar saati geri alınınca süresi dolmuş pin seti yeniden kabul ediliyor | Kütüphane | Orta |
| L-2 | Keystore anahtarları sessizce zayıflıyor (StrongBox → TEE → atestasyonsuz → kilit gereksinimi olmadan); uygulama ve sunucu bunu öğrenmiyor | Kütüphane | Orta |
| L-3 | Çalışma zamanı bütünlük koruması (RASP) yok ve `consumer-rules.pro` tüm sınıf adlarını koruyor: iki satırlık Frida hook pinlemeyi tamamen kapatıyor | Kütüphane | Orta (hedef kitleye göre Yüksek) |
| L-4 | Root erişimiyle şifreli depo dosyalarının toptan geri yüklenmesine karşı rollback koruması yok (platform sınırı, kodda açıkça yazılmış) | Kütüphane | Orta |
| S-1 | Yönetim API'sinin tamamı cihazlara açık Config API portlarında da yayında; sızan tek `API_KEY` internetten pin yazabiliyor | Sunucu | Orta |
| S-2 | Scope'ta host ACL tanımlı değilse **her** kayıtlı cihaz, host'un paylaşılan mTLS özel anahtarını (P12) indirebiliyor | Sunucu | Orta |
| S-3 | Vault indirmeleri tamamen belleğe alınıyor, global eşzamanlılık sınırı ve `-Xmx` yok: 50 MB'lık bir `public` dosya ile heap tüketimi | Sunucu | Düşük–Orta |
| A-1 | `sample-client`'taki `ProductionStyleClient`, kütüphanenin trust manager'ı yerine `okhttp3.CertificatePinner` kullanıyor; objection / CodeShare gibi hazır bypass betikleri doğrudan çalışıyor | Örnek uygulama | Orta |
| A-2 | `demo-app` release'te düz metin yönetim kanalı, imzasız config (`?signed=false`), minify kapalı, koşulsuz Timber | Demo | Orta (demo kapsamı) |

Ayrıntılar ve 25'ten fazla Düşük/Bilgi seviyesi bulgu Bölüm 4'te.

**Soru 2 — Approov Dynamic Cert Pinning ile farkımız var mı?**

Evet, ve fark **pinlemenin kendisinde değil, pinlemenin etrafındaki katmanda**. Pin dağıtımı tarafında PinVault, Approov ile eşdeğer ya da daha güçlü (imzalı config, süre sonu, replay filigranı, m-of-n, çevrimdışı kurtarma anahtarı, kendi sunucunuz, HSM, iki kişilik onay, hash zincirli denetim kaydı, Keystore'da üretilen mTLS kimliği). Approov'un asıl ürünü ise **uygulama atestasyonu**: pinler ve API sırları yalnızca "bozulmamış uygulama + bozulmamış cihaz" ölçümünü geçen örneklere teslim ediliyor, bu ölçüm her 5 dakikada tekrarlanıyor ve backend her istekte kısa ömürlü bir Approov token'ı arıyor. Dolayısıyla Frida ile pin bypass edilse bile API cevap vermiyor. PinVault'ta bu katman **bilinçli olarak kapsam dışı** (README "What PinVault does NOT do"). Kayıt sırasındaki Android key attestation bu boşluğu sadece kayıt anında ve sunucu enforce ederse kapatıyor; çalışma zamanı hooking'ine karşı bir şey yapmıyor. Tam karşılaştırma Bölüm 6'da.

---

## 2. Kapsam ve yöntem

| Bileşen | Satır | Okunan |
|---|---|---|
| `pinvault/` (Android kütüphanesi, Kotlin) | ~15.9k | `ssl/`, `crypto/`, `store/`, `keystore/`, `internal/`, `api/`, `worker/`, `PinVault.kt`, manifest, backup kuralları, consumer ProGuard kuralları; testlerin kapsamı |
| `demo-server/` (Ktor referans sunucu) | ~37.8k | `Main.kt`, tüm `plugin/`, ilgili `route/`, `service/`, `store/`, 20 Flyway migration, dashboard JS (escape taraması) |
| `sample-client/`, `demo-app/` | — | Kaynak, manifest, NSC, ProGuard, Gradle, DEXPROTECTOR.md |
| `sample-host/`, `demo-server/` Docker | — | Dockerfile, compose (demo + production), entrypoint, .env örnekleri, scriptler |
| Git geçmişi | — | Gizli anahtar/parola/`.p12`/`.jks` taraması (temiz; tek istisna Google'ın açık atestasyon kök sertifikaları) |

Approov tarafı: approov.io bu ortamın ağ politikasında engelli olduğu için bilgiler Approov'un açık kaynak OkHttp servis katmanının kodundan (`approov/approov-service-okhttp`), quickstart/REFERENCE dokümanlarından ve arama motoru üzerinden erişilen resmi doküman özetlerinden derlendi. Kaynaklar Bölüm 8'de.

---

## 3. Tehdit modeli (bulguların okunması için)

| Saldırgan | PinVault'ta elde edebildiği |
|---|---|
| **Ağda, yolda (MITM), cihaza erişimi yok** | Hiçbir şey okuyamaz/değiştiremez. Yalnızca DoS, yenilemeyi kurtarma kapısına itme, config refetch tetikleme (bütçeli). İstisna: L-1 (saat geri sarma + eski pinin özel anahtarı). |
| **Config API'nin TLS anahtarını ele geçirmiş ama imza anahtarı yok** | Pin değiştiremez (imza), vault içeriği değiştiremez. `user_auth` dosyalarını bozabilir (kullanılabilirlik), büyük gövde ile OOM. |
| **İmza anahtarını çalmış** | Pinleri belirler. Sınırlar: 30 gün azami geçerlilik, `requireCaTrust` ile CA zorunluluğu, m-of-n, kurtarma anahtar seti ile iptal. |
| **Root / dosya erişimi** | Keystore anahtarlarını çıkaramaz ama uygulama gibi kullanabilir; şifreli depoları toptan eski haline döndürebilir (L-4); Frida ile pin kontrolünü kapatabilir (L-3). |

---

## 4. Bulgular

### 4.1 Kütüphane (`pinvault/`)

#### L-1 · Orta · Yakalanmış imzalı config + duvar saati geri sarma süresi dolmuş pinleri canlandırıyor
- **Kod:** `ssl/TrustedClock.kt:78-91` (`resetTo`), `ssl/SSLCertificateUpdater.kt:778-780` (`acceptedAsNewest`), `ssl/SSLCertificateUpdater.kt:872-879` ve `crypto/SignedConfigVerifier.kt:200-210` (`expiryNow`).
- **Ne oluyor:** Güvenilir saat normalde geri gitmez. Tek istisna: `issuedAt` değeri cihazın filigranından büyük bir config kabul edildiğinde. O config'in süresi dolup dolmadığına **duvar saatiyle** bakılıyor (`expiryNow` wall döner) ve kabulden sonra referans `max(wall, issuedAt)`'a indiriliyor. "Filigrandan yeni" olmak "taze" olmak demek değil.
- **Senaryo:** Saldırganın elinde (a) cihazın şu an taşıdığından sonra yayınlanmış ama gerçek zamanda süresi dolmuş, meşru imzalı bir zarf E2, (b) E2'nin hâlâ listelediği bir pinin özel anahtarı (örn. rotasyonla çıkarılmış eski sertifika) var. Yolda SNTP/NITZ sahteciliğiyle cihaz saatini `[E2.issuedAt − 1 saat, E2.expiresAt)` aralığına çeker, gerçek Config API'yi keser, E2'yi sunar. `checkPlausible` geçer, saat geri çekilir, cihaz E2'nin TTL'i boyunca (varsayılan 24 saat, en fazla 30 gün) eski pine güvenir.
- **Güven:** Orta-yüksek (kod izi takip edildi, çalıştırılmadı). Ön koşul olarak pinli bir anahtarın ele geçirilmiş olması gerekiyor; bu zaten rotasyonun koruduğu durum, dolayısıyla tam da işe yaraması gereken anda deliniyor.
- **Öneri:** Referansı yalnızca yeni config'in `expiresAt` değeri taşınan referansın da ilerisindeyse indir; indirme miktarını sınırla; her `resetTo`'da bir bağlantı olayı yayınla; test ekle: "hiç görülmemiş, süresi dolmuş zarf + geri alınmış saat referansı indirmez".

#### L-2 · Orta · Keystore anahtarları sessizce zayıflıyor
- **Kod:** `keystore/ClientIdentityKeyProvider.kt:129-150` (StrongBox+atestasyon → TEE+atestasyon → TEE atestasyonsuz), `keystore/UserAuthKeys.kt:285-302`, `keystore/DeviceKeyProvider.kt:88-102`, `keystore/KeystoreOptions.kt:31-40` (`requireUnlockedDevice()` reddedilirse bayraksız yeniden üretim, yalnızca `Timber.w`).
- **Ne oluyor:** `src/main` içinde hiçbir yerde `KeyInfo.isInsideSecureHardware` / `securityLevel` okunmuyor; `InitResult`/olaylarda ulaşılan seviye yok; "donanım zorunlu" seçeneği yok. Atestasyon reddeden bir ROM'da kimlik anahtarı yazılım destekli olabilir ve sunucu bunu ancak atestasyonu **enforce** ediyorsa anlar. `requireUnlockedDevice()` çağıran uygulama depolarının kilide bağlı olduğunu sanır, değildir.
- **Öneri:** Üretimden sonra `KeyInfo` oku; seviyeyi `ClientCertEnrollmentResult`/`InitResult`/olayda bildir; `requireHardwareBackedKeys()` seçeneği (düşüş yerine hata); seviyeyi kayıt JSON'una ekle.

#### L-3 · Orta (ödeme/SoftPOS gibi hedeflerde Yüksek) · RASP yok, sınıf adları korunuyor, iki satırlık Frida bypass
- **Kanıt (negatif):** `pinvault/src/main` ve `sample-client/` içinde `isDebuggerConnected`, `FLAG_DEBUGGABLE`, imza özeti karşılaştırması, root/emülatör/Frida/Xposed/Play Integrity'ye dair **sıfır** referans. README `:1910-1918` bunu açıkça kapsam dışı ilan ediyor; `sample-client/DEXPROTECTOR.md:5` DexProtector entegrasyonunun **test edilmediğini** söylüyor.
- **`pinvault/consumer-rules.pro:13`:** `-keepnames class io.github.umutcansu.pinvault.**` — gerekçe Timber etiketleri. Sonuç: her tüketici uygulamanın release APK'sında Frida hedefleri kaynak adlarıyla adreslenebilir; `checkServerTrusted` ve `intercept` arayüz metodu oldukları için zaten yeniden adlandırılamaz.
- **Karar noktası:** `ssl/DynamicSSLManager.kt:655-729` anonim trust manager (`DynamicSSLManager$pinnedTrustManager$1`), `:801-817` `matchPins`, `ssl/PinnedConnectionInterceptor.kt:77-104`. İki hook (trust manager'ın `checkServerTrusted` aşırı yüklemeleri boş gövde; interceptor `chain.proceed`) el sıkışmayı, istek başına yeniden kontrolü ve `requireCaTrust`'ı birlikte kapatıyor. Eşdeğer smali yaması + yeniden imzalama çalışır; imza sertifikasını kontrol eden bir şey yok.
- **Olumlu not:** Kütüphane `okhttp3.CertificatePinner` veya platform `TrustManagerImpl` kullanmadığı için objection / genel CodeShare "universal unpinning" betikleri **kütüphane yolunu kapatamıyor**; hedefe özel hook gerekiyor. `SSLContext.init` hook'u da tek başına yetmiyor çünkü interceptor zinciri yeniden kontrol ediyor.
- **Öneri:** `-keepnames` kaldırılsın (`Timber.tag("PinVault")` ile etiket sorunu çözülür); örnek uygulamaya `PinVault.init` ve kayıt/unlock öncesi hata ayıklayıcı, debuggable, imza özeti ve temel root kontrolü; kayıt ön koşulu olarak Play Integrity sunucu kararı; DexProtector rehberi test edilene kadar "test edilmedi" ibaresi kalsın.

#### L-4 · Orta · Root ile toptan dosya geri yükleme (rollback) koruması yok
- **Kod:** `store/SecurePreferences.kt`, `store/EncryptedFileStorageProvider.kt` (AES-GCM + AAD doğru), filigranlar `store/CertificateConfigStore.kt:85-102,120-126`, saat referansı `:302-308`, dosya onay zamanları `store/VaultFileMeta.kt:92-96` — hepsi aynı iki prefs dosyasında; `internal/VaultFileGuard.kt:47-51` sınırı açıkça yazıyor.
- **Etki:** Keystore anahtarları değişmediği için geri yüklenen dosya çözülür; pinler/filigran/saat config ömrü içinde geriye alınabilir. Kısmi azaltım: `expiresAt` + 30 gün üst sınır, `TrustedClock` (saldırganın duvar saatini de geri alması gerekir).
- **Öneri:** Android'de uygulamaya açık güvenli sayaç yok; gerçekçi kaldıraçlar kısa `expiresAt`, `vaultFileMaxOfflineAge`, filigran/saat kopyasını ayrı dosyada tutmak (tembel geri yüklemeyi yakalar). README'de belgelensin.

#### Düşük seviye kütüphane bulguları

| # | Bulgu | Kod | Öneri |
|---|---|---|---|
| L-5 | Kütüphanenin kendi ürettiği pinli istemci HTTPS→HTTP yönlendirmesini izliyor; cleartext istek interceptor'dan kontrolsüz geçiyor (bootstrap istemcisinde `followSslRedirects(false)` var, `buildDynamicClient`'ta yok) | `ssl/DynamicSSLManager.kt:556-567`, `ssl/PinnedConnectionInterceptor.kt:81` | `followSslRedirects(false)`; kütüphane istemcilerinde `http://` reddi |
| L-6 | Bootstrap istemcisi aynı şema yönlendirmelerini izliyor; `X-Vault-Token`, `X-Device-Id`, kayıt gövdesi wildcard/CA pin kapsamındaki başka bir host'a taşınabilir | `ssl/DynamicSSLManager.kt:603-615` | `followRedirects(false)` |
| L-7 | Issuer pin host adını doğrulamaz; `applyTo` açık `hostnameVerifier` koymaz. Uygulama gevşek bir verifier takmışsa, pinlenen aracı CA'dan (örn. Let's Encrypt R3) alınmış herhangi bir sertifika geçer | `ssl/ChainPinMatcher.kt:30-42`, `ssl/DynamicSSLManager.kt:499-508` | `applyTo` içinde `OkHostnameVerifier` zorla; README'de issuer pin = CA güveni + hostname notu |
| L-8 | HTTP CONNECT proxy ardında trust manager proxy portunu, interceptor URL portunu görür; `host:port` pinleri ve mTLS kimliği el sıkışmada eşleşmez (fail-closed, erişilebilirlik) | `ssl/DynamicSSLManager.kt:664,367` vs `PinnedConnectionInterceptor.kt:84` | `LiveSocketFactory.createSocket`'teki gerçek portu kaydet |
| L-9 | "En az 2 pin" kuralı farklı olmalarını istemiyor (`["A","A"]` geçer); demo-app'te yedek pin birincilin karıştırılmış kopyası | `ssl/PinConfigValidator.kt:88-93` | `toSet().size >= 2` |
| L-10 | `user_auth` vault dosyası: doğrulanmamış sunucu içeriği doğrulanmış kopyanın üzerine yazılıyor ve `confirmedAt` tazeleniyor; kilit açılınca imza tutmazsa silinir (kullanılabilirlik, TLS anahtarı seviyesinde saldırgan) | `internal/VaultFileRouter.kt:332-377` | Gölge slot; yalnızca doğrulanmış kopya için onay yaz |
| L-11 | E2E zarf imza kontrolünden **önce** çözülüyor ve hata metni sunucuya `failureReason` olarak gidiyor (zayıf OAEP kahini şekli) | `internal/VaultFileRouter.kt:184-187`, `PinVault.kt:1727` | Sabit hata dizgisi; şifreli metin üzerinde imza |
| L-12 | v2 vault kanonik dizgisi `configApiId` ve `key` içinde `:` varsa belirsiz | `crypto/ConfigSignatureVerifier.kt:126-127` | `:` yasakla veya uzunluk ön ekli v3 |
| L-13 | Config ve vault gövdelerinde boyut sınırı yok (`body.bytes()`), OOM | `api/DefaultCertificateConfigApi.kt:176,228` | Sınırlı okuma |
| L-14 | `EncryptedFileStorageProvider.getVersion` kimliği doğrulanmamış başlığı okuyor; yerel yazıcı güncellemeleri durdurabilir | `store/EncryptedFileStorageProvider.kt:150-162` | Doğrulanmış sürümü kullan |
| L-15 | `save()` istisnayı yutuyor, router yazılmamış kopya için `Updated` döndürüyor | `store/EncryptedFileStorageProvider.kt:87-90`, `VaultFileRouter.kt:259-266` | `save` fırlatsın |
| L-16 | API 24-29'da güçlü parmak izi yoksa kullanıcı-kimlik anahtarı 10 sn `TIME_BOUND`; prompt `CryptoObject`siz | `keystore/UserAuthKeys.kt:329-331`, `internal/UserAuthPrompt.kt:53-54` | KDoc'ta belgele; `USER_AUTH` için opsiyonel ret |
| L-17 | Keystore içe aktarmayı reddettiğinde P12 derleme sabiti `changeit` ile saklanıyor; ara dizilerin bir kısmı sıfırlanmıyor | `model/ConfigApiBlock.kt:70`, `PinVault.kt:1155,1868-1873` | Kurulum başına rastgele parola |
| L-18 | Host istemci sertifikası P12 indirmesinde `X-P12-SHA256` kontrolü yok (kayıtta var) | `api/DefaultCertificateConfigApi.kt:163-171` | Tutarlılık |
| L-19 | `enrolledLeaf` etiketin değil ilk bloğun parolasını kullanıyor | `PinVault.kt:1450` | Doğru bloğu seç |
| L-20 | İstisna metni tüm pinli host envanterini sızdırıyor (crash raporlarına gider) | `ssl/DynamicSSLManager.kt:788-791` | Yalnızca istenen host |
| L-21 | Bootstrap pinler `PinConfigValidator`'dan geçmiyor; bozuk giriş build zamanında değil "pin mismatch" olarak görünür | `model/ConfigApiBlock.kt:214` | `build()`'de doğrula |
| L-22 | Anahtar seti herhangi bir EC eğrisini kabul eder (secp192r1 dahil) | `crypto/ConfigSignatureVerifier.kt:71-82` | P-256/P-384 ile sınırla |
| L-23 | `enroll(context, token, label)` etiket ne olursa olsun varsayılan bloğa gidiyor | `PinVault.kt:1023-1049` | Düzelt veya belgele |
| L-24 | Sağlık kontrolü yeni pinleri değil bootstrap kanalını sınar; log satırı yanıltıcı | `ssl/SSLCertificateUpdater.kt:264-298` | Log metni |
| L-25 | Kayıt atestasyon challenge'ı deterministik (`SHA-256("pinvault-identity-key:v1:<deviceUid>")`), sunucu nonce'u yok; yakalanan zincir aynı anahtar için süresiz tekrar oynatılabilir | `keystore/ClientIdentityKeyProvider.kt:91-93` | Sunucu nonce'u karıştır |
| L-26 | Bağımlılıklar: kullanılmayan `okhttp3:logging-interceptor`; kullanımdan kaldırılmış `security-crypto` yalnız geçiş için ama Tink'i her uygulamaya taşıyor. Bilinen zafiyetli sürüm yok | `pinvault/build.gradle.kts:100,107` | Kaldır / opsiyonel artefakt |

**Bilgi:** `allowUnpinnedConfigApi()` açıkken cihaz-güvenilir CA'lı bir MITM, 403 `reenroll_required` ile `wipeVaultFilesOnRevocation` tetikleyebilir ve bekleyen kaydın anahtarını terk ettirebilir — KDoc'a bir cümle. Anahtar seti/anchor değişiminde filigran sıfırlanması kısa bir replay penceresi açar (bilinçli, belgeli; SECURE_OPERATIONS'a "rotasyondan hemen sonra taze config yayınla" notu).

### 4.2 Referans sunucu (`demo-server/`, `sample-host/`)

#### S-1 · Orta · Yönetim API'si cihaz portlarında da yayında
- `service/ConfigApiManager.kt:104-110`, `Main.kt:528-575`. Config API dinleyicileri (production profilde 6651/6652) `X-API-Key` kabul ediyor ve pin yazma (`PUT /certificate-config`), sertifika yükleme, `fetch-from-url`, `ping-remote`, `start-mock` sunuyor. Sızan paylaşılan anahtar internetten kullanılabilir; çevrimiçi tahmin yalnızca `ADMIN_AUTH_FAILURE_LIMIT` (30/10 dk/kaynak) ile sınırlı. Bilinçli ve `openapi.yaml:41`'de belgeli.
- **Öneri:** `CONFIG_API_ADMIN_ROUTES=off` (production compose'da varsayılan) ile cihaz portlarında yalnızca public rotalar.

#### S-2 · Orta · ACL yokken host'un mTLS özel anahtarı her kayıtlı cihaza veriliyor
- `route/CertificateConfigRoute.kt:548-566`: ACL yalnızca `deviceHostAclStore.isConfigured(configApiId)` ise uygulanıyor; değilse mTLS el sıkışmasını geçen her cihaz `hostClientCertStore.getP12(hostname)` alıyor. Anahtar host başına tek ve filo tarafından paylaşılıyor; cihazı iptal etmek anahtarı geçersiz kılmıyor. Kayıt koduyla giren bir cihaz (veya iptalden önce ele geçirilmiş telefon) scope'taki tüm mTLS host anahtarlarını toplayabilir.
- **Öneri:** Fail-closed (açık grant veya en az `deviceUidProven`), cihaz başına `host_client_cert_downloaded` denetim kaydı, iptal sonrası host sertifikası rotasyonu belgesi.

#### S-3 · Düşük–Orta · Vault indirmelerinde global bellek sınırı yok
- `route/VaultRoutes.kt:402,413-414,481` (tüm BLOB + çözülmüş kopya + `respondBytes`), kaynak başına eşzamanlılık 4, dosya sınırı 50 MB, `-Xmx`/`MaxRAMPercentage` yok, `mem_limit: 1g` ile varsayılan heap ~256 MB. 5-6 farklı kaynaktan eşzamanlı indirme → `OutOfMemoryError`, tüm dinleyiciler etkilenir.
- **Öneri:** Global `ConcurrencyLimiter`, `respondOutputStream` ile akış, `-XX:MaxRAMPercentage`, `public` için daha düşük varsayılan boyut.

#### Düşük seviye sunucu bulguları

| # | Bulgu | Kod |
|---|---|---|
| S-4 | İddia edilen `deviceUid` kurbanın cihaz kimliğini kilitler (`409 device_already_enrolled`), `X-Device-Id` ile kurbanın ACL filtreli pin listesi okunur. V20 sayesinde sırlar `deviceUidProven` ardında, etki DoS + bilgi | `route/CertificateConfigRoute.kt:293-302`, `route/ClientCertIdentity.kt:189-201` |
| S-5 | Tüm sunucu keystore'ları JKS (eski SHA-1 anahtar koruması; JDK bile PKCS12'ye geçti). İstemci CA anahtarı burada | `service/CertificateService.kt:219-222,701-703,1001-1003` |
| S-6 | Vault yükleme sürüm artışı oku-sonra-yaz; eşzamanlı iki yükleme aynı sürümü üretir, cihazlar sonsuza dek 304 alır | `store/VaultFileStore.kt:51-72` |
| S-7 | Önerilen ters proxy ardında tüm sınırlayıcılar ve "loopback güvenilir" kuralları proxy adresine çöker; 30 yanlış anahtar herkesi 10 dk kilitler | `plugin/ApiKeyAuth.kt:266-271,284`, `plugin/CleartextGuard.kt:45` |
| S-8 | Config API ve recovery dinleyicilerinde `StatusPages` yok; bare 500, `errorId` yok | `service/ConfigApiManager.kt:84-112`, `service/RecoveryListener.kt:68-76` |
| S-9 | TLS Config API'de `X-Device-Id` başka cihazın host ACL'ini saydırıyor | `route/CertificateConfigRoute.kt:589-612` |
| S-10 | Kalan `changeit` varsayılanları: `CLIENT_P12_PASSWORD`, yükleme formu; P12 ömrü sabit 365 gün | `service/P12Transfer.kt:31-32`, `route/HostRoutes.kt:256` |
| S-11 | Seri numaraları 63 bit (CA/B asgari 64); self-signed sunucu sertifikasında seri = `currentTimeMillis()`; atestasyon challenge'ında tazelik yok | `service/CertificateService.kt:1037,201`, `service/AndroidKeyAttestation.kt:472-483` |
| S-12 | `MANAGEMENT_HTTPS_PORT`'ta HSTS yok; tüm sırlar ortam değişkeni (`/proc/<pid>/environ`); `demo-server.pins` CWD'ye yazılıyor; `test-connection` JSON'u dizge birleştirmeyle | `Main.kt:739-749,307`, `route/HostRoutes.kt:433-441` |

**Açıkça kontrol edilip bulunmayanlar:** path traversal (`VAULT_KEY_REGEX`, `EncodedPathGuard`), token loglama, SSRF (`EgressFilter` tek çözümleme + kontrol edilen adrese bağlanma), SQL/LIKE enjeksiyonu (tamamı prepared statement), XSS (tüm değerler `esc()`, CSP `script-src 'self'`), IDOR (scope kontrolü, 128-bit istek kimlikleri), `X-Forwarded-For` güveni (hiç okunmuyor), API anahtarı zaman karşılaştırması (sabit zamanlı), kayıt token yarışı (tek koşullu `UPDATE`), CSR konu enjeksiyonu (konu yok sayılıyor, RDN'ler sunucuda kuruluyor).

### 4.3 Örnek uygulamalar

| # | Bulgu | Kod | Seviye |
|---|---|---|---|
| A-1 | `ProductionStyleClient` PinVault pinlerini `okhttp3.CertificatePinner`'a kopyalıyor; `requireCaTrust` yok, istek başına yeniden kontrol yok; objection `android sslpinning disable` doğrudan çalışır. Kütüphane yolu (`PinVault.applyTo`) bu betiklere dayanıklı | `sample-client/.../ProductionStyleClient.java:71-75` | Orta |
| A-2 | `demo-app`: yönetim portuna cleartext (`http://$HOST_IP:8090`), `allowUnsigned()` + `?signed=false`, `isMinifyEnabled=false`, koşulsuz `Timber.plant`, sahte yedek pin | `demo-app/.../network_security_config.xml:11-14`, `BaseDemoActivity.kt:44,113-115,398-401,681-686` | Orta (demo) |
| A-3 | Release'te `Log.w/e` korunuyor; pin özeti ve host hata metni logcat'e düşüyor | `sample-client/app/proguard-release.pro:11-15`, `ActionActivity.java:111` | Düşük |
| A-4 | `MockDns` ve mock-host düğmeleri release'te; token/sır `String` olarak heap'te kalıyor (belgeli) | `MockDns.java:23-27`, `VaultActivity.java:220-222` | Bilgi |

Git geçmişi: `.p12/.jks/.pem/.key` olarak yalnızca Google'ın açık atestasyon kökleri; tek `-----BEGIN PRIVATE KEY-----` geçici test anahtarı yazan bir test. Daha önce commitlenen `signing-key.pem` (SECURITY_AUDIT N-4) kaldırılmış, geçmiş yeniden yazılmamış (lab anahtarı).

---

## 5. İyi yapılanlar (doğrulandı)

1. **Her yerde fail-closed.** Null config, boş pin, bilinmeyen host, boş hostname, boş zincir, bootstrap pin yokluğu → `CertificateException`; sistem güvenine tek geçiş `allowUnpinnedConfigApi()` ve o da açık opt-in (`DynamicSSLManager.kt:760-792,596-602`).
2. **Pinleme sadece el sıkışmada değil.** Özel `X509ExtendedTrustManager` + her istekte `PinnedConnectionInterceptor` + pin değişiminde yeni `SSLContext` ve havuz boşaltma: keep-alive, HTTP/2 birleştirme ve TLS oturum devam ettirme ile pin bypass kapanıyor; bu aynı zamanda genel `SSLContext.init` hook'larını etkisizleştiriyor.
3. **Issuer pin doğru yapılmış.** `ChainPinMatcher` pinli sertifikayı tek anchor alarak PKIX doğruluyor; sahte leaf + gerçek intermediate reddediliyor ve test ediliyor.
4. **İmza ve replay modeli.** Tam bayt üzerinde imza, sabit `SHA256withECDSA`, kanonik anahtarla tekilleştirilmiş m-of-n, kurtarma/imza anahtarı ayrıklığı, yalnızca yükselen eşik, monoton anahtar seti sürümü, `reset()` ve rollback'i aşan filigranlar, 1 saat skew / 30 gün geçerlilik / 1M sürüm sıçraması sınırları, imzalı `configApiId` scope'u, fuzz testi.
5. **Depolama mühürleme.** AAD = dosya adı ‖ HMAC(namespace, key) + düz metin içinde mantıksal anahtar; Keystore IV'leri; "Keystore okunamıyor" asla "yok" olarak okunmuyor (`StoreUnreadableException`); backup/D2D hariç tutma kuralları tam ve testli.
6. **Kimlik yaşam döngüsü.** CSR ile kayıt, dışa aktarılamaz Keystore anahtarı, StrongBox öncelikli, zincir ≥2, anahtar eşleşmesi, CA pini veya aynı CA, 825 gün tavan; P12'ler dışa aktarılamaz içe aktarılıp siliniyor; imzasız 403 yalnızca o anda yüklü leaf'i sunan bağlantıdan geldiyse hüküm doğuruyor.
7. **Sunucu.** Sabit zamanlı API anahtarı, 256-bit CSPRNG token + SHA-256 + TTL + atomik tek kullanım, 125-bit kayıt kodu, `RevocationGate` ile CA anahtarı sızsa bile kayıt dışı üretilmiş sertifikanın reddi, atestasyon doğrulayıcısında paket+imzacı+verified-boot, iki kişilik onay, hash zincirli salt-ekle denetim kaydı, HMAC webhook, sıkı CSP, `Sec-Fetch-Site` CSRF, production compose'da non-root / `cap_drop: ALL` / salt okunur kök / digest sabitli imajlar ve her başlangıçta demo anahtarlarının kapalı olduğunun yeniden kontrolü.
8. **Dürüst dokümantasyon.** Sınırlar (`VaultFileGuard`, `TrustedClock`, `expiryNow`, `verifyPinnedConnection`, README "does NOT do", DEXPROTECTOR "test edilmedi") abartılmadan yazılmış.

---

## 6. Approov Dynamic Certificate Pinning ile karşılaştırma

### 6.1 Approov nasıl çalışıyor (birincil kaynaklardan)

- Pinler uygulama paketinde değil **Approov bulutunda** tutuluyor; SDK her atestasyonda (uygulama aktifken ~5 dakikada bir) en güncel pin setini alıyor; CLI'den yapılan pin değişikliği en geç 5 dakikada yayılıyor.
- Dinamik SDK yapılandırması (pinler dahil) hesaba özel **ECC özel anahtarıyla imzalı**; açık anahtar ilk yapılandırma dizgesinde; yerel depoya yazılıp bir sonraki token alımında devreye giriyor.
- Pinler ve API sırları **yalnızca atestasyonu geçen** (bozulmamış uygulama, bozulmamış cihaz) örneklere teslim ediliyor. Varsayılan ret politikası root/jailbreak, emülatör ve cloner uygulamalarını reddediyor; debugger, Frida/Xposed/DobbyHook hooking, bellek kurcalama ve yeniden paketleme tespitleri var; bayraklar hesap bazında özelleştirilebiliyor.
- Backend her istekte kısa ömürlü (5 dk + tolerans) imzalı **Approov-Token** JWT'si bekliyor. Approov'un iddiası: Frida ile pinleme bypass edilse bile saldırgan geçerli token alamaz, API cevap vermez.
- **Managed Trust Roots:** cihazın güven deposu yerine Approov'un yönettiği kök seti; OkHttp servis katmanında `"*"` wildcard pinleri olarak geliyor ve pinsiz hostlar için varsayılan oluyor.
- OkHttp entegrasyonu (`approov-service-okhttp`, açık kaynak): `Approov.getPins("public-key-sha256")` → `CertificatePinner.Builder.add(domain, "sha256/"+pin)`; `isConfigChanged()` olunca `fetchConfig()` + `rebuildPins()`; ağ interceptor'ı; SSL hatasında soketi kapatıp hatayı fırlatıyor; doğrulanmış el sıkışmaları (en çok 10) önbellekliyor. Pinleme kontrolünün kendisi **standart `okhttp3.CertificatePinner`**.
- Ticari, kapalı kaynak SaaS. MAU bazlı fiyat: Aspire (10k), Launch (100k), Velocity (1M MAU, AWS Marketplace'te 10.000 USD/ay), Enterprise. Android, iOS ve çapraz platform (Flutter, React Native vb.) quickstart'ları var.

### 6.2 Özellik karşılaştırması

| Boyut | PinVault (2.2.0 dalı) | Approov Dynamic Pinning |
|---|---|---|
| Güven kökü | Kendi sunucunuz + APK'ya gömülü ECDSA açık anahtar(lar) | Approov bulutu + yapılandırma dizgesindeki ECC açık anahtar |
| Pin dağıtım kanalı | Bootstrap pinli, fail-closed kendi Config API'niz | Approov atestasyon kanalı |
| Pin config bütünlüğü | ECDSA imza, `issuedAt`/`expiresAt`, replay filigranı, 30 gün tavan, **m-of-n**, **çevrimdışı kurtarma anahtarıyla rotasyon/iptal**, `serverScope` | ECDSA imza (hesap başına anahtar). m-of-n / anahtar rotasyonu müşteri tarafında yok (Approov yönetir) |
| Pin yayılma gecikmesi | WorkManager aralığı (≥15 dk, varsayılan saatler) + pin uyuşmazlığında anında kurtarma + `forceUpdate`; config TTL 24 sa | ≤5 dk (aktif uygulamada) |
| Uygulama zorlaması | Özel `X509ExtendedTrustManager` + **istek başına** yeniden kontrol + yeni `SSLContext`; genel bypass betiklerine dayanıklı, hedefli hook'a değil | Standart `okhttp3.CertificatePinner` (genel bypass betikleri etkiler) + atestasyon |
| CA ile birlikte pin | `requireCaTrust` (platform CA + pin), issuer pin | Managed Trust Roots (Approov yönetimli kök seti) |
| **Çalışma zamanı bütünlüğü (RASP)** | **Yok** (belgeli kapsam dışı); DexProtector rehberi test edilmemiş | Root, emülatör, debugger, Frida/Xposed/Dobby, cloner, bellek kurcalama, yeniden paketleme; 5 dk'da bir yeniden ölçüm |
| **Backend tarafında istek doğrulama** | mTLS istemci sertifikası (Keystore anahtarı). Rootlu cihazda anahtar imza kahini olarak kullanılabilir; sertifika "cihaz" der, "bozulmamış uygulama" demez | Her istekte kısa ömürlü Approov-Token; token yalnızca atestasyon geçince üretilir |
| Cihaz kimliği | Keystore EC P-256 + **Android key attestation** (donanım köküne kadar, paket+imzacı+verified boot) — yalnızca kayıt anında, sunucu enforce ederse | Approov'un kendi yazılım ölçümü (donanım atestasyonu değil), süreklilik var |
| Pin bypass'a karşı iddia | Bypass edilirse backend bunu fark etmez (mTLS dışında) | Bypass edilse bile token yok → API reddeder |
| Çevrimdışı davranış | Saklı config `expiresAt`'e kadar; `expiredConfigGrace` opsiyonel; `forceUpdate` ile fail-closed | Saklı yapılandırma; token alınamazsa istek başarısız (mutator ile gevşetilebilir) |
| Ek yetenekler | mTLS kayıt/yenileme, kayıt kodları, onaylı kayıt, vault dosya dağıtımı, cihaz başına şifreleme, ekran kilidine bağlı dosyalar, iptalde silme, HSM/KMS imzacı, iki kişilik onay, denetim kaydı, webhook | Runtime secrets (API anahtarlarını uygulamadan çıkarma), header/query ikame, cihaz bazlı politika ve iptal, telemetri paneli |
| Platform | Android (minSdk 24) | Android, iOS, çapraz platform |
| Operasyon modeli | Self-hosted; Docker referans sunucu; veriler sizde | SaaS; üçüncü taraf bağımlılığı; CLI |
| Lisans/maliyet | Apache 2.0, ücretsiz | MAU bazlı; 1M MAU ≈ 10k USD/ay |
| Kaynak kodu | Tamamen açık, denetlenebilir | SDK kapalı; servis katmanları açık |

### 6.3 Farkın özü

1. **PinVault'un güçlü olduğu yer: kanal ve dağıtım güvenliği.** İmzalı config etrafındaki replay/süre/filigran/m-of-n/kurtarma anahtarı modeli, Approov'un müşteriye sunduğundan daha zengin ve tamamen sizin kontrolünüzde. Pinleme kontrolü de Approov'un kullandığı `CertificatePinner`'dan daha dayanıklı (istek başına yeniden kontrol, genel bypass betiklerine bağışıklık). mTLS kimliğinin donanım atestasyonlu Keystore anahtarına bağlanması, Approov'un sunmadığı bir şey.

2. **Approov'un güçlü olduğu yer: "pinleme bypass edildikten sonra" katmanı.** Approov'un ürün tezi pinlemenin rootlu bir cihazda her zaman atlatılabileceğini kabul edip savunmayı iki yere taşımak: (a) pinleri yalnızca bütünlüğü ölçülmüş uygulamaya vermek, (b) backend'i her istekte kısa ömürlü token'a bağlamak. PinVault'ta bu katman yok. Bu bir **açık değil, kapsam farkı**; ama ürün kıyaslamasında kullanıcının "pin bypass'a karşı dayanıklılık" olarak algıladığı şey tam olarak bu.

3. **Kayıt zamanı atestasyonu ≠ çalışma zamanı atestasyonu.** PinVault'un key attestation'ı "bu anahtar bu cihazın donanımında, bu paket tarafından üretildi" der; kayıt sonrası Frida, root, repack hakkında hiçbir şey söylemez ve challenge'ta sunucu nonce'u yoktur. Approov her 5 dakikada ölçer.

4. **Bağımlılık ve maliyet.** Approov üçüncü taraf bir buluta sürekli bağımlılık ve MAU faturası getirir; PinVault sıfır lisans maliyetiyle self-hosted çalışır ve kaynak denetlenebilir. Yüksek değerli hedeflerde iki yaklaşım birbirinin alternatifi değil tamamlayıcısıdır: PinVault'un kanal güvenliği + bir RASP/atestasyon ürünü (Approov, Play Integrity + sunucu kararı, DexProtector).

### 6.4 Farkı kapatmak için en kısa yol (PinVault tarafında)

| Adım | Etki | Maliyet |
|---|---|---|
| `consumer-rules.pro`'dan `-keepnames` kaldır | Frida hedefleri haritasını sil | Çok düşük |
| Örnek uygulamaya `IntegrityGate`: debugger, debuggable, imza özeti, temel root; `init`/kayıt/unlock öncesi | Düşük çıtalı bypassları durdur | Düşük |
| Kayıt challenge'ına sunucu nonce'u | Atestasyon tekrarını kapat | Düşük |
| Sunucu tarafında kayıt + periyodik güncellemede **Play Integrity** kararı; mTLS sertifikasına "integrity-ok" ömrü bağla | Approov'un "token" katmanının Google eşdeğeri | Orta |
| `ProductionStyleClient`'ı `PinVault.applyTo` ile değiştir | Genel bypass betiklerine bağışıklık | Düşük |
| DexProtector (veya eşdeğeri) rehberini gerçekten test et ve belgele | RASP boşluğunu kapat | Orta |
| Pin yayılma süresini kısalt: `updateIntervalMinutes(15)` + `forceUpdate` + sunucu webhook'u ile push tetikleyici | Approov'un 5 dk'sına yaklaş | Düşük |

### 6.5 Bu dalda yapılan: Approov'un çalışma mantığı PinVault'a taşındı

Rapordan sonra aynı dalda, Approov'un üç katmanı birebir aynı mantıkla
kuruldu; sözleşme [ATTESTATION.md](ATTESTATION.md)'de.

| Approov | PinVault karşılığı (bu dal) |
|---|---|
| SDK uygulamayı ve cihazı ölçer (root, emülatör, debugger, hooking, klon, bütünlük) | `integrity/DeviceIntegrityProbe`: 12 sinyal, kanıt listeleriyle; `IntegrityVerdictProvider` SPI ile Play Integrity ikinci görüş |
| Ölçüm Approov bulutuna gider, her ~5 dakikada tekrarlanır | `POST /api/v1/attest`: nonce + Keystore kimlik anahtarıyla imzalı rapor; `AttestationManager` `min(nextAttestIn, aralık, token−60 s)` ile yeniler, WorkManager arka planda da |
| Pinler yalnızca geçen uygulamaya verilir | İmzalı config atestasyon yanıtının içinde gelir (`applySigned`), kalan cihaz config almaz; cihaz anahtarı ilk kayıtta Android key attestation ile bağlanır (`ATTESTATION_KEY_POLICY`) |
| Kısa ömürlü Approov-Token, backend doğrular | `PinVault-Token` (HS256 JWT, 5 dk, `aud`=Config API, `anno`); kütüphane başlığı token host'larına ekler; `PinVaultTokenAuth` Ktor eklentisi + Node/Python/Java örnekleri; mock host `MOCK_HOST_REQUIRE_TOKEN` |
| Ret politikası bayrak bayrak özelleştirilir; cihaz ek açıklamaları; ARC | Config API başına politika (`reject/warn/ignore` × 12 bayrak, strict/lenient), `forcePass/forceFail/annotations`, 8 karakterlik ARC, `revealReasons` |
| Managed Trust Roots | `trustRoots` imzalı config alanı + `managedTrustRoots()`: pinsiz host için platform doğrulaması + listelenen kök + host adı. Sunucu tarafı: `pin_config.trust_roots` (V22), pin kurallarıyla doğrulama (format, tekrar yok, en fazla 64), boşken payload'da yok (eski istemci yeni alan görmez), `PUT /api/v1/certificate-config` alan gönderilince listeyi değiştirir / gönderilmeyince korur, `trust_roots_updated` geçmiş + denetim olayı, panelde Config API "Genel" sekmesinde düzenleme (`TrustRootsTest`) |
| Yönetim: CLI + panel | Panel sekmesi (politika, cihazlar, istatistik, token sırları) + yönetim API'si + denetim kaydı/webhook olayları |

Kalan fark, mimari değil kalite ve güvence farkıdır: Approov'un probe'ları
kapalı kaynak ve kendini denetleyen, sürekli güncellenen imzalarla gelir;
PinVault'unkiler düz Kotlin'dir (R8 + gerekirse packer önerilir) ve
cihazdan bağımsız bir karar için Play Integrity sağlayıcısı takılmalıdır.
Buna karşılık PinVault'un cihaz kimliği donanım atestasyonlu Keystore
anahtarına bağlıdır, her şey self-hosted ve açık kaynaktır.

---

## 7. Öncelikli düzeltme listesi

**Hemen (kod, küçük) — bu dalda uygulandı:**

| Bulgu | Yapılan |
|---|---|
| L-1 TrustedClock | Kod değişmedi, **belgelendi** (README "What the clock cannot tell"). Daha derin analiz: yakalanmış-ama-görülmemiş imzalı zarf ile "saati ileri kaçmış cihazın tazelenmesi" cihaz tarafında ayırt edilemiyor; sıçrama kredisi, eşik veya önceki config süresi gibi her kural ya saldırıya da izin veriyor ya da meşru düzeltmeyi bozuyor. Gerçek azaltımlar: kısa `CONFIG_TTL_SECONDS` ve Config API host'u için `requireCaTrust` (sızan eski anahtar CA'dan geçmez). |
| L-5 / L-6 | `buildDynamicClient` → `followSslRedirects(false)`; bootstrap istemcisi → `followRedirects(false)` + `followSslRedirects(false)` |
| L-7 | `applyTo`'da verifier ezmek yerine (uygulamanın kendi verifier'ı ve SAN'sız test sertifikaları kırılırdı) kontrol kütüphanenin içine alındı: `matchPins` issuer pini eşleştiğinde leaf'in SAN'ını `OkHostnameVerifier` kurallarıyla host'a karşı doğrular; yeni `HostnameMismatchException`, kurtarma interceptor'ı için refetch dışı. Leaf pini için ad kontrolü yok (pin = kimlik). Test: `ChainPinMatcherTest` |
| L-9 | `PinConfigValidator`: `toSet().size >= 2`. `HostPin` kurucusu değişmedi (testler aynı pini iki kez kullanıyor). Test: `PinConfigValidatorTest` |
| L-3 | `consumer-rules.pro`'dan `-keepnames` kaldırıldı; gerekçe yorumda |
| A-1 | `ProductionStyleClient` artık `CertificatePinner` kurmuyor; PinVault'u import etmeden `PinningInstaller` geri çağrısı alıyor, `App` ona `PinVault::applyTo` veriyor; kendi recovery interceptor'ı kaldırıldı (kütüphaneninki geliyor) |
| S-2 | `HOST_CLIENT_CERT_REQUIRE_GRANT` (varsayılan kapalı; üretim profili `true` sabitler ve `entrypoint.sh` denetler). Test: `HostClientCertAclTest` |
| S-3 | `VAULT_DOWNLOAD_CONCURRENCY_TOTAL` (varsayılan 16) toplam eşzamanlılık sınırı; her iki Dockerfile `JAVA_OPTS=-XX:MaxRAMPercentage=60` |

Doğrulama: demo-server bu ortamda JDK 17 ile derlendi ve ilgili testler koşturuldu (sonuç commit mesajında); atestasyon ve yönetilen kök katmanının sunucu testleri (`AttestationRoutesTest`, `AttestationAdminRoutesTest`, `PinVaultTokenTest`, `AttestationPolicyTest`, `PinVaultTokenAuthTest`, `TrustRootsTest`, `DashboardGovernanceLabelsTest`, `AuditCoverageTest`) geçiyor. Kütüphane ve örnek uygulama **derlenemedi** (Android SDK yok, `dl.google.com` engelli); bu değişiklikler Android SDK'lı bir ortamda `./gradlew :pinvault:testDebugUnitTest` ve `sample-client` derlemesiyle doğrulanmalı.

**Kısa vade — bu dalda uygulananlar:** L-2 Keystore seviyesi raporlama + `requireHardwareBackedKeys()` (`KeySecurityLevel`, `HardwareBackedKeyRequiredException`) · S-1 `CONFIG_API_ADMIN_ROUTES=off` (üretim profili sabitler) · L-25/S-11 nonce: atestasyon protokolü her turda sunucu nonce'u imzalatır (kayıt challenge'ı değişmedi; cihaz anahtarı artık her 5 dakikada taze bir nonce'la kanıtlanıyor) · L-3 RASP: `integrity/` probe'ları ve atestasyon katmanı (bkz. 6.5).

**Kısa vade — açık kalanlar:** S-5 PKCS12 keystore · L-10/L-11 vault doğrula-sonra-yaz · L-13 gövde boyutu sınırı · A-2 demo-app release korkuluğu.

**Belgeleme:** L-4 rollback sınırı README'ye · anahtar rotasyonunda replay penceresi · `allowUnpinnedConfigApi` yan etkileri · issuer pin = CA güveni notu · kayıt atestasyonunun neyi kanıtlamadığı.

---

## 8. Kaynaklar

PinVault: bu depo, commit `a5204d5`; `README.md`, `SECURITY_AUDIT.md`, `SECURE_OPERATIONS.md`, `SERVER_IMPLEMENTATION_GUIDE.md`, `sample-client/DEXPROTECTOR.md`.

Approov (approov.io ve ext.approov.io bu ortamdan erişilemedi; arama motoru özetleri ve GitHub):
- [Dynamic Certificate Pinning](https://approov.io/mobile-app-security/rasp/dynamic-cert-pinning/)
- [How Approov Dynamic Certificate Pinning Works](https://approov.io/blog/approov-dynamic-pinning)
- [How Approov Managed Trust Roots and Dynamic Pinning Eliminate MitM Threats](https://approov.io/knowledge/how-approov-managed-trust-roots-and-dynamic-pinning-eliminate-man-in-the-middle-threats)
- [How to Protect Against Certificate Pinning Bypassing](https://approov.io/blog/how-to-protect-against-certificate-pinning-bypassing)
- [Frida Detection & Prevention](https://approov.io/knowledge/frida-detection-prevention)
- [Approov CLI Reference](https://ext.approov.io/docs/latest/approov-cli-tool-reference/) · [Approov Release Notes](https://ext.approov.io/docs/latest/changelog/)
- [Approov Security and Compliance (PDF)](https://approov.io/hubfs/download/Approov-Security-and-Compliance.pdf)
- [approov/approov-service-okhttp — ApproovService.java](https://github.com/approov/approov-service-okhttp/blob/main/approov-service/src/main/java/io/approov/service/okhttp/ApproovService.java) · [REFERENCE.md](https://github.com/approov/approov-service-okhttp/blob/main/REFERENCE.md)
- [approov/quickstart-android-kotlin-okhttp](https://github.com/approov/quickstart-android-kotlin-okhttp/blob/master/README.md)
- [Approov Pricing](https://approov.io/pricing/) · [AWS Marketplace — Velocity Plan](https://aws.amazon.com/marketplace/pp/prodview-nv6dnr6ev3k4i) · [MAU tanımı](https://approov.io/knowledge/what-is-a-monthly-active-user-mau-how-does-approov-billing-work)
- [OWASP MASTG-TECH-0012: Bypassing Certificate Pinning](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/)
