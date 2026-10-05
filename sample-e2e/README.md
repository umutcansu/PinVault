# sample-e2e

[sample-host](../sample-host) ile [sample-client](../sample-client) arasında uçtan uca testler. Her senaryo web dashboard'unda gerçek bir tarayıcıyla işlem yapar ve sonucunu Android uygulamasının ekranında doğrular, ya da tersini yapar.

- **Web tarafı:** Playwright, dashboard'u (`http://localhost:6650`) ekransız (headless) Chromium'da kullanır. Sayfadaki öğeler, arayüz dilinden bağımsız `data-action` öznitelikleriyle bulunur.
- **Mobil tarafı:** adb, uygulamaya bir kullanıcı gibi dokunur, yazı yazar ve ekrandaki metni UI Automator dökümünden okur. Uygulamaya test kodu gömülmez.
- **Ağ trafiği ve cihaz:** saldırgan proxy (`lib/proxy.js`) telefonla host arasına girip trafiği değiştirebilir; `run-as` ile uygulamanın şifreli depoları okunur. Bu kanıtlar rapora metin paneli olarak girer. Trafiği yalnızca gözleyen adımlar `Ağ trafiği:`, saldırgan proxy'nin devrede olduğu adımlar `Saldırgan:` önekiyle başlar.
- **Kanıt:** Her adımda web ve telefon ekran görüntüleri rapora ve tek dosyalık kanıt sayfasına eklenir; sayfanın başında kapsam matrisi (özellik → senaryo → durum) durur.

Kapsam planı ve senaryo listesi: [PLAN.md](PLAN.md).

## Senaryolar

| # | Ne doğrulanır |
|---|---|
| 1 | Telefondaki pinli istek, dashboard'da "Bağlı Cihazlar" ve "Bağlantı Geçmişi" kartlarında aynı pin sürümüyle görünür. |
| 2 | Web'de yedek pin eklenince sürüm artar, telefon yeni sürümü alır ve iki client da bağlanır. Pin kaldırılınca döngü tekrar eder. |
| 3 | Web'de yanlış pin girilince telefon bağlantıyı reddeder, uyuşmazlık dashboard'a düşer. Pin'ler düzeltilince telefon elle yenilemeden toparlanır. |
| 4 | Force update açıkken telefon config'i sürüm değişmese de yeniden uygular; kapatılınca normale döner. |
| 5 | PinVault'u import etmeyen production-style client (pinlemeyi `PinVault::applyTo` geri çağrısıyla takar) da yanlış pin'i reddeder ve kütüphanenin kurtarma interceptor'ıyla toparlanır. |
| 6 | Host kapalıyken ilk açılışta uygulama başlatılamadığını söyler ve istek yapılmasına izin vermez. Host dönünce "Tekrar dene" ile toparlanır. |
| 7 | Host kapalıyken sonraki açılışta uygulama saklı config ile açılır ve hedefe pinli bağlanır. |
| 8 | Web'de host silinince telefon o host'a bağlanmaz. Geri eklenince sürüm kaldığı yerden devam eder ve bağlantı döner. |
| 9 | Web'de bütün host'lar silinince sunucu boş config yayınlar; telefon bunu reddedip eski config'le çalışır. |
| 10 | Web'de hatalı biçimli pin reddedilir, başarı mesajı çıkmaz, telefon etkilenmez. |
| 11 | Web'deki değişiklik, uygulamada hiçbir şeye dokunmadan WorkManager'ın periyodik göreviyle telefona ulaşır. Yalnızca emülatör. |
| 12 | Web'de kayıt token'ı üretilir, telefon onunla kayıt olur, sertifika dashboard'da görünür, mTLS bağlantısı geçer. Web'de iptal edilince aynı bağlantı reddedilir. |
| 13 | Web'de yüklenen dosya telefonda iner, içerik imzası doğrulanır, indirme dağıtım geçmişinde görünür. Güncellenince yeni sürüm gelir. |
| 14 | Gizli dosya (mTLS + token_mtls + user_auth): cihaz kayıtlı ve telefonda ekran kilidi varken token olmadan inmez; bu cihaz için üretilen token'la iner ama içerik gösterilmez; "Aç" ekran kilidini sorar, PIN girilince içerik görünür; token iptal edilince yine reddedilir. |
| 15 | Gizli, cihaza özel şifreli dosya (mTLS + token_mtls + end_to_end): telefon cihaz anahtarıyla çözer, ekran kilidi anahtarıyla yeniden kilitler; içerik yalnızca "Aç" + ekran kilidiyle görünür. Şifrelemeyi sunucu yapar, yani içeriği sunucu görür. |

Yeni senaryolar PLAN.md'deki gruplara göre eklenir: sıfırdan kurulum (K), pin yönetimi ve imzalı config (A), mTLS (B), vault (C), telefonda şifreli saklama (D), sunucu işletimi (E), sunucuya ulaşılamadığında (F), araya girme saldırıları (G), kendi sunucusuyla ya da sunucusuz kullanım (H), imza anahtarlarının korunması (S, isteğe bağlı), değişiklik denetimi ve onay (Y, isteğe bağlı), sürüm yükseltme (U). Dosya adı grup harfiyle başlar (`K01-…`, `E03-…`); kanıt sayfası grubu buradan okur.

| Grup | Ne doğrulanır |
|---|---|
| K01–K07 | Sıfırdan kurulum: gereksinimler, `setup.sh`, compose + Flyway + smoke-test, dashboard'un ilk açılışı ve API anahtarını sorması, Config API sekmeleri, host ekleme dört yolla, mTLS API ve test için kurulan hedef sunucular (mock host), vault yükleme, istemci değerleri + derleme + telefonun ilk bağlantısı, Swagger/TR-EN/sayfalama. Adım adım anlatım: [SETUP.md](SETUP.md). |
| E01–E10 | Sunucu işletimi: imzalama anahtarının diskte şifrelenmesi, yetkilendirme ve anahtarsız (anonim) mod, sunucu sertifikasının yenilenmesi ve saklı yedek anahtara geçiş, sertifika süresi izleme, Config API'yi açma/durdurma/silme, pin geçmişi ve sürümün geri gitmemesi (watermark), cihaz raporları (telemetri) ve cihaz listeleri, Docker down/up sonrası verilerin kalması, `wantPinsFor` + cihaz bazlı host izin listesi. |
| A16–A31 | Pin yönetimi ve imzalı config: tek pin'li ya da aynı pini iki kez yazan host reddi (en az 2 farklı pin kuralı), joker alan adı eşleşmesi (`*.example.com` geçer, `*.com` yok sayılır), config'in geçerlilik süresi (kısa TTL + cihaz saati ileri → "expired"), imzalama anahtarının değiştirilmesi (rotasyon), mock host'ta gerçek sertifika yenileme, CA (ara sertifika) pini ve gerçek CA'yı sahte sertifikanın arkasına ekleyen saldırganın reddi, özel bağlantı ayarlı istemci (otomatik kurtarma yok), `reset()` + init'in iki kez çağrılmasına karşı koruma, cihaz raporu (telemetri) seçenekleri. |
| F01–F03 | Sunucuya ulaşılamadığında: zorunlu güncelleme işaretliyken sunucuya ulaşılamazsa açılış başarısız, otomatik kurtarmanın yeniden deneme freni (3 hatadan sonra 10 dk denemez), cihaz raporlarının gittiği port (Config API) kesikken pinli isteklerin akıcı kalması ve uygulamanın saklı config ile çalışması. |
| S01–S06, G09 | İmza anahtarlarının korunması (isteğe bağlı): APK'da tanımlı, çevrimdışı saklanan yedek anahtara uygulama güncellemesi olmadan geçiş; kurtarma anahtarıyla imzalı anahtar seti (telefonun güvendiği imza anahtarlarının listesi) ile anahtar değiştirme (rotasyon) ve iptal; çoklu imza (en az 2 imza şartı; config ve vault); HSM (SoftHSM, PKCS#11) ve harici komutla (KMS benzeri) imzalama; imza önbelleği ve aynı config'in "güncel" sayılması; saldırganın yanıta eklediği sahte anahtar setinin reddi (G09). |
| U01 | Sürüm yükseltme: önceki sürüm (örnek uygulamanın main dalı, Maven Central'daki PinVault) temiz kurulur, güncel sunucuya karşı hazır olur, kayıt olur ve bir vault dosyası indirir. Güncel APK üstüne kurulunca (`adb install -r`) yeni sürüm saklı config'i okur, eski sürümün sertifikasıyla mTLS bağlantısı geçer, eski sürümün indirdiği dosya güncel sayılır, eski sürümün planladığı arka plan işi yeni kodla çalışır. |
| Y01–Y04 | Değişiklik denetimi ve onay (kim, neyi, kimin onayıyla değiştirdi): kişiye özel yönetici anahtarları, denetim kaydı ve webhook bildirimi (paylaşılan gizli anahtarla imzalı, HMAC), sonradan değiştirilirse fark edilen denetim kaydı (kayıtları birbirine bağlayan hash zinciri), iki kişi onayı (bekleyen istek, kendi isteğini onaylayamama, onay, ret, eskimiş istek), canlı sertifika kontrolü (engelleme modu `enforce`, uyarı modu `warn`, gerekçe yazıp yine de kaydetme). |

**Geçici test sunucusu (ikinci host örneği):** K ve E'nin yıkıcı adımları (sıfırdan kurulum, sertifika yenileme, Config API silme, down/up) ana host'u bozmasın diye `lib/freshHost.js` sample-host'un bir kopyasını `.local/host-fresh` altında, 6650–6656 yerine **6750–6756** portlarında ve `pinvault-host-fresh` container'ıyla kurar. Koşu sonunda `docker compose down -v` ile tamamen silinir. Telefon bu sunucuya yalnızca K06, E03, E10, A19 ve S01–S05'te bağlanır: bu senaryolar uygulamayı geçici sunucunun değerleriyle derleyip kurar, sonunda ana host'un değerleriyle derlenmiş uygulamayı geri kurar. Y02 bu sunucuyu yalnızca web tarafında kullanır.

## Gereksinimler

- Host ayakta ve hazırlanmış: `cd ../sample-host && docker compose up -d && ./scripts/provision.sh`. Kurulum aşaması provision'ı zaten çağırır.
- Bir Android cihaz: USB ile bağlı telefon ya da bir emülatör AVD'si. Saat, iptables ve root gerektiren senaryolar yalnızca emülatörde çalışır.
- Node 18+ ve Docker CLI (bazı senaryolar host container'ını durdurup başlatır ya da ortam değişkenlerini geçici değiştirir).
- İstemciyi derlemek için JDK 17 (JAVA_HOME yoksa Android Studio'nun ya da `~/Library/Java` altındaki JDK aranır).
- Araya giren proxy için host'un anahtarı: `cd ../sample-host && ./scripts/export-server-key.sh`.

## Çalıştırma

```bash
npm install
npm test                    # bağlı cihazda
npm run test:emulator       # cihaz yoksa AVD'yi ekransız açar, bitince kapatır
npm run report              # Playwright'ın HTML raporu
npm run evidence            # tek dosyalık kanıt sayfası
npm run check-evidence      # kanıt sayfası denetimi (kanıtsız adım, tekrar görüntü, gizli değer)
```

Tek bir senaryo için: `npx playwright test tests/12-mtls-enroll-and-revoke.spec.js`.

Kurulum aşaması şunları yapar:

1. Host'un sağlığını ve `.env`'deki API anahtarını kontrol eder, `scripts/provision.sh` ile mTLS Config API'sini, host'un kendi pin kaydını ve mock hedef host'ları açar.
2. Cihaz yoksa ve `E2E_AVD` verilmişse emülatörü salt-okunur açar. AVD'ye kalıcı hiçbir şey yazılmaz.
3. Host değerlerini `.local/sample-host.properties` dosyasına yazar: IP, cihazların bağlandığı portlar, Config API kimlikleri, uygulamaya gömülen ilk pin'ler (bootstrap), imza anahtarları, hedefin canlı pin'leri, özel backend anahtarları. İstemciyi bu dosyayla derleyip kurar. İmza anahtarları sunucunun birincil anahtarı (`GET /api/v1/signing-key`) ile çevrimdışı yedek anahtar `.local/offline-keys/backup-1`'dir; kurtarma anahtarı `recovery-1`. Bu çevrimdışı anahtarlar bir kez üretilir ve koşular arasında korunur, yoksa APK her koşuda yeniden derlenirdi.
4. Sunucuyu temel duruma getirir.

Her test host'u ayağa kaldırıp sunucuyu temel duruma döndürerek ve uygulamanın verisini silerek başlar; bitince yine temel duruma döndürür. Vault senaryoları yükledikleri dosyaları siler. Pin değişiklikleri host sürümünü her seferinde artırır; istemciler eski sürüme geri dönmeyi reddettiği için geri alma da her zaman yeni bir sürümle yapılır.

## Kanıt sayfası

Her koşu `evidence/index.html` dosyasını yeniden üretir. En üstte kapsam matrisi, sonra gruplara ayrılmış senaryolar; senaryo başına adımlar, web ve telefon ekran görüntüleri, metin panelleri (terminal çıktısı, ağ trafiğindeki ham veri, cihaz dosyaları) ve süreler. Görüntüler dosyanın içine gömülüdür; tek başına açılır ve paylaşılabilir. Görüntüye tıklayınca büyür. Başarısız bir senaryoda tarayıcının yanında telefonun hata anındaki ekranı da eklenir. Sayfanın başındaki "Nasıl okunur" notu rozetleri, 📱/🌐/📄 işaretlerini ve matrisi açıklar.

`npm run check-evidence` sayfayı ayrıştırıp kanıtsız adımları (ne görüntü ne panel), görüntüsüz senaryoları, bayt bayt aynı görüntünün birden fazla yerde kullanılmasını ve tam uzunlukta token/anahtar dizilerini (bilinen gizli değerler dahil) listeler; sıfır bulguda 0 ile çıkar.

## Ayarlar

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `ANDROID_SERIAL` | ilk bağlı cihaz | Birden fazla cihaz varsa hangisi |
| `E2E_AVD` | yok | Cihaz yoksa açılacak AVD |
| `E2E_ANDROID_ID` | adb'den okunur | Uygulamanın ANDROID_ID'si: kayıt token'ları varsayılan olarak buna bağlanır (panelde "Cihaz kimliği"). Emülatörde kendiliğinden okunur (API 26+ root ile `settings_ssaid.xml`, shell'in `settings get secure android_id` değeri uygulamanınki değil); gerçek telefonda uygulamanın mTLS ekranındaki "Cihaz kimliği" verilir |
| `E2E_KEEP_EMULATOR` | yok | `1` ise açılan emülatör test sonunda kapatılmaz |
| `E2E_SKIP_BUILD` | yok | `1` ise istemci derlenmez (host değerleri değişmediyse) |
| `E2E_VARIANT` | `debug` | `e2e`: uygulamanın `e2e` derleme türü test edilir (`./gradlew :app:assembleE2e`): release ile aynı R8 küçültmesi, aynı keep kuralları ve aynı paket adı; üstüne test kontrolleri, debug anahtarıyla imzalı. Teşhis log'ları `-Psample.diagnosticLogs=true` ile açık; uygulama verisi run-as yerine emülatörün su'suyla okunur, yani yalnızca emülatör. Gerçek `release` türü test edilmez: test kontrolleri onda yoktur, test bayraklarıyla derlenmez ve yayın anahtarı ister (`release` değeri eski addır, `e2e` sayılır) |
| `E2E_OLD_CLIENT_REF` | `sample-client-2.0.9` | U01'de önceki sürüm olarak kurulan örnek uygulama (etiket, dal ya da commit); kütüphane sürümü oradaki `pinvault.version` |
| `E2E_TARGET_HOST` | `sample-host/.env`'deki `TARGET_HOST`, yoksa `www.example.com` | Pin'leri değiştirilen hedef |
| `E2E_TARGET_REQUIRE_CA_TRUST` | `true` | `false`: hedefin sertifikası herkesin güvendiği bir CA'dan değil; uygulama `requireCaTrust` istemez ve host'un `client-config.sh` betiği `--target-private-ca` ile çağrılır (betik onsuz, doğrulanmayan bir zincirden pin almaz) |
| `E2E_SCREEN_LOCK_PIN` | `1357` | Gizli dosya senaryolarının emülatöre geçici koyduğu ekran kilidi PIN'i. Kendi kilidi olan telefonda o kilidin PIN'i verilmeli (senaryo kilide dokunmaz, yalnızca sorulunca yazar) |
| `E2E_CONTAINER` | `pinvault-host` | Durdurulup başlatılan host container'ı |
| `E2E_PROXY_PORT` | `6661` | Araya giren proxy'nin dinlediği port |
| `E2E_CUSTOM_BACKEND_PORT` | `6660` | Özel backend'in dinlediği port |
| `E2E_WEBHOOK_PORT` | `6662` | Webhook alıcısının dinlediği port (Y senaryoları) |
| `E2E_HOST_DIR`, `E2E_CLIENT_DIR` | kardeş klasörler | Host ve istemci projelerinin yolu |

## Bilinmesi gerekenler

- Testler host'un gerçek pin config'ini ve vault dosyalarını değiştirir; sonunda temel duruma döndürür. Yarıda kesilirse bir sonraki koşunun kurulumu düzeltir.
- Bazı senaryolar host container'ını birkaç saniyeliğine durdurur ya da sunucu ortam değişkenlerini geçici değiştirir (`scripts/env-override.sh`).
- Arka plan senaryosu emülatörün saatini bir WorkManager periyodu kadar ileri alır ve sonunda geri alır; bunun için emülatör imajındaki `su` kullanılır. WorkManager periyodik görevi zamanı gelmeden, zorlansa bile çalıştırmaz.
- Araya girme senaryoları (G) emülatörde `iptables` ile trafiği saldırgan proxy'ye yönlendirir; kurallar test sonunda silinir.
- mTLS senaryoları dashboard'da her koşuda yeni bir istemci sertifikası oluşturur ve iptal eder.
- Telefonda testler uygulamanın verisini siler. Telefonun genel ayarlarına dokunulmaz; animasyonlar yalnızca emülatörde kapatılır.
- Gizli vault dosyaları (sample-secret, sample-e2e, sample-mtls-secret) uygulamada yalnızca cihaz mTLS'e kayıtlıyken, sample-mtls'te ve ekran kilidi arkasında tanımlı. Onları kullanan senaryolar (14, 15, C03) emülatöre geçici bir ekran kilidi PIN'i koyar (`locksettings set-pin`), o süre ekranı açık tutar, "Aç"ta sistemin sorduğu kilide PIN'i yazar ve sonunda kilidi kaldırır; yarıda kalırsa global teardown kaldırır. Cihazın RSA anahtarı da yalnızca kayıtlıyken üretildiği için C10, C11 ve D03 önce kayıt olur (`lib/secureVault.js`). Kendi kilidi olan telefonda `E2E_SCREEN_LOCK_PIN` o kilidin PIN'i olmalı; Android 7–10'da parmak izi kayıtlıysa kilit anahtarı yalnızca parmak iziyle açılır, bu senaryolar orada çalışmaz.
- Uygulamanın bütün ekranları normalde ekran görüntüsüne kapalıdır (`FLAG_SECURE`; görüntü siyah çıkar). Testlerin derlemesi kanıt görüntüleri için `-Psample.e2eScreenshots=true` ile bunu kapatır; bu bayrak yalnızca debug ve e2e derleme türlerinde çalışır, release türü onunla derlenmez.
- Senaryoların kullandığı test kontrolleri (Ayarlar ve Depolama ekranları, `--es mode <MOD>` intent eki, otomatik kayıt, elle P12) yalnızca debug ve e2e derleme türlerinde vardır (`sample-client/app/src/testControls`). Release türünde bu ekranlar ve kod yolları yoktur; o yüzden senaryolar release türüne karşı koşmaz.
- Cihaz raporları (telemetri) Config API portuna (6651) gider; telefon yönetim portuna (6655) bağlanmaz. Config API portunu kesen ya da başka yere yönlendiren senaryolarda (F03, A31, G01, H02) raporlar da kesilir: bu senaryolar hatayı sunucudaki rapordan değil telefonun olay listesinden doğrular. Host'un anahtarıyla dinleyen saldırgan proxy'nin (G02–G09) gördüğü istekler arasında artık rapor POST'ları da bulunur.
- Uygulamanın blokları sunucudaki Config API kimliklerine bağlıdır (`host.tlsScope=default-tls`, `host.mtlsScope=sample-mtls` → `serverScope`); global setup ve `client-config.sh` bu değerleri yazar.
- Elle yüklenen P12 (B05) parolayla içe aktarılır; uygulama dosyayı Keystore anahtarıyla şifreleyip düz kopyayı siler.
- Telefon, host'a `.local/sample-host.properties` içindeki IP'den ulaşabilmeli.
- Uygulama her işlem sonucunun altına `#<sıra> · <saat>` yazar. Testler yeni sonucu eskisinden bununla ayırır.
- İmza anahtarını değiştiren ya da anahtar seti (telefonun güvendiği imza anahtarlarının listesi) yayımlayan senaryolar (S01–S05) geçici test sunucusunda çalışır. Sunucuda anahtar setleri yalnızca eklenir ve geri alınamaz; ana host'ta yayımlanan bir set, ana APK'nın güvendiği anahtarları eskitirdi. Bu senaryolar geçici test sunucusunun değerleriyle yalnızca bu test için bir uygulama derler ve sonunda ana APK'yı geri kurar.
- Değişiklik denetimi senaryoları (Y) sunucu ortamını geçici değiştirir (`ADMIN_KEYS`, `PIN_CHANGE_APPROVALS`, `PIN_LIVE_CHECK`, `NOTIFY_WEBHOOK_URL`) ve temel duruma dönmeden önce sıfırlar. Webhook alıcısı Mac'te dinler; container ona `host.docker.internal` ile ulaşır.
- Yönetici anahtarları (`.local/admins.json`) ve çevrimdışı özel anahtarlar (`.local/offline-keys/`) kanıt sayfasında asla görünmez; `npm run check-evidence` bunları da gizli değer sayar.
- U01 önceki sürümü (`sample-client-2.0.9` etiketi) deponun bir git worktree'sinde derler (`.local/upgrade/sample-client-old`, APK aynı klasörde saklanır); `git worktree list` çıktısında görünür. Silmek için `git worktree remove --force sample-e2e/.local/upgrade/sample-client-old` yeterli, bir sonraki koşu yeniden kurar. Senaryo sonunda güncel APK temiz kurulur.
- `E2E_VARIANT=e2e` ile koşuda uygulama verisi `run-as` yerine emülatörün `su`'suyla, uygulamanın kullanıcısına geçilerek okunur; küçültülmüş derlemede (debuggable değil) `run-as` çalışmaz.

## Yapı

```
PLAN.md                                kapsam planı, özellik matrisi, yürütme
global-setup.js / global-teardown.js   host, cihaz, host değerleri, APK, sunucu durumu
lib/env.js          yollar, portlar, API anahtarı (host .env'den), vault anahtarları, modlar
lib/hostApi.js      hazırlık/temizlik, tazelik kontrolü, ağ trafiğindeki ham vault yanıtı
lib/hostControl.js  host container'ı: durdur/başlat, ortam değişkeni ezme, log
lib/freshHost.js    geçici test sunucusu (tek kullanımlık ikinci host): kur, hazırla, dashboard'unu aç, sil
lib/clientBuild.js  istemciyi verilen host değerleriyle derle ve cihaza kur
lib/android.js      adb: cihaz, emülatör, UI dökümü, dokunma, yazma, klavye, saat, iptables, run-as
lib/sampleApp.js    uygulama ekranları: ana, mTLS, Vault, Depolama, Ayarlar
lib/dashboard.js    web dashboard: host'lar, pin'ler, force, vault, mTLS
lib/proxy.js        araya giren saldırgan proxy (sahte anahtarla ya da host'un anahtarıyla) ve hazır trafik değişiklikleri (config/vault imzası, kayıt yanıtındaki sertifika zinciri)
lib/custom-backend.js  özel uç yollu, kendi anahtarıyla imzalayan örnek backend
lib/offlineKeys.js  çevrimdışı anahtarlar (yedek, kurtarma, ek imzalayıcı) ve anahtar seti imzalama
lib/signingLab.js   imza senaryolarının ortak araçları: geçici test sunucusu, bu test için derlenen uygulama, operatör komutu panelleri, eski duruma dönüş
lib/webhookSink.js  sunucunun güvenlik bildirimlerini yakalayan alıcı; paylaşılan gizli anahtarla atılan imzayı (HMAC, "<X-PinVault-Timestamp>.<gövde>" üzerinden) ve zaman damgasının tazeliğini doğrular
lib/signingKeyFile.js  sunucunun imzalama anahtarı dosyası: diskte SIGNING_KEY_PASSWORD ile şifreli (ENCv1:); .env'deki parolayla açar
lib/admins.js       kişisel yönetici anahtarları (ADMIN_KEYS); sunucuya yalnızca SHA-256'ları gider
lib/evidence.js     metin panelleri: terminal çıktısı, ağ trafiğinin hex dökümü, cihaz dosyaları
lib/coverage.js     kapsam matrisi (özellik → senaryo)
lib/evidence-reporter.js   koşu sonunda evidence/index.html kanıt sayfası
lib/fixtures.js     her test için ayakta host + temel durum + temiz uygulama + açık dashboard
tests/              senaryolar
```
