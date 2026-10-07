## Frame — İki tür Config API: TLS ve mTLS

- scene: İki sütun: solda TLS (yalnız sunucu kimlik gösterir), sağda mTLS (iki taraf da gösterir); her sütunda küçük el sıkışma çizimi ve ne getirdiği
- voiceover:
- duration: 17s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/c1-config-api-turleri.html
- type: feature_showcase
- persuasion: Comparison of two options (split) + concretization (el sıkışma)
- beat: comprehension + orientation
- blueprint: compose
- focal: iki sütundaki el sıkışma çizimleri
- roles: iki sütun kartı = foreground subject · el sıkışma okları = foreground subject · ortak satır = supporting · not = supporting

narrativeRole: Uygulamanın PinVault'a hangi kapıdan, hangi kimlikle bağlandığının iki yolunu ayırır; kimlik katmanının neden isteğe bağlı olduğunu açıklar.
keyMessage: TLS Config API'de yalnızca sunucu kimliğini gösterir, kayıt gerekmez; mTLS Config API'de telefon da kartını gösterir, bu yüzden önce bir kez kayıt olur ve tanınma, iptal, yenileme kazanılır.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 2 ÇÖZÜM"
- üst çubuk hap: "CONFIG API"
- başlık (display-head): "İKİ TÜR CONFIG API"
- açıklama (body-lg): "Config API, uygulamanın pin listesini, PinVault-Token'ını ve dosyalarını aldığı kapıdır. İki türü var."
- sütun 1 başlığı (Archivo): "TLS" / alt (mono): "tek yönlü · örnek: 8091"
- sütun 1 çizim: telefon ← sunucu sertifikası (mor değil, krem-2 kart) · telefon kendi kartını göstermez
- sütun 1 satırları (body-md): "Yalnızca sunucu kimliğini gösterir." / "Kayıt yok, kayıt token'ı yok: uygulama kurulur kurulmaz çalışır." / "Sunucu, hangi cihazla konuştuğunu kanıtlayamaz."
- sütun 2 başlığı (Archivo): "mTLS" / alt (mono): "çift yönlü · örnek: 8092"
- sütun 2 çizim: telefon ← sunucu sertifikası · telefon → pembe kart "tablet-07"
- sütun 2 satırları (body-md): "İki taraf da kimliğini gösterir." / "Telefon önce bir kez kayıt olur ve kartını alır." / "Ek olarak: tanınan cihaz, iptal, kart yenileme, “token + mTLS” dosyalar."
- ortak satır (mono, iki sütunun altında, yeşil ✓): "İKİSİNDE DE: imzalı pin listesi · atestasyon ve PinVault-Token · dosyalar"
- not (body-md): "Bir uygulama ikisini birden kullanabilir. Bu filmdeki örnek uygulama mTLS kullanır; kaydını TLS kapısından (8091) yapar."
- künye: "Config API türleri"

Compose. Yerleşim: başlık ve açıklama üstte; altında iki eşit sütun kartı (split, her biri ≈ 820×420; sol krem, sağ pembe kenarlı); her kartın üst yarısında küçük el sıkışma çizimi (telefon solda, sunucu sağda, aralarında oklar), alt yarısında satırlar; kartların altında ortak satır ve not.
Scene 1 (0.0–2.5s): Başlık, sonra açıklama.
Scene 2 (2.5–7.0s): Sol kart: başlık; çizimde sunucudan telefona sertifika kartı kayar ve yeşil ✓ alır; telefon tarafında boş kesik çizgili kutu "kart yok"; üç satır sırayla.
Scene 3 (7.0–12.0s): Sağ kart: başlık; çizimde sunucudan telefona sertifika, telefondan sunucuya pembe kart "tablet-07" kayar; ikisi de ✓; üç satır sırayla (sert gölge bu kartta).
Scene 4 (12.0–17.0s): Ortak satır, sonra not. Tutma.

## Frame — Panelde: mTLS Config API açılır

- scene: Panelde "+ Config API" → "Yeni Config API" formu: API ID mtls-8092, Port 8092, Mod mTLS; Config API Başlat; kenar çubuğunda default-tls ve mtls-8092 alt alta
- voiceover:
- duration: 14s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/c2-panel-config-api.html
- type: feature_showcase
- persuasion: Demonstration (panel adımları)
- beat: comprehension + control
- blueprint: compose
- focal: "Yeni Config API" formu
- roles: panel ekranı = foreground subject · kenar çubuğu listesi = supporting · not = supporting · benzetme = supporting

narrativeRole: Bir önceki karedeki mTLS türünün panelde nasıl açıldığını gösterir.
keyMessage: TLS Config API sunucuyla kendiliğinden açılır; mTLS Config API'yi yönetici panelden "+ Config API" ile açar.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 2 ÇÖZÜM"
- üst çubuk hap: "PANELDE"
- kicker (mono, siyah kutu): "KİM: YÖNETİCİ · NEREDE: PANEL → + CONFIG API"
- başlık (display-head): "PANELDE: mTLS CONFIG API AÇILIR"
- panel başlığı (mono): "Panel · 8090"
- kenar çubuğu başlığı (mono): "CONFIG API'LER"
- kenar çubuğu satırı 1 (mono): "default-tls · 8091" + rozet "varsayılan"
- kenar çubuğu satırı 2 (mono, sonradan eklenir): "mtls-8092 · 8092"
- kenar çubuğu düğmesi (mono): "+ Config API"
- form başlığı: "Yeni Config API" / alt (body-md): "TLS veya mTLS config API başlatın"
- alan 1 etiketi: "API ID" / değer (mono): "mtls-8092"
- alan 2 etiketi: "Port" / değer (mono): "8092"
- alan 3 etiketi: "Mod" / açılır liste seçenekleri (mono): "TLS (tek yönlü)" · "mTLS (çift yönlü — client cert gerekir)" (seçilen)
- düğme: "Config API Başlat"
- not (body-md): "default-tls sunucuyla kendiliğinden açılır. mTLS kapısı yalnızca istemci CA'sının imzaladığı kartlara güvenir; kartı olmayan telefon içeri giremez."
- benzetme: "Binaya ikinci bir kapı açılır: bu kapıdan yalnızca kartı olan girer."
- künye: "mTLS açılır"

Compose. Yerleşim: başlık üstte; altında panel ekranı (çerçeve genişliğinin ≈ %80'i): solda dar kenar çubuğu (Config API listesi), sağda form; altta not ve benzetme.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–4.0s): Panel açılır; kenar çubuğunda yalnız "default-tls · 8091 · varsayılan" var; "+ Config API"ye basılır.
Scene 3 (4.0–9.0s): Form açılır; "API ID" ve "Port" harf harf dolar; "Mod" listesi açılır, iki seçenek görünür, mTLS seçilir.
Scene 4 (9.0–11.5s): "Config API Başlat"a basılır; kenar çubuğunda "mtls-8092 · 8092" satırı belirir (yeşil ✓; karenin tek sert gölgesi bu satırda).
Scene 5 (11.5–14.0s): Not ve benzetme. Tutma.

## Frame — Neden eliptik eğri?

- scene: Telefonun kasasında EC P-256 anahtarı; RSA ile boy karşılaştırması; aynı anahtarın dört işi
- voiceover:
- duration: 16s
- transition_in: crossfade
- status: animated
- src: compositions/frames/e1-eliptik-egri.html
- type: feature_showcase
- persuasion: Comparison (anahtar boyu) + enumeration (dört iş)
- beat: fascination + comprehension
- blueprint: compose
- focal: anahtar boyu karşılaştırma çubukları
- roles: telefon ve kasa = supporting · iki çubuk (EC 256 bit, RSA 3072 bit) = foreground subject · dört iş listesi = foreground subject · not = supporting

narrativeRole: Kayıt isteğinde üretilen telefon anahtarının türünü ve bu seçimin nedenini açıklar.
keyMessage: Telefonun kimlik anahtarı eliptik eğri (EC P-256) anahtarıdır: aynı güvenliği çok daha kısa anahtarla verir, telefonun güvenli donanımında üretilir ve dışarı çıkmaz; kayıtta, mTLS'te, atestasyonda ve kurtarmada aynı anahtar imza atar.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 3 AKIŞ"
- üst çubuk hap: "ANAHTAR"
- başlık (display-head): "NEDEN ELİPTİK EĞRİ?"
- kasa etiketi (mono): "Android Keystore · StrongBox ya da TEE"
- anahtar etiketi (mono, pembe çerçeve): "EC P-256 · yalnızca imza"
- karşılaştırma başlığı (mono): "AYNI GÜVENLİK İÇİN ANAHTAR BOYU"
- çubuk 1 (pembe, kısa): "EC P-256 · 256 bit"
- çubuk 2 (krem-2, uzun): "RSA · 3072 bit"
- karşılaştırma altı (body-md): "Kısa anahtar, küçük ve hızlı imza. Telefonun güvenli donanımı bu eğriyi destekler."
- dört iş başlığı (mono): "AYNI ANAHTAR İMZA ATAR"
- iş 1 (mono, yeşil ✓): "kayıt: sertifika isteği (CSR)"
- iş 2 (mono, yeşil ✓): "mTLS: her bağlantıda el sıkışma"
- iş 3 (mono, yeşil ✓): "atestasyon: ölçüm raporu"
- iş 4 (mono, yeşil ✓): "kurtarma: 8093'te kimlik kanıtı"
- not (body-md): "Özel anahtar kasadan hiç çıkmaz; sunucu yalnızca açık anahtarı görür."
- benzetme: "Kısa ama taklit edilemeyen bir imza; kalem de hiç kasadan çıkmaz."
- künye: "Eliptik eğri"

Compose. Yerleşim: solda (%30) telefon ve altındaki kasa, kasanın içinde pembe anahtar etiketi; ortada (%35) iki yatay çubuk (EC çubuğu RSA çubuğunun ≈ 1/12'si uzunluğunda); sağda (%35) dört iş listesi; altta not ve benzetme. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Başlık.
Scene 2 (1.8–4.5s): Telefon ve kasa; kasanın içinde anahtar etiketi belirir.
Scene 3 (4.5–9.0s): Karşılaştırma başlığı; önce RSA çubuğu soldan sağa uzar, sonra EC çubuğu kısa kalarak oturur (sert gölge EC çubuğunda); karşılaştırma altı satır.
Scene 4 (9.0–13.5s): Dört iş ≈0,9 sn arayla ✓ ile gelir; her biri gelirken kasadaki anahtardan ona ince bir çizgi çekilir.
Scene 5 (13.5–16.0s): Not ve benzetme. Tutma.

## Frame — Hangi anahtar, hangi algoritma

- scene: Anahtar haritası tablosu: anahtar · algoritma · nerede üretilir · ne işe yarar; EC satırları pembe imli, RSA satırları krem, HMAC sarı
- voiceover:
- duration: 18s
- transition_in: crossfade
- status: animated
- src: compositions/frames/e2-anahtar-haritasi.html
- type: social_proof
- persuasion: Structure (comparison ledger) + distillation
- beat: mastery
- blueprint: compose
- focal: anahtar tablosu
- roles: tablo = foreground subject · renk imleri = supporting · alt not = supporting

narrativeRole: Filmde geçen bütün anahtarları tek tabloda toplar; eliptik eğrinin nerede kullanıldığını, nerede kullanılmadığını dürüstçe ayırır.
keyMessage: İmza işleri eliptik eğriyle (EC P-256) yapılır; sunucunun TLS sertifikası ve dosya şifreleme RSA'dır; PinVault-Token HMAC ile imzalanır.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · ÖZET"
- üst çubuk hap: "ANAHTARLAR"
- başlık (display-head): "HANGİ ANAHTAR, HANGİ ALGORİTMA"
- tablo başlıkları (mono): "Anahtar" · "Algoritma" · "Nerede" · "Ne işe yarar"
- satır 1 (pembe im): "Telefonun kimlik anahtarı" · "EC P-256" · "telefonun kasası" · "kayıt, mTLS, atestasyon, kurtarma"
- satır 2 (pembe im): "İstemci CA'sı" · "EC P-256" · "sunucu" · "cihaz kartlarını imzalar (90 gün)"
- satır 3 (pembe im): "Sunucu CA'sı" · "EC P-256" · "sunucu" · "kurtarma kapısının (8093) sertifikası"
- satır 4 (pembe im): "Pin listesi imza anahtarı" · "EC P-256 (ECDSA)" · "dosya, HSM ya da KMS" · "pin listesini ve dosyaları mühürler"
- satır 5 (krem im): "Sunucunun TLS sertifikası" · "RSA 2048" · "sunucu" · "8091 ve 8092 bağlantıları"
- satır 6 (krem im): "Dosya şifreleme anahtarları" · "RSA 2048 + AES-256-GCM" · "telefonun kasası" · "uçtan uca ve ekran kilitli dosyalar"
- satır 7 (sarı im): "PinVault-Token" · "HMAC (HS256)" · "sunucu" · "API sunucunuz doğrular"
- alt not (body-md): "İmza işleri eliptik eğriyle yapılır. Şifreleme ve sunucunun TLS sertifikası RSA'dır."
- künye: "Anahtar haritası"

Compose. Yerleşim: başlık üstte; altında çerçeve genişliğinde krem-2 tablo (comparison ledger), ink başlık satırı, yedi satır; her satırın solunda küçük renk imi; tablo altında alt not. Tablo metni ≥ 22px. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Başlık.
Scene 2 (1.8–3.0s): Tablonun başlık satırı.
Scene 3 (3.0–12.5s): Yedi satır ≈1,3 sn arayla yukarıdan aşağı gelir.
Scene 4 (12.5–15.0s): EC P-256 hücreleri sırayla kısa pembe vurgu alır (kenar), sonra RSA hücreleri krem kalır.
Scene 5 (15.0–18.0s): Alt not. Tutma.
