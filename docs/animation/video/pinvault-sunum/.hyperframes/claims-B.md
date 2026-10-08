## Frame 11 — Bölüm 3: Baştan sona
compositions/frames/p5-bolum-akis.html
keyMessage: Kurulumdan ilk korumalı isteğe, on halkada.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 3 / 4"
- numara bloğu (Archivo, çok büyük): "3"
- kicker (mono, siyah kutu): "BÖLÜM 3"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Kurulumdan ilk korumalı isteğe, on halkada."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti) · "2 ÇÖZÜM" (bitti) · "3 AKIŞ" (şu anki) · "4 DOSYALAR"
- künye: "Bölüm 3" / sayaç "11 • 39"


## Frame 12 — Kutudan yeni çıkmış bir tablet
compositions/frames/01-yeni-tablet.html
keyMessage: Yeni bir telefon sunucunuzla güvenle konuşmadan önce on halkadan geçer.
Ekran metni:
- üst çubuk hap: "GİRİŞ"
- satır 1 (display-head): "KUTUDAN YENİ ÇIKMIŞ BİR TABLET."
- satır 2 (display-head): "SUNUCUNUZLA İLK GÜVENLİ İSTEĞE KADAR NE OLUR?"
- tablet etiketi (mono): "tablet-07"
- API kutusu: "API SUNUCUNUZ" / "api.ornek.com"
- zincir hücreleri: "1 KURULUM" "2 APK" "3 HOST" "4 KAYIT TOKEN'I" "5 TELEFONA" "6 KAYIT İSTEĞİ" "7 KART" "8 PİN LİSTESİ" "9 ATESTASYON" "10 İLK İSTEK"
- alt satır (body-lg): "On halka, bu sırayla. Her birinde kim, nerede, ne yapıyor."
- künye: "Giriş"


## Frame 13 — İki yanlış inanış
compositions/frames/02-iki-yanlis.html
keyMessage: Telefon pin'siz başlamaz, PinVault sunucusunun pin'leri APK'dadır; token ise APK'da değildir, her cihaza sonradan verilir.
Ekran metni:
- üst çubuk hap: "ÖNCE BİR DÜZELTME"
- başlık (display-head): "BAŞLAMADAN İKİ DÜZELTME"
- kart 1 yanlış (turuncu üstü çizili, body-lg): "Telefon hiç pin'siz başlar, önce token'la kayıt olur."
- kart 1 doğru (yeşil ✓, body-lg): "PinVault sunucusunun pin'leri APK'nın içindedir. Kayıt bile pinli bağlantıyla yapılır."
- kart 2 yanlış (turuncu üstü çizili, body-lg): "Token APK'ya gömülür."
- kart 2 doğru (yeşil ✓, body-lg): "Token APK'da değildir. Herkes aynı APK'yı yükler; her cihaz kendi token'ını sonradan alır."
- APK kutusu başlığı (mono): "APK'DA OLAN"
- APK kutusu satırları (mono): "✓ PinVault sunucusunun adresi" / "✓ PinVault sunucusunun pin'leri" / "✗ token" / "✗ API sunucularınızın pin'leri"
- künye: "Düzeltme"


## Frame 14 — Halka 1: Sunucu kurulur
compositions/frames/03-kurulum.html
keyMessage: Sunucu ilk açılışta kendi sertifikalarını üretir; yönetici panelde telefonların ulaşacağı adresi ve kapıları yazar.
Ekran metni:
- üst çubuk hap: "HALKA 1 / 10"
- zincir: şu anki hücre "1 KURULUM"
- kicker (mono, siyah kutu): "KİM: YÖNETİCİ · NEREDE: SUNUCU MAKİNESİ VE PANEL"
- başlık (display-head): "SUNUCU KURULUR"
- sunucu kutusu altı satır 1 (body-md): "Docker ile açılır. Parolalar ve yönetici anahtarı verilmeden açılmaz."
- üretilen dosyalar başlığı (mono): "İLK AÇILIŞTA KENDİSİ ÜRETİR"
- dosya 1 (mono): "sunucu sertifikası + yedeği → pin'leri APK'ya gidecek"
- dosya 2 (mono): "istemci CA'sı → cihaz kartlarını imzalar"
- dosya 3 (mono): "sunucu CA'sı → kurtarma kapısı (8093)"
- dosya 4 (mono): "imza anahtarı → pin listesini mühürler"
- panel başlığı (mono): "Panel · 8090 · Kurulum Sihirbazı · 1 · Sunucu"
- panel alanı 1 etiketi: "Telefonların sunucuya ulaştığı adres" / değer (mono): "192.168.1.10"
- panel alanı 2 etiketi: "Port eşlemesi" / değer (mono, soluk): "boş · Docker dışarıda başka numara verirse doldurulur"
- panel düğmesi: "Kaydet"
- panel altı not (body-md): "Kaydedip sunucuyu yeniden başlatırsınız. mTLS kapısını (8092) panelde “+ Config API” ile açarsınız."
- dipnot (mono, küçük): "Kapı numaraları demo kurulumundan (PORT=8090)."
- benzetme: "Bina açılır; kapı mühürleri ve kart basma makinesi hazırlanır."
- künye: "Kurulum"


## Frame 17 — Halka 2: APK hazırlanır
compositions/frames/04-apk.html
keyMessage: APK'ya PinVault sunucusunun adresi, pin'leri ve kayıt/kurtarma adresleri girer; token girmez.
Ekran metni:
- üst çubuk hap: "HALKA 2 / 10"
- zincir: şu anki hücre "2 APK"
- kicker: "KİM: GELİŞTİRİCİ · NEREDE: PANEL → KURULUM SİHİRBAZI → 3 · KOD"
- başlık (display-head): "APK HAZIRLANIR"
- kod (mono, 12 satır, girintili):
  ".configApi(\"mtls-8092\", \"https://192.168.1.10:8092/\") {"
  "    bootstrapPins(listOf("
  "        HostPin(\"192.168.1.10\","
  "                listOf(\"ziA0hyMD…\", \"vXC1UZ8O…\")),"
  "        HostPin(\"192.168.1.10:8093\","
  "                listOf(\"WnVy/Wig…\", \"TOZS0AAI…\"))"
  "    ))"
  "    enrollmentUrl(\"https://192.168.1.10:8091/\")"
  "    renewalUrl(\"https://192.168.1.10:8093/\")"
  "    attestation()   // sihirbaz üretmez, elle eklenir"
  "}"
- kod yanı not 1 (yeşil kenarlı kutucuk, mono): "8091 ve 8092'nin pin'leri"
- kod yanı not 2 (yeşil kenarlı kutucuk, mono): "kurtarma kapısının pin'leri"
- kod yanı not 3 (sarı kenarlı kutucuk, mono): "kayıt buraya gider"
- APK kutusu (Archivo): "APK" / alt (mono): "herkes aynısını yükler"
- APK altı satır (body-md, turuncu ✗): "Token yok. API sunucularınızın pin'leri yok."
- benzetme: "Yeni çalışana binanın adresi ve kapı mührünün resmi verilir; henüz kartı yok."
- künye: "APK"


## Frame 18 — Halka 3: Panelde API sunucunuz eklenir
compositions/frames/05-host.html
keyMessage: Yönetici API sunucusunu panelde ekler; pin'leri imzalı listeye girer; API sunucusu da PinVault-Token'ı doğrulamak için sırrını alır.
Ekran metni:
- üst çubuk hap: "HALKA 3 / 10"
- zincir: şu anki hücre "3 HOST"
- kicker: "KİM: YÖNETİCİ · NEREDE: PANEL → mtls-8092 → + HOST EKLE"
- başlık (display-head): "API SUNUCUNUZ EKLENİR"
- panel başlığı (mono): "Panel · 8090 · mtls-8092 · Yeni Host Ekle"
- sekmeler (mono): "Elle Gir" "Sertifika Üret" "URL'den Al" (seçili)
- alan etiketi: "Sunucu adresi" / değer (mono): "api.ornek.com"
- düğme: "Oluştur"
- sonuç satırı 1 (mono): "Primary Pin  q8Hs2LkP…"
- sonuç satırı 2 (mono): "Backup Pin  Xm4tR9wE…"
- sonuç notu (body-md): "Panel sunucuya bağlanır, sertifikasından iki pin'i kendisi çıkarır."
- imzalı liste kartı (mono): "PİN LİSTESİ · mtls-8092" / "api.ornek.com · q8Hs2LkP… · Xm4tR9wE…" / sarı mühür "İMZALI"
- alt bölüm başlığı (mono): "API SUNUCUNUZ İÇİN BİR KEZ"
- alt bölüm satırı (body-md): "PinVault-Token sırrını panelin İmzalama sekmesinden alır; PinVault-Token'ı sonra kendisi doğrular."
- benzetme: "Çalışanın gidebileceği ofislerin listesi hazırlanır ve mühürlenir."
- künye: "Host"


## Frame 19 — Halka 4: Token üretilir
compositions/frames/06-token.html
keyMessage: Yönetici panelde cihaz için token üretir; token bir kez gösterilir, sunucu yalnızca özetini saklar; isterseniz bunu giriş sunucunuz yapar.
Ekran metni:
- üst çubuk hap: "HALKA 4 / 10"
- zincir: şu anki hücre "4 KAYIT TOKEN'I"
- kicker: "KİM: YÖNETİCİ · NEREDE: PANEL → mtls-8092 → CLIENT SERTİFİKALARI"
- başlık (display-head): "TOKEN ÜRETİLİR"
- panel başlığı (mono): "Panel · 8090 · Client Sertifikaları · Enrollment Token"
- alan 1 etiketi: "Client ID" / değer (mono): "tablet-07"
- alan 2 etiketi: "Cihaz kimliği (ANDROID_ID)" / değer (mono, soluk): "isteğe bağlı"
- düğme: "Token Üret"
- açılan pencere başlığı: "Token yalnızca bir kez gösterilir"
- token değeri (mono, sarı şerit içinde): "Qk3xAbCdE5fGh7…"
- sunucuda kalan satırı başlığı (mono): "SUNUCUDA KALAN"
- sunucuda kalan satırı (mono): "SHA-256 özeti · Qk3xAbCd… · tablet-07 · Bekliyor · 24 saat"
- not (body-md): "Düz token saklanmaz; kaybolursa yenisi üretilir."
- alternatif kutusu başlığı (mono): "YA DA OTOMATİK"
- alternatif kutusu satırı (body-md): "Kullanıcı uygulamanıza giriş yapınca giriş sunucunuz token'ı 8090'dan kendisi ister ve uygulamaya verir."
- benzetme: "İK yeni çalışan için tek kullanımlık bir davet kodu üretir."
- künye: "Token"


## Frame 20 — Halka 5: Token telefona ulaşır
compositions/frames/07-telefona.html
keyMessage: Token mesajla ya da giriş cevabıyla telefona ulaşır; kullanıcı Kayıt Ol'a yapıştırır; uygulama init'ten önce enroll çağırır.
Ekran metni:
- üst çubuk hap: "HALKA 5 / 10"
- zincir: şu anki hücre "5 TELEFONA"
- kicker: "KİM: KULLANICI VE UYGULAMA · NEREDE: TELEFON"
- başlık (display-head): "TOKEN TELEFONA ULAŞIR"
- mesaj balonu (mono): "Kayıt token'ınız: Qk3xAbCdE5fGh7…"
- mesaj balonu altı (mono, küçük): "mesaj ya da e-posta · PinVault'un dışında"
- telefon ekranı başlığı: "Kayıt Ol"
- telefon ekranı alanı (mono): "Qk3xAbCdE5fGh7…"
- telefon ekranı düğmesi: "Kayıt Ol"
- kod kutusu başlığı (mono): "UYGULAMANIN KODU · İLK AÇILIŞ"
- kod (mono): "if (!PinVault.isEnrolled(context, config)) {" / "    PinVault.enrollForResult(context, config, token)" / "}" / "PinVault.init(context, config)"
- kod yanı not (body-md): "mTLS'te önce kayıt, sonra init: kartı olmayan telefon 8092'ye giremez."
- benzetme: "Davet kodu yeni çalışana mesajla gelir; o da danışmaya gitmeye hazırlanır."
- künye: "Telefona"


## Frame 21 — Halka 6: Kayıt isteği
compositions/frames/08-kayit-istegi.html
keyMessage: Telefon kendi anahtarını kasasında üretir, token'la birlikte sertifika isteğini 8091'e gönderir; özel anahtar hiç çıkmaz.
Ekran metni:
- üst çubuk hap: "HALKA 6 / 10"
- zincir: şu anki hücre "6 KAYIT İSTEĞİ"
- kicker: "KİM: PINVAULT KÜTÜPHANESİ · NEREDE: TELEFON → 8091 (TLS)"
- başlık (display-head): "KAYIT İSTEĞİ GİDER"
- kasa etiketi (mono): "Android Keystore"
- kasa altı (body-md): "Anahtar çifti burada üretilir."
- bağlantı etiketi (mono, yeşil ✓): "8091 · sunucu sertifikası APK'daki pin'le tuttu"
- paket başlığı (mono): "POST /api/v1/client-certs/enroll"
- paket satırları (mono): "token · Qk3xAbCd…" / "cihaz adı · Samsung SM-T505" / "deviceUid · a41c7e09d3b2f586" / "CSR · açık anahtar + imza" / "anahtarın donanım belgesi"
- gitmeyen satırı (mono, turuncu ✗): "özel anahtar · telefondan hiç çıkmaz"
- benzetme: "Çalışan danışmaya davet kodunu ve kendi fotoğrafını getirir; evinin anahtarını vermez."
- künye: "Kayıt isteği"


## Frame 23 — Halka 7: Sunucu kartı basar
compositions/frames/09-kart.html
keyMessage: Sunucu kontrolleri geçirir, token'ı harcar ve 90 günlük kartı verir; bundan sonra telefonun kimliği bu karttır, token bir daha sorulmaz.
Ekran metni:
- üst çubuk hap: "HALKA 7 / 10"
- zincir: şu anki hücre "7 KART"
- kicker: "KİM: PINVAULT SUNUCUSU · NEREDE: 8091"
- başlık (display-head): "SUNUCU KARTI BASAR"
- kontrol başlığı (mono): "SIRAYLA KONTROL"
- kontroller (mono, her biri yeşil ✓ ile): "token'ın özeti kayıtlı, kullanılmamış, süresi geçmemiş" / "bağlı bir telefon varsa o mu" / "kimlik iptal edilmemiş" / "CSR imzası tutuyor" / "anahtarın donanım belgesi (politikaya göre)"
- harcama satırı (body-md): "Hepsi geçerse token tek adımda harcanır."
- panel token satırı (mono): "Qk3xAbCd… · tablet-07 · Bekliyor" → "Kullanıldı"
- kart (pembe, mono): "tablet-07" / "90 gün" / "imzalayan: istemci CA'sı"
- telefon notu (body-md): "Telefon kartın kendi anahtarına ait olduğunu kontrol eder ve saklar."
- son satır (display-head küçük, ≈2.4cqw): "TOKEN BİTTİ. KİMLİK ARTIK KART."
- benzetme: "Danışma davet kodunu yakar ve fotoğraflı kimlik kartını basar."
- künye: "Kart"


## Frame 24 — Halka 8: İmzalı pin listesi
compositions/frames/10-pin-listesi.html
keyMessage: init önce kartın tarihine bakar, sonra 8092'ye kartla girip imzalı listeyi alır; api.ornek.com'un pin'leri telefona burada yerleşir.
Ekran metni:
- üst çubuk hap: "HALKA 8 / 10"
- zincir: şu anki hücre "8 PİN LİSTESİ"
- kicker: "KİM: PINVAULT KÜTÜPHANESİ (init) · NEREDE: TELEFON → 8092 (mTLS)"
- başlık (display-head): "İMZALI PİN LİSTESİ GELİR"
- init rayı başlığı (mono): "PinVault.init İÇİNDE, SIRAYLA"
- init rayı adım 1 (mono): "1 · kartın tarihi: vakti geldiyse yenile"
- init rayı adım 2 (mono): "2 · 8092'ye kartla gir, listeyi al"
- init rayı adım 3 (mono): "3 · imzayı ve 24 saatlik süreyi kontrol et"
- init rayı adım 4 (mono): "4 · pin'leri yerleştir"
- init rayı adım 5 (mono): "5 · sunucuya hâlâ ulaşılıyor mu"
- bağlantı etiketi (mono, yeşil ✓): "8092 · iki taraf da kimliğini gösterdi"
- liste kartı (mono): "PİN LİSTESİ · mtls-8092" / "api.ornek.com · q8Hs2LkP… · Xm4tR9wE…" / "son kullanma: 24 saat" / sarı mühür "İMZALI"
- telefon içi satır (mono, yeşil ✓): "api.ornek.com → pinli"
- benzetme: "Çalışan kartını gösterip içeri girer ve güncel, mühürlü ofis listesini alır."
- künye: "Pin listesi"


## Frame 25 — Halka 9: PinVault-Token alınır
compositions/frames/11-bilet.html
keyMessage: init'in sonunda telefon kendini ölçüp imzalar; geçerse 5 dakikalık PinVault-Token alır ve PinVault-Token arka planda yenilenir.
Ekran metni:
- üst çubuk hap: "HALKA 9 / 10"
- zincir: şu anki hücre "9 ATESTASYON"
- kicker: "KİM: PINVAULT KÜTÜPHANESİ · NEREDE: TELEFON → 8092"
- başlık (display-head): "PINVAULT-TOKEN ALINIR"
- adım 1 (mono kicker): "1 · SUNUCUDAN TEK KULLANIMLIK SORU"
- adım 2 (mono kicker): "2 · ÖLÇ VE KASA ANAHTARIYLA İMZALA"
- ölçüm çipleri (mono, kare): "root?" "emülatör?" "debugger?" "Frida?" "APK değişmiş mi?"
- adım 3 (mono kicker): "3 · SUNUCU KARAR VERİR"
- karar damgası (yeşil): "GEÇTİ"
- PinVault-Token (sarı): "PINVAULT-TOKEN" / "5 DK"
- not (body-md): "Kurulum sihirbazı attestation() satırını üretmez; geliştirici ekler (Halka 2)."
- not 2 (body-md): "PinVault-Token arka planda yaklaşık 5 dakikada bir kendiliğinden yenilenir."
- benzetme: "Güvenlik masası çantayı kontrol eder ve 5 dakikalık ziyaret bandı takar."
- künye: "PinVault-Token"


## Frame 26 — Halka 10: İlk gerçek istek
compositions/frames/12-ilk-istek.html
keyMessage: İlk korumalı istek, Halka 8'deki pin'le kurulan bağlantıdan ve Halka 9'daki PinVault-Token'la gider; API sunucusu PinVault-Token'ı kendisi doğrular.
Ekran metni:
- üst çubuk hap: "HALKA 10 / 10"
- zincir: şu anki hücre "10 İLK İSTEK"
- kicker: "KİM: UYGULAMANIZ · NEREDE: TELEFON → API SUNUCUNUZ"
- başlık (display-head): "İLK GERÇEK İSTEK"
- kod satırı (mono): "PinVault.getClient().newCall(GET https://api.ornek.com/siparisler)"
- istek kartı satırları (mono): "GET /siparisler" / "PinVault-Token: eyJhbGciOiJIUzI1NiIs…"
- geri çağrı 1 (mono, yeşil kutucuk): "pin: Halka 8'deki listeden"
- geri çağrı 2 (mono, sarı kutucuk): "PinVault-Token: Halka 9'dan"
- API kutusu içi satırlar (mono, her biri yeşil ✓): "imza (HS256) tutuyor" / "süresi geçmemiş" / "aud: mtls-8092"
- API kutusu altı (body-md): "PinVault'a sormaz; sırrı Halka 3'te almıştı."
- cevap (Archivo, yeşil kutu): "200 OK"
- benzetme: "Çalışan ofise gider; kapıdaki görevli kartın listede, bandın geçerli olduğuna kendisi bakar."
- künye: "İlk istek"


## Frame 27 — Root'lu telefon PinVault-Token alamaz
compositions/frames/10-ret.html
keyMessage: Geçmeyen uygulama PinVault-Token alamaz, API sunucunuz onu çevirir; pin listesi gizli değildir, asıl kilit PinVault-Token'dır.
Ekran metni:
- üst çubuk hap: "3/3 · ATESTASYON"
- başlık (display-head): "ROOT'LU TELEFON NE OLUR"
- telefon etiketi (turuncu kenarlı): "root · Frida"
- ölçüm çipleri: "root!" "Frida!" (turuncu ✗ ile)
- karar damgası (turuncu): "RET"
- PinVault-Token yerine boş kesik çizgili çerçeve (mono): "PinVault-Token yok"
- API kutusu cevabı (mono, turuncu): "401 · PinVault-Token yok"
- gerçek satırı (display-head): "KAPIYI TUTAN, PINVAULT-TOKEN'DIR."
- gerçek alt satırı (body-md): "Pin listesi gizli değildir; herkes alabilir. Değiştirilmiş uygulama yine de PinVault-Token alamaz."
- künye: "Ret"


## Frame 28 — Panelde: atestasyon ayarı
compositions/frames/a1-panel-atestasyon.html
keyMessage: Hangi sinyalin reddedileceğine siz panelde karar verirsiniz; reddedilen cihazı ve nedenini aynı sekmede görürsünüz.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 3 AKIŞ"
- üst çubuk hap: "PANELDE"
- kicker (mono, siyah kutu): "KİM: YÖNETİCİ · NEREDE: PANEL → mtls-8092 → ATTESTATION"
- başlık (display-head): "PANELDE: ATESTASYON AYARI"
- panel başlığı (mono): "Panel · 8090 · mtls-8092"
- sekmeler (mono): "Genel" "İmzalama" "Client Sertifikaları" "Vault" "Attestation" (seçili)
- kart 1 başlığı: "Red politikası" / sürüm rozeti (mono): "v3"
- hazır ayar satırı (mono): "Hazır ayar:" düğmeler "Sıkı" "Gevşek"
- tablo başlıkları (mono): "Bayrak" "Anlamı" "Karar"
- tablo satırları (mono · body · mono açılır kutu):
  "rooted" · "root'lu cihaz" · "reddet"
  "emulator" · "emülatör" · "reddet"
  "hooking_framework" · "Frida, Xposed gibi araçlar" · "reddet"
  "app_integrity" · "APK değiştirilmiş" · "reddet"
  "unknown_installer" · "mağaza dışından kurulmuş" · "uyar"
  "adb_enabled" · "USB hata ayıklama açık" · "yoksay"
- tablo altı (mono, küçük): "… 14 bayrak"
- alan (mono): "Token ömrü (saniye, tokenTtlSeconds)" / değer "300"
- düğme: "Politikayı Kaydet" → bildirim (mono): "Politika kaydedildi — sürüm v4"
- kart 2 başlığı: "Attestation yapan cihazlar"
- kart 2 satır 1 (mono): "tablet-07 · Geçti · ARC 7f3a9c1e"
- kart 2 satır 2 (mono): "tablet-11 · Reddedildi · ARC b21e04c9"
- ARC açılır kutusu başlığı: "Red nedenleri" / satırlar (mono): "rooted" "hooking_framework"
- yan not (body-md): "Telefona yalnızca ARC kodu gider; nedeni siz panelde görürsünüz."
- benzetme: "Güvenlik masasının kural listesi: neye takılan girmez, neye yalnızca not düşülür."
- künye: "Atestasyon ayarı"


## Frame 35 — İşleyen fabrika: hepsi bir arada
compositions/frames/f1-fabrika.html
keyMessage: PinVault işleyen bir fabrika gibidir: aynı harita üzerinde kurulumdan ilk isteğe ve dosyaya kadar her parça sırayla çalışır, sonra da çalışmaya devam eder.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · ÖZET"
- üst çubuk hap: "HEPSİ BİR ARADA"
- zincir hücreleri (ring karelerindeki geometriyle aynı): "1 KURULUM" "2 APK" "3 HOST" "4 KAYIT TOKEN'I" "5 TELEFONA" "6 KAYIT İSTEĞİ" "7 KART" "8 PİN LİSTESİ" "9 ATESTASYON" "10 İLK İSTEK"
- telefon: "Uygulamanız" / şerit "PinVault kütüphanesi"
- telefon içi küçük satırlar (sırayla belirir, mono): "APK: PinVault pin'leri" · "kart: tablet-07" · "liste: api.ornek.com pinli" · "PinVault-Token: 5 dk" · "dosya: saha-ayarlari" · (yenilemede "kart: tablet-07" satırının yanına "yenilendi", kurtarmada önce "süresi doldu" sonra "yenilendi")
- sunucu başlığı (mono, siyah şerit): "PinVault sunucusu"
- sunucu içi makine 1 (pembe kenar): "İstemci CA'sı" / alt (mono): "kartları imzalar"
- sunucu içi makine 2 (sarı kenar): "İmza anahtarı · HSM" / alt (mono): "listeyi mühürler"
- sunucu içi makine 3 (gri): "Depo" / alt (mono): "kayıtlar · liste · dosyalar"
- kapılar (mono): "8091 · TLS" "8092 · mTLS" "8093 · kurtarma" "8090 · yönetim"
- API kutusu: "API SUNUCUNUZ" / "api.ornek.com"
- yönetici kutusu: "YÖNETİCİ · PANEL"
- paket etiketleri (mono): "token" (sarı) · "kayıt isteği" (krem-2) · "tablet-07" (pembe kart) · "liste · İMZALI" (krem-2, sarı mühür) · "rapor" (krem-2) · "PINVAULT-TOKEN" (sarı) · "istek" (ink) · "200 OK" (yeşil) · "dosya" (krem-2, kilit) · "yenileme isteği" (krem-2) · "kurtarma isteği · imzalı" (krem-2)
- adım satırları (alt açıklama, body-lg, her biri kendi adımında yazılır, öncekinin yerini alır):
  "1 · Sunucu açılır: kendi sertifikalarını ve imza anahtarını üretir."
  "2 · APK'ya PinVault sunucusunun adresi ve pin'leri girer."
  "3 · Yönetici API sunucusunu panelde ekler; pin'leri imzalı listeye girer."
  "4 · Yönetici panelde kayıt token'ı üretir."
  "5 · Kayıt token'ı telefona ulaşır: mesajla ya da girişte."
  "6 · Telefon 8091'e kayıt isteği gönderir: kayıt token'ı + sertifika isteği."
  "7 · İstemci CA'sı kartı imzalar; token harcanır, kart telefona döner."
  "8 · Telefon kartıyla 8092'ye girer, imzalı pin listesini alır."
  "9 · Atestasyon: telefon raporunu gönderir, 5 dakikalık PinVault-Token alır."
  "10 · İlk istek: pin listeden, PinVault-Token başlıkta; API sunucusu doğrular: 200 OK."
  "Dosya: yönetici panelden yükler; telefon kendi dosyasını 8092'den alır."
  "Yenileme: kartın süresinin üçte biri kalınca telefon 8092'den aynı anahtarla yeni kart alır."
  "Kurtarma: kartın süresi dolduysa telefon 8093'e gider, kimliğini aynı anahtarın imzasıyla kanıtlar ve yeni kartını alır."
  "Fabrika çalışmaya devam eder: her açılışta kart, liste, PinVault-Token; her istekte PinVault-Token."
- kapanış başlığı (display-head, son 5 sn, alt açıklama satırının yerinde): "İŞLEYEN FABRİKA."
- künye: "Hepsi bir arada"


## Frame 37 — Sonrası
compositions/frames/13-sonrasi.html
keyMessage: Token bir daha sorulmaz; kart yenilenir, liste ve PinVault-Token tazelenir; yönetici isterse iptal eder.
Ekran metni:
- üst çubuk hap: "SONRASI"
- başlık (display-head): "ZİNCİR BİR KEZ KURULUR"
- istasyon 1: "HER AÇILIŞ" / "init: kart tarihi → liste → PinVault-Token. Token sorulmaz."
- istasyon 2: "ARKA PLAN" / "PinVault-Token ≈5 dakikada bir. Liste, schedulePeriodicUpdates() çağırırsanız."
- istasyon 3: "60. GÜN" / "Kart, süresinin üçte biri kalınca 8092'den yenilenir. Anahtar aynı."
- istasyon 4: "SÜRE DOLDUYSA" / "8093'ten kurtarılır; kimliği aynı anahtarla atılan imza kanıtlar."
- istasyon 5: "İPTAL" / "Panel → Client Sertifikaları → İptal Et. Kart hiçbir kapıyı açmaz."
- künye: "Sonrası"


## Frame 38 — Üç cümlede PinVault
compositions/frames/12-uc-cumle.html
keyMessage: Doğru sunucu, tanınan cihaz, gerçek uygulama; hepsi sizin makinenizde.
Ekran metni:
- üst çubuk hap: "ÖZET"
- satır 1 (display-lg): "DOĞRU SUNUCU."
- satır 2 (display-lg): "TANINAN CİHAZ."
- satır 3 (display-lg): "GERÇEK UYGULAMA."
- alt satır (body-lg): "Hepsi sizin makinenizde; veri dışarı çıkmaz."
- künye: "Özet"


## Frame 39 — On halka, tek cümle
compositions/frames/14-kapanis.html
keyMessage: Token yalnızca bir kez, kayıtta kullanılır; sonra telefonun kimliği kartı, güveni imzalı liste ve PinVault-Token'dır.
Ekran metni:
- üst çubuk hap (krem varyant): "SON"
- zincir hücreleri (krem çerçeve, krem yazı, hepsi dolu): "1 KURULUM" "2 APK" "3 HOST" "4 KAYIT TOKEN'I" "5 TELEFONA" "6 KAYIT İSTEĞİ" "7 KART" "8 PİN LİSTESİ" "9 ATESTASYON" "10 İLK İSTEK"
- başlık (display-lg, krem): "TOKEN BİR KEZ."
- başlık 2 (display-head, krem): "SONRA KİMLİK KART, GÜVEN LİSTE VE PINVAULT-TOKEN."
- alt satır (mono, krem): "Ayrıntı: docs/animation/pinvault-request-flow.tr.html"
- künye: "Kapanış"
