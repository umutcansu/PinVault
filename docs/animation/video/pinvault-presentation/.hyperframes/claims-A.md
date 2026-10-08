## Frame 1 — Bölüm 1: Amaç
compositions/frames/p1-bolum-amac.html
keyMessage: Önce SSL pinning'in neden gerektiğini konuşacağız.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 1 / 4"
- numara bloğu (Archivo, çok büyük): "1"
- kicker (mono, siyah kutu): "BÖLÜM 1"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Telefon, konuştuğu sunucunun gerçekten sizin sunucunuz olduğunu nasıl bilir?"
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (şu anki) · "2 ÇÖZÜM" · "3 AKIŞ" · "4 DOSYALAR"
- künye: "Bölüm 1" / sayaç "01 • 39"


## Frame 2 — Arada kim var?
compositions/frames/01-arada-kim-var.html
keyMessage: Uygulama ile sunucu arasındaki hat güvenli değilse, arada biri olabilir.
Ekran metni:
- üst çubuk hap: "GİRİŞ"
- satır 1 (display-lg): "UYGULAMANIZ SUNUCUSUYLA KONUŞUYOR."
- satır 2 (display-lg, turuncu altı çizgi): "PEKİ ARADA KİM VAR?"
- künye: "Arada kim var?"


## Frame 3 — Normal TLS neye güvenir
compositions/frames/p2-normal-tls.html
keyMessage: Normal TLS'te telefon, güven deposundaki herhangi bir kurumun imzaladığı sertifikaya güvenir; araya giren biri o depoya kendi kurumunu ekletirse sahte sunucu da güvenilir görünür.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 1 AMAÇ"
- üst çubuk hap: "AMAÇ"
- başlık (display-head): "NORMAL TLS NEYE GÜVENİR?"
- açıklama (body-lg): "Sunucu bağlantının başında sertifikasını gösterir. Telefon, güven deposundaki kurumlardan (CA) biri imzaladıysa kabul eder."
- depo kutusu başlığı (mono): "TELEFONUN GÜVEN DEPOSU"
- depo çipleri (mono, krem-2 kare): "Kurum A" "Kurum B" "Kurum C" "Kurum D" "Kurum E" "… ve onlarcası"
- turuncu çip (mono): "ARAYA GİRENİN KURUMU"
- turuncu çip altı (body-md): "Kurumsal ağ, zararlı bir profil ya da kandırılmış kullanıcı bunu telefona ekletebilir."
- sahte sunucu kutusu: "SAHTE SUNUCU" / sertifika kartı (mono): "imzalayan: araya girenin kurumu"
- sonuç damgası (turuncu kenarlı, krem dolgu): "GÜVENİLİR ✓" — ve hemen altında turuncu not: "ama sahte"
- son satır (display-head küçük, ≈ 2.6cqw): "SSL PINNING BU AÇIĞI KAPATIR."
- künye: "Normal TLS" / sayaç "03 • 39"


## Frame 4 — Parmak izi kontrolü
compositions/frames/05-parmak-izi.html
keyMessage: Telefon, sunucunun gösterdiği sertifikanın parmak izini bildiği listeyle karşılaştırır; tutmazsa tek bayt göndermeden bağlantıyı keser.
Ekran metni:
- üst çubuk hap: "AMAÇ"
- başlık (display-head): "PARMAK İZİ KONTROLÜ"
- açıklama (body-lg): "Sunucu her bağlantıda sertifikasını gösterir. Telefon onun parmak izini (pin) bildiği listeyle karşılaştırır."
- telefonun yanındaki kart başlığı (mono): "BİLDİĞİM PARMAK İZLERİ"
- kart satırları (mono): "q8Hs2LkP…" ve "Xm4tR9wE…"
- gerçek sunucunun (API sunucunuz) sertifika kartı (mono): "q8Hs2LkP…"
- yeşil damga: "EŞLEŞTİ ✓"
- yeşil alt yazı: "Bağlantı kurulur."
- sahte sunucu kutusu: "SAHTE SUNUCU"
- sahte sertifika kartı (mono): "Xk91Pq7R…"
- turuncu damga: "EŞLEŞMEDİ ✗"
- turuncu alt yazı: "Telefon tek bayt göndermeden bağlantıyı keser."
- künye: "Pinleme"


## Frame 5 — Pinlemenin üç eksiği
compositions/frames/p3-uc-eksik.html
keyMessage: Pinleme kanalı korur ama pin'ler APK'da kalır, sunucu cihazı tanımaz ve uygulamanın gerçek olduğunu bilmez.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 1 AMAÇ"
- üst çubuk hap: "AMAÇ"
- başlık (display-head): "PİNLEME TEK BAŞINA ÜÇ ŞEYİ ÇÖZMEZ"
- kart 1 (krem dolgu): büyük "1" / başlık "PİN'LER APK'DA KALIR" / alt satır "Sunucunun sertifikası değişince uygulama güncellemesi gerekir; eski sürümler bağlanamaz."
- kart 2 (pembe dolgu): büyük "2" / başlık "SUNUCU CİHAZI TANIMAZ" / alt satır "Hangi telefonla konuştuğunu bilmez; tek bir cihazı uzaktan kesemez."
- kart 3 (sarı dolgu): büyük "3" / başlık "UYGULAMANIN GERÇEK OLDUĞUNU BİLMEZ" / alt satır "Kopya, root'lu telefondaki ya da Frida ile değiştirilmiş uygulama da aynı pinli bağlantıyı kurar."
- alt satır (body-lg): "PinVault bu üçüne birer cevap verir."
- künye: "Üç eksik" / sayaç "05 • 39"


## Frame 6 — Bölüm 2: PinVault ne ekler
compositions/frames/p4-bolum-pinvault.html
keyMessage: Üç eksiğe üç cevap ve parçaların nerede durduğu.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 2 / 4"
- numara bloğu (Archivo, çok büyük): "2"
- kicker (mono, siyah kutu): "BÖLÜM 2"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Üç eksiğe üç cevap ve parçaların nerede durduğu."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti: ink dolgu) · "2 ÇÖZÜM" (şu anki) · "3 AKIŞ" · "4 DOSYALAR"
- künye: "Bölüm 2" / sayaç "06 • 39"


## Frame 7 — PinVault: üç iş, tek kurulum
compositions/frames/03-uc-is.html
keyMessage: PinVault üç iş yapar: doğru sunucu, tanınan cihaz, gerçek uygulama.
Ekran metni:
- üst çubuk hap: "ÇÖZÜM"
- wordmark (display-xl): "PİNVAULT"
- alt satır (body-lg): "Uygulamanıza giren bir kütüphane ve sizin makinenizde çalışan bir sunucu."
- kart 1: büyük rakam "1", başlık "PİNLEME", alt satır "Pin listesi sunucudan, imzalı gelir; APK değişmez." / panel şeridi (siyah, mono) "PANELDE · + Host ekle → URL'den Al"
- kart 2: büyük rakam "2", başlık "KİMLİK", alt satır "Sunucu, tanıdığı cihazı içeri alır." / panel şeridi "PANELDE · Client Sertifikaları → Token Üret"
- kart 3: büyük rakam "3", başlık "ATESTASYON", alt satır "PinVault-Token yalnızca değiştirilmemiş uygulamaya verilir." / panel şeridi "PANELDE · Attestation → Red politikası"
- künye: "Üç iş"


## Frame 8 — İki tür Config API: TLS ve mTLS
compositions/frames/c1-config-api-turleri.html
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


## Frame 9 — Panelde: mTLS Config API açılır
compositions/frames/c2-panel-config-api.html
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


## Frame 10 — Parçalar nerede durur
compositions/frames/04-topoloji.html
keyMessage: Cihazlar yalnızca üç kapıyla konuşur; yönetim kapısı ve depo iç ağda kalır; PinVault-Token'ı sizin arka ucunuz kendisi doğrular.
Ekran metni:
- üst çubuk hap: "TOPOLOJİ"
- başlık (display-head): "PARÇALAR NEREDE DURUR"
- bölge 1 etiketi (mono): "CİHAZ"
- telefon: "Uygulamanız" / "PinVault kütüphanesi"
- bölge 2 etiketi (mono): "PİNVAULT SUNUCUSU · SİZİN MAKİNENİZ"
- kapı 8091 kutusu: "8091 · TLS" / "pin listesi · kayıt · atestasyon"
- kapı 8092 kutusu: "8092 · mTLS" / "kimlikli cihaz: dosya · yenileme"
- kapı 8093 kutusu: "8093 · KURTARMA" / "süresi dolan sertifika"
- depo kutusu: "DEPO" / "sertifikalar · kayıtlar · imza anahtarı"
- bölge 3 etiketi (mono): "SİZİN ARKA UCUNUZ"
- arka uç kutusu 1: "API SUNUCULARINIZ" / "PinVault-Token'ı kendisi doğrular"
- arka uç kutusu 2: "GİRİŞ SUNUCUNUZ" / "cihazlara kayıt token'ı ister"
- telefon → API çizgisi etiketi (mono): "istek + PinVault-Token"
- iç ağ bölgesi etiketi (mono): "YALNIZCA İÇ AĞ"
- kapı 8090 kutusu: "8090 · YÖNETİM" / "panel · API anahtarı"
- yönetici kutusu: "YÖNETİCİ"
- özet satırı 1 (body-md, yeşil kare imli): "İnternete açık: 8091 · 8092 · 8093 ve sizin arka ucunuz."
- özet satırı 2 (body-md, turuncu kare imli): "İç ağda: 8090 yönetim kapısı ve depo."
- dipnot (mono, küçük): "Kapı numaraları demo kurulumundan."
- künye: "Topoloji"


## Frame 15 — Seçenek: imza anahtarı nerede durur?
compositions/frames/h1-hsm-secenek.html
keyMessage: Telefonlar bu anahtarın mühürlediği listeye güvenir; anahtarı ele geçiren sahte bir liste mühürleyip telefonları kendi sunucusuna bağlatabilir; bu yüzden anahtarın nerede durduğu seçilir: dosya, HSM ya da KMS.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 3 AKIŞ"
- üst çubuk hap: "SEÇENEK"
- kicker (mono, siyah kutu): "KİM: YÖNETİCİ · NEREDE: SUNUCU AYARI (CONFIG_SIGNERS)"
- başlık (display-head): "İMZA ANAHTARI NEREDE DURUR?"
- neden önemli şeridi başlığı (mono, turuncu im): "NEDEN ÖNEMLİ"
- neden önemli satırı (body-lg): "Telefonlar bu anahtarın mühürlediği pin listesine güvenir. Anahtarı ele geçiren, sahte bir liste mühürleyip telefonlarınızı kendi sunucusuna bağlatabilir."
- kart 1 başlığı (Archivo): "DOSYA" / ayar (mono): "CONFIG_SIGNERS=local"
- kart 1 satırı (body-md): "signing-key.pem, diskte parolayla şifreli."
- kart 1 "seçerseniz" satırı (mono, küçük): "En kolayı. Sunucu ya da yedeği çalınırsa anahtar da kopyalanabilir."
- kart 2 başlığı (Archivo, yeşil kenar): "HSM" / ayar (mono): "CONFIG_SIGNERS=pkcs11"
- kart 2 satırı (body-md): "Donanım güvenlik modülü. Anahtar içinde üretilir, dışarı hiç çıkmaz."
- kart 2 "seçerseniz" satırı (mono, küçük, yeşil ✓): "Anahtar kopyalanamaz; sunucu yalnızca imza ister."
- kart 3 başlığı (Archivo): "KMS" / ayar (mono): "CONFIG_SIGNERS=command"
- kart 3 satırı (body-md): "Bulut anahtar servisi imzalar."
- kart 3 "seçerseniz" satırı (mono, küçük): "Anahtar sağlayıcıda kalır; erişim kuralları ve kayıt onun tarafında."
- benzetme: "Mühür kasada durur; kasa mührü vermez, yalnızca belgeyi mühürleyip geri uzatır."
- künye: "İmza anahtarı"


## Frame 16 — HSM kullanırsanız
compositions/frames/h2-hsm-kazanc.html
keyMessage: HSM'de imza anahtarı çalınamaz, kopyalanamaz ve rotasyonu donanımda yapılır; ama sunucuyu ele geçiren HSM'e yine imza attırabilir; buna karşı ikinci bir imzalayıcı ve uygulamada requiredSignatures(2) kullanılır.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 3 AKIŞ"
- üst çubuk hap: "SEÇENEK"
- kicker (mono, siyah kutu): "HSM SEÇERSENİZ"
- başlık (display-head): "HSM KULLANIRSANIZ"
- kazanç 1 (body-lg, yeşil ✓): "Sunucunun diski ya da yedeği çalınsa bile imza anahtarı çalınmaz."
- kazanç 2 (body-lg, yeşil ✓): "Anahtar başka bir makineye kopyalanıp sahte liste mühürlemek için kullanılamaz; çalışanlar dahil kimse dışarı alamaz."
- kazanç 3 (body-lg, yeşil ✓): "Anahtarın donanımda tutulmasını şart koşan güvenlik denetimlerini karşılamaya yardımcı olur."
- kazanç 4 (body-lg, yeşil ✓): "Anahtarı değiştirmek gerekince yenisi HSM'de üretilir; sunucu yeni anahtarla yeniden başlatılır."
- panel başlığı (mono): "Panel · 8090 · mtls-8092 · İmzalama"
- panel kart başlığı: "İmzalayıcılar"
- tablo başlıkları (mono): "Ad" · "Tür" · "Anahtar kimliği"
- tablo satırı 1 (mono): "hsm" · "pkcs11" · "3fA9c2…" + rozet "birincil"
- tablo satırı 2 (mono, sınır kutusuyla birlikte gelir): "ekip-b" · "command" · "Qm7Lr0…"
- sınır kutusu başlığı (mono, turuncu im): "TEK BAŞINA ÇÖZMEDİĞİ"
- sınır kutusu satırı (body-md): "Sunucuyu ele geçiren, HSM'e yine imza attırabilir. Buna karşı ikinci bir imzalayıcı: anahtarı başka bir ekipte ya da sistemde durur."
- sınır kutusu kod (mono): "sunucu: CONFIG_SIGNERS=hsm,ekip-b · uygulama: requiredSignatures(2)"
- not (body-md): "Telefon, iki imzası birden olmayan listeyi kabul etmez."
- künye: "HSM kazancı"


## Frame 22 — Neden eliptik eğri?
compositions/frames/e1-eliptik-egri.html
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


## Frame 36 — Hangi anahtar, hangi algoritma
compositions/frames/e2-anahtar-haritasi.html
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
