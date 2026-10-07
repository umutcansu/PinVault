---
format: 1920x1080
duration: 169s
message: "PinVault, telefonunuzun yalnızca gerçek sunucunuzla, sunucunuzun da yalnızca gerçek uygulamanızla konuşmasını sağlar; hepsi sizin makinenizde."
arc: concept-explainer with process
audience: PinVault'u ilk kez gören Android geliştiricileri ve ekip yöneticileri
mode: autonomous
music: none
---

# PinVault nasıl çalışır — storyboard

Sessiz video. Anlatım ekrandaki yazıyla yapılır; ses, müzik ve efekt yoktur. Her karedeki ekran metni aşağıda `Ekran metni` altında birebir verilmiştir; işçiler metni değiştirmez, kısaltmaz, çevirmez.

## Video direction

**Dil ve yazım.** Bütün ekran metni Türkçedir. `<html lang="tr">` kullan. Archivo Black satırları büyük harftir; büyük harfli metin kaynakta zaten büyük harfle yazılmıştır (İ, Ş, Ğ, Ü, Ö, Ç dahil). CSS `text-transform` ile büyütme yapma, çünkü "i" harfi yanlış büyür. Mono ve gövde metni yazıldığı gibi kalır.

**Palet (frame.md, creative-mode).** Zemin `cream`, çizgi ve yazı `ink`, ikinci yüzey `cream-2`. Vurguların anlamı bütün videoda sabittir ve izleyici bunu öğrenir:
- `green` = geçti, güvenli, eşleşti (✓).
- `orange` = saldırgan, ret, kesilen bağlantı (✗). Sert gölgenin rengi de turuncudur; bir karede en çok bir sert gölge.
- `yellow` = bilet (PinVault-Token) ve imzalı liste mührü.
- `pink` = cihazın kimlik kartı (cihaz sertifikası).
Bir karede en çok üç vurgu. Yeşil zemin yalnızca son karede. Saf beyaz, degrade, bulanık gölge, parıltı yok. Köşeler kare; tek yuvarlak öğe üst çubuktaki hap etiket.

**Sabit oyuncular.** Telefon: ink çerçeveli, köşeleri kare, dikey bir dikdörtgen; içinde mono "Uygulamanız" ve alt satırda "PinVault kütüphanesi". Sunucu: ink çerçeveli yatay kutu, başlıkta "PinVault sunucusu". Kapılar: sunucu kutusunun yan kenarında küçük etiketli kutucuklar (8090, 8091, 8092, 8093). Kimlik kartı: pembe, kare köşeli küçük kart. Bilet: sarı, kenarı ink, yan yüzünde mono "5 DK". Saldırgan: turuncu dolgulu kare, içinde "?" ya da "SAHTE". Bu şekiller her karede aynı çizilir; böylece kareler tek bir film gibi okunur.

**Çerçeve süsü.** Her karede üstte mono üst çubuk: solda "PINVAULT NASIL ÇALIŞIR", sağda hap etiket (karede verilir). Altta mono künye: solda kare adı, sağda "NN • 13". Son kare krem renkli künye varyantını kullanır.

**Hareket dili.** Uzun kuyruklu yumuşak oturma (`power3`); zıplama, aşma, elastik yok. Her parça kendi okuma anında girer: sessiz video olduğu için zamanlama seslendirmeye değil okuma ritmine göre yapılır. Bir satır ekrana gelince bir sonrakinden önce okunmaya yetecek kadar (kabaca kelime başına 0,35 sn, en az 1,2 sn) bekler. Hiçbir kare ilk %25'te her şeyi dökmez. Paket ve okların hareketi çizgi boyunca kayan küçük daire ya da karttır; yolun kendisi `svg-path-draw` ile çizilir.

**Ritim.** Tutma (nefes) kareleri: Kare 10'un son 3 sn'si ve Kare 12. Geri kalanlar okuma ritmiyle açılır, son parçası geldikten sonra sakin durur; tutma sırasında en çok hafif titreşim.

**Asla.** Slayt gösterisi (her şeyi başta dökmek, sonra donmak). Ekran koruyucu (bağımsız yüzen çok öğe). Döngüsel nefes alma. Arka yarıda yavaş kaydırma ya da itme. Rastgelelik. CSS transition veya keyframes. Uydurulmuş sayı: yalnızca ekran metnindeki sayılar kullanılır. Gerçek şirket logoları. Mor-mavi "yapay zekâ" degradeleri.

**Alt bant.** İçerik çerçevenin üst %83'ünde kalır; alt künye dışında alt banda yük taşıyan öğe konmaz.

---

## Frame 1 — Arada kim var?

- scene: Telefon ile sunucu arasında bir çizgi; ortasına turuncu bir yabancı kayıyor
- voiceover:
- duration: 7s
- transition_in: cut
- status: animated
- src: compositions/frames/01-arada-kim-var.html
- type: hook
- persuasion: Rhetorical question + concretization
- beat: curiosity + unease
- blueprint: compose
- focal: "PEKİ ARADA KİM VAR?" satırı
- roles: telefon ve sunucu = supporting · aradaki çizgi = supporting · turuncu yabancı = foreground subject · krem zemin = background

narrativeRole: Sorunu izleyicinin dilinde açar; her bağlantıda görünmez bir üçüncü kişi ihtimali olduğunu hissettirir.
keyMessage: Uygulama ile sunucu arasındaki hat güvenli değilse, arada biri olabilir.

Ekran metni:
- üst çubuk hap: "GİRİŞ"
- satır 1 (display-lg): "UYGULAMANIZ SUNUCUSUYLA KONUŞUYOR."
- satır 2 (display-lg, turuncu altı çizgi): "PEKİ ARADA KİM VAR?"
- künye: "Arada kim var?"

Compose: ifade iki vuruşta kurulur, son vuruş oturur; vuruşlar arasına küçük bir telefon–sunucu diyagramı girer.
Scene 1 (0.0–2.2s): Ortada, üst üçte birde satır 1 kelime kelime gelir (`dynamic-content-sequencing`). Altında, ekranın %60'ını kaplayan yatay şerit: solda telefon, sağda sunucu kutusu; aradaki çizgi soldan sağa çizilir (`svg-path-draw`). Centered, 3 katman.
Scene 2 (2.2–4.4s): Çizgi üzerinde iki mavi-olmayan ink nokta gidip gelir (istek ve cevap, ink dolgu). Sonra çizginin ortasına yukarıdan turuncu "?" karesi kayıp oturur; çizgi iki parçaya ayrılır ve nokta artık turuncu kareye çarpıp durur.
Scene 3 (4.4–7.0s): Satır 1 hafifçe soluklaşır, satır 2 aynı yerde kelime kelime oturur; "KİM" kelimesinin altına turuncu işaretleyici çizgisi çekilir (`css-marker-patterns`, highlight). Tutma, en çok hafif titreşim.

## Frame 2 — Bugünkü iki çözüm, üç dert

- scene: Üç dert kartı sırayla düşer; her birinde kısa bir neden-sonuç
- voiceover:
- duration: 13s
- transition_in: crossfade
- status: animated
- src: compositions/frames/02-uc-dert.html
- type: pain_point
- persuasion: Rule of three + causal chain (A → B)
- beat: recognition + tension
- blueprint: kinetic-type-beats (Adapt)
- focal: üç dert kartı
- roles: başlık = supporting · üç kart = foreground subject · kartlardaki turuncu "✗" = supporting

narrativeRole: Geliştiricinin zaten yaşadığı üç sorunu adlandırır; PinVault'un neye cevap olduğunu kurar.
keyMessage: Telefonun genel güven deposu da, APK'ya gömülü pin'ler de yetmez; sunucu da karşısındakinin kim olduğunu bilmez.

Ekran metni:
- üst çubuk hap: "SORUN"
- başlık (display-head): "BUGÜN İŞLER NASIL BOZULUYOR"
- kart 1 başlık: "TELEFONUN GÜVEN DEPOSUNA GÜVENMEK"
- kart 1 alt satır: "Araya giren biri telefona kendi sertifikasını ekletirse, sahte sunucu da güvenilir görünür."
- kart 2 başlık: "PİN'LERİ APK'YA GÖMMEK"
- kart 2 alt satır: "Sunucunun sertifikası değişince uygulama güncellemesi gerekir; eski sürümler bağlanamaz."
- kart 3 başlık: "SUNUCU KİMİNLE KONUŞTUĞUNU BİLMEZ"
- kart 3 alt satır: "Karşısındaki gerçek uygulamanız mı, bir kopya mı, root'lu bir telefonda değiştirilmiş hâli mi?"
- künye: "Sorun"

Adapt: kinetic-type-beats'in "3–5 kısa dert ifadesi, her biri tek başına iner" Problem varyantı; ifadeler tam ekran yerine üç dikey kart olarak yan yana birikir.
Scene 1 (0.0–1.5s): Başlık üstte soldan per-word gelir. Altında üç boş kart yuvası yoktur; yalnızca başlık.
Scene 2 (1.5–5.0s): Kart 1 alttan kayıp sol üçte birlik yuvaya oturur (`waterfall-entry`); başlık önce, alt satır 0,6 sn sonra. Kartın sağ üst köşesine küçük turuncu "✗" kare damga basılır.
Scene 3 (5.0–8.5s): Kart 2 orta yuvaya aynı hareketle gelir, sonra "✗".
Scene 4 (8.5–13.0s): Kart 3 sağ yuvaya gelir; bu kart sert turuncu gölgeyi taşır (karenin tek sert gölgesi), çünkü PinVault'un en farklı cevabı buna. Triptych, yoğun. Tutma.

## Frame 3 — PinVault: üç iş, tek kurulum

- scene: PinVault yazısı oturur, altında üç adım kartı dizilir: Pinleme, Kimlik, Atestasyon
- voiceover:
- duration: 11s
- transition_in: crossfade
- status: animated
- src: compositions/frames/03-uc-is.html
- type: product_intro
- persuasion: Frame-then-fill + rule of three
- beat: clarity + orientation
- blueprint: grid-card-assemble (Adapt)
- focal: "PİNVAULT" kelimesi, sonra üç kart
- roles: wordmark = foreground subject · alt açıklama = supporting · üç adım kartı = foreground subject (ikinci perde)

narrativeRole: Çözümü ve vaadi ikinci vuruşta söyler; videonun geri kalanının haritasını verir.
keyMessage: PinVault üç iş yapar: doğru sunucu, tanınan cihaz, gerçek uygulama.

Ekran metni:
- üst çubuk hap: "ÇÖZÜM"
- wordmark (display-xl): "PİNVAULT"
- alt satır (body-lg): "Uygulamanıza giren bir kütüphane ve sizin makinenizde çalışan bir sunucu."
- kart 1: büyük rakam "1", başlık "PİNLEME", alt satır "Telefon yalnızca gerçek sunucunuzla konuşur."
- kart 2: büyük rakam "2", başlık "KİMLİK", alt satır "Sunucu, tanıdığı cihazı içeri alır."
- kart 3: büyük rakam "3", başlık "ATESTASYON", alt satır "Bilet yalnızca değiştirilmemiş uygulamaya verilir."
- künye: "Üç iş"

Adapt: grid-card-assemble'ın "kartlar sırayla yuvalarına oturur, sonra tutar" yapısı; üstte wordmark kitap ayracı gibi durur, kartlar sırayla değil okuma ritmiyle gelir.
Scene 1 (0.0–2.5s): Ortada "PİNVAULT" büyük ve tek başına oturur (per-word değil, tek blok, uzun kuyruklu yükseliş). Altında alt satır 0,8 sn sonra gelir. Centered, %55 boş.
Scene 2 (2.5–3.5s): Wordmark ve alt satır birlikte üst üçte birliğe kayar (`nudge-curve`), alta yer açılır.
Scene 3 (3.5–9.0s): Üç adım kartı soldan sağa, her biri ≈1,8 sn arayla yuvasına oturur (`center-outward-expansion`, doğrudan yuva biçimi). Kart renkleri: 1 krem, 2 pembe, 3 sarı. Kart başlıkları Archivo Black, alt satırlar Space Grotesk.
Scene 4 (9.0–11.0s): Tutma.

## Frame 4 — Parçalar nerede durur

- scene: Üç bölge sırayla kurulur: cihaz, PinVault sunucusu (dört kapı), sizin arka ucunuz; altta iç ağdaki yönetim
- voiceover:
- duration: 17s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/04-topoloji.html
- type: feature_showcase
- persuasion: Progressive disclosure + frame-then-fill
- beat: orientation + comprehension
- blueprint: compose
- focal: üç bölgeli topoloji diyagramı
- roles: üç kesik çizgili bölge = background · telefon, kapı kutuları, arka uç kutuları = foreground subject · bağlantı çizgileri ve etiketleri = supporting · alttaki iki satırlık özet = supporting

narrativeRole: Sistemin haritasını verir: neyin nerede çalıştığı ve hangi kapının internete açık olduğu.
keyMessage: Cihazlar yalnızca üç kapıyla konuşur; yönetim kapısı ve depo iç ağda kalır; bileti sizin arka ucunuz kendisi doğrular.

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
- arka uç kutusu 1: "API SUNUCULARINIZ" / "bileti kendisi doğrular"
- arka uç kutusu 2: "GİRİŞ SUNUCUNUZ" / "cihazlara kayıt token'ı ister"
- telefon → API çizgisi etiketi (mono): "istek + bilet"
- iç ağ bölgesi etiketi (mono): "YALNIZCA İÇ AĞ"
- kapı 8090 kutusu: "8090 · YÖNETİM" / "panel · API anahtarı"
- yönetici kutusu: "YÖNETİCİ"
- özet satırı 1 (body-md, yeşil kare imli): "İnternete açık: 8091 · 8092 · 8093 ve sizin arka ucunuz."
- özet satırı 2 (body-md, turuncu kare imli): "İç ağda: 8090 yönetim kapısı ve depo."
- dipnot (mono, küçük): "Kapı numaraları demo kurulumundan."
- künye: "Topoloji"

Compose: hiçbir kalıp üç bölgeli ağ diyagramını taşımıyor; diyagram bölge bölge kendini kurar. Yerleşim (1920 genişlikte, soldan sağa): cihaz bölgesi ≈%18, sunucu bölgesi ≈%44, arka uç bölgesi ≈%26; iç ağ bölgesi sunucu bölgesinin altında, aynı genişlikte ince bir şerit. Diyagram çerçevenin ≈%60'ını kaplar.
Scene 1 (0.0–1.5s): Başlık üstte gelir. Hiçbir bölge yok.
Scene 2 (1.5–4.0s): Cihaz bölgesinin kesik çizgisi çizilir, telefon içine oturur. Sunucu bölgesinin kesik çizgisi çizilir; içinde sağda depo kutusu belirir.
Scene 3 (4.0–7.0s): 8091, 8092, 8093 kutuları sunucu bölgesinin sol kenarına yukarıdan aşağı sırayla oturur. Telefondan her birine birer çizgi çizilir (`svg-path-draw`). Her çizginin sunucu ucu depoya ince çizgiyle bağlanır.
Scene 4 (7.0–10.0s): Arka uç bölgesi çizilir; API kutusu ve giriş sunucusu kutusu oturur. Telefondan API kutusuna, üstten dolaşan uzun bir çizgi çizilir; etiketi "istek + bilet". Çizgi boyunca küçük sarı bilet bir kez kayar.
Scene 5 (10.0–13.0s): Sunucu bölgesinin altında iç ağ şeridi çizilir; içinde 8090 kutusu ve yönetici kutusu oturur. Yöneticiden 8090'a kısa çizgi. Giriş sunucusundan 8090'a kesik çizgi çizilir (kayıt token'ı isteği).
Scene 6 (13.0–17.0s): Diyagramın altında özet satırı 1, 1,5 sn sonra özet satırı 2 gelir; dipnot en son. Sağdaki üç açık kapı kutusuna kısa yeşil vurgu, 8090'a kısa turuncu vurgu (kenar rengi değişir, dolgu değişmez). Tutma.

## Frame 5 — Parmak izi kontrolü

- scene: Sunucu sertifikasını gösterir; telefon parmak izini cebindeki listeyle karşılaştırır; sahte sertifika eşleşmez
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/05-parmak-izi.html
- type: feature_showcase
- persuasion: Analogy (kimlikteki parmak izi) + before/after contrast
- beat: "aha" + confidence
- blueprint: compose
- focal: telefonun üstündeki karşılaştırma: gelen parmak izi ve listedeki parmak izi yan yana
- roles: telefon = foreground subject · sunucu ve sahte sunucu = supporting · "bildiğim parmak izleri" kartı = foreground subject · eşleşme/eşleşmeme damgası = supporting

narrativeRole: Katman 1'in mekanizmasını benzetmeyle somutlar.
keyMessage: Telefon, sunucunun gösterdiği sertifikanın parmak izini bildiği listeyle karşılaştırır; tutmazsa tek bayt göndermeden bağlantıyı keser.

Ekran metni:
- üst çubuk hap: "1/3 · PİNLEME"
- başlık (display-head): "PARMAK İZİ KONTROLÜ"
- açıklama (body-lg): "Sunucu her bağlantıda sertifikasını gösterir. Telefon onun parmak izini (pin) bildiği listeyle karşılaştırır."
- telefonun yanındaki kart başlığı (mono): "BİLDİĞİM PARMAK İZLERİ"
- kart satırları (mono): "ziA0hyMD…" ve "vXC1UZ8O…"
- gerçek sunucunun sertifika kartı (mono): "ziA0hyMD…"
- yeşil damga: "EŞLEŞTİ ✓"
- yeşil alt yazı: "Bağlantı kurulur."
- sahte sunucu kutusu: "SAHTE SUNUCU"
- sahte sertifika kartı (mono): "Xk91Pq7R…"
- turuncu damga: "EŞLEŞMEDİ ✗"
- turuncu alt yazı: "Telefon tek bayt göndermeden bağlantıyı keser."
- künye: "Pinleme"

Compose. Yerleşim: asimetrik 60/40. Solda (%60) sahne: telefon solda, gerçek sunucu sağda, arada çizgi. Sağda (%40) başlık ve açıklama metin rayı.
Scene 1 (0.0–2.5s): Sağ rayda başlık, sonra açıklama gelir. Solda telefon ve "BİLDİĞİM PARMAK İZLERİ" kartı (telefonun üstünde, iki satır) oturur.
Scene 2 (2.5–6.0s): Gerçek sunucu sağdan oturur. Sunucudan mor-olmayan, krem-2 dolgulu küçük sertifika kartı ("ziA0hyMD…") çizgi boyunca telefona kayar ve telefonun yanında, listenin karşısında durur. Listedeki eşleşen satır ve gelen kart aynı anda yeşil kenar alır; aralarına kısa yeşil çizgi çekilir.
Scene 3 (6.0–8.0s): "EŞLEŞTİ ✓" yeşil damgası oturur, altında "Bağlantı kurulur." Çizgi üzerinde ink nokta bir kez gidip gelir.
Scene 4 (8.0–11.5s): Gerçek sunucu ve onun kartı soluklaşır; aynı yere turuncu kenarlı "SAHTE SUNUCU" kayar (düz yer değiştirme, zıplamasız). Sahte sertifika kartı "Xk91Pq7R…" telefona kayar; listeyle karşılaştırılır, hiçbir satır yanmaz.
Scene 5 (11.5–15.0s): "EŞLEŞMEDİ ✗" turuncu damgası basılır, telefon ile sahte sunucu arasındaki çizgi ortadan kopar (iki parça geri çekilir). Altında turuncu alt yazı. Bu damga karenin tek sert gölgesi. Tutma.

## Frame 6 — Liste sunucudan, mühürlü gelir

- scene: Panelden çıkan mühürlü ve son kullanma tarihli liste telefonlara gider; sertifika değişince yeni liste, APK aynı
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/06-muhurlu-liste.html
- type: feature_showcase
- persuasion: Concretization (mühürlü, tarihli belge) + before/after
- beat: comprehension + relief
- blueprint: compose
- focal: sarı mühürlü pin listesi belgesi
- roles: belge = foreground subject · panel kutusu ve telefonlar = supporting · APK kutusu = supporting · "son liste" notu = supporting

narrativeRole: Pin'lerin APK'da değil, sunucudan imzalı ve süreli bir liste olarak geldiğini ve bunun güncelleme derdini çözdüğünü gösterir.
keyMessage: Pin listesi imzalı ve süreli gelir; sertifika değişince panelden güncellenir, APK değişmez.

Ekran metni:
- üst çubuk hap: "1/3 · PİNLEME"
- başlık (display-head): "LİSTE SUNUCUDAN GELİR"
- belge başlığı (mono): "PİN LİSTESİ"
- belge satırları (mono): "api.ornek.com · ziA0hyMD…" / "cdn.ornek.com · kök CA" / "son kullanma: 24 saat"
- mühür (sarı, −4° badge): "İMZALI"
- adım 1 (body-md): "Telefon listeyi ister, imzasını kontrol eder, saklar."
- adım 2 (body-md): "Sertifika değişti mi? Panelde güncellenir, telefonlar yeni listeyi alır."
- APK kutusu: "APK" / "aynı kalır"
- not (body-md, ince ink kenarlı kutu): "Sunucuya ulaşılamazsa telefon son listeyle, süresi dolana kadar çalışır."
- künye: "Mühürlü liste"

Compose. Yerleşim: soldan sağa akış şeridi (full-width strip): panel kutusu → belge → üç telefon; altta adım satırları.
Scene 1 (0.0–2.0s): Başlık üstte. Solda "PANEL" kutusu (ink çerçeve, mono) oturur.
Scene 2 (2.0–5.0s): Panelden belge çıkar, ortaya kayar ve satırları teker teker yazılır (`discrete-text-sequence`). Sonra sarı "İMZALI" mührü −4° açıyla basılır (karenin tek sert gölgesi bu mühürde).
Scene 3 (5.0–8.0s): Belgenin küçük kopyaları sağdaki üç telefona çizgiler boyunca kayar; her telefonun üstünde küçük yeşil ✓. Adım 1 satırı belirir.
Scene 4 (8.0–11.5s): Belgedeki "ziA0hyMD…" satırı turuncu çizgiyle üstü çizilir ve yerine "vXC1UZ8O…" yazılır (geri silme ve yeniden yazma, `discrete-text-sequence`). Yeni kopyalar telefonlara tekrar kayar. Adım 2 satırı belirir. Aynı anda sağ altta APK kutusu belirir, üstünde "aynı kalır" ve yeşil ✓.
Scene 5 (11.5–15.0s): Not kutusu en altta belirir. Tutma.

## Frame 7 — Cihazın kimlik kartı

- scene: Cihaz bir kez kayıt olur, kendi pembe kimlik kartını alır, 8092'de her bağlantıda gösterir; dosyalar yalnızca ona gider
- voiceover:
- duration: 16s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/07-kimlik-karti.html
- type: feature_showcase
- persuasion: Analogy (personel kartı) + numbered enumeration
- beat: comprehension + confidence
- blueprint: grid-card-assemble (Adapt)
- focal: pembe kimlik kartı
- roles: dört adımlık dikey liste = foreground subject · telefon ve pembe kart = foreground subject · 8092 kapısı = supporting

narrativeRole: Katman 2'yi personel kartı benzetmesiyle kurar.
keyMessage: Cihaz bir kez kayıt olur, kendi kartını alır; sunucu kartı tanıdığı cihazı içeri alır ve dosyayı yalnızca ona verir.

Ekran metni:
- üst çubuk hap: "2/3 · KİMLİK"
- başlık (display-head): "CİHAZIN KİMLİK KARTI"
- benzetme satırı (body-lg): "Bir personel kartı gibi: kapıda gösterilir, gerekirse iptal edilir."
- adım 1: "1" / "BİR KEZ KAYIT" / "Yöneticinin verdiği token, ortak kayıt kodu ya da yönetici onayıyla."
- adım 2: "2" / "KART TELEFONDA ÜRETİLİR" / "Anahtarı telefonun kasasından çıkmaz."
- adım 3: "3" / "HER BAĞLANTIDA GÖSTERİLİR" / "8092 yalnızca tanıdığı kartı içeri alır."
- adım 4: "4" / "DOSYALAR YALNIZCA ONA" / "Dosya, kartı tanınan cihaza gider."
- pembe kart üstü (mono): "tablet-07"
- künye: "Kimlik"

Adapt: grid-card-assemble'ın "Benefits vertical-list" varyantı: sağda dört adım dikey listede ≈1 adım / 3 sn birikir; solda telefon ve kart, adımlarla eşzamanlı değişir.
Scene 1 (0.0–2.5s): Başlık ve benzetme satırı sağ üstte. Solda telefon oturur, yanında kart yok.
Scene 2 (2.5–5.5s): Adım 1 listeye girer. Solda telefonun üstünden küçük bir token şeridi (krem, ink kenarlı, mono "token") telefona girer.
Scene 3 (5.5–8.5s): Adım 2 girer. Telefonun içinden pembe kart "tablet-07" yükselir ve telefonun yanına oturur; kartın içindeki küçük anahtar simgesi telefonun içinde kalır (anahtar çıkmaz).
Scene 4 (8.5–12.0s): Adım 3 girer. Sağda 8092 kapı kutusu belirir; kart çizgi boyunca kapıya kayar, kapı yeşil kenar alır ve açılır (kapının iki yarısı ayrılır).
Scene 5 (12.0–16.0s): Adım 4 girer. Kapıdan telefona küçük bir dosya kartı kayar. Tutma. Dört adım kartı: 1 krem, 2 krem, 3 pembe, 4 yeşil (adım dizisi yeşille biter).

## Frame 8 — Kartın ömrü

- scene: Yatay zaman şeridi: kayıt → yenileme → kurtarma → iptal
- voiceover:
- duration: 13s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/08-kartin-omru.html
- type: feature_showcase
- persuasion: Signposting (önce… sonra… en son) + timeline
- beat: comprehension + foresight
- blueprint: compose
- focal: dört istasyonlu zaman şeridi
- roles: şerit ve dört istasyon = foreground subject · şerit üstünde kayan pembe kart = supporting · istasyon açıklamaları = supporting

narrativeRole: Kartın kaybolmadan nasıl yenilendiğini, süresi geçince nasıl kurtarıldığını ve nasıl iptal edildiğini tek bakışta gösterir.
keyMessage: Kart süresi dolmadan yenilenir; dolduysa 8093'ten aynı anahtarla kurtarılır; yönetici isterse iptal eder.

Ekran metni:
- üst çubuk hap: "2/3 · KİMLİK"
- başlık (display-head): "KARTIN ÖMRÜ"
- istasyon 1: "KAYIT" / "Kart bir kez alınır."
- istasyon 2: "YENİLEME" / "Süre dolmadan, 8092'den. Anahtar aynı, kart yeni."
- istasyon 3: "KURTARMA" / "Süre dolduysa 8093'ten. Kimliği, aynı anahtarla atılan imza kanıtlar."
- istasyon 4: "İPTAL" / "Yönetici panelden iptal eder; kart artık hiçbir kapıyı açmaz."
- künye: "Kartın ömrü"

Compose. Yerleşim: çerçeve genişliğinde yatay şerit, şeridin üstünde dört istasyon noktası, altlarında açıklama kartları.
Scene 1 (0.0–1.5s): Başlık. Şerit soldan sağa çizilir.
Scene 2 (1.5–4.0s): İstasyon 1 noktası ve kartı belirir; pembe kart şeridin başına oturur.
Scene 3 (4.0–6.5s): Pembe kart istasyon 2'ye kayar; kart çevrilir ve yenisi gelir (kart üstünde kısa yeşil ✓). İstasyon 2 açıklaması belirir.
Scene 4 (6.5–9.5s): İstasyon 3: kart soluk gri olur ("süresi doldu"), sonra imza simgesiyle (kart üzerinde küçük mono "imza") yeniden pembeleşir. Açıklama belirir.
Scene 5 (9.5–13.0s): İstasyon 4: kartın üstüne turuncu "İPTAL" damgası basılır (karenin tek sert gölgesi); açıklama belirir. Tutma.

## Frame 9 — Kapıdaki kontrol: atestasyon

- scene: Telefon kendini ölçer, raporu imzalar, sunucu karar verir, geçene 5 dakikalık sarı bilet; bilet API sunucunuza gider
- voiceover:
- duration: 17s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/09-atestasyon.html
- type: feature_showcase
- persuasion: Analogy (kapıda bilet kontrolü) + causal chain
- beat: fascination + comprehension
- blueprint: compose
- focal: sarı bilet "PINVAULT-TOKEN · 5 DK"
- roles: telefonun ölçüm listesi = foreground subject (ilk yarı) · bilet = foreground subject (ikinci yarı) · sunucu ve API sunucusu = supporting

narrativeRole: Katman 3'ü bilet benzetmesiyle kurar: kimlik yetmez, uygulamanın kendisinin değiştirilmemiş olduğu da kanıtlanmalı.
keyMessage: Telefon kendini ölçüp imzalar, karar sunucunundur; geçen uygulama 5 dakikalık bir bilet alır ve API sunucunuz bileti kendisi kontrol eder.

Ekran metni:
- üst çubuk hap: "3/3 · ATESTASYON"
- başlık (display-head): "KAPIDAKİ KONTROL"
- adım satırı 1 (mono kicker): "1 · TELEFON KENDİNİ ÖLÇER"
- ölçüm çipleri (mono, krem hap değil, kare): "root?" "emülatör?" "debugger?" "Frida?" "kopya uygulama?" "APK değişmiş mi?"
- adım satırı 2 (mono kicker): "2 · SONUCU İMZALAR"
- imza etiketi (mono): "telefonun kasasındaki anahtarla"
- adım satırı 3 (mono kicker): "3 · SUNUCU KARAR VERİR"
- karar damgası (yeşil): "GEÇTİ"
- bilet (sarı): "PINVAULT-TOKEN" / "5 DK"
- adım satırı 4 (mono kicker): "4 · BİLET HER İSTEKTE GİDER"
- API kutusu: "API SUNUCUNUZ" / "bileti kendisi doğrular"
- alt not (body-md): "Bilet arka planda yaklaşık 5 dakikada bir yenilenir."
- künye: "Atestasyon"

Compose. Yerleşim: soldan sağa üç durak: telefon (sol), PinVault sunucusu (orta), API sunucunuz (sağ); adım satırları üstte bir rayda soldan sağa birikir.
Scene 1 (0.0–2.0s): Başlık. Solda telefon oturur.
Scene 2 (2.0–6.0s): Adım satırı 1. Telefonun yanında altı ölçüm çipi teker teker belirir (≈0,4 sn arayla); her birinin yanına küçük yeşil ✓ gelir.
Scene 3 (6.0–8.5s): Adım satırı 2. Çipler bir "rapor" kartında toplanır (`center-outward-expansion` tersine, kart içine toplanma); kartın köşesine ink mühür, yanında imza etiketi.
Scene 4 (8.5–11.5s): Adım satırı 3. Rapor kartı ortadaki sunucuya kayar; sunucunun üstünde yeşil "GEÇTİ" damgası belirir. Sunucudan sarı bilet çıkıp telefona kayar (karenin tek sert gölgesi bilette).
Scene 5 (11.5–15.0s): Adım satırı 4. API kutusu sağda belirir. Telefondan API'ye istek çizgisi çizilir; bilet çizgi boyunca kayar, API kutusunun üstünde yeşil ✓ belirir.
Scene 6 (15.0–17.0s): Alt not belirir. Tutma.

## Frame 10 — Root'lu telefon bilet alamaz

- scene: Root'lu, Frida'lı telefon aynı yolu dener: rapor reddedilir, bilet yok, API 401 döner; liste gizli değil, kilit bilettir
- voiceover:
- duration: 13s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/10-ret.html
- type: social_proof
- persuasion: Counterexample + common-belief vs reality
- beat: unease → clarity
- blueprint: compose
- focal: API kutusunun döndüğü "401" ve son satır "KAPIYI TUTAN, BİLETTİR"
- roles: turuncu telefon = foreground subject · sunucu ve API kutusu = supporting · gerçek satırı = foreground subject (son 3 sn)

narrativeRole: Kanıt karesi: geçmeyen uygulamaya ne olduğunu ve neyin kilit olduğunu gösterir; pin listesinin gizli olmadığı yanlış anlamasını düzeltir.
keyMessage: Geçmeyen uygulama bilet alamaz, API sunucunuz onu çevirir; pin listesi gizli değildir, asıl kilit bilettir.

Ekran metni:
- üst çubuk hap: "3/3 · ATESTASYON"
- başlık (display-head): "ROOT'LU TELEFON NE OLUR"
- telefon etiketi (turuncu kenarlı): "root · Frida"
- ölçüm çipleri: "root!" "Frida!" (turuncu ✗ ile)
- karar damgası (turuncu): "RET"
- bilet yerine boş kesik çizgili çerçeve (mono): "bilet yok"
- API kutusu cevabı (mono, turuncu): "401 · bilet yok"
- gerçek satırı (display-head): "KAPIYI TUTAN, BİLETTİR."
- gerçek alt satırı (body-md): "Pin listesi gizli değildir; herkes alabilir. Değiştirilmiş uygulama yine de bilet alamaz."
- künye: "Ret"

Compose. Aynı üç duraklı sahne, Frame 9'un aynası; telefon turuncu kenarlı.
Scene 1 (0.0–2.0s): Başlık. Turuncu kenarlı telefon solda; "root · Frida" etiketi.
Scene 2 (2.0–4.5s): İki ölçüm çipi belirir, her birine turuncu ✗.
Scene 3 (4.5–7.0s): Rapor ortadaki sunucuya kayar; turuncu "RET" damgası basılır. Bilet çıkacak yerde boş kesik çizgili çerçeve "bilet yok" belirir.
Scene 4 (7.0–9.5s): Telefon yine de API'ye istek atar; çizgi API kutusunun önünde kesilir ve kutuda "401 · bilet yok" yazar (sert gölge bu kutuda).
Scene 5 (9.5–13.0s): Sahne yukarı kayar ve soluklaşır; altta gerçek satırı büyük, sonra alt satırı gelir. Son 3 sn tutma (nefes karesi).

## Frame 11 — Her açılışta, bu sırayla

- scene: Beş numaralı adım kartı yukarıdan aşağı birikir: yenileme, liste, sağlık kontrolü, atestasyon, anahtarlar
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/11-acilis-sirasi.html
- type: feature_showcase
- persuasion: Numbered enumeration + causal chain (neden bu sıra)
- beat: mastery + momentum
- blueprint: grid-card-assemble (Adapt)
- focal: beş adımlık dikey liste
- roles: beş adım kartı = foreground subject · sağdaki "neden" notları = supporting

narrativeRole: Üç katmanın uygulama açılırken hangi sırayla çalıştığını, nedenleriyle gösterir.
keyMessage: Her açılışta önce kart yenilenir, sonra liste alınır ve kontrol edilir, en son atestasyon bileti alınır.

Ekran metni:
- üst çubuk hap: "SIRA"
- başlık (display-head): "HER AÇILIŞTA, BU SIRAYLA"
- adım 1: "1" / "KART YENİLENİR" / "Vakti geldiyse. Yalnız kimlikli (mTLS) uygulamada."
- adım 1 neden (mono, sağda): "süresi dolmuş kartla 8092'ye girilmez"
- adım 2: "2" / "PİN LİSTESİ ALINIR" / "İmzası kontrol edilir, saklanır."
- adım 3: "3" / "SUNUCUYA HÂLÂ ULAŞILIYOR MU?" / "Yeni liste bağlantıyı kopardıysa eskisine dönülür."
- adım 4: "4" / "ATESTASYON → BİLET" / "Uygulamada açıksa. Kart ve liste hazır olmalı."
- adım 4 neden (mono, sağda): "imza için anahtar ve kart gerekir"
- adım 5: "5" / "ŞİFRELEME ANAHTARLARI BİLDİRİLİR" / "Uçtan uca şifreli ya da ekran kilitli dosya varsa."
- dipnot (mono, küçük): "Ayrıntı: adım adım animasyonun 2. bölümü."
- künye: "Açılış sırası"

Adapt: grid-card-assemble'ın dikey liste varyantı; her satır ≈2,4 sn arayla, okunma süresi kadar bekleyerek birikir.
Scene 1 (0.0–1.5s): Başlık.
Scene 2 (1.5–4.0s): Adım 1 kartı girer (sol %65), sağında neden notu ince ink çizgiyle bağlanır.
Scene 3 (4.0–6.5s): Adım 2 kartı girer; 1 ile 2 arasına kısa aşağı ok çizilir.
Scene 4 (6.5–9.0s): Adım 3 kartı girer, ok.
Scene 5 (9.0–11.5s): Adım 4 kartı girer (sarı dolgu: bilet), ok; neden notu sağda.
Scene 6 (11.5–15.0s): Adım 5 kartı girer (yeşil dolgu, liste yeşille biter), ok. Dipnot en altta. Tutma.

## Frame 12 — Üç cümlede PinVault

- scene: Üç kısa cümle tek tek oturur, altında tek satır
- voiceover:
- duration: 9s
- transition_in: crossfade
- status: animated
- src: compositions/frames/12-uc-cumle.html
- type: branding
- persuasion: Distillation + callback (Kare 3'teki üç kart)
- beat: "now I get it" + satisfaction
- blueprint: kinetic-type-beats (Adapt)
- focal: üç satırlık özet
- roles: üç satır = foreground subject · alt satır = supporting

narrativeRole: Mesajı tek bakışta hatırlanır biçimde damıtır; Kare 3'ün üç işine geri döner.
keyMessage: Doğru sunucu, tanınan cihaz, gerçek uygulama; hepsi sizin makinenizde.

Ekran metni:
- üst çubuk hap: "ÖZET"
- satır 1 (display-lg): "DOĞRU SUNUCU."
- satır 2 (display-lg): "TANINAN CİHAZ."
- satır 3 (display-lg): "GERÇEK UYGULAMA."
- alt satır (body-lg): "Hepsi sizin makinenizde; veri dışarı çıkmaz."
- künye: "Özet"

Adapt: kinetic-type-beats'in "ifade vuruş vuruş kurulur, son vuruş oturur" yapısı; üç satır alt alta birikir.
Scene 1 (0.0–2.0s): Satır 1 soldan oturur; solunda küçük krem kare "1".
Scene 2 (2.0–4.0s): Satır 2 oturur; solunda pembe kare "2".
Scene 3 (4.0–6.0s): Satır 3 oturur; solunda sarı kare "3".
Scene 4 (6.0–9.0s): Alt satır gelir. Tutma (nefes karesi). Centered-left, %50 boş.

## Frame 13 — Adım adım izleyin

- scene: Yeşil kapanış plakası; animasyonun yolu ve mühür
- voiceover:
- duration: 8s
- transition_in: crossfade
- status: animated
- src: compositions/frames/13-kapanis.html
- type: cta
- persuasion: Call to explore + callback
- beat: resolve + inspiration
- blueprint: titlecard-reveal (Reproduce)
- focal: "ADIM ADIM İZLEYİN" satırı
- roles: yeşil zemin = background · başlık = foreground subject · dosya yolu = supporting · pembe mühür = supporting

narrativeRole: İzleyiciyi ayrıntılı adım adım animasyona yollar.
keyMessage: Her isteğin ayrıntısı adım adım animasyonda.

Ekran metni:
- üst çubuk hap (krem varyant): "SON"
- başlık (display-lg, krem): "ADIM ADIM İZLEYİN"
- alt satır (mono, krem): "docs/animation/pinvault-request-flow.tr.html"
- alt satır 2 (body-md, krem): "15 bölüm · 99 adım · panel ve telefon ekranlarıyla"
- mühür (pembe, −6°): "PINVAULT" / "2.2"
- künye: "Kapanış"

Reproduce: titlecard-reveal'in tek sakin hareketi (yukarı kayıp beliren başlık), sonra durağan tutma.
Scene 1 (0.0–2.5s): Yeşil zemin. Başlık yukarı kayarak belirir, ortada.
Scene 2 (2.5–5.0s): Dosya yolu ve ikinci alt satır sırayla belirir.
Scene 3 (5.0–8.0s): Sağ alt köşede pembe mühür −6° açıyla oturur. Tutma; videonun tek gerçek çıkışı: son 0,8 sn'de her şey krem zemine sönümlenir.
