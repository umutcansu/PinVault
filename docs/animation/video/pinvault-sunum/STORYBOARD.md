---
format: 1920x1080
duration: 412s
message: "SSL pinning telefonu sahte sunucudan korur; PinVault pinlemenin üç eksiğini kapatır, kurulumdan ilk isteğe on halkada çalışır ve dosyaları seçtiğiniz cihaza, seçtiğiniz korumayla dağıtır."
arc: concept-explainer with process
audience: PinVault'u ilk kez görecek geliştirici ve yöneticiler (sunum)
mode: autonomous
music: none
---

# PinVault — sunum filmi (storyboard)

Dört bölüm: 1 · Amaç (SSL pinning ve eksikleri), 2 · PinVault ne ekler (üç cevap, panel karşılıkları ve topoloji), 3 · Baştan sona akış (on halka, geçmeyen telefon, panelde atestasyon ayarı), 4 · Dosyalar ve şifreleme (panelden yükleme, kim alabilir, telefon alır, üç koruma, telefonda kilit/süre/iptal). Kare 1, 6, 9 ve 24 bölüm kartlarıdır.
Kopyalanan kareler "pinvault-nasil-calisir" (01-arada-kim-var, 05-parmak-izi, 03-uc-is, 04-topoloji, 10-ret, 12-uc-cumle) ve "pinvault-bastan-sona" (01-yeni-tablet … 14-kapanis) projelerinden alınmıştır; yalnızca üst çubuk etiketi, hap etiketi ve sayaçları bu filme göre değiştirildi, 03-uc-is'e panel şeritleri eklendi. Yeni kareler: p1–p6 (bölüm kartları, normal TLS, üç eksik), a1 (panelde atestasyon), d1–d5 (dosyalar).

Sessiz video. Ekran metni her karede birebir verilmiştir.

## Video direction

**Dil ve yazım.** Bütün ekran metni Türkçedir. Kök öğeye `lang="tr"` koy. Archivo Black satırları büyük harftir; büyük harfli metin kaynakta zaten büyük harfle yazılmıştır (İ, Ş, Ğ, Ü, Ö, Ç dahil). CSS `text-transform` kullanma. Mono ve gövde metni yazıldığı gibi kalır. Kod satırları JetBrains Mono ile, girintisi korunarak yazılır.

**Palet (frame.md, creative-mode).** Zemin `cream`, çizgi ve yazı `ink`, ikinci yüzey `cream-2`. Vurguların anlamı bütün videoda sabittir:
- `green` = geçti, güvenli, eşleşti (✓).
- `orange` = saldırgan, ret, yanlış inanış (✗). Sert gölgenin rengi de turuncudur; bir karede en çok bir sert gölge.
- `yellow` = kayıt token'ı ve PinVault-Token ve imza mührü.
- `pink` = cihazın kimlik kartı (cihaz sertifikası).
Bir karede en çok üç vurgu. Yeşil zemin yalnızca son karede. Saf beyaz, degrade, bulanık gölge, parıltı yok. Köşeler kare; tek yuvarlak öğe üst çubuktaki hap etiket.

**Sabit oyuncular** (her karede aynı çizilir):
- Telefon: ink çerçeveli dikey dikdörtgen, üstte kısa hoparlör çizgisi; ekranında mono "Uygulamanız", altında siyah şerit içinde "PinVault kütüphanesi".
- PinVault sunucusu: ink çerçeveli kutu, siyah başlık şeridinde mono "PinVault sunucusu"; sol kenarında küçük kapı etiketleri (8090, 8091, 8092, 8093).
- Panel ekranı: ink çerçeveli tarayıcı benzeri kutu; üstte siyah şerit ve mono "Panel · 8090"; içinde sekmeler ve kartlar gerçek etiketleriyle; düğmeler ink çerçeveli kare kutular.
- API sunucunuz: ink çerçeveli kutu, başlık "API SUNUCUNUZ", altında mono "api.ornek.com".
- Token: sarı, kenarı ink, yatay kısa şerit; içinde mono "token".
- Kimlik kartı: pembe, kare köşeli küçük kart; üstünde mono "tablet-07".
- PinVault-Token: sarı kart, solda "PINVAULT-TOKEN", sağda kesik çizgiyle ayrılmış "5 DK".
- Pin: krem-2 kutucuk içinde mono parmak izi ("ziA0hyMD…").

**Zincir şeridi (halka kareleri 3–12'de, kare 1'de tanıtılır, kare 14'te tamamlanır).** Üst çubuğun hemen altında, y = 104 px'ten başlayan, 40 px yüksekliğinde yatay bir şerit: 10 hücre, her biri 160 px genişlikte, x = 96 + i × 174 (i = 0…9). Hücre metni mono 15 px, büyük harf: "1 KURULUM", "2 APK", "3 HOST", "4 KAYIT TOKEN'I", "5 TELEFONA", "6 KAYIT İSTEĞİ", "7 KART", "8 PİN LİSTESİ", "9 ATESTASYON", "10 İLK İSTEK". Hücreler arasında 14 px'lik ince ink çizgi (zincir). Biten halkalar: ink dolgu, krem yazı. Şu anki halka: krem dolgu, 4 px ink kenar, ink yazı, altında 4 px turuncu değil sarı alt çizgi. Gelecek halkalar: 2 px ink kenar, %35 saydamlık. Şerit karenin ilk 0,6 saniyesinde zaten durur (önceki kareden devam ediyor gibi); yalnızca şu anki hücrenin dolgusu ve alt çizgisi 0,2–0,8 sn arasında oturur.

**Benzetme şeridi (halka kareleri 3–12).** Her halka karesinin altında, y ≈ 830–880 arasında, sol kenara yaslı, krem-2 dolgulu, 2 px ink kenarlı yatay kutu: solda siyah zeminli küçük mono etiket "BENZETME", sağında gövde metni (Space Grotesk, ≈26 px). Karenin son üçte birinde belirir.

**Çerçeve süsü.** Üstte mono üst çubuk: solda bölüm etiketi ("PINVAULT · 1 AMAÇ", "PINVAULT · 2 ÇÖZÜM", "PINVAULT · 3 AKIŞ", "PINVAULT · 4 DOSYALAR", "PINVAULT · ÖZET"; karede verilir), sağda hap etiket. Altta mono künye: solda kare adı, sağda "NN • 32". Son kare krem renkli künye varyantını kullanır.

**Hareket dili.** Uzun kuyruklu yumuşak oturma (`power3`); zıplama, aşma, elastik yok. Her parça kendi okuma anında girer: sessiz video olduğu için zamanlama okuma ritmine göre yapılır. Bir satır geldikten sonra bir sonraki parça gelmeden önce kabaca kelime başına 0,35 sn (en az 1,2 sn) beklenir. Hiçbir kare ilk %25'te her şeyi dökmez. Paketler (token, kart, PinVault-Token, liste) çizgi boyunca kayan küçük kartlardır; yolun kendisi soldan sağa çizilerek belirir. Panelde bir düğmeye "basılması" düğmenin kısa bir an içe çökmesi ve ink dolguya dönmesiyle gösterilir; imleç çizilmez.

**Ritim.** Tutma (nefes) kareleri: Kare 2'nin sonu ve Kare 14. Diğerleri okuma ritmiyle açılır, son parça geldikten sonra sakin durur; tutma sırasında en çok hafif titreşim.

**Asla.** Slayt gösterisi (her şeyi başta dökmek, sonra donmak). Ekran koruyucu (bağımsız yüzen çok öğe). Döngüsel nefes alma. Arka yarıda yavaş kaydırma ya da itme. Rastgelelik. CSS transition veya keyframes. Uydurulmuş sayı: yalnızca ekran metnindeki sayılar kullanılır. Gerçek şirket logoları. Fare imleci.

**Alt bant.** Yük taşıyan içerik y ≤ 900 px içinde kalır; altında yalnızca künye.


---

## Frame 1 — Bölüm 1: Amaç

- scene: Bölüm başlık kartı: büyük "1", "AMAÇ: SSL PINNING", altta dört bölümlük ilerleme
- voiceover:
- duration: 4.5s
- transition_in: cut
- status: animated
- src: compositions/frames/p1-bolum-amac.html
- type: hook
- persuasion: Signposting (önce amaç)
- beat: orientation
- blueprint: compose
- focal: büyük bölüm numarası ve başlık
- roles: numara bloğu = foreground subject · başlık = foreground subject · üç bölüm şeridi = supporting

narrativeRole: Sunumun yapısını ilk saniyede gösterir: önce amaç, sonra çözüm, sonra akış.
keyMessage: Önce SSL pinning'in neden gerektiğini konuşacağız.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 1 / 4"
- numara bloğu (Archivo, çok büyük): "1"
- kicker (mono, siyah kutu): "BÖLÜM 1"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Telefon, konuştuğu sunucunun gerçekten sizin sunucunuz olduğunu nasıl bilir?"
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (şu anki) · "2 ÇÖZÜM" · "3 AKIŞ" · "4 DOSYALAR"
- künye: "Bölüm 1" / sayaç "01 • 32"

Compose. Yerleşim: solda (%30) ink çerçeveli kare numara bloğu (≈ 360×360, krem-2 dolgu, sert gölge karenin tek sert gölgesi); sağda (%60) kicker, başlık, alt satır; altta (y ≈ 760–800) çerçeve genişliğinde dört hücreli bölüm şeridi (hücre ≈ 394×44, aralarında ince ink çizgi; şu anki hücre ink dolgu krem yazı, diğerleri 2 px ink kenar %35 saydam).
Scene 1 (0.0–1.2s): Numara bloğu soldan oturur; içinde "1" yukarı kayarak belirir.
Scene 2 (1.2–2.6s): Kicker, sonra başlık kelime kelime.
Scene 3 (2.6–4.5s): Alt satır; bölüm şeridi soldan çizilir, şu anki hücre dolar. Tutma.

## Frame 2 — Arada kim var?

- scene: Telefon ile sunucu arasında bir çizgi; ortasına turuncu bir yabancı kayıyor
- voiceover:
- duration: 7s
- transition_in: crossfade
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

## Frame 3 — Normal TLS neye güvenir

- scene: Telefonun güven deposu kurum çipleriyle dolu; araya girenin kurumu depoya eklenir; sahte sunucunun sertifikası "güvenilir" geçer
- voiceover:
- duration: 13s
- transition_in: crossfade
- status: animated
- src: compositions/frames/p2-normal-tls.html
- type: pain_point
- persuasion: Causal chain + concretization (güven deposu bir anahtarlık gibi)
- beat: unease + recognition
- blueprint: compose
- focal: telefonun güven deposu kutusu
- roles: telefon = supporting · güven deposu kutusu ve çipleri = foreground subject · turuncu "araya girenin kurumu" çipi = foreground subject · sahte sunucu = supporting · son satır = foreground subject (son 3 sn)

narrativeRole: Pinlemenin neden gerektiğini kurar: normal TLS'in güvendiği şey çok geniştir ve genişletilebilir.
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
- künye: "Normal TLS" / sayaç "03 • 32"

Compose. Yerleşim: üstte başlık ve açıklama; ortada solda telefon, ortada güven deposu kutusu (≈ %40 genişlik, çipler 3×2 ızgara), sağda sahte sunucu; altta son satır.
Scene 1 (0.0–2.5s): Başlık, sonra açıklama.
Scene 2 (2.5–5.0s): Telefon ve yanında güven deposu kutusu; altı çip ≈0,3 sn arayla dolar.
Scene 3 (5.0–8.0s): Turuncu çip sağdan kayıp depodaki boş yuvaya girer; altında açıklaması.
Scene 4 (8.0–10.5s): Sağda sahte sunucu belirir; sertifika kartı telefona kayar; depodaki turuncu çip ile kart arasına turuncu çizgi; "GÜVENİLİR ✓" damgası ve "ama sahte" notu (sert gölge bu damgada).
Scene 5 (10.5–13.0s): Son satır gelir. Tutma.

## Frame 4 — Parmak izi kontrolü

- scene: Sunucu sertifikasını gösterir; telefon parmak izini cebindeki listeyle karşılaştırır; sahte sertifika eşleşmez
- voiceover:
- duration: 15s
- transition_in: crossfade
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
- üst çubuk hap: "AMAÇ"
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

## Frame 5 — Pinlemenin üç eksiği

- scene: Üç numaralı kart: pin'ler APK'da kalır, sunucu cihazı tanımaz, uygulamanın gerçek olduğunu bilmez
- voiceover:
- duration: 14s
- transition_in: crossfade
- status: animated
- src: compositions/frames/p3-uc-eksik.html
- type: pain_point
- persuasion: Rule of three + frame-then-fill (bir sonraki karedeki üç cevaba hazırlık)
- beat: tension + recognition
- blueprint: compose
- focal: üç eksik kartı
- roles: başlık = supporting · üç kart = foreground subject · alt satır = supporting

narrativeRole: Pinlemeyi tek başına yapmanın üç eksiğini sayar; her biri bir sonraki bölümde PinVault'un bir işine karşılık gelir.
keyMessage: Pinleme kanalı korur ama pin'ler APK'da kalır, sunucu cihazı tanımaz ve uygulamanın gerçek olduğunu bilmez.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 1 AMAÇ"
- üst çubuk hap: "AMAÇ"
- başlık (display-head): "PİNLEME TEK BAŞINA ÜÇ ŞEYİ ÇÖZMEZ"
- kart 1 (krem dolgu): büyük "1" / başlık "PİN'LER APK'DA KALIR" / alt satır "Sunucunun sertifikası değişince uygulama güncellemesi gerekir; eski sürümler bağlanamaz."
- kart 2 (pembe dolgu): büyük "2" / başlık "SUNUCU CİHAZI TANIMAZ" / alt satır "Hangi telefonla konuştuğunu bilmez; tek bir cihazı uzaktan kesemez."
- kart 3 (sarı dolgu): büyük "3" / başlık "UYGULAMANIN GERÇEK OLDUĞUNU BİLMEZ" / alt satır "Kopya, root'lu telefondaki ya da Frida ile değiştirilmiş uygulama da aynı pinli bağlantıyı kurar."
- alt satır (body-lg): "PinVault bu üçüne birer cevap verir."
- künye: "Üç eksik" / sayaç "05 • 32"

Compose. Yerleşim: başlık üstte; altında üç eşit kart yan yana (triptych, her biri ≈ 540×440); alt satır kartların altında.
Scene 1 (0.0–1.8s): Başlık kelime kelime.
Scene 2 (1.8–5.5s): Kart 1 alttan yuvasına oturur; büyük rakam, başlık, sonra alt satır.
Scene 3 (5.5–9.0s): Kart 2 aynı şekilde.
Scene 4 (9.0–12.5s): Kart 3 aynı şekilde; karenin tek sert gölgesi bu kartta.
Scene 5 (12.5–14.0s): Alt satır. Tutma.

## Frame 6 — Bölüm 2: PinVault ne ekler

- scene: Bölüm başlık kartı: büyük "1", "PINVAULT NE EKLER", altta dört bölümlük ilerleme
- voiceover:
- duration: 4.5s
- transition_in: crossfade
- status: animated
- src: compositions/frames/p4-bolum-pinvault.html
- type: hook
- persuasion: Signposting (önce amaç)
- beat: orientation
- blueprint: compose
- focal: büyük bölüm numarası ve başlık
- roles: numara bloğu = foreground subject · başlık = foreground subject · üç bölüm şeridi = supporting

narrativeRole: Bölüm 2'ye geçişi işaretler.
keyMessage: Üç eksiğe üç cevap ve parçaların nerede durduğu.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 2 / 4"
- numara bloğu (Archivo, çok büyük): "2"
- kicker (mono, siyah kutu): "BÖLÜM 2"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Üç eksiğe üç cevap ve parçaların nerede durduğu."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti: ink dolgu) · "2 ÇÖZÜM" (şu anki) · "3 AKIŞ" · "4 DOSYALAR"
- künye: "Bölüm 2" / sayaç "06 • 32"

Compose. Yerleşim: solda (%30) ink çerçeveli kare numara bloğu (≈ 360×360, krem-2 dolgu, sert gölge karenin tek sert gölgesi); sağda (%60) kicker, başlık, alt satır; altta (y ≈ 760–800) çerçeve genişliğinde dört hücreli bölüm şeridi (hücre ≈ 394×44, aralarında ince ink çizgi; şu anki hücre ink dolgu krem yazı, diğerleri 2 px ink kenar %35 saydam).
Scene 1 (0.0–1.2s): Numara bloğu soldan oturur; içinde "2" yukarı kayarak belirir.
Scene 2 (1.2–2.6s): Kicker, sonra başlık kelime kelime.
Scene 3 (2.6–4.5s): Alt satır; bölüm şeridi soldan çizilir, şu anki hücre dolar. Tutma.

## Frame 7 — PinVault: üç iş, tek kurulum

- scene: PinVault yazısı oturur, altında üç adım kartı dizilir: Pinleme, Kimlik, Atestasyon
- voiceover:
- duration: 13s
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
- kart 1: büyük rakam "1", başlık "PİNLEME", alt satır "Pin listesi sunucudan, imzalı gelir; APK değişmez." / panel şeridi (siyah, mono) "PANELDE · + Host ekle → URL'den Al"
- kart 2: büyük rakam "2", başlık "KİMLİK", alt satır "Sunucu, tanıdığı cihazı içeri alır." / panel şeridi "PANELDE · Client Sertifikaları → Token Üret"
- kart 3: büyük rakam "3", başlık "ATESTASYON", alt satır "PinVault-Token yalnızca değiştirilmemiş uygulamaya verilir." / panel şeridi "PANELDE · Attestation → Red politikası"
- künye: "Üç iş"

Adapt: grid-card-assemble'ın "kartlar sırayla yuvalarına oturur, sonra tutar" yapısı; üstte wordmark kitap ayracı gibi durur, kartlar sırayla değil okuma ritmiyle gelir.
Scene 1 (0.0–2.5s): Ortada "PİNVAULT" büyük ve tek başına oturur (per-word değil, tek blok, uzun kuyruklu yükseliş). Altında alt satır 0,8 sn sonra gelir. Centered, %55 boş.
Scene 2 (2.5–3.5s): Wordmark ve alt satır birlikte üst üçte birliğe kayar (`nudge-curve`), alta yer açılır.
Scene 3 (3.5–9.0s): Üç adım kartı soldan sağa, her biri ≈1,8 sn arayla yuvasına oturur (`center-outward-expansion`, doğrudan yuva biçimi). Kart renkleri: 1 krem, 2 pembe, 3 sarı. Kart başlıkları Archivo Black, alt satırlar Space Grotesk.
Scene 4 (9.0–11.0s): Tutma.

## Frame 8 — Parçalar nerede durur

- scene: Üç bölge sırayla kurulur: cihaz, PinVault sunucusu (dört kapı), sizin arka ucunuz; altta iç ağdaki yönetim
- voiceover:
- duration: 17s
- transition_in: crossfade
- status: animated
- src: compositions/frames/04-topoloji.html
- type: feature_showcase
- persuasion: Progressive disclosure + frame-then-fill
- beat: orientation + comprehension
- blueprint: compose
- focal: üç bölgeli topoloji diyagramı
- roles: üç kesik çizgili bölge = background · telefon, kapı kutuları, arka uç kutuları = foreground subject · bağlantı çizgileri ve etiketleri = supporting · alttaki iki satırlık özet = supporting

narrativeRole: Sistemin haritasını verir: neyin nerede çalıştığı ve hangi kapının internete açık olduğu.
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

Compose: hiçbir kalıp üç bölgeli ağ diyagramını taşımıyor; diyagram bölge bölge kendini kurar. Yerleşim (1920 genişlikte, soldan sağa): cihaz bölgesi ≈%18, sunucu bölgesi ≈%44, arka uç bölgesi ≈%26; iç ağ bölgesi sunucu bölgesinin altında, aynı genişlikte ince bir şerit. Diyagram çerçevenin ≈%60'ını kaplar.
Scene 1 (0.0–1.5s): Başlık üstte gelir. Hiçbir bölge yok.
Scene 2 (1.5–4.0s): Cihaz bölgesinin kesik çizgisi çizilir, telefon içine oturur. Sunucu bölgesinin kesik çizgisi çizilir; içinde sağda depo kutusu belirir.
Scene 3 (4.0–7.0s): 8091, 8092, 8093 kutuları sunucu bölgesinin sol kenarına yukarıdan aşağı sırayla oturur. Telefondan her birine birer çizgi çizilir (`svg-path-draw`). Her çizginin sunucu ucu depoya ince çizgiyle bağlanır.
Scene 4 (7.0–10.0s): Arka uç bölgesi çizilir; API kutusu ve giriş sunucusu kutusu oturur. Telefondan API kutusuna, üstten dolaşan uzun bir çizgi çizilir; etiketi "istek + PinVault-Token". Çizgi boyunca küçük sarı PinVault-Token bir kez kayar.
Scene 5 (10.0–13.0s): Sunucu bölgesinin altında iç ağ şeridi çizilir; içinde 8090 kutusu ve yönetici kutusu oturur. Yöneticiden 8090'a kısa çizgi. Giriş sunucusundan 8090'a kesik çizgi çizilir (kayıt token'ı isteği).
Scene 6 (13.0–17.0s): Diyagramın altında özet satırı 1, 1,5 sn sonra özet satırı 2 gelir; dipnot en son. Sağdaki üç açık kapı kutusuna kısa yeşil vurgu, 8090'a kısa turuncu vurgu (kenar rengi değişir, dolgu değişmez). Tutma.

## Frame 9 — Bölüm 3: Baştan sona

- scene: Bölüm başlık kartı: büyük "1", "BAŞTAN SONA NASIL ÇALIŞIR", altta dört bölümlük ilerleme
- voiceover:
- duration: 4.5s
- transition_in: crossfade
- status: animated
- src: compositions/frames/p5-bolum-akis.html
- type: hook
- persuasion: Signposting (önce amaç)
- beat: orientation
- blueprint: compose
- focal: büyük bölüm numarası ve başlık
- roles: numara bloğu = foreground subject · başlık = foreground subject · üç bölüm şeridi = supporting

narrativeRole: Bölüm 3'ye geçişi işaretler.
keyMessage: Kurulumdan ilk korumalı isteğe, on halkada.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 3 / 4"
- numara bloğu (Archivo, çok büyük): "3"
- kicker (mono, siyah kutu): "BÖLÜM 3"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Kurulumdan ilk korumalı isteğe, on halkada."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti) · "2 ÇÖZÜM" (bitti) · "3 AKIŞ" (şu anki) · "4 DOSYALAR"
- künye: "Bölüm 3" / sayaç "09 • 32"

Compose. Yerleşim: solda (%30) ink çerçeveli kare numara bloğu (≈ 360×360, krem-2 dolgu, sert gölge karenin tek sert gölgesi); sağda (%60) kicker, başlık, alt satır; altta (y ≈ 760–800) çerçeve genişliğinde dört hücreli bölüm şeridi (hücre ≈ 394×44, aralarında ince ink çizgi; şu anki hücre ink dolgu krem yazı, diğerleri 2 px ink kenar %35 saydam).
Scene 1 (0.0–1.2s): Numara bloğu soldan oturur; içinde "3" yukarı kayarak belirir.
Scene 2 (1.2–2.6s): Kicker, sonra başlık kelime kelime.
Scene 3 (2.6–4.5s): Alt satır; bölüm şeridi soldan çizilir, şu anki hücre dolar. Tutma.

## Frame 10 — Kutudan yeni çıkmış bir tablet

- scene: Yeni bir tablet ve uzakta API sunucusu; aralarında on halkalı bir zincir soldan sağa kurulur
- voiceover:
- duration: 10s
- transition_in: crossfade
- status: animated
- src: compositions/frames/01-yeni-tablet.html
- type: hook
- persuasion: Imagine / scenario + frame-then-fill
- beat: curiosity + orientation
- blueprint: compose
- focal: on halkalı zincir
- roles: tablet = supporting · API sunucusu = supporting · zincir = foreground subject · başlık = foreground subject

narrativeRole: Videonun haritasını verir: ilk istekten önce on halka var ve hepsini sırayla göreceğiz.
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

Compose. Yerleşim: üst üçte birde iki satırlık başlık; ortada (y ≈ 470–620) solda tablet, sağda API kutusu, aralarında büyük boy zincir (her hücre burada ≈130×64, iki satır metin); alt satır altta.
Scene 1 (0.0–2.5s): Satır 1 kelime kelime gelir. Solda tablet oturur.
Scene 2 (2.5–4.5s): Satır 2 gelir. Sağda API kutusu oturur; tablet ile API arasında kesik çizgili boş bir hat belirir.
Scene 3 (4.5–8.0s): Hattın üzerinde zincirin on hücresi soldan sağa birer birer oturur (≈0,3 sn arayla); her yeni hücre bir öncekine kısa ink çizgiyle bağlanır.
Scene 4 (8.0–10.0s): Alt satır gelir. Tutma.

## Frame 11 — İki yanlış inanış

- scene: İki kart: "telefon pin'siz başlar" ve "token APK'dadır" yanlış diye çizilir, altlarına doğrusu yazılır
- voiceover:
- duration: 13s
- transition_in: crossfade
- status: animated
- src: compositions/frames/02-iki-yanlis.html
- type: pain_point
- persuasion: Common-belief vs reality
- beat: surprise + recognition
- blueprint: compose
- focal: iki yanlış/doğru kartı
- roles: iki kart = foreground subject · turuncu üstü çizgiler = supporting · yeşil doğru satırları = supporting · APK kutusu = supporting

narrativeRole: İzleyicinin kafasındaki iki yanlış başlangıç noktasını düzeltir; zincirin neden token'la değil kurulumla başladığını açıklar.
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

Compose. Yerleşim: solda (%62) üst üste iki kart, sağda (%38) APK kutusu.
Scene 1 (0.0–1.5s): Başlık.
Scene 2 (1.5–4.5s): Kart 1 yanlış cümlesi gelir; okunduktan sonra üstüne turuncu çizgi çekilir; altında yeşil ✓ ile doğrusu gelir.
Scene 3 (4.5–8.0s): Kart 2 aynı şekilde: yanlış, turuncu çizgi, doğru.
Scene 4 (8.0–13.0s): Sağda APK kutusu belirir; dört satır ≈0,7 sn arayla gelir (✓ satırlar yeşil işaretli, ✗ satırlar turuncu işaretli). Kutunun sert gölgesi karenin tek sert gölgesi. Tutma.

## Frame 12 — Halka 1: Sunucu kurulur

- scene: Sunucu ilk açılışta kendi mühürlerini üretir; panelde Kurulum Sihirbazı'na telefonların ulaşacağı adres yazılır
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/03-kurulum.html
- type: feature_showcase
- persuasion: Signposting + concretization
- beat: orientation + comprehension
- blueprint: compose
- focal: panelde Kurulum Sihirbazı ekranı
- roles: zincir şeridi = supporting · sunucu kutusu ve ürettiği dosyalar = foreground subject (ilk yarı) · panel ekranı = foreground subject (ikinci yarı) · benzetme şeridi = supporting

narrativeRole: Zincirin ilk halkası: her şeyin dayandığı sunucu ve onun kendi sertifikaları.
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
- panel alanı 1 etiketi: "Telefonların sunucuya ulaştığı adres" / değer (mono): "192.168.1.80"
- panel alanı 2 etiketi: "Port eşlemesi" / değer (mono, soluk): "boş · Docker dışarıda başka numara verirse doldurulur"
- panel düğmesi: "Kaydet"
- panel altı not (body-md): "Kaydedip sunucuyu yeniden başlatırsınız. mTLS kapısını (8092) panelde “+ Config API” ile açarsınız."
- dipnot (mono, küçük): "Kapı numaraları demo kurulumundan (PORT=8090)."
- benzetme: "Bina açılır; kapı mühürleri ve kart basma makinesi hazırlanır."
- künye: "Kurulum"

Compose. Yerleşim: zincir şeridi üstte; altında kicker ve başlık; solda (%45) sunucu kutusu ve dört dosya satırı, sağda (%55) panel ekranı; altta benzetme şeridi.
Scene 1 (0.0–1.5s): Zincir şeridi durur; "1 KURULUM" hücresi oturur. Kicker, sonra başlık.
Scene 2 (1.5–4.0s): Solda sunucu kutusu oturur; altında satır 1.
Scene 3 (4.0–8.0s): "İLK AÇILIŞTA KENDİSİ ÜRETİR" başlığı ve dört dosya satırı sunucu kutusunun içinden aşağı ≈0,8 sn arayla çıkar (her satırın başında küçük ink kutucuk; satır 1'in kutucuğu krem-2, satır 2'ninki pembe, satır 4'ünkü sarı).
Scene 4 (8.0–12.0s): Sağda panel ekranı açılır; iki alan sırayla "yazılır" (değerler harf harf), sonra "Kaydet" düğmesine basılır; altında not gelir.
Scene 5 (12.0–15.0s): Benzetme şeridi ve dipnot gelir. Tutma.

## Frame 13 — Halka 2: APK hazırlanır

- scene: Kurulum Sihirbazı'nın Kod sekmesinden hazır init bloğu çıkar; geliştirici attestation() satırını ekler; APK paketlenir
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/04-apk.html
- type: feature_showcase
- persuasion: Demonstration (gerçek kod) + subtractive framing (APK'da olmayan)
- beat: comprehension + confidence
- blueprint: compose
- focal: kod bloğu
- roles: kod paneli = foreground subject · APK kutusu = supporting · vurgulanan satırlar = supporting · benzetme şeridi = supporting

narrativeRole: İkinci halka: geliştiricinin APK'ya koyduğu tek şey, PinVault sunucusuna pinli bağlanma bilgisi.
keyMessage: APK'ya PinVault sunucusunun adresi, pin'leri ve kayıt/kurtarma adresleri girer; token girmez.

Ekran metni:
- üst çubuk hap: "HALKA 2 / 10"
- zincir: şu anki hücre "2 APK"
- kicker: "KİM: GELİŞTİRİCİ · NEREDE: PANEL → KURULUM SİHİRBAZI → 3 · KOD"
- başlık (display-head): "APK HAZIRLANIR"
- kod (mono, 12 satır, girintili):
  ".configApi(\"mtls-8092\", \"https://192.168.1.80:8092/\") {"
  "    bootstrapPins(listOf("
  "        HostPin(\"192.168.1.80\","
  "                listOf(\"ziA0hyMD…\", \"vXC1UZ8O…\")),"
  "        HostPin(\"192.168.1.80:8093\","
  "                listOf(\"WnVy/Wig…\", \"TOZS0AAI…\"))"
  "    ))"
  "    enrollmentUrl(\"https://192.168.1.80:8091/\")"
  "    renewalUrl(\"https://192.168.1.80:8093/\")"
  "    attestation()   // sihirbaz üretmez, elle eklenir"
  "}"
- kod yanı not 1 (yeşil kenarlı kutucuk, mono): "8091 ve 8092'nin pin'leri"
- kod yanı not 2 (yeşil kenarlı kutucuk, mono): "kurtarma kapısının pin'leri"
- kod yanı not 3 (sarı kenarlı kutucuk, mono): "kayıt buraya gider"
- APK kutusu (Archivo): "APK" / alt (mono): "herkes aynısını yükler"
- APK altı satır (body-md, turuncu ✗): "Token yok. API sunucularınızın pin'leri yok."
- benzetme: "Yeni çalışana binanın adresi ve kapı mührünün resmi verilir; henüz kartı yok."
- künye: "APK"

Compose. Yerleşim: solda (%64) kod paneli (krem-2 zemin, ink çerçeve, üst şeridinde mono "Kurulum Sihirbazı · 3 · Kod"); sağda (%36) APK kutusu ve not.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–6.0s): Kod paneli açılır; satırlar yukarıdan aşağı ≈0,3 sn arayla yazılır (`discrete-text-sequence` biçiminde satır satır).
Scene 3 (6.0–9.0s): bootstrapPins'in ilk HostPin satırları yeşil kenarla çerçevelenir ve not 1 belirir; ikinci HostPin satırları çerçevelenir ve not 2; enrollmentUrl satırı sarı kenarla çerçevelenir ve not 3.
Scene 4 (9.0–11.0s): attestation() satırı en son, yorumuyla birlikte "elle" yazılır (harf harf).
Scene 5 (11.0–15.0s): Sağda kod panelinden APK kutusuna kısa bir ok; APK kutusu oturur (karenin tek sert gölgesi). Altında turuncu ✗ satırı. Benzetme şeridi. Tutma.

## Frame 14 — Halka 3: Panelde API sunucunuz eklenir

- scene: Panelde mTLS Config API'nin altına + Yeni Host; URL'den Al ile api.ornek.com'un iki pin'i çıkar ve imzalı listeye girer
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/05-host.html
- type: feature_showcase
- persuasion: Demonstration (panel adımları) + causal chain
- beat: comprehension
- blueprint: compose
- focal: panel ekranındaki "Yeni Host Ekle" penceresi
- roles: panel = foreground subject · api.ornek.com kutusu = supporting · iki pin kutucuğu = foreground subject · imzalı liste = supporting · benzetme = supporting

narrativeRole: Üçüncü halka: telefonun konuşacağı asıl sunucunun pin'leri APK'ya değil, panelden imzalı listeye girer.
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

Compose. Yerleşim: solda (%58) panel ekranı; sağda (%42) üstte api.ornek.com kutusu, ortada imzalı liste kartı, altta "bir kez" bölümü.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–5.0s): Panel ekranı açılır; sekmeler görünür, "URL'den Al" sekmesi seçilir (ink dolgu); "Sunucu adresi" alanına "api.ornek.com" harf harf yazılır; "Oluştur"a basılır.
Scene 3 (5.0–8.0s): Sağda api.ornek.com kutusu belirir; panelden ona ince kesik çizgi uzanır ve geri döner (bağlanıp sertifikayı okuma); panelde iki pin satırı sırayla belirir; altında sonuç notu.
Scene 4 (8.0–11.0s): İki pin satırı panelden sağdaki imzalı liste kartına kayar; liste kartına sarı "İMZALI" mührü basılır (karenin tek sert gölgesi).
Scene 5 (11.0–15.0s): "API SUNUCUNUZ İÇİN BİR KEZ" bölümü gelir; küçük sarı PinVault-Token simgesi panelden api.ornek.com kutusuna kayar. Benzetme şeridi. Tutma.

## Frame 15 — Halka 4: Token üretilir

- scene: Panelde Client Sertifikaları → Enrollment Token kartı; Client ID tablet-07, Token Üret; token bir kez gösterilir, sunucuda yalnızca özeti kalır
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/06-token.html
- type: feature_showcase
- persuasion: Demonstration (panel adımları) + contrast (gösterilen vs saklanan)
- beat: comprehension + "aha"
- blueprint: compose
- focal: bir kez gösterilen sarı token
- roles: panel = foreground subject · sarı token = foreground subject · sunucu deposu satırı = supporting · alternatif yol kutusu = supporting · benzetme = supporting

narrativeRole: Dördüncü halka: token burada doğar. Kullanıcının "token'la başlıyoruz" dediği şey aslında dördüncü halka.
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

Compose. Yerleşim: solda (%58) panel ekranı; sağda (%42) üstte "sunucuda kalan" kartı, altta "ya da otomatik" kutusu.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–5.0s): Panel açılır; "Client ID" alanına "tablet-07" yazılır; ikinci alan soluk "isteğe bağlı" ile görünür; "Token Üret"e basılır.
Scene 3 (5.0–8.0s): Panelin üstünde pencere açılır; pencere başlığı, sonra sarı şerit içinde token değeri soldan sağa açılır (karenin tek sert gölgesi bu pencerede).
Scene 4 (8.0–11.0s): Sağda "SUNUCUDA KALAN" kartı belirir; token şeridinin küçük bir kopyası karta kayarken sarıdan krem-2'ye döner ve "SHA-256 özeti…" satırına dönüşür. Not gelir.
Scene 5 (11.0–15.0s): "YA DA OTOMATİK" kutusu gelir. Benzetme şeridi. Tutma.

## Frame 16 — Halka 5: Token telefona ulaşır

- scene: Token mesajla telefona gelir; kullanıcı Kayıt Ol'a yapıştırır; uygulama init'ten önce enroll çağırır
- voiceover:
- duration: 14s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/07-telefona.html
- type: feature_showcase
- persuasion: Demonstration (telefon ekranı) + code callout
- beat: comprehension
- blueprint: compose
- focal: telefonun Kayıt Ol ekranı
- roles: telefon = foreground subject · mesaj balonu = supporting · kod kutusu = supporting · benzetme = supporting

narrativeRole: Beşinci halka: token PinVault'un dışından telefona gelir ve uygulama onu kütüphaneye verir.
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

Compose. Yerleşim: solda mesaj balonu, ortada telefon (büyük, ≈380×620), sağda kod kutusu.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–4.0s): Soldan mesaj balonu kayarak gelir, altındaki küçük not.
Scene 3 (4.0–7.5s): Telefon ekranında "Kayıt Ol" penceresi açılır; balondaki token değeri (sarı) telefonun alanına kayar ve yerleşir; düğmeye basılır.
Scene 4 (7.5–11.0s): Sağda kod kutusu açılır, dört satır sırayla yazılır; ikinci satır sarı kenarla vurgulanır. Not gelir.
Scene 5 (11.0–14.0s): Benzetme şeridi. Tutma.

## Frame 17 — Halka 6: Kayıt isteği

- scene: Telefon kasasında anahtar üretir; kayıt isteği 8091'e APK'daki pin'le doğrulanmış bağlantıdan gider; özel anahtar telefonda kalır
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/08-kayit-istegi.html
- type: feature_showcase
- persuasion: Causal chain + subtractive framing (gitmeyen)
- beat: fascination + comprehension
- blueprint: compose
- focal: telefon ile 8091 arasındaki paket ve içeriği
- roles: telefon = foreground subject · kasa (anahtar) simgesi = supporting · 8091 kapısı = supporting · paket içeriği listesi = foreground subject · benzetme = supporting

narrativeRole: Altıncı halka: token ilk ve son kez burada sunucuya gider; bağlantı APK'daki pin'le korunur.
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

Compose. Yerleşim: solda telefon ve altında kasa simgesi (küçük kare kasa, içinde anahtar); sağda PinVault sunucusu kutusunun 8091 kapısı; aralarında hat; hattın üstünde paket kartı açılır.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–4.0s): Telefonun altında kasa belirir; içinde anahtar simgesi çizilir; kasa altı satırı.
Scene 3 (4.0–6.0s): Sağda sunucu ve 8091 kapısı; hat çizilir; sunucudan telefona küçük sertifika kartı gelir, telefonun içindeki pin satırıyla eşleşir; bağlantı etiketi yeşil ✓ ile belirir.
Scene 4 (6.0–11.0s): Hattın ortasında paket kartı açılır: başlık, sonra beş satır ≈0,8 sn arayla (token satırı sarı imli). Sonra paket 8091'e kayar.
Scene 5 (11.0–15.0s): Kasanın yanında turuncu ✗ ile "gitmeyen" satırı gelir; kasa kapısı kapanır (karenin tek sert gölgesi kasada). Benzetme şeridi. Tutma.

## Frame 18 — Halka 7: Sunucu kartı basar

- scene: Sunucu kontrolleri tek tek geçirir, ancak hepsi geçince token'ı harcar; istemci CA'sı 90 günlük pembe kartı imzalar; telefon saklar
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/09-kart.html
- type: feature_showcase
- persuasion: Checklist + causal chain
- beat: comprehension + satisfaction
- blueprint: compose
- focal: pembe kimlik kartı "tablet-07"
- roles: kontrol listesi = foreground subject (ilk yarı) · pembe kart = foreground subject (ikinci yarı) · panel token satırı = supporting · telefon = supporting · benzetme = supporting

narrativeRole: Yedinci halka: token burada biter, telefonun kalıcı kimliği (kart) burada başlar.
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

Compose. Yerleşim: solda (%50) kontrol listesi; sağda (%50) üstte panel token satırı, ortada kart basımı (sunucudan çıkan pembe kart telefona gider), altta son satır.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–6.0s): Kontrol başlığı; beş kontrol ≈0,8 sn arayla gelir, her birinin yanına yeşil ✓.
Scene 3 (6.0–8.5s): Harcama satırı; sağda panel token satırı belirir ve durum "Bekliyor"dan "Kullanıldı"ya döner (kısa geri silme ve yazma).
Scene 4 (8.5–12.0s): Pembe kart sunucu tarafında belirir (karenin tek sert gölgesi), sağa telefona kayar ve telefonun yanına oturur; telefon notu.
Scene 5 (12.0–15.0s): Son satır gelir. Benzetme şeridi. Tutma.

## Frame 19 — Halka 8: İmzalı pin listesi

- scene: init başlar; telefon kartıyla 8092'ye girer, imzalı listeyi alır; api.ornek.com'un pin'leri yerleşir; sağlık kontrolü
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/10-pin-listesi.html
- type: feature_showcase
- persuasion: Numbered enumeration + callback (Halka 3'teki liste)
- beat: comprehension + momentum
- blueprint: compose
- focal: telefona gelen imzalı liste
- roles: telefon ve pembe kart = foreground subject · 8092 kapısı = supporting · imzalı liste = foreground subject · init adım rayı = supporting · benzetme = supporting

narrativeRole: Sekizinci halka: Halka 3'te hazırlanan liste, kartla girilen kapıdan telefona gelir.
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

Compose. Yerleşim: solda (%32) dikey init rayı; ortada telefon (pembe kart yanında); sağda sunucu 8092 kapısı; liste kartı ikisinin arasında hareket eder.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–4.0s): Init rayı başlığı; adım 1 gelir ve yanında küçük yeşil ✓ ("vakti gelmedi").
Scene 3 (4.0–7.0s): Adım 2 gelir. Telefondan 8092'ye hat çizilir; pembe kart hattan kapıya gidip döner; sunucudan küçük sertifika kartı telefona gelir; bağlantı etiketi yeşil ✓ ile belirir.
Scene 4 (7.0–11.0s): Liste kartı 8092'den telefona kayar (mühür karenin tek sert gölgesi); adım 3 gelir, liste kartının "son kullanma" satırı ve mühür kısa yeşil kenar alır.
Scene 5 (11.0–15.0s): Adım 4: telefonun içinde "api.ornek.com → pinli" satırı belirir. Adım 5 gelir, ✓. Benzetme şeridi. Tutma.

## Frame 20 — Halka 9: PinVault-Token alınır

- scene: Telefon kendini ölçer, raporu kasa anahtarıyla imzalar, 8092 karar verir, 5 dakikalık sarı PinVault-Token gelir
- voiceover:
- duration: 14s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/11-bilet.html
- type: feature_showcase
- persuasion: Causal chain + analogy (güvenlik kontrolü)
- beat: fascination
- blueprint: compose
- focal: sarı PinVault-Token "PINVAULT-TOKEN · 5 DK"
- roles: ölçüm çipleri = foreground subject (ilk yarı) · PinVault-Token = foreground subject (ikinci yarı) · sunucu = supporting · benzetme = supporting

narrativeRole: Dokuzuncu halka: kart kimliği kanıtlar; PinVault-Token uygulamanın değiştirilmemiş olduğunu kanıtlar.
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

Compose. Yerleşim: solda telefon, sağda sunucu; adım kickerları üstte bir rayda soldan sağa birikir; ölçüm çipleri telefonun yanında.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–3.5s): Adım 1; sunucudan telefona küçük "?" kartı (soru) kayar.
Scene 3 (3.5–7.0s): Adım 2; beş ölçüm çipi ≈0,4 sn arayla gelir, her birine yeşil ✓; çipler bir rapor kartına toplanır, köşesine kasa simgesiyle mühür.
Scene 4 (7.0–10.5s): Adım 3; rapor sunucuya kayar; yeşil "GEÇTİ"; sunucudan sarı PinVault-Token telefona kayar (karenin tek sert gölgesi PinVault-Token'da).
Scene 5 (10.5–14.0s): Not ve not 2. Benzetme şeridi. Tutma.

## Frame 21 — Halka 10: İlk gerçek istek

- scene: Uygulama getClient() ile api.ornek.com'a bağlanır: pin listeden, PinVault-Token başlıkta; API sunucusu PinVault-Token'ı kendisi doğrular ve 200 döner
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/12-ilk-istek.html
- type: benefit_highlight
- persuasion: Callback (Halka 3, 8, 9) + demonstration
- beat: satisfaction + "now I get it"
- blueprint: compose
- focal: telefondan api.ornek.com'a giden istek ve "200 OK"
- roles: telefon = foreground subject · API sunucusu = foreground subject · istek kartı = supporting · üç geri çağrı etiketi = supporting · benzetme = supporting

narrativeRole: Onuncu halka: bütün zincirin amacı; önceki halkaların her biri burada bir işe yarar.
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

Compose. Yerleşim: solda telefon, sağda API sunucusu kutusu (büyük); aralarında hat; hattın üstünde istek kartı; altta geri çağrı etiketleri.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–4.0s): Telefonun üstünde kod satırı yazılır.
Scene 3 (4.0–7.5s): Hat çizilir; API'den telefona sertifika kartı gelir ve telefondaki "api.ornek.com → pinli" satırıyla eşleşir (yeşil); geri çağrı 1 belirir. İstek kartı açılır, iki satırı gelir; PinVault-Token satırı sarı; geri çağrı 2 belirir.
Scene 4 (7.5–11.5s): İstek kartı API'ye kayar; API kutusunun içinde üç kontrol ≈0,7 sn arayla ✓ alır; API altı satırı.
Scene 5 (11.5–15.0s): API'den telefona yeşil "200 OK" kutusu döner (karenin tek sert gölgesi). Benzetme şeridi. Tutma.

## Frame 22 — Root'lu telefon PinVault-Token alamaz

- scene: Root'lu, Frida'lı telefon aynı yolu dener: rapor reddedilir, PinVault-Token yok, API 401 döner; liste gizli değil, kilit PinVault-Token'dır
- voiceover:
- duration: 13s
- transition_in: crossfade
- status: animated
- src: compositions/frames/10-ret.html
- type: social_proof
- persuasion: Counterexample + common-belief vs reality
- beat: unease → clarity
- blueprint: compose
- focal: API kutusunun döndüğü "401" ve son satır "KAPIYI TUTAN, PINVAULT-TOKEN'DIR"
- roles: turuncu telefon = foreground subject · sunucu ve API kutusu = supporting · gerçek satırı = foreground subject (son 3 sn)

narrativeRole: Kanıt karesi: geçmeyen uygulamaya ne olduğunu ve neyin kilit olduğunu gösterir; pin listesinin gizli olmadığı yanlış anlamasını düzeltir.
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

Compose. Aynı üç duraklı sahne, Frame 9'un aynası; telefon turuncu kenarlı.
Scene 1 (0.0–2.0s): Başlık. Turuncu kenarlı telefon solda; "root · Frida" etiketi.
Scene 2 (2.0–4.5s): İki ölçüm çipi belirir, her birine turuncu ✗.
Scene 3 (4.5–7.0s): Rapor ortadaki sunucuya kayar; turuncu "RET" damgası basılır. PinVault-Token çıkacak yerde boş kesik çizgili çerçeve "PinVault-Token yok" belirir.
Scene 4 (7.0–9.5s): Telefon yine de API'ye istek atar; çizgi API kutusunun önünde kesilir ve kutuda "401 · PinVault-Token yok" yazar (sert gölge bu kutuda).
Scene 5 (9.5–13.0s): Sahne yukarı kayar ve soluklaşır; altta gerçek satırı büyük, sonra alt satırı gelir. Son 3 sn tutma (nefes karesi).

## Frame 23 — Panelde: atestasyon ayarı

- scene: Panelin Attestation sekmesi: Red politikası tablosu (reddet / uyar / yoksay), Politikayı Kaydet; altta cihaz listesi, reddedilen cihazın ARC kodu ve nedenleri
- voiceover:
- duration: 16s
- transition_in: crossfade
- status: animated
- src: compositions/frames/a1-panel-atestasyon.html
- type: feature_showcase
- persuasion: Demonstration (panel adımları) + callback (önceki karedeki RET)
- beat: control + comprehension
- blueprint: compose
- focal: Red politikası tablosu
- roles: panel ekranı = foreground subject · politika tablosu = foreground subject · cihaz listesi = supporting · ARC açılır kutusu = supporting · benzetme = supporting

narrativeRole: Atestasyon kararının panelde nereden yönetildiğini ve sonucun nerede görüldüğünü gösterir.
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

Compose. Yerleşim: başlık ve kicker üstte; solda (%62) panel ekranı (sekmeler, Red politikası kartı); sağda (%38) "Attestation yapan cihazlar" kartı ve altında ARC açılır kutusu; altta benzetme şeridi. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–4.0s): Panel ekranı açılır; sekmeler görünür, "Attestation" sekmesi seçilir (ink dolgu).
Scene 3 (4.0–9.0s): Red politikası kartı: başlık ve rozet, hazır ayar satırı, sonra altı satır ≈0,6 sn arayla gelir; "reddet" olan karar kutularının kenarı turuncu, "uyar" sarı, "yoksay" gri. Token ömrü alanı.
Scene 4 (9.0–11.0s): "Politikayı Kaydet"e basılır; bildirim belirir, rozet "v3"ten "v4"e döner.
Scene 5 (11.0–14.0s): Sağda cihaz kartı; iki satır gelir; ikinci satırdaki ARC kodunun altı turuncu çizilir ve açılır kutu belirir (karenin tek sert gölgesi bu kutuda); yan not.
Scene 6 (14.0–16.0s): Benzetme şeridi. Tutma.

## Frame 24 — Bölüm 4: Dosyalar

- scene: Bölüm başlık kartı: büyük "1", "DOSYALAR VE ŞİFRELEME", altta dört bölümlük ilerleme
- voiceover:
- duration: 4.5s
- transition_in: crossfade
- status: animated
- src: compositions/frames/p6-bolum-dosyalar.html
- type: hook
- persuasion: Signposting (önce amaç)
- beat: orientation
- blueprint: compose
- focal: büyük bölüm numarası ve başlık
- roles: numara bloğu = foreground subject · başlık = foreground subject · üç bölüm şeridi = supporting

narrativeRole: Bölüm 4'e geçişi işaretler.
keyMessage: Panelden eklenen dosya, seçtiğiniz cihazlara, seçtiğiniz korumayla gider.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 4 / 4"
- numara bloğu (Archivo, çok büyük): "4"
- kicker (mono, siyah kutu): "BÖLÜM 4"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Panelden eklenen dosya, seçtiğiniz cihazlara, seçtiğiniz korumayla gider."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti) · "2 ÇÖZÜM" (bitti) · "3 AKIŞ" (bitti) · "4 DOSYALAR" (şu anki)
- künye: "Bölüm 4" / sayaç "24 • 32"

Compose. Yerleşim: solda (%30) ink çerçeveli kare numara bloğu (≈ 360×360, krem-2 dolgu, sert gölge karenin tek sert gölgesi); sağda (%60) kicker, başlık, alt satır; altta (y ≈ 760–800) çerçeve genişliğinde dört hücreli bölüm şeridi (hücre ≈ 394×44, aralarında ince ink çizgi; şu anki hücre ink dolgu krem yazı, diğerleri 2 px ink kenar %35 saydam).
Scene 1 (0.0–1.2s): Numara bloğu soldan oturur; içinde "4" yukarı kayarak belirir.
Scene 2 (1.2–2.6s): Kicker, sonra başlık kelime kelime.
Scene 3 (2.6–4.5s): Alt satır; bölüm şeridi soldan çizilir, şu anki hücre dolar. Tutma.

## Frame 25 — Panelden dosya yüklenir

- scene: Panelin Vault sekmesinde "Vault'a Yükle" kartı: anahtar, dosya, Policy, Encryption seçilir, Yükle; dosya sunucunun deposuna şifreli girer, sürüm v1
- voiceover:
- duration: 16s
- transition_in: crossfade
- status: animated
- src: compositions/frames/d1-dosya-yukle.html
- type: feature_showcase
- persuasion: Demonstration (panel adımları)
- beat: comprehension
- blueprint: compose
- focal: "Vault'a Yükle" kartı
- roles: panel ekranı = foreground subject · sunucu deposu kutusu = supporting · kilit simgesi = supporting · benzetme = supporting

narrativeRole: Dosya dağıtımının ilk adımı: yönetici dosyayı panele koyar ve iki şeyi seçer: kim alabilir, nasıl korunur.
keyMessage: Yönetici dosyayı panelden yükler; kimin alacağını (Policy) ve korumayı (Encryption) seçer; dosya sunucuda şifreli saklanır ve her yüklemede sürümü artar.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 4 DOSYALAR"
- üst çubuk hap: "DOSYA 1 / 5"
- kicker: "KİM: YÖNETİCİ · NEREDE: PANEL → mtls-8092 → VAULT"
- başlık (display-head): "PANELDEN DOSYA YÜKLENİR"
- panel başlığı (mono): "Panel · 8090 · mtls-8092 · Vault"
- kart başlığı: "Vault'a Yükle"
- geçiş düğmeleri (mono): "Dosya" (seçili) "Metin"
- alan 1 etiketi: "Anahtar" / değer (mono): "saha-ayarlari"
- alan 2 etiketi: "Dosya" / değer (mono): "saha-ayarlari.json"
- alan 3 etiketi: "Policy" / değer (mono): "token (önerilen)"
- alan 4 etiketi: "Encryption" / değer (mono): "at_rest"
- alan 4 açılır listesi (mono, kısa süre açık kalır): "plain" "at_rest" "end_to_end" "user_auth — ekran kilidiyle açılır"
- düğme: "Yükle"
- bildirim (mono): "saha-ayarlari v1 [token/at_rest] uploaded"
- depo kutusu başlığı (mono): "SUNUCU DEPOSU"
- depo satırı (mono): "saha-ayarlari · v1 · diskte şifreli"
- depo altı not (body-md): "plain dışındaki her seçenekte dosya sunucunun diskinde şifreli durur (VAULT_AT_REST_PASSWORD)."
- not 2 (body-md): "Her yükleme sürümü bir artırır; telefonlar yenisini indirir."
- benzetme: "Arşive bir belge konur: kimin alacağı ve hangi zarfla gönderileceği yazılır."
- künye: "Dosya yükle"

Compose. Yerleşim: solda (%60) panel ekranı ve kart; sağda (%40) sunucu deposu kutusu ve notlar; altta benzetme. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–6.0s): Panel açılır; kart başlığı; "Anahtar" ve "Dosya" alanları sırayla dolar (değerler harf harf).
Scene 3 (6.0–9.5s): "Policy" alanı dolar. "Encryption" alanının açılır listesi açılır, dört seçenek görünür, "at_rest" seçilir ve liste kapanır.
Scene 4 (9.5–12.5s): "Yükle"ye basılır; bildirim belirir; dosya simgesi sağdaki depoya kayar, üstüne sarı kilit mührü basılır (karenin tek sert gölgesi); depo satırı yazılır.
Scene 5 (12.5–16.0s): Depo altı not, not 2, benzetme. Tutma.

## Frame 26 — Kim alabilir: Policy ve dosya token'ı

- scene: Dört Policy seçeneği yan yana; dosyanın ayrıntı sayfasında Token Yönetimi: ANDROID_ID yazılır, + Yeni Token, dosya token'ı bir kez gösterilir
- voiceover:
- duration: 16s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/d2-kim-alabilir.html
- type: feature_showcase
- persuasion: Comparison of options + demonstration
- beat: comprehension
- blueprint: compose
- focal: Policy karşılaştırma şeridi, sonra sarı dosya token'ı
- roles: dört Policy kartı = foreground subject · panel Token Yönetimi kartı = foreground subject · not = supporting

narrativeRole: Dosyanın kime gideceğinin iki katmanını gösterir: Policy (kural) ve cihaza özel dosya token'ı.
keyMessage: Policy "token" ya da "token + mTLS" ise dosyayı yalnızca, panelde o cihaz için üretilen dosya token'ını getiren telefon alır; "token + mTLS"te ayrıca o cihazın kartı gerekir.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 4 DOSYALAR"
- üst çubuk hap: "DOSYA 2 / 5"
- kicker: "KİM: YÖNETİCİ · NEREDE: PANEL → VAULT → saha-ayarlari → TOKEN YÖNETİMİ"
- başlık (display-head): "KİM ALABİLİR?"
- Policy kartı 1 (mono başlık + body): "public (demo)" / "Herkes indirir. Yalnız deneme için."
- Policy kartı 2 (yeşil kenar): "token (önerilen)" / "Doğru cihaz kimliği + o cihazın dosya token'ı."
- Policy kartı 3 (yeşil kenar): "token + mTLS" / "Dosya token'ı + o cihazın kartı. Yalnız 8092'de açılır."
- Policy kartı 4 (gri): "api_key" / "Cihazdan hiç inmez; yalnız yönetici okur."
- panel kartı başlığı (mono): "Token Yönetimi"
- alan (mono): "ANDROID_ID" / değer "a41c7e09d3b2f586"
- düğme: "+ Yeni Token"
- açılan pencere (mono): "Token üretildi ve panoya kopyalandı. Cihaza güvenli kanaldan iletin."
- dosya token'ı (sarı şerit, mono): "Vt8sKq2mPz4…"
- not (body-md): "Sunucu yalnızca özetini saklar. Dosya token'ı da APK'da değildir: uygulama her indirmede onu isteğe ekler."
- künye: "Kim alabilir"

Compose. Yerleşim: üstte başlık; altında dört Policy kartı yan yana (full-width strip, her biri ≈ 400×170); altında solda panel "Token Yönetimi" kartı, sağda not.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–7.0s): Dört Policy kartı soldan sağa ≈1,2 sn arayla gelir; 2 ve 3 yeşil kenar alır.
Scene 3 (7.0–11.0s): Token Yönetimi kartı açılır; ANDROID_ID harf harf yazılır; "+ Yeni Token"e basılır; pencere ve sarı dosya token'ı belirir (karenin tek sert gölgesi).
Scene 4 (11.0–16.0s): Not gelir. Tutma.

## Frame 27 — Telefon dosyayı alır

- scene: Uygulama fetchFile çağırır; telefon 8092'ye kartı ve dosya token'ıyla gider; sunucu kontrol eder, imzalı dosyayı yollar; telefon şifreli deposuna yazar; panelde Dağıtım Geçmişi'ne ✓ düşer
- voiceover:
- duration: 16s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/d3-telefon-alir.html
- type: feature_showcase
- persuasion: Causal chain + callback (panel)
- beat: comprehension + satisfaction
- blueprint: compose
- focal: telefon ile 8092 arasındaki istek ve dönen dosya
- roles: telefon = foreground subject · 8092 kapısı = supporting · istek kartı = supporting · sunucu kontrol listesi = supporting · panel Dağıtım Geçmişi = supporting

narrativeRole: Dosyanın telefona nasıl ve hangi kontrollerden geçerek indiğini, sonra panelde nasıl görüldüğünü gösterir.
keyMessage: Telefon dosyayı kartı ve dosya token'ıyla ister; sunucu cihazı ve token'ı kontrol edip imzalı gönderir; telefon imzayı doğrular, şifreli saklar; panel kimin hangi sürümü aldığını gösterir.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 4 DOSYALAR"
- üst çubuk hap: "DOSYA 3 / 5"
- kicker: "KİM: UYGULAMANIZ VE PINVAULT KÜTÜPHANESİ · NEREDE: TELEFON → 8092"
- başlık (display-head): "TELEFON DOSYAYI ALIR"
- kod satırı (mono): "PinVault.fetchFile(\"saha-ayarlari\")"
- istek kartı (mono): "GET /api/v1/vault/saha-ayarlari" / "X-Device-Id: a41c7e09d3b2f586" / "X-Vault-Token: Vt8sKq2m…" / "+ cihaz kartı (mTLS)"
- sunucu kontrolleri (mono, yeşil ✓): "kart bu cihazın" / "dosya token'ı bu cihaz ve dosya için" / "cihaz iptal edilmemiş"
- cevap kartı (mono): "saha-ayarlari · v1 · imzalı"
- telefon içi satırlar (mono, yeşil ✓): "imza doğru" / "sürüm geri gitmiyor" / "şifreli depoya yazıldı"
- panel kartı başlığı (mono): "Panel · Vault · Dağıtım Geçmişi"
- panel satırı (mono): "saha-ayarlari · v1 · tablet-07 · ✓"
- not (body-md): "Sürüm değişmediyse sunucu dosyayı tekrar göndermez (304)."
- künye: "Telefon alır"

Compose. Yerleşim: solda telefon, sağda sunucu 8092 kapısı; aralarında hat; hat üstünde istek kartı, hat altında cevap kartı; sağ altta panel Dağıtım Geçmişi kartı.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–4.0s): Telefonun üstünde kod satırı yazılır.
Scene 3 (4.0–7.5s): Hat çizilir; istek kartı açılır, dört satırı gelir (token satırı sarı imli); kart sunucuya kayar.
Scene 4 (7.5–10.0s): Sunucu kontrolleri ≈0,6 sn arayla ✓ alır.
Scene 5 (10.0–13.0s): Cevap kartı telefona kayar (sarı mühür "İMZALI" küçük; karenin tek sert gölgesi); telefon içi üç satır ✓ alır.
Scene 6 (13.0–16.0s): Sağ altta panel kartı açılır, satırı yazılır; not. Tutma.

## Frame 28 — Üç koruma: sunucuda şifreli, uçtan uca, ekran kilitli

- scene: Üç sütun: at_rest, end_to_end, user_auth; her birinde dosyanın yolculuğu ve kimin açabildiği
- voiceover:
- duration: 18s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/d4-uc-koruma.html
- type: feature_showcase
- persuasion: Comparison of three options (triptych)
- beat: comprehension + "aha"
- blueprint: compose
- focal: üç sütun
- roles: üç sütun kartı = foreground subject · her sütundaki küçük sunucu→telefon şeridi = supporting · "kim açar" satırları = foreground subject

narrativeRole: Panelde seçilen Encryption değerinin telefona giden yolda ne değiştirdiğini yan yana gösterir.
keyMessage: at_rest dosyayı sunucuda korur; end_to_end her indirmede dosyayı o telefonun anahtarına sarar, yalnız o telefon açar; user_auth ayrıca ekran kilidi ister.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 4 DOSYALAR"
- üst çubuk hap: "DOSYA 4 / 5"
- kicker: "PANELDE SEÇİLEN: ENCRYPTION"
- başlık (display-head): "ÜÇ KORUMA"
- sütun 1 başlığı (Archivo): "SUNUCUDA ŞİFRELİ" / etiket (mono): "at_rest"
- sütun 1 satırları (body-md): "Sunucunun diskinde şifreli durur." / "Telefona açık iner; telefon kendi şifreli deposuna yazar."
- sütun 1 kim açar (mono): "Açabilen: sunucu · telefon"
- sütun 2 başlığı (Archivo): "UÇTAN UCA" / etiket (mono): "end_to_end"
- sütun 2 satırları (body-md): "Telefon açılışta açık anahtarını sunucuya bildirir." / "Her indirmede sunucu dosyayı o telefonun anahtarına sarar." / "Yolda ve başka cihazda açılamaz."
- sütun 2 kim açar (mono): "Açabilen: yalnız o telefonun kasası"
- sütun 2 dipnot (mono, küçük): "Anahtar bildirilmemişse sunucu vermez (412)."
- sütun 3 başlığı (Archivo): "EKRAN KİLİTLİ" / etiket (mono): "user_auth"
- sütun 3 satırları (body-md): "Telefonun ekran kilidi anahtarına sarılır." / "Telefona kilitli iner ve kilitli durur."
- sütun 3 kim açar (mono): "Açabilen: telefon, ekran kilidi açılınca"
- alt satır (body-md): "Dosyayı panelden yükleyen sunucu içeriği bilir; uçtan uca, onu yolda ve başka cihazlarda korur."
- künye: "Üç koruma"

Compose. Yerleşim: başlık üstte; altında üç eşit sütun kartı (triptych, her biri ≈ 540×560); her kartın üstünde küçük bir sunucu→telefon şeridi (sunucu kutusu, ok, telefon) ve şeridin üstünde dosyanın durumu simgesi (sütun 1: sunucuda kilit, yolda açık; sütun 2: yolda pembe zarf "tablet-07"; sütun 3: yolda ve telefonda kilit + parmak izi); altında satırlar ve "kim açar". Sütun 1 krem, sütun 2 pembe kenarlı, sütun 3 sarı kenarlı.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–6.5s): Sütun 1 gelir: şerit, simge yolculuğu, satırlar, "kim açar".
Scene 3 (6.5–11.5s): Sütun 2 aynı şekilde; zarf yolculuğu; dipnot.
Scene 4 (11.5–15.5s): Sütun 3 aynı şekilde (sert gölge bu sütunda).
Scene 5 (15.5–18.0s): Alt satır. Tutma.

## Frame 29 — Telefonda: kilit, süre, iptal

- scene: Telefonda ekran kilitli dosya açılırken sistem kilit penceresi; altında iki kural: çevrimdışı ömür dolunca dosya açılmaz/silinir, cihaz iptal edilince dosyalar silinir
- voiceover:
- duration: 15s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/d5-telefonda.html
- type: benefit_highlight
- persuasion: Demonstration (telefon ekranı) + enumeration
- beat: confidence
- blueprint: compose
- focal: telefondaki sistem kilit penceresi
- roles: telefon = foreground subject · kilit penceresi = foreground subject · iki kural kartı = supporting · kod satırları = supporting

narrativeRole: Dosyanın telefona indikten sonra nasıl korunduğunu gösterir: açarken kilit, zamanla sona erme, iptalde silme.
keyMessage: Ekran kilitli dosya ancak kilit açılınca okunur; sunucu uzun süre doğrulamazsa dosya açılmaz ya da silinir; cihaz iptal edilirse dosyaları silinir.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · 4 DOSYALAR"
- üst çubuk hap: "DOSYA 5 / 5"
- kicker: "KİM: KULLANICI VE UYGULAMA · NEREDE: TELEFON"
- başlık (display-head): "TELEFONDA: KİLİT, SÜRE, İPTAL"
- telefon ekranı başlığı (mono): "saha-ayarlari"
- telefon ekranı kilitli durum (mono): "🔒 kilitli"
- sistem penceresi başlığı (body): "Kilidi açın"
- sistem penceresi alt yazı (body-md): "Parmak izi, PIN ya da desen"
- kilit açılınca (mono, yeşil ✓): "açıldı · içerik okundu"
- kod satırı (mono): "PinVault.unlockFile(activity, \"saha-ayarlari\", prompt)"
- kural 1 başlığı: "ÇEVRİMDIŞI ÖMÜR" / satır (body-md): "Sunucu dosyayı belirlediğiniz süre boyunca doğrulamazsa dosya açılmaz; isterseniz silinir." / kod (mono): "maxOfflineAge(7, TimeUnit.DAYS) · wipeWhenStale()"
- kural 2 başlığı: "İPTAL EDİLİNCE" / satır (body-md): "Panelden iptal edilen cihazdaki dosyalar silinir." / kod (mono): "wipeVaultFilesOnRevocation()"
- not (body-md): "Bu iki kural uygulamanın kodunda açılır."
- künye: "Telefonda"

Compose. Yerleşim: solda (%38) büyük telefon; sağda (%62) iki kural kartı alt alta ve not.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–4.0s): Telefon ekranında dosya adı ve "kilitli" durumu; altında kod satırı yazılır.
Scene 3 (4.0–7.5s): Telefonun üstünde sistem penceresi açılır (karenin tek sert gölgesi), parmak izi simgesi çizilir; sonra pencere kapanır ve "açıldı · içerik okundu" satırı yeşil ✓ ile belirir.
Scene 4 (7.5–11.0s): Kural 1 kartı gelir: başlık, satır, kod.
Scene 5 (11.0–15.0s): Kural 2 kartı gelir; not. Tutma.

## Frame 30 — Sonrası

- scene: Zaman şeridi: her açılış, arka plan, 60. gün yenileme, süre dolarsa 8093, iptal
- voiceover:
- duration: 14s
- transition_in: crossfade
- status: animated
- src: compositions/frames/13-sonrasi.html
- type: feature_showcase
- persuasion: Signposting (sonra… gerekirse… en son)
- beat: foresight + mastery
- blueprint: compose
- focal: yatay zaman şeridi
- roles: şerit = foreground subject · beş istasyon kartı = foreground subject · pembe kart = supporting

narrativeRole: Zincir bir kez kurulur; sonrasında neyin kendiliğinden, neyin panelden olduğunu gösterir.
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

Compose. Yerleşim: çerçeve genişliğinde yatay şerit, üstünde beş istasyon noktası, altlarında beş açıklama kartı; şeridin başında küçük pembe kart.
Scene 1 (0.0–1.5s): Başlık. Şerit soldan sağa çizilir.
Scene 2 (1.5–4.0s): İstasyon 1 noktası ve kartı; pembe kart istasyon 1'e oturur.
Scene 3 (4.0–6.5s): İstasyon 2; kartın yanında küçük sarı PinVault-Token bir kez yenilenir (eski soluklaşır, yenisi gelir).
Scene 4 (6.5–9.0s): İstasyon 3; pembe kart çevrilir, yenisi gelir, kısa yeşil ✓.
Scene 5 (9.0–11.5s): İstasyon 4; kart griye döner, sonra imza simgesiyle yeniden pembeleşir.
Scene 6 (11.5–14.0s): İstasyon 5; kartın üstüne turuncu "İPTAL" damgası (karenin tek sert gölgesi). Tutma.

## Frame 31 — Üç cümlede PinVault

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

## Frame 32 — On halka, tek cümle

- scene: Yeşil kapanış plakası; on halkalı zincirin tamamı dolu; tek cümlelik özet ve animasyona yönlendirme
- voiceover:
- duration: 11s
- transition_in: crossfade
- status: animated
- src: compositions/frames/14-kapanis.html
- type: cta
- persuasion: Distillation + callback (Kare 1'deki zincir)
- beat: resolve + "now I get it"
- blueprint: titlecard-reveal (Adapt)
- focal: dolu zincir ve özet cümlesi
- roles: yeşil zemin = background · zincir = foreground subject · özet = foreground subject · dosya yolu = supporting

narrativeRole: Kare 1'deki boş zinciri dolu hâliyle geri getirir ve izleyiciyi ayrıntıya yollar.
keyMessage: Token yalnızca bir kez, kayıtta kullanılır; sonra telefonun kimliği kartı, güveni imzalı liste ve PinVault-Token'dır.

Ekran metni:
- üst çubuk hap (krem varyant): "SON"
- zincir hücreleri (krem çerçeve, krem yazı, hepsi dolu): "1 KURULUM" "2 APK" "3 HOST" "4 KAYIT TOKEN'I" "5 TELEFONA" "6 KAYIT İSTEĞİ" "7 KART" "8 PİN LİSTESİ" "9 ATESTASYON" "10 İLK İSTEK"
- başlık (display-lg, krem): "TOKEN BİR KEZ."
- başlık 2 (display-head, krem): "SONRA KİMLİK KART, GÜVEN LİSTE VE PINVAULT-TOKEN."
- alt satır (mono, krem): "Ayrıntı: docs/animation/pinvault-request-flow.tr.html"
- künye: "Kapanış"

Adapt: titlecard-reveal'in tek sakin hareketi korunur (başlık yukarı kayarak belirir, sonra durağan tutma); üstüne zincirin bir kez dolması eklenir.
Scene 1 (0.0–3.0s): Yeşil zemin. Ortanın üstünde krem çerçeveli on hücreli zincir (hücreler ≈150×56) boş durur; hücreler soldan sağa ≈0,2 sn arayla krem dolguya döner (yazı yeşile).
Scene 2 (3.0–6.0s): Başlık yukarı kayarak belirir; 1 sn sonra başlık 2.
Scene 3 (6.0–11.0s): Alt satır belirir. Tutma; videonun tek gerçek çıkışı: son 0,8 sn'de her şey krem zemine sönümlenir.
