---
format: 1920x1080
duration: 196s
message: "Yeni bir telefon, sunucunuzla ilk güvenli isteğe kadar on halkadan geçer: sunucu kurulur, APK hazırlanır, token verilir, telefon kartını alır, listesini ve PinVault-Token'ıni alır, sonra konuşur."
arc: how-to-process
audience: PinVault'u ilk kez kuracak geliştirici ve yöneticiler
mode: autonomous
music: none
---

# PinVault baştan sona — storyboard

Sessiz video. Anlatım ekrandaki yazıyla yapılır; ses, müzik ve efekt yoktur. Her karedeki ekran metni `Ekran metni` altında birebir verilmiştir; işçiler metni değiştirmez, kısaltmaz, çevirmez.

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

**Çerçeve süsü.** Üstte mono üst çubuk: solda "PINVAULT BAŞTAN SONA", sağda hap etiket (karede verilir). Altta mono künye: solda kare adı, sağda "NN • 14". Son kare krem renkli künye varyantını kullanır.

**Hareket dili.** Uzun kuyruklu yumuşak oturma (`power3`); zıplama, aşma, elastik yok. Her parça kendi okuma anında girer: sessiz video olduğu için zamanlama okuma ritmine göre yapılır. Bir satır geldikten sonra bir sonraki parça gelmeden önce kabaca kelime başına 0,35 sn (en az 1,2 sn) beklenir. Hiçbir kare ilk %25'te her şeyi dökmez. Paketler (token, kart, PinVault-Token, liste) çizgi boyunca kayan küçük kartlardır; yolun kendisi soldan sağa çizilerek belirir. Panelde bir düğmeye "basılması" düğmenin kısa bir an içe çökmesi ve ink dolguya dönmesiyle gösterilir; imleç çizilmez.

**Ritim.** Tutma (nefes) kareleri: Kare 2'nin sonu ve Kare 14. Diğerleri okuma ritmiyle açılır, son parça geldikten sonra sakin durur; tutma sırasında en çok hafif titreşim.

**Asla.** Slayt gösterisi (her şeyi başta dökmek, sonra donmak). Ekran koruyucu (bağımsız yüzen çok öğe). Döngüsel nefes alma. Arka yarıda yavaş kaydırma ya da itme. Rastgelelik. CSS transition veya keyframes. Uydurulmuş sayı: yalnızca ekran metnindeki sayılar kullanılır. Gerçek şirket logoları. Fare imleci.

**Alt bant.** Yük taşıyan içerik y ≤ 900 px içinde kalır; altında yalnızca künye.

---

## Frame 1 — Kutudan yeni çıkmış bir tablet

- scene: Yeni bir tablet ve uzakta API sunucusu; aralarında on halkalı bir zincir soldan sağa kurulur
- voiceover:
- duration: 10s
- transition_in: cut
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

## Frame 2 — İki yanlış inanış

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

## Frame 3 — Halka 1: Sunucu kurulur

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

## Frame 4 — Halka 2: APK hazırlanır

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

## Frame 5 — Halka 3: Panelde API sunucunuz eklenir

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
- sonuç notu (body-md): "Panel sunucuya bağlanır; sitenin ve onu imzalayan CA'nın pin'ini kendisi çıkarır."
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

## Frame 6 — Halka 4: Token üretilir

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

## Frame 7 — Halka 5: Token telefona ulaşır

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

## Frame 8 — Halka 6: Kayıt isteği

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

## Frame 9 — Halka 7: Sunucu kartı basar

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

## Frame 10 — Halka 8: İmzalı pin listesi

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

## Frame 11 — Halka 9: PinVault-Token alınır

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
- not 2 (body-md): "PinVault-Token süresi dolmadan, yaklaşık 4 dakikada bir kendiliğinden yenilenir."
- benzetme: "Güvenlik masası çantayı kontrol eder ve 5 dakikalık ziyaret bandı takar."
- künye: "PinVault-Token"

Compose. Yerleşim: solda telefon, sağda sunucu; adım kickerları üstte bir rayda soldan sağa birikir; ölçüm çipleri telefonun yanında.
Scene 1 (0.0–1.5s): Zincir, kicker, başlık.
Scene 2 (1.5–3.5s): Adım 1; sunucudan telefona küçük "?" kartı (soru) kayar.
Scene 3 (3.5–7.0s): Adım 2; beş ölçüm çipi ≈0,4 sn arayla gelir, her birine yeşil ✓; çipler bir rapor kartına toplanır, köşesine kasa simgesiyle mühür.
Scene 4 (7.0–10.5s): Adım 3; rapor sunucuya kayar; yeşil "GEÇTİ"; sunucudan sarı PinVault-Token telefona kayar (karenin tek sert gölgesi PinVault-Token'da).
Scene 5 (10.5–14.0s): Not ve not 2. Benzetme şeridi. Tutma.

## Frame 12 — Halka 10: İlk gerçek istek

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

## Frame 13 — Sonrası

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
- istasyon 2: "ARKA PLAN" / "PinVault-Token ≈4 dakikada bir; değişen liste onunla gelir. Kapalıyken: schedulePeriodicUpdates() ile."
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

## Frame 14 — On halka, tek cümle

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
