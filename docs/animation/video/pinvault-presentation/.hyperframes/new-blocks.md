## Frame — Bölüm 1: Amaç

- scene: Bölüm başlık kartı: büyük "1", "AMAÇ: SSL PINNING", altta üç bölümlük ilerleme
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
- üst çubuk hap: "BÖLÜM 1 / 3"
- numara bloğu (Archivo, çok büyük): "1"
- kicker (mono, siyah kutu): "BÖLÜM 1"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Telefon, konuştuğu sunucunun gerçekten sizin sunucunuz olduğunu nasıl bilir?"
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (şu anki) · "2 ÇÖZÜM" · "3 AKIŞ"
- künye: "Bölüm 1" / sayaç "01 • 25"

Compose. Yerleşim: solda (%30) ink çerçeveli kare numara bloğu (≈ 360×360, krem-2 dolgu, sert gölge karenin tek sert gölgesi); sağda (%60) kicker, başlık, alt satır; altta (y ≈ 760–800) çerçeve genişliğinde üç hücreli bölüm şeridi (hücre ≈ 540×44, aralarında ince ink çizgi; şu anki hücre ink dolgu krem yazı, diğerleri 2 px ink kenar %35 saydam).
Scene 1 (0.0–1.2s): Numara bloğu soldan oturur; içinde "1" yukarı kayarak belirir.
Scene 2 (1.2–2.6s): Kicker, sonra başlık kelime kelime.
Scene 3 (2.6–4.5s): Alt satır; bölüm şeridi soldan çizilir, şu anki hücre dolar. Tutma.

## Frame — Normal TLS neye güvenir

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
- künye: "Normal TLS" / sayaç "03 • 25"

Compose. Yerleşim: üstte başlık ve açıklama; ortada solda telefon, ortada güven deposu kutusu (≈ %40 genişlik, çipler 3×2 ızgara), sağda sahte sunucu; altta son satır.
Scene 1 (0.0–2.5s): Başlık, sonra açıklama.
Scene 2 (2.5–5.0s): Telefon ve yanında güven deposu kutusu; altı çip ≈0,3 sn arayla dolar.
Scene 3 (5.0–8.0s): Turuncu çip sağdan kayıp depodaki boş yuvaya girer; altında açıklaması.
Scene 4 (8.0–10.5s): Sağda sahte sunucu belirir; sertifika kartı telefona kayar; depodaki turuncu çip ile kart arasına turuncu çizgi; "GÜVENİLİR ✓" damgası ve "ama sahte" notu (sert gölge bu damgada).
Scene 5 (10.5–13.0s): Son satır gelir. Tutma.

## Frame — Pinlemenin üç eksiği

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
- künye: "Üç eksik" / sayaç "05 • 25"

Compose. Yerleşim: başlık üstte; altında üç eşit kart yan yana (triptych, her biri ≈ 540×440); alt satır kartların altında.
Scene 1 (0.0–1.8s): Başlık kelime kelime.
Scene 2 (1.8–5.5s): Kart 1 alttan yuvasına oturur; büyük rakam, başlık, sonra alt satır.
Scene 3 (5.5–9.0s): Kart 2 aynı şekilde.
Scene 4 (9.0–12.5s): Kart 3 aynı şekilde; karenin tek sert gölgesi bu kartta.
Scene 5 (12.5–14.0s): Alt satır. Tutma.
