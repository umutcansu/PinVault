---
format: 1920x1080
duration: 212s
message: "Sunucunun çalışması üretime hazır olduğu anlamına gelmez. Kurulum Sihirbazı dört adımda ölçer: sunucu ayarları, sertifikalar, uygulamanın korumaları, uygulamaya girecek kod."
arc: how-to-process
audience: PinVault sunucusunu ilk kez üretime hazırlayacak yönetici ve geliştiriciler
mode: autonomous
music: none
---

# PinVault Kurulum Sihirbazı — storyboard

Sessiz film. Anlatım ekrandaki yazıyla yapılır; ses, müzik ve efekt yoktur. Her karedeki ekran metni `Ekran metni` altında birebir verilmiştir; işçiler metni değiştirmez, kısaltmaz, çevirmez. Her karenin `English screen text` bloğu İngilizce ikiz dosya içindir (`../pinvault-setup-wizard/compositions/frames/<aynı ad>.html`): aynı yerleşim, aynı zamanlama, yalnızca metin değişir; üst çubuk solu orada "PINVAULT · SETUP WIZARD", adım hücreleri "1 · SERVER", "2 · CERTIFICATES", "3 · APP", "4 · CODE", NEDEN etiketi "WHY", künye sayacı aynı.

## Video direction

Bkz. `.hyperframes/video-direction.md` (bütün karelerde ortak; işçi paketine birebir kopyalanır).

---

## Frame 1 — Sunucu açıldı, telefon bağlandı

- scene: Sol menüde "Kurulum Sihirbazı" vurgulu küçük panel; ortada büyük boy dört adımlı şerit soldan sağa kurulur
- voiceover:
- duration: 10s
- transition_in: cut
- status: animated
- src: compositions/frames/01-giris.html
- type: hook
- persuasion: Question hook + frame-then-fill
- beat: curiosity + orientation
- blueprint: compose
- focal: dört adımlı şerit
- roles: panel menüsü = supporting · şerit = foreground subject · başlık = foreground subject

narrativeRole: Filmin haritasını verir: dört adım var ve hepsini sırayla, nedeniyle göreceğiz.
keyMessage: Çalışan bir sunucu hazır bir sunucu değildir; sihirbaz hazır mı diye ölçer.

Ekran metni:
- üst çubuk hap: "GİRİŞ"
- satır 1 (display-head): "SUNUCU AÇILDI. TELEFON BAĞLANDI."
- satır 2 (display-head): "ÜRETİME HAZIR MI?"
- panel menüsü (mono, küçük panel kutusunun sol sütunu): "Config API" / "Kurulum Sihirbazı" (vurgulu) / "Bağlantı Geçmişi" / "Onaylar" / "Denetim Kaydı"
- şerit hücreleri (büyük boy, iki satır: numara + ad): "1" "SUNUCU" · "2" "SERTİFİKALAR" · "3" "UYGULAMA" · "4" "KOD"
- alt satır (body-lg): "Sihirbaz dört adımda ölçer: sunucu ayarları, sertifikalar, uygulamanın koruması ve uygulamaya girecek kod. Hiçbirini kendisi değiştirmez; nerede değişeceğini gösterir."
- künye: "Giriş"

English screen text:
- pill: "INTRO"
- line 1: "THE SERVER IS UP. THE PHONE CONNECTS."
- line 2: "IS IT READY FOR PRODUCTION?"
- panel menu: "Config API" / "Setup Wizard" (highlighted) / "Connection History" / "Approvals" / "Audit Log"
- strip cells: "1" "SERVER" · "2" "CERTIFICATES" · "3" "APP" · "4" "CODE"
- bottom line: "The wizard measures in four steps: server settings, certificates, the app's protections and the code that goes into the app. It changes none of them itself; it shows where each one changes."
- footer: "Intro"

Compose. Yerleşim: üst üçte birde iki satırlık başlık; solda (x ≈ 96–560, y ≈ 420–760) küçük panel kutusu (siyah şerit "Panel · 8090", sol sütunda menü, "Kurulum Sihirbazı" satırı ink dolgulu); sağda (x ≈ 640–1824, y ≈ 470–620) büyük boy dört hücreli şerit (her hücre ≈ 250×110, iki satır metin, aralarında 46 px ink çizgi); alt satır altta (y ≈ 700–780), geniş.
Scene 1 (0.0–2.5s): Satır 1 kelime kelime gelir. Solda panel kutusu oturur, menü satırları yukarıdan aşağıya.
Scene 2 (2.5–4.5s): Satır 2 gelir. Menüde "Kurulum Sihirbazı" satırı ink dolguya döner (basılma).
Scene 3 (4.5–7.5s): Sağda şeridin dört hücresi soldan sağa birer birer oturur (≈0,5 sn arayla), her yeni hücre bir öncekine ink çizgiyle bağlanır.
Scene 4 (7.5–10.0s): Alt satır gelir. Tutma.

## Frame 2 — Çalışmak ile korumak

- scene: Bir yanlış inanış kartı üstü çizilir, altına doğrusu; sağda "SİHİRBAZ NE YAPAR" kutusu
- voiceover:
- duration: 13s
- transition_in: crossfade
- status: animated
- src: compositions/frames/02-neden.html
- type: pain_point
- persuasion: Common-belief vs reality
- beat: surprise + recognition
- blueprint: compose
- focal: yanlış/doğru kartı
- roles: kart = foreground subject · turuncu üstü çizgi = supporting · yeşil doğru satırı = supporting · sağ kutu = supporting

narrativeRole: İzleyicinin "çalışıyor, bitti" inanışını düzeltir ve sihirbazın ne yapıp ne yapmadığını tek kutuda verir.
keyMessage: Demo ayarlarıyla açılan sunucu çalışır ama korumaz; sihirbaz eksikleri sayar, kendisi değiştirmez.

Ekran metni:
- üst çubuk hap: "ÖNCE NEDEN"
- başlık (display-head): "ÇALIŞMAK İLE KORUMAK AYNI ŞEY DEĞİL"
- kart yanlış (turuncu üstü çizili, body-lg): "Sunucu demo ayarlarıyla açıldı ve telefon bağlandı. Demek ki hazır."
- kart doğru (yeşil ✓, body-lg): "Çalışır ama korumaz: ortak yönetici anahtarı, tek imza anahtarı, açık test uçları, açık kayıt. Her biri bir saldırı yolu."
- sağ kutu başlığı (mono): "SİHİRBAZ NE YAPAR"
- sağ kutu satırları (mono): "✓ Sunucu ayarlarını ölçer: 13 madde" / "✓ Sertifikaları ve sürelerini toplar: 21 madde" / "✓ Uygulamanın korumalarını seçtirir" / "✓ Kodu bu sunucunun değerleriyle üretir" / "✗ Hiçbir ayarı kendisi değiştirmez"
- künye: "Neden"

English screen text:
- pill: "FIRST, WHY"
- title: "RUNNING IS NOT THE SAME AS PROTECTING"
- card wrong: "The server started with the demo settings and the phone connected. So it is ready."
- card right: "It runs, but it does not protect: a shared admin key, a single signing key, open test endpoints, open enrollment. Each one is an attack path."
- right box title: "WHAT THE WIZARD DOES"
- right box lines: "✓ Measures the server settings: 13 items" / "✓ Collects the certificates and their expiry: 21 items" / "✓ Lets you choose the app's protections" / "✓ Generates the code from this server's values" / "✗ Changes no setting itself"
- footer: "Why"

Compose. Yerleşim: solda (%60) tek kart (yanlış cümle üstte, doğru cümle altında), sağda (%40) "SİHİRBAZ NE YAPAR" kutusu.
Scene 1 (0.0–1.5s): Başlık.
Scene 2 (1.5–5.0s): Yanlış cümle gelir; okunduktan sonra (≈3,2 sn) üstüne turuncu çizgi çekilir; altında yeşil ✓ ile doğrusu gelir.
Scene 3 (5.0–11.0s): Sağda kutu belirir; beş satır ≈0,9 sn arayla gelir (✓ satırlar yeşil işaretli, ✗ satır turuncu işaretli). Kutunun sert gölgesi karenin tek sert gölgesi.
Scene 4 (11.0–13.0s): Tutma.

## Frame 3 — Adım 1: sunucu ayarları ölçülür

- scene: Panelde 1 · Sunucu adımı: "3 / 13 madde hazır" kartı ve rozetli kontrol tablosu satır satır dolar
- voiceover:
- duration: 16s
- transition_in: push-slide
- status: animated
- src: compositions/frames/03-adim1-kontrol.html
- type: process_step
- persuasion: Show the real screen + reason per row
- beat: orientation + concern
- blueprint: compose
- focal: kontrol tablosu
- roles: panel = foreground subject · rozetler = supporting · sağ açıklama notları = supporting

narrativeRole: İlk adımın gerçek ekranını gösterir: sunucunun şu anki durumu satır satır, her satırın nedeni.
keyMessage: Her satır bir saldırı yolunu kapatır; "şu an" sütunu sunucunun gerçek durumudur.

Ekran metni:
- üst çubuk hap: "ADIM 1 / 4"
- kicker (mono, siyah zemin): "KİM: YÖNETİCİ · NEREDE: PANEL → KURULUM SİHİRBAZI → 1 · SUNUCU"
- başlık (display-head): "SUNUCU AYARLARI ÖLÇÜLÜR"
- panel başlığı (mono): "Panel · 8090 · Kurulum Sihirbazı · 1 · Sunucu"
- kart başlığı (mono): "3 / 13 MADDE HAZIR"
- tablo başlıkları (mono): "" / "Kontrol" / "Şu an" / ".env"
- satır 1: rozet "UYARI" · "Yönetici kimliği" · "ortak API_KEY" · "ADMIN_KEYS=<ad>:<sha256>"
- satır 2: rozet "UYARI" · "Config imzalayıcıları" · "1 imzalayıcı (yerel)" · "CONFIG_SIGNERS=pkcs11,command"
- satır 3: rozet "UYARI" · "Canlı sertifika kontrolü" · "kapalı" · "Ayarlardan ↓"
- satır 4: rozet "UYARI" · "Sunucuda üretilen anahtar" · "açık" · "ENROLLMENT_P12=off"
- satır 5: rozet "UYARI" · "Kayıtta donanım belgesi" · "warn, uygulamaya bağlı değil" · "Ayarlardan ↓"
- satır 6: rozet "HAZIR" · "Yönetim paneli TLS" · "port 8082" · "—"
- satır 7: rozet "HAZIR" · "Kayıt modu" · "token" · "—"
- not 1 (sağda, body-md, satır 1'e bağlı): "Ortak anahtar kimin ne yaptığını göstermez."
- not 2 (sağda, body-md, satır 2'ye bağlı): "Pin'leri imzalayan anahtar çalınırsa saldırgan istediği pin'i yayınlar. En az iki imzalayıcı, biri bu diskte olmayan."
- NEDEN şeridi: "Her satır bir saldırı yolunu kapatır. 'Şu an' sütunu sunucunun gerçek durumudur, varsayım değil."
- künye: "Adım 1 · Kontrol"

English screen text:
- pill: "STEP 1 / 4"
- kicker: "WHO: ADMIN · WHERE: DASHBOARD → SETUP WIZARD → 1 · SERVER"
- title: "THE SERVER SETTINGS ARE MEASURED"
- panel head: "Dashboard · 8090 · Setup Wizard · 1 · Server"
- card title: "3 OF 13 ITEMS READY"
- table heads: "" / "Check" / "Now" / ".env"
- row 1: "WARNING" · "Admin identity" · "shared API_KEY" · "ADMIN_KEYS=<name>:<sha256>"
- row 2: "WARNING" · "Config signers" · "1 signer (local)" · "CONFIG_SIGNERS=pkcs11,command"
- row 3: "WARNING" · "Live certificate check" · "off" · "In Settings ↓"
- row 4: "WARNING" · "Server-made keys" · "on" · "ENROLLMENT_P12=off"
- row 5: "WARNING" · "Key attestation at enrollment" · "warn, app not bound" · "In Settings ↓"
- row 6: "READY" · "Admin panel over TLS" · "port 8082" · "—"
- row 7: "READY" · "Enrollment mode" · "token" · "—"
- note 1: "A shared key does not show who did what."
- note 2: "Whoever steals the key that signs pins can publish any pin. At least two signers, one not on this disk."
- WHY strip: "Every row closes one attack path. The 'Now' column is the server's real state, not an assumption."
- footer: "Step 1 · Check"

Compose. Yerleşim: başlık altında (y ≈ 300–800) sola yaslı geniş panel (x ≈ 96–1330); panel içinde kart başlığı ve dört sütunlu tablo (rozet 110 px, kontrol 380 px, şu an 300 px, .env kalan); sağda (x ≈ 1370–1824) iki açıklama notu, ince ink çizgiyle ilgili satıra bağlı. NEDEN şeridi altta.
Scene 1 (0.0–1.5s): Şerit durur, 1. hücre oturur; kicker ve başlık.
Scene 2 (1.5–3.0s): Panel oturur; kart başlığı "3 / 13 MADDE HAZIR" gelir; tablo başlıkları.
Scene 3 (3.0–9.0s): Yedi satır yukarıdan aşağıya ≈0,8 sn arayla; her satırın rozeti satırdan 0,2 sn sonra oturur (UYARI sarı dolgu, HAZIR yeşil kenar).
Scene 4 (9.0–12.5s): Not 1 belirir ve çizgisi 1. satıra çizilir; 1,5 sn sonra not 2 ve çizgisi 2. satıra.
Scene 5 (12.5–16.0s): NEDEN şeridi. Tutma.

## Frame 4 — Adım 1: iki yoldan düzeltilir

- scene: Solda panelin Ayarlar kartı (değiştir, Kaydet, yeniden başlat), sağda .env satırları kutusu (Kopyala)
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/04-adim1-duzeltme.html
- type: process_step
- persuasion: Two paths, one rule
- beat: relief + clarity
- blueprint: compose
- focal: iki kart
- roles: Ayarlar kartı = foreground subject · .env kutusu = foreground subject · yeniden başlat uyarısı = supporting

narrativeRole: Ölçülen eksiklerin nerede düzeltildiğini gösterir: panelden değişenler ve yalnızca .env'den değişenler.
keyMessage: Gizli değerler panelden geçmez; her iki yol da yeniden başlatma ister.

Ekran metni:
- üst çubuk hap: "ADIM 1 / 4"
- başlık (display-head): "İKİ YOLDAN DÜZELTİLİR"
- sol kart başlığı (mono): "AYARLARDAN ↓ · PANELİN AYARLAR KARTI"
- sol kart satır 1 (body-md): "Canlı sertifika kontrolü" · seçim "Kapalı → Engelle"
- sol kart satır 2 (body-md): "Pin değişikliği için gereken yönetici sayısı" · değer "1 → 2"
- sol kart düğme: "Kaydet"
- sol kart bildirim (yeşil ✓, body-md): "Kaydedildi. Sunucu yeniden başlayınca geçerli olacak."
- sol kart düğme 2: "Şimdi yeniden başlat"
- sağ kart başlığı (mono): "ÖNERİLEN .ENV SATIRLARI" · düğme "Kopyala"
- sağ kart kod (mono): "# Yönetici kimliği" / "ADMIN_KEYS=ayse:3f9c…,mehmet:a81d…" / "# Config imzalayıcıları" / "CONFIG_SIGNERS=pkcs11,command" / "# Sunucuda üretilen anahtar" / "ENROLLMENT_P12=off"
- sağ kart not (body-md): "Parolalar, gizli anahtarlar ve portlar yalnızca .env dosyasında; panel onları görmez."
- NEDEN şeridi: "Gizli değerler panelden geçmez: paneli ele geçiren biri imza anahtarını ya da parolayı değiştiremez."
- künye: "Adım 1 · Düzeltme"

English screen text:
- pill: "STEP 1 / 4"
- title: "FIXED IN TWO PLACES"
- left card title: "IN SETTINGS ↓ · THE DASHBOARD'S SETTINGS CARD"
- left row 1: "Live certificate check" · "Off → Block"
- left row 2: "Admins needed for a pin change" · "1 → 2"
- left button: "Save"
- left notice: "Saved. Applies when the server restarts."
- left button 2: "Restart now"
- right card title: "SUGGESTED .ENV LINES" · button "Copy"
- right code: "# Admin identity" / "ADMIN_KEYS=ayse:3f9c…,mehmet:a81d…" / "# Config signers" / "CONFIG_SIGNERS=pkcs11,command" / "# Server-made keys" / "ENROLLMENT_P12=off"
- right note: "Passwords, secret keys and ports live only in the .env file; the dashboard never sees them."
- WHY strip: "Secrets never pass through the dashboard: whoever takes over the dashboard cannot change the signing key or a password."
- footer: "Step 1 · Fix"

Compose. Yerleşim: başlık altında yan yana iki kart (sol x ≈ 96–940, sağ x ≈ 980–1824; y ≈ 300–790). Sol kartta iki satır, Kaydet düğmesi, bildirim, ikinci düğme. Sağ kartta altı satır kod ve not.
Scene 1 (0.0–1.2s): Şerit durur (1. adım hâlâ şu anki); başlık.
Scene 2 (1.2–6.0s): Sol kart oturur; satır 1 gelir, seçimi "Kapalı"dan "Engelle"ye döner (eski değer soluklaşır, yeni değer gelir); satır 2 aynı şekilde 1'den 2'ye; "Kaydet" basılır (4,8 sn); bildirim yeşil ✓ ile gelir; "Şimdi yeniden başlat" düğmesi belirir.
Scene 3 (6.0–11.0s): Sağ kart oturur; altı satır kod ≈0,45 sn arayla yazılır; "Kopyala" basılır (9,5 sn); not gelir.
Scene 4 (11.0–15.0s): NEDEN şeridi. Tutma.

## Frame 5 — Adım 2: hangi sertifika kimin?

- scene: Sunucu, telefon ve API sunucusu arasında sertifikalar sahibine göre yerleşir; altta dört kartın adı
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/05-adim2-harita.html
- type: process_step
- persuasion: Map before detail
- beat: orientation
- blueprint: compose
- focal: üç sahipli topoloji
- roles: PinVault sunucusu = foreground subject · telefon = supporting · API sunucunuz = supporting · dört kart etiketi = foreground subject

narrativeRole: İkinci adımın dört kartını, sertifikaların kimin olduğuna göre haritaya oturtur; sonraki dört kare bu haritayı tek tek açar.
keyMessage: Üç ayrı sahip, üç ayrı süre: Config API sertifikası ve istemci CA'sı bizim, host sertifikaları API sunucularınızın.

Ekran metni:
- üst çubuk hap: "ADIM 2 / 4"
- kicker (mono): "KİM: YÖNETİCİ · NEREDE: 2 · SERTİFİKALAR · 13 / 21 MADDE HAZIR"
- başlık (display-head): "HANGİ SERTİFİKA KİMİN?"
- sunucu kutusu başlığı: "PinVault sunucusu"
- sunucu sertifika 1 (krem-2 kart, mono): "Config API sertifikası" · alt yazı "pin'leri APK'ya"
- sunucu sertifika 2 (pembe kart, mono): "İstemci CA'sı" · alt yazı "cihaz kartlarını imzalar"
- telefon ekranı: "Uygulamanız" / "PinVault kütüphanesi"
- API kutusu: "API SUNUCUNUZ" / "api.ornek.com"
- API sertifikası (krem-2 kart, mono): "Host sertifikası" · alt yazı "pin'i imzalı listede"
- kart etiketi 1 (mono): "1 · CONFIG API'NİN KENDİ SERTİFİKASI" · (body-md) "bizim"
- kart etiketi 2 (mono): "2 · mTLS: CİHAZ SERTİFİKALARI" · (body-md) "bizim CA'mız"
- kart etiketi 3 (mono): "3 · PİNLENEN HOST'LAR" · (body-md) "API sunucularınızın"
- kart etiketi 4 (mono): "4 · VAULT DOSYALARININ SÜRELERİ" · (body-md) "dosya, sertifika değil"
- NEDEN şeridi: "Üç ayrı sahip, üç ayrı süre. Biri dolunca telefonun nerede duracağını önceden bilmeniz gerekir."
- künye: "Adım 2 · Harita"

English screen text:
- pill: "STEP 2 / 4"
- kicker: "WHO: ADMIN · WHERE: 2 · CERTIFICATES · 13 OF 21 ITEMS READY"
- title: "WHICH CERTIFICATE BELONGS TO WHOM?"
- server box head: "PinVault server"
- server cert 1: "Config API certificate" · "its pins go into the APK"
- server cert 2: "Client CA" · "signs device ID cards"
- phone screen: "Your app" / "PinVault library"
- API box: "YOUR API SERVER" / "api.example.com"
- API cert: "Host certificate" · "its pin is in the signed list"
- card label 1: "1 · THE CONFIG API'S OWN CERTIFICATE" · "ours"
- card label 2: "2 · mTLS: DEVICE CERTIFICATES" · "our CA"
- card label 3: "3 · PINNED HOSTS" · "your API servers'"
- card label 4: "4 · VAULT FILE EXPIRY" · "a file, not a certificate"
- WHY strip: "Three owners, three expiry dates. When one runs out you need to know in advance where the phone will stop."
- footer: "Step 2 · Map"

Compose. Yerleşim: ortada (y ≈ 300–620) solda PinVault sunucusu kutusu (x ≈ 150–600) içinde iki sertifika kartı yan yana; ortada telefon (x ≈ 880–1040); sağda API kutusu (x ≈ 1320–1770) içinde bir sertifika kartı; sunucudan telefona ve telefondan API'ye ince ink hatlar. Altta (y ≈ 660–800) dört kart etiketi yan yana (her biri ≈ 410 px).
Scene 1 (0.0–1.5s): Şerit durur, 2. hücre oturur (1. hücre ink dolgu); kicker ve başlık.
Scene 2 (1.5–4.5s): Sunucu kutusu oturur; iki sertifika kartı arka arkaya çıkar (krem-2, sonra pembe) ve alt yazıları gelir.
Scene 3 (4.5–7.0s): Telefon oturur; sunucudan telefona hat çizilir. API kutusu oturur; telefondan API'ye hat; host sertifikası kartı çıkar.
Scene 4 (7.0–11.0s): Dört kart etiketi soldan sağa ≈0,9 sn arayla; her etiket ilgili sertifikaya ince çizgiyle bağlanır (1 → Config API sertifikası, 2 → İstemci CA'sı, 3 → Host sertifikası, 4 → bağlantısız).
Scene 5 (11.0–15.0s): NEDEN şeridi. Tutma.

## Frame 6 — Adım 2: uygulamadaki ilk pin'ler

- scene: Panelde "Config API'nin kendi sertifikası" kartı: bilgi satırları, dört rozetli satır, "Bootstrap sekmesi" basılınca düğme şeridi
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/06-adim2-config-api.html
- type: process_step
- persuasion: Real rows + where it changes
- beat: understanding
- blueprint: compose
- focal: kartın dört satırı
- roles: panel kartı = foreground subject · UYARI satırı = supporting · Bootstrap düğme şeridi = supporting

narrativeRole: Dört karttan ilkini açar: uygulamaya gömülen pin'lerin sertifikası, süresi, kaynağı, yedeği ve nereden değiştiği.
keyMessage: Self-signed olması sorun değil, pinli; yedek anahtar yoksa anahtar kaybı uygulama güncellemesi ister.

Ekran metni:
- üst çubuk hap: "ADIM 2 / 4"
- başlık (display-head): "UYGULAMADAKİ İLK PİN'LER"
- panel başlığı (mono): "Panel · 8090 · Kurulum Sihirbazı · 2 · Sertifikalar"
- kart başlığı (mono): "CONFIG API'NİN KENDİ SERTİFİKASI (UYGULAMADAKİ İLK PİN'LER)"
- bilgi 1 (mono, küçük): "Sertifika: CN=localhost, O=PinVault Demo · Geçerlilik sonu 08.05.2027"
- bilgi 2 (mono, küçük): "Pin'ler: ojdBCq6J… · NictvYYY…"
- bilgi 3 (mono, küçük): "Dinleyiciler: default-tls :8091 TLS · sample-mtls :8092 MTLS"
- tablo başlıkları (mono): "Ne" / "Şu an" / "Nerede değişir"
- satır 1: rozet "HAZIR" · "Sertifika süresi" · "2027-05-08'e kadar" · düğme "Bootstrap sekmesi"
- satır 2: rozet "HAZIR" · "Sertifikanın kaynağı" · "self-signed, pinli" · düğme "Bootstrap sekmesi"
- satır 3: rozet "UYARI" · "Yedek anahtar" · "yok" · düğme "Bootstrap sekmesi"
- satır 4: rozet "HAZIR" · "Telefonların bağlandığı ad sertifikada" · "192.168.1.10" · düğme "Bootstrap sekmesi"
- Bootstrap şeridi (mono düğmeler, satır 3'ün düğmesine basılınca açılır): "Yedek Anahtara Geç" · "Sertifikayı Yenile" · "JKS Yükle" · "URL'den Al"
- Bootstrap şeridi notu (body-md): "Sertifika değişirse uygulama güncellemesi gerekir; yedek anahtara geçiş gerekmez."
- NEDEN şeridi: "Telefon adı değil pin'i doğrular: self-signed sertifika üretimde geçerlidir. Yedek anahtar yoksa anahtar çalındığında yeni sertifika ve uygulama güncellemesi gerekir."
- künye: "Adım 2 · Config API"

English screen text:
- pill: "STEP 2 / 4"
- title: "THE APP'S FIRST PINS"
- panel head: "Dashboard · 8090 · Setup Wizard · 2 · Certificates"
- card title: "THE CONFIG API'S OWN CERTIFICATE (THE APP'S FIRST PINS)"
- info 1: "Certificate: CN=localhost, O=PinVault Demo · Valid until 2027-05-08"
- info 2: "Pins: ojdBCq6J… · NictvYYY…"
- info 3: "Listeners: default-tls :8091 TLS · sample-mtls :8092 MTLS"
- table heads: "What" / "Now" / "Where it changes"
- row 1: "READY" · "Certificate validity" · "until 2027-05-08" · "Bootstrap tab"
- row 2: "READY" · "Where the certificate is from" · "self-signed, pinned" · "Bootstrap tab"
- row 3: "WARNING" · "Backup key" · "none" · "Bootstrap tab"
- row 4: "READY" · "The name phones connect to is in the certificate" · "192.168.1.10" · "Bootstrap tab"
- Bootstrap strip: "Switch to Backup Key" · "Renew Certificate" · "Upload JKS" · "Fetch from URL"
- strip note: "A new certificate needs an app update; a switch to the backup key does not."
- WHY strip: "The phone checks the pin, not the name: a self-signed certificate is fine in production. Without a backup key, a stolen key means a new certificate and an app update."
- footer: "Step 2 · Config API"

Compose. Yerleşim: başlık altında geniş panel (x ≈ 96–1824, y ≈ 290–720): kart başlığı, üç bilgi satırı, dört satırlık tablo (rozet 110 px, ne 560 px, şu an 420 px, düğme sağda). Panelin altında (y ≈ 735–800) Bootstrap düğme şeridi ve notu.
Scene 1 (0.0–1.2s): Şerit durur (2. adım şu anki); başlık.
Scene 2 (1.2–3.5s): Panel oturur; kart başlığı; üç bilgi satırı ≈0,5 sn arayla.
Scene 3 (3.5–8.0s): Dört satır ≈0,9 sn arayla, rozetler 0,2 sn sonra; UYARI satırı sarı rozetiyle ve krem-2 zeminle hafifçe öne çıkar.
Scene 4 (8.0–11.0s): Satır 3'ün "Bootstrap sekmesi" düğmesi basılır (8,2 sn); altta dört düğmeli şerit soldan sağa açılır; "Sertifikayı Yenile" düğmesi 0,6 sn sarı kenarla vurgulanır; not gelir.
Scene 5 (11.0–15.0s): NEDEN şeridi. Tutma.

## Frame 7 — Adım 2: cihaz kartlarını kim basar?

- scene: Panelde "mTLS: cihaz sertifikaları" kartı; yanında sunucudan telefona giden pembe kart ve koda giden clientCaPins çipi
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/07-adim2-mtls.html
- type: process_step
- persuasion: Real rows + the one dangerous expiry
- beat: understanding + foresight
- blueprint: compose
- focal: kartın satırları ve pembe kart
- roles: panel kartı = foreground subject · pembe kart = supporting · clientCaPins çipi = supporting

narrativeRole: İkinci kartı açar: cihaz sertifikalarını imzalayan CA, ömürler, kayıt modu, kurtarma kapısı.
keyMessage: CA'nın süresi dolunca hiçbir cihaz yenilenemez; CA değişimi bütün cihazların yeniden kaydı demektir.

Ekran metni:
- üst çubuk hap: "ADIM 2 / 4"
- başlık (display-head): "CİHAZ KARTLARINI KİM BASAR?"
- kart başlığı (mono): "mTLS: CİHAZ SERTİFİKALARI"
- bilgi 1 (mono, küçük): "Sertifika: CN=PinVault Client CA · Geçerlilik sonu 28.09.2036"
- bilgi 2 (mono, küçük): "Client CA pin'i (clientCaPins): OGdpcSUL…"
- tablo başlıkları (mono): "Ne" / "Şu an" / "Nerede değişir"
- satır 1: rozet "HAZIR" · "Client CA süresi" · "2036-09-28'e kadar" · düğme "mTLS sekmesi"
- satır 2: rozet "HAZIR" · "Cihaz sertifikası ömrü" · "90 gün" · düğme "mTLS sekmesi"
- satır 3: rozet "HAZIR" · "Kayıt modu" · "token" · düğme "mTLS sekmesi"
- satır 4: rozet "UYARI" · "Sunucu üretimli anahtar (P12)" · "açık" · düğme "mTLS sekmesi"
- satır 5: rozet "HAZIR" · "Kurtarma kapısı" · "port 8093" · düğme "mTLS sekmesi"
- satır 6: rozet "HAZIR" · "Sunucu CA süresi" · "2036-09-28'e kadar" · düğme "mTLS sekmesi"
- satır 7: rozet "HAZIR" · "Kayıtlı cihaz" · "0" · düğme "mTLS sekmesi"
- sağ görsel: PinVault sunucusu kutusu (kapılar 8090–8093), telefon; aralarında pembe kart "tablet-07" sunucudan telefona kayar; kartın altında mono "90 gün · üçte biri kalınca yenilenir"
- çip (pembe kenarlı, mono): "clientCaPins → 4 · Kod adımı"
- NEDEN şeridi: "Client CA'nın süresi dolunca hiçbir cihaz yenilenemez; CA değişimi bütün cihazların yeniden kaydıdır. 90 gün, çalınan bir kartın işe yarama süresini kısaltır."
- künye: "Adım 2 · mTLS"

English screen text:
- pill: "STEP 2 / 4"
- title: "WHO ISSUES THE DEVICE ID CARDS?"
- card title: "mTLS: DEVICE CERTIFICATES"
- info 1: "Certificate: CN=PinVault Client CA · Valid until 2036-09-28"
- info 2: "Client CA pin (clientCaPins): OGdpcSUL…"
- table heads: "What" / "Now" / "Where it changes"
- row 1: "READY" · "Client CA validity" · "until 2036-09-28" · "mTLS tab"
- row 2: "READY" · "Device certificate lifetime" · "90 days" · "mTLS tab"
- row 3: "READY" · "Enrollment mode" · "token" · "mTLS tab"
- row 4: "WARNING" · "Server-made keys (P12)" · "on" · "mTLS tab"
- row 5: "READY" · "Recovery door" · "port 8093" · "mTLS tab"
- row 6: "READY" · "Server CA validity" · "until 2036-09-28" · "mTLS tab"
- row 7: "READY" · "Enrolled devices" · "0" · "mTLS tab"
- right visual labels: "PinVault server", phone "Your app" / "PinVault library", pink card "tablet-07", under it "90 days · renewed with a third left"
- chip: "clientCaPins → 4 · Code step"
- WHY strip: "When the client CA expires no device can renew; a CA change means every device enrolls again. 90 days limits how long a stolen card works."
- footer: "Step 2 · mTLS"

Compose. Yerleşim: solda (x ≈ 96–1240, y ≈ 290–800) panel kartı: başlık, iki bilgi satırı, yedi satırlık tablo (satır yüksekliği ≈ 52 px). Sağda (x ≈ 1290–1824) üstte sunucu kutusu, altta telefon, aralarında kart yolu; en altta çip.
Scene 1 (0.0–1.2s): Şerit durur; başlık.
Scene 2 (1.2–3.0s): Panel oturur; kart başlığı ve iki bilgi satırı.
Scene 3 (3.0–9.0s): Yedi satır ≈0,8 sn arayla; UYARI satırı sarı rozet.
Scene 4 (9.0–11.5s): Sağda sunucu ve telefon oturur; pembe kart sunucudan telefona kayar (1,2 sn), altında ömür yazısı; çip belirir ve bilgi 2'deki pin'e ince çizgiyle bağlanır.
Scene 5 (11.5–15.0s): NEDEN şeridi. Tutma.

## Frame 8 — Adım 2: API sunucularınızın pin'leri

- scene: Panelde "Pinlenen host'lar" kartı: üç host satırı, yedek pin'in kaynağı; "Host sayfası" basılınca "URL'den Al" ve yedek pin alanı
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/08-adim2-hostlar.html
- type: process_step
- persuasion: The hidden trust in a backup pin
- beat: surprise + resolve
- blueprint: compose
- focal: yedek pin sütunu
- roles: panel kartı = foreground subject · CA pin'i notu = supporting · Host sayfası kutusu = supporting

narrativeRole: Üçüncü kartı açar: telefonun bağlanacağı API sunucularının sertifikaları ve yedek pin'in aslında kime güvendiği.
keyMessage: URL'den alınan yedek pin çoğu zaman CA'nındır; CA'nın anahtarı çalınırsa sahte sertifika da geçer.

Ekran metni:
- üst çubuk hap: "ADIM 2 / 4"
- başlık (display-head): "API SUNUCULARINIZIN PİN'LERİ"
- kart başlığı (mono): "PİNLENEN HOST'LAR (3)"
- tablo başlıkları (mono): "Hostname" / "Şu an" / "Nerede değişir"
- satır 1: rozet "UYARI" · "api.ornek.com" · alt yazı "default-tls · URL'den alındı" · "Sertifika süresi: 2027-03-02'ye kadar" / "Yedek pin: CA pin'i (sertifikayı veren kurum)" · düğme "Host sayfası"
- satır 2: rozet "HAZIR" · "odeme.ornek.com" · alt yazı "default-tls · elle girildi" · "Sertifika süresi: 2026-12-14'e kadar" / "Yedek pin: sunucuda saklı yedek anahtar" · düğme "Host sayfası"
- satır 3: rozet "UYARI" · "mock-tls.sample" · alt yazı "default-tls · sunucu üretti · mock" · "Bu sunucunun sunduğu host: test hedefi" / "Üretimde gerçek sunucunun pin'leri girilmeli" · düğme "Host sayfası"
- not (body-md, satır 1'in yedek pin'ine bağlı): "CA pin'i = o kurumun verdiği her sertifika kabul edilir."
- Host sayfası kutusu (satır 1'in düğmesine basılınca): başlık (mono) "api.ornek.com · Host sayfası" · düğme "URL'den Al" · alan etiketi "Yedek pin" · alan değeri (mono) "kendi ikinci anahtarınızın pin'i" · düğme "Kaydet"
- NEDEN şeridi: "URL'den alınan yedek pin çoğu zaman sertifikayı veren CA'nındır: o CA'nın anahtarı çalınırsa sahte sertifika da geçer. Kendi ikinci anahtarınızın pin'ini girin."
- künye: "Adım 2 · Host'lar"

English screen text:
- pill: "STEP 2 / 4"
- title: "YOUR API SERVERS' PINS"
- card title: "PINNED HOSTS (3)"
- table heads: "Hostname" / "Now" / "Where it changes"
- row 1: "WARNING" · "api.example.com" · "default-tls · from URL" · "Certificate validity: until 2027-03-02" / "Backup pin: CA pin (the issuing authority)" · "Host page"
- row 2: "READY" · "pay.example.com" · "default-tls · entered by hand" · "Certificate validity: until 2026-12-14" / "Backup pin: backup key stored on this server" · "Host page"
- row 3: "WARNING" · "mock-tls.sample" · "default-tls · server-made · mock" · "Served by this server: a test target" / "In production enter the real server's pins" · "Host page"
- note: "CA pin = every certificate that authority issues is accepted."
- Host page box: "api.example.com · Host page" · "Fetch from URL" · "Backup pin" · "the pin of your own second key" · "Save"
- WHY strip: "A backup pin taken from a URL is usually the issuing CA's: if that CA's key is stolen, a forged certificate passes too. Enter the pin of your own second key."
- footer: "Step 2 · Hosts"

Compose. Yerleşim: solda (x ≈ 96–1300, y ≈ 290–760) panel kartı: başlık, üç satırlık tablo (her satır iki metin satırı, yükseklik ≈ 110 px). Sağda (x ≈ 1340–1824) üstte not, altta Host sayfası kutusu (y ≈ 520–800).
Scene 1 (0.0–1.2s): Şerit durur; başlık.
Scene 2 (1.2–7.0s): Panel oturur; üç satır ≈1,6 sn arayla (her satırın ikinci metin satırı 0,5 sn sonra); satır 1'in "Yedek pin: CA pin'i" ifadesi sarı alt çizgiyle vurgulanır (5,5 sn).
Scene 3 (7.0–8.5s): Not belirir, vurgulu ifadeye çizgi.
Scene 4 (8.5–11.5s): Satır 1'in "Host sayfası" düğmesi basılır (8,6 sn); sağda Host sayfası kutusu oturur; "URL'den Al" düğmesi, yedek pin alanı ve "Kaydet" ≈0,6 sn arayla.
Scene 5 (11.5–15.0s): NEDEN şeridi. Tutma.

## Frame 9 — Adım 2: dosyaların da süresi var

- scene: Panelde "Vault dosyalarının süreleri" kartı: iki dosya satırı ve yükleme alanındaki "expiresAt"
- voiceover:
- duration: 12s
- transition_in: push-slide
- status: animated
- src: compositions/frames/09-adim2-vault.html
- type: process_step
- persuasion: Reminder, not a lock
- beat: clarity
- blueprint: compose
- focal: iki dosya satırı
- roles: panel kartı = foreground subject · yükleme alanı = supporting

narrativeRole: Dördüncü kartı açar: süre girilen vault dosyaları; bunun bir hatırlatma olduğunu, kilit olmadığını söyler.
keyMessage: Süre bir hatırlatmadır; dosya cihazlara yine verilir, yöneticiye "yenisini yükle" der.

Ekran metni:
- üst çubuk hap: "ADIM 2 / 4"
- başlık (display-head): "DOSYALARIN DA SÜRESİ VAR"
- kart başlığı (mono): "VAULT DOSYALARININ SÜRELERİ"
- tablo başlıkları (mono): "Dosya" / "Şu an" / "Nerede değişir"
- satır 1: rozet "UYARI" · "ml-model · v12" · "21 gün kaldı · 2026-11-29" · düğme "Vault sekmesi"
- satır 2: rozet "HAZIR" · "terms.pdf · v3" · "2027-06-30'a kadar" · düğme "Vault sekmesi"
- not (body-md): "Süre bir hatırlatmadır; dosya cihazlara yine verilir. Günlük denetim kaydı: vault_file_expiring."
- yükleme kutusu (satır 1'in düğmesine basılınca): başlık (mono) "Vault'a Yükle" · alan "Anahtar: ml-model" · alan "Dosya: model-v13.tflite" · alan "Süre (expiresAt): 2027-02-28" · düğme "Yükle"
- NEDEN şeridi: "Model ya da sözleşme eskiyince telefon bunu bilemez; süre yöneticiye yenisini yükle der, dosyayı kesmez."
- künye: "Adım 2 · Vault"

English screen text:
- pill: "STEP 2 / 4"
- title: "FILES EXPIRE TOO"
- card title: "VAULT FILE EXPIRY"
- table heads: "File" / "Now" / "Where it changes"
- row 1: "WARNING" · "ml-model · v12" · "21 days left · 2026-11-29" · "Vault tab"
- row 2: "READY" · "terms.pdf · v3" · "until 2027-06-30" · "Vault tab"
- note: "The expiry is a reminder; devices are still served the file. Daily audit entry: vault_file_expiring."
- upload box: "Upload to Vault" · "Key: ml-model" · "File: model-v13.tflite" · "Expiry (expiresAt): 2027-02-28" · "Upload"
- WHY strip: "When a model or a contract goes stale the phone cannot tell; the expiry tells the admin to upload a new one, it does not cut the file off."
- footer: "Step 2 · Vault"

Compose. Yerleşim: solda (x ≈ 96–1240, y ≈ 290–620) panel kartı: başlık, iki satır, not. Sağda (x ≈ 1290–1824, y ≈ 290–720) yükleme kutusu.
Scene 1 (0.0–1.2s): Şerit durur; başlık.
Scene 2 (1.2–4.5s): Panel oturur; iki satır ≈1,0 sn arayla; not gelir.
Scene 3 (4.5–8.0s): Satır 1'in "Vault sekmesi" düğmesi basılır (4,7 sn); sağda yükleme kutusu oturur; üç alan ≈0,6 sn arayla; "Süre (expiresAt)" alanı sarı kenarla vurgulanır; "Yükle" basılır (7,6 sn).
Scene 4 (8.0–12.0s): NEDEN şeridi. Tutma.

## Frame 10 — Adım 3: uygulama neye bağlanır, neyi açar?

- scene: Panelde 3 · Uygulama formu: Config API seçimi, adres, kayıt API'si, dil; sağda koruma kutuları işaretlenir
- voiceover:
- duration: 16s
- transition_in: push-slide
- status: animated
- src: compositions/frames/10-adim3-secimler.html
- type: process_step
- persuasion: Show the choices as they are made
- beat: agency
- blueprint: compose
- focal: koruma kutuları listesi
- roles: form = foreground subject · kutu listesi = foreground subject · gri kutu notu = supporting

narrativeRole: Üçüncü adımın ekranı: geliştirici hangi Config API'ye bağlanacağını ve hangi korumaları açacağını seçer.
keyMessage: Gri seçenek sunucunun henüz sunmadığı korumadır; önce 1. adımdaki satır, sonra bu kutu.

Ekran metni:
- üst çubuk hap: "ADIM 3 / 4"
- kicker (mono): "KİM: GELİŞTİRİCİ · NEREDE: 3 · UYGULAMA"
- başlık (display-head): "UYGULAMA NEYE BAĞLANIR, NEYİ AÇAR?"
- panel başlığı (mono): "Panel · 8090 · Kurulum Sihirbazı · 3 · Uygulama"
- form ipucu (body-md): "Uygulamanın bağlanacağı Config API'yi ve açılacak korumaları seç. Kod bir sonraki adımda."
- alan 1 etiketi: "Config API" · değer (mono): "sample-mtls · MTLS · :8092" · açılır listenin diğer satırı (soluk): "default-tls · TLS · :8091"
- alan 2 etiketi: "Uygulamanın bağlanacağı adres (host ya da IP)" · değer (mono): "192.168.1.10"
- alan 3 etiketi: "Kayıt için TLS Config API" · değer (mono): "default-tls · :8091"
- alan 4 etiketi: "Dil" · değer (mono): "Kotlin"
- kutu 1 (işaretli ✓): "İmzalı config (sunucunun imza anahtarları)"
- kutu 2 (işaretli ✓): "Config'i bu Config API'ye bağla (serverScope)"
- kutu 3 (gri, işaretsiz): "İmza anahtarı döndürme (recoveryPublicKeys)" · gri not (mono küçük): "sunucuda kurtarma anahtarı yok"
- kutu 4 (işaretli ✓): "İstemci CA'sını pin'le (clientCaPins)"
- kutu 5 (işaretli ✓): "Süresi dolan sertifikayı kurtarma kapısından yenile"
- kutu 6 (işaretli ✓): "Ortam kontrolü (environmentGuard: root / kanca tespitinin kararı)"
- kutu 7 (işaretsiz): "Kayıtta Play Integrity token'ı gönder (integrityTokenProvider)"
- kutu 8 (işaretsiz): "Anahtarlar yalnızca telefon kilidi açıkken çalışsın (requireUnlockedDevice)"
- kutu 9 (işaretli ✓): "Cihaz iptal edilince dosyaları sil (wipeVaultFilesOnRevocation)"
- sayı 1: "Vault dosyalarının çevrimdışı ömrü (gün)" · "7"
- sayı 2: "Pin güncelleme aralığı (saat)" · "12"
- NEDEN şeridi: "Gri seçenek sunucunun henüz sunmadığı korumadır: önce 1. adımdaki .env satırı, sonra bu kutu. Uygulama sunucunun verebileceğinden fazlasını isteyemez."
- künye: "Adım 3 · Seçimler"

English screen text:
- pill: "STEP 3 / 4"
- kicker: "WHO: DEVELOPER · WHERE: 3 · APP"
- title: "WHAT THE APP CONNECTS TO, WHAT IT TURNS ON"
- panel head: "Dashboard · 8090 · Setup Wizard · 3 · App"
- form hint: "Pick the Config API the app connects to and the protections to turn on. The code is in the next step."
- field 1: "Config API" · "sample-mtls · MTLS · :8092" · other option "default-tls · TLS · :8091"
- field 2: "Address the app connects to (host or IP)" · "192.168.1.10"
- field 3: "TLS Config API for enrollment" · "default-tls · :8091"
- field 4: "Language" · "Kotlin"
- box 1 (✓): "Signed configs (the server's signing keys)"
- box 2 (✓): "Bind configs to this Config API (serverScope)"
- box 3 (grey): "Signing-key rotation (recoveryPublicKeys)" · grey note "no recovery key on the server"
- box 4 (✓): "Pin the client CA (clientCaPins)"
- box 5 (✓): "Renew an expired certificate through the recovery door"
- box 6 (✓): "Environment check (environmentGuard: your root / hooking detection's verdict)"
- box 7: "Send a Play Integrity token at enrollment (integrityTokenProvider)"
- box 8: "Keys work only while the phone is unlocked (requireUnlockedDevice)"
- box 9 (✓): "Delete files when the device is revoked (wipeVaultFilesOnRevocation)"
- number 1: "Offline lifetime of vault files (days)" · "7"
- number 2: "Pin update interval (hours)" · "12"
- WHY strip: "A grey option is a protection the server does not offer yet: first the .env line from step 1, then this box. The app cannot ask for more than the server can give."
- footer: "Step 3 · Choices"

Compose. Yerleşim: başlık altında geniş panel (x ≈ 96–1824, y ≈ 290–800) iki sütun: solda (≈ 700 px) form ipucu ve dört alan (alan: etiket üstte, ink çerçeveli değer kutusu altta); sağda (≈ 960 px) dokuz onay kutusu (kare kutu + metin, satır yüksekliği 44 px) ve iki sayı alanı yan yana.
Scene 1 (0.0–1.5s): Şerit durur, 3. hücre oturur (1 ve 2 ink dolgu); kicker ve başlık.
Scene 2 (1.5–5.5s): Panel oturur; form ipucu; dört alan ≈0,8 sn arayla; alan 1'in değeri açılır liste gibi iki satır gösterip "sample-mtls" satırında kalır.
Scene 3 (5.5–11.5s): Dokuz kutu yukarıdan aşağıya ≈0,6 sn arayla; işaretli olanların ✓'si 0,2 sn sonra oturur; kutu 3 gri gelir ve gri notu belirir; iki sayı alanı en sonda.
Scene 4 (11.5–16.0s): NEDEN şeridi. Tutma.

## Frame 11 — Adım 3: her kutu bir soruya cevap

- scene: Beş kart: her biri bir korumanın adı, kapattığı soru ve cevabı
- voiceover:
- duration: 15s
- transition_in: push-slide
- status: animated
- src: compositions/frames/11-adim3-neden.html
- type: feature_showcase
- persuasion: Question → answer per protection
- beat: understanding
- blueprint: compose
- focal: beş kart
- roles: beş kart = foreground subject · küçük simgeler = supporting

narrativeRole: Seçilen korumaların neden var olduğunu, her birini bir soruyla açıklar.
keyMessage: Kapalı bir kutu bir soruyu cevapsız bırakır; üretimde cevapsız soru kalmasın.

Ekran metni:
- üst çubuk hap: "ADIM 3 / 4"
- başlık (display-head): "HER KUTU BİR SORUYA CEVAP"
- kart 1 başlığı (mono): "İMZALI CONFIG" · soru (body-md): "Pin listesini kim yayınlayabilir?" · cevap (body-md, ✓): "Yalnızca imza anahtarının sahibi. Telefon imzayı her yüklemede doğrular."
- kart 2 başlığı (mono): "serverScope" · soru: "Başka bir PinVault sunucusunun listesi geçer mi?" · cevap: "Hayır. Liste bu Config API'nin kimliğini taşır."
- kart 3 başlığı (mono): "clientCaPins" · soru: "Cihaz kartını kim basmış olabilir?" · cevap: "Yalnızca bizim istemci CA'mız; başka CA'nın kartı reddedilir."
- kart 4 başlığı (mono): "environmentGuard" · soru: "Root ya da kanca varsa ne olur?" · cevap: "Sizin tespitiniz karar verir. INIT açık kalır, pinli trafik durmaz."
- kart 5 başlığı (mono): "wipeVaultFilesOnRevocation" · soru: "İptal edilen telefondaki dosyalar?" · cevap: "Silinir. Kart geçersiz olunca dosya da gider."
- NEDEN şeridi: "Kapalı bir kutu bir soruyu cevapsız bırakır. Üretimde cevapsız soru kalmasın."
- künye: "Adım 3 · Neden"

English screen text:
- pill: "STEP 3 / 4"
- title: "EVERY BOX ANSWERS A QUESTION"
- card 1: "SIGNED CONFIG" · "Who can publish the pin list?" · "Only the owner of the signing key. The phone verifies the signature on every load."
- card 2: "serverScope" · "Would another PinVault server's list pass?" · "No. The list carries this Config API's identity."
- card 3: "clientCaPins" · "Who could have issued the device card?" · "Only our client CA; a card from another CA is refused."
- card 4: "environmentGuard" · "What happens on a rooted or hooked phone?" · "Your detection decides. INIT stays open, pinned traffic keeps working."
- card 5: "wipeVaultFilesOnRevocation" · "The files on a revoked phone?" · "Deleted. When the card becomes invalid the files go too."
- WHY strip: "A closed box leaves a question unanswered. Leave no question unanswered in production."
- footer: "Step 3 · Why"

Compose. Yerleşim: başlık altında (y ≈ 300–790) beş dik kart yan yana (her biri ≈ 320×480, aralık 32 px, x ≈ 96'dan başlar): üstte küçük simge (kart 1 sarı "İMZA" mührü, kart 2 ink rozet "sample-mtls", kart 3 pembe kart, kart 4 turuncu ✗ ve yeşil ✓ yan yana, kart 5 krem-2 dosya kartı üstü turuncu çizgili), altında mono başlık, soru, ince çizgi, cevap. Kart 4'ün sert gölgesi karenin tek sert gölgesi.
Scene 1 (0.0–1.2s): Şerit durur (3. adım şu anki); başlık.
Scene 2 (1.2–11.0s): Beş kart soldan sağa ≈1,9 sn arayla: kart oturur, simge, başlık, soru; 0,8 sn sonra cevap.
Scene 3 (11.0–15.0s): NEDEN şeridi. Tutma.

## Frame 12 — Adım 4: kod bu sunucunun değerleriyle üretilir

- scene: Panelde 4 · Kod: Kotlin kodu satır satır yazılır; sağda her değerin nereden geldiğini gösteren çipler; "Kopyala" basılır
- voiceover:
- duration: 16s
- transition_in: push-slide
- status: animated
- src: compositions/frames/12-adim4-kod.html
- type: process_step
- persuasion: Provenance of every value
- beat: confidence
- blueprint: compose
- focal: kod bloğu
- roles: kod = foreground subject · kaynak çipleri = supporting · Kopyala düğmesi = supporting

narrativeRole: Dördüncü adımın ekranı: üretilen kod ve her değerin sunucudaki kaynağı.
keyMessage: Elle kopyalanan pin yanlış olur; sihirbaz değerleri sunucunun kendisinden okur ve yalnızca açık değerleri yazar.

Ekran metni:
- üst çubuk hap: "ADIM 4 / 4"
- kicker (mono): "KİM: GELİŞTİRİCİ · NEREDE: 4 · KOD → UYGULAMANIN APPLICATION SINIFI"
- başlık (display-head): "KOD BU SUNUCUNUN DEĞERLERİYLE ÜRETİLİR"
- panel başlığı (mono): "Panel · 8090 · Kurulum Sihirbazı · 4 · Kod · Kotlin" · düğme "Kopyala"
- kod (mono, girinti korunur):
  "// PinVault configuration — setup wizard, 2026-11-08, Config API \"sample-mtls\" (mtls)."
  "val config = PinVaultConfig.Builder()"
  "    .configApi(\"sample-mtls\", \"https://192.168.1.10:8092/\") {"
  "        bootstrapPins(listOf("
  "            HostPin(\"192.168.1.10\", listOf(\"ojdBCq6J…\", \"NictvYYY…\")),        // Config API certificate"
  "            HostPin(\"192.168.1.10:8093\", listOf(\"i6Vddf5Y…\", \"ejDTyiOV…\"))    // recovery door (server CA)"
  "        ))"
  "        signaturePublicKeys(\"MFkwEwYH…\")"
  "        serverScope(\"sample-mtls\")"
  "        clientCaPins(\"OGdpcSUL…\")"
  "        enrollmentUrl(\"https://192.168.1.10:8091/\")"
  "        renewalUrl(\"https://192.168.1.10:8093/\")"
  "    }"
  "    .vaultFileMaxOfflineAge(7, TimeUnit.DAYS)"
  "    .wipeVaultFilesOnRevocation()"
  "    .updateIntervalHours(12)"
  "    .environmentGuard { op -> op == GuardedOperation.INIT || !DeviceShield.isCompromised() }"
  "    .build()"
  ""
  "if (!PinVault.isEnrolled(context, config)) {"
  "    PinVault.enrollForResult(context, config, enrollmentToken)"
  "}"
  "val result = PinVault.init(context, config)"
- çip 1 (mono): "pin'ler ← Config API sertifikası (2. adım, kart 1)"
- çip 2 (mono): "imza anahtarı ← İmzalama sekmesi"
- çip 3 (mono): "clientCaPins ← istemci CA'sı (2. adım, kart 2)"
- çip 4 (mono): "8091 / 8093 ← kayıt ve kurtarma kapıları"
- not (body-md): "Sertifika ya da imza anahtarı değişirse sihirbazı yeniden çalıştırın; kod yenilenir."
- NEDEN şeridi: "Elle kopyalanan pin yanlış olur. Sihirbaz değerleri sunucunun kendisinden okur ve yalnızca açık değerleri yazar: gizli anahtar koda girmez."
- künye: "Adım 4 · Kod"

English screen text:
- pill: "STEP 4 / 4"
- kicker: "WHO: DEVELOPER · WHERE: 4 · CODE → THE APP'S APPLICATION CLASS"
- title: "THE CODE IS GENERATED FROM THIS SERVER'S VALUES"
- panel head: "Dashboard · 8090 · Setup Wizard · 4 · Code · Kotlin" · button "Copy"
- code: identical to the Turkish frame (the code is already English)
- chip 1: "pins ← Config API certificate (step 2, card 1)"
- chip 2: "signing key ← Signing tab"
- chip 3: "clientCaPins ← client CA (step 2, card 2)"
- chip 4: "8091 / 8093 ← enrollment and recovery doors"
- note: "Run the wizard again after the certificate or a signing key changes; the code is regenerated."
- WHY strip: "A pin copied by hand goes wrong. The wizard reads the values from the server itself and writes only public ones: no secret key enters the code."
- footer: "Step 4 · Code"

Compose. Yerleşim: solda (x ≈ 96–1290, y ≈ 290–820) panel: başlık şeridi (sağında Kopyala), içinde kod bloğu (mono 19 px, satır yüksekliği 26 px, 23 satır). Sağda (x ≈ 1330–1824) dört çip alt alta (y ≈ 330–600), ilgili kod satırına ince çizgiyle bağlı; altında not.
Scene 1 (0.0–1.5s): Şerit durur, 4. hücre oturur (1–3 ink dolgu); kicker ve başlık.
Scene 2 (1.5–8.0s): Panel oturur; kod satır satır yazılır (≈0,27 sn/satır).
Scene 3 (8.0–11.5s): Çipler ≈0,7 sn arayla belirir ve satırlarına bağlanır (çip 1 → HostPin satırı, çip 2 → signaturePublicKeys, çip 3 → clientCaPins, çip 4 → enrollmentUrl/renewalUrl); "Kopyala" basılır (11,0 sn); not gelir.
Scene 4 (11.5–16.0s): NEDEN şeridi. Tutma.

## Frame 13 — İlk telefon bağlanır

- scene: Telefon 8091'e kayıt olur, pembe kartını alır; 8092'den imzalı listeyi alır; panelde Bağlantı Geçmişi satırı
- voiceover:
- duration: 14s
- transition_in: crossfade
- status: animated
- src: compositions/frames/13-ilk-telefon.html
- type: payoff
- persuasion: Show the result of the four steps
- beat: satisfaction
- blueprint: compose
- focal: telefon ile sunucu arasındaki iki yol
- roles: telefon = foreground subject · PinVault sunucusu = foreground subject · pembe kart = supporting · sarı mühürlü liste = supporting · panel şeridi = supporting

narrativeRole: Dört adımın sonucunu gösterir: sihirbazın ürettiği kodla ilk bağlantı nasıl başlar.
keyMessage: İlk bağlantı pinli, imzalı ve kimlikli başlar; sonradan sıkılaştırma yok.

Ekran metni:
- üst çubuk hap: "SONUÇ"
- başlık (display-head): "İLK TELEFON BAĞLANIR"
- telefon ekranı: "Uygulamanız" / "PinVault kütüphanesi" · etiket (mono): "tablet-07"
- sunucu kutusu: "PinVault sunucusu" · kapılar "8090" "8091" "8092" "8093"
- yol 1 etiketi (mono, 8091'e): "1 · KAYIT: token + CSR · pinli bağlantı"
- yol 1 dönüş (pembe kart): "tablet-07" · alt yazı (mono): "90 gün"
- yol 2 etiketi (mono, 8092'ye): "2 · init: imzalı pin listesi · mTLS"
- yol 2 dönüş (krem-2 liste kartı, sarı "İMZA" mührü): "api.ornek.com · odeme.ornek.com"
- telefon durumu (yeşil ✓, mono): "InitResult.Ready"
- satır 1 (body-md): "Kayıt init'ten önce: mTLS kapısı kartsız açılmaz."
- satır 2 (body-md): "Liste imzalı ve bu sunucuya bağlı; telefon ikisini de kontrol eder."
- panel şeridi (mono): "Panel · Bağlantı Geçmişi · tablet-07 · sample-mtls · config v1 · ✓"
- NEDEN şeridi: "Sihirbazın ürettiği kodla ilk bağlantı pinli, imzalı ve kimlikli başlar; sonradan sıkılaştırma yok."
- künye: "İlk telefon"

English screen text:
- pill: "RESULT"
- title: "THE FIRST PHONE CONNECTS"
- phone: "Your app" / "PinVault library" · "tablet-07"
- server: "PinVault server" · doors "8090" "8091" "8092" "8093"
- path 1 label: "1 · ENROLLMENT: token + CSR · pinned connection"
- path 1 return (pink card): "tablet-07" · "90 days"
- path 2 label: "2 · init: signed pin list · mTLS"
- path 2 return (list card, yellow "SIGNED" seal): "api.example.com · pay.example.com"
- phone status: "InitResult.Ready"
- line 1: "Enrollment before init: the mTLS door does not open without a card."
- line 2: "The list is signed and bound to this server; the phone checks both."
- dashboard strip: "Dashboard · Connection History · tablet-07 · sample-mtls · config v1 · ✓"
- WHY strip: "With the code the wizard generated, the first connection starts pinned, signed and identified; nothing is tightened later."
- footer: "First phone"

Compose. Yerleşim: solda telefon (x ≈ 200–360, y ≈ 330–700), sağda sunucu kutusu (x ≈ 1300–1760, y ≈ 330–560); aralarında iki yatay yol (y ≈ 400 ve y ≈ 520), yol etiketleri yolların üstünde; dönüş paketleri yol boyunca sunucudan telefona kayar. Altta (y ≈ 640–720) iki satır; panel şeridi y ≈ 760.
Scene 1 (0.0–1.5s): Şerit durur (dört hücre de ink dolgu); başlık. Telefon ve sunucu oturur.
Scene 2 (1.5–5.0s): Yol 1 soldan sağa çizilir, etiketi gelir; pembe kart 8091'den telefona kayar (1,2 sn), alt yazısı gelir; satır 1.
Scene 3 (5.0–9.0s): Yol 2 çizilir, etiketi; liste kartı 8092'den telefona kayar, mühür oturur; telefon durumu yeşil ✓ "InitResult.Ready"; satır 2.
Scene 4 (9.0–10.5s): Panel şeridi belirir.
Scene 5 (10.5–14.0s): NEDEN şeridi. Tutma.

## Frame 14 — Sihirbaz bir kez, hatırlatmalar her gün

- scene: Zaman şeridi: beş istasyon: her gün süre kontrolü, pin değişince geçmiş, sertifika değişince sihirbaz, iki kişi onayı, 1. adımı yeniden açmak
- voiceover:
- duration: 15s
- transition_in: crossfade
- status: animated
- src: compositions/frames/14-sonrasi.html
- type: feature_showcase
- persuasion: Signposting (her gün… değişince… ara ara)
- beat: foresight + mastery
- blueprint: compose
- focal: yatay zaman şeridi
- roles: şerit = foreground subject · beş istasyon kartı = foreground subject

narrativeRole: Sihirbazın bir kerelik, panelin sürekli işini ayırır: sonrasında neyin kendiliğinden hatırlatıldığını gösterir.
keyMessage: Üretim bir an değil süreçtir; panel her gün ölçer, sihirbaz her açılışta aynı listeyi yeniden sayar.

Ekran metni:
- üst çubuk hap: "SONRASI"
- başlık (display-head): "SİHİRBAZ BİR KEZ, HATIRLATMALAR HER GÜN"
- istasyon 1: "HER GÜN" / "Süre kontrolü: Config API sertifikası, CA'lar, host sertifikaları, vault dosyaları. Panelde ve denetim kaydında."
- istasyon 2: "PİN DEĞİŞİNCE" / "Önceki set saklanır: Pin Seti Geçmişi → Geri yükle. Geri alma yeni bir sürümdür; telefonlar eskiye dönmez, yenisini alır."
- istasyon 3: "SERTİFİKA DEĞİŞİNCE" / "Sihirbazı yeniden çalıştırın; 4. adımdaki kod yeni pin'lerle üretilir."
- istasyon 4: "İKİ KİŞİ" / "PIN_CHANGE_APPROVALS=2: pin değişikliği ikinci yöneticinin onayını bekler."
- istasyon 5: "ARA ARA" / "1. adımı yeniden açın: 13 / 13 olana kadar."
- NEDEN şeridi: "Üretim bir an değil süreçtir. Panel her gün ölçer; sihirbaz her açılışta aynı listeyi yeniden sayar."
- künye: "Sonrası"

English screen text:
- pill: "AFTERWARDS"
- title: "THE WIZARD ONCE, REMINDERS EVERY DAY"
- station 1: "EVERY DAY" / "Expiry check: the Config API certificate, the CAs, host certificates, vault files. In the dashboard and the audit log."
- station 2: "WHEN PINS CHANGE" / "The previous set is kept: Pin Set History → Restore. A restore is a new version; phones do not go back, they take the new one."
- station 3: "WHEN A CERTIFICATE CHANGES" / "Run the wizard again; the code in step 4 is generated with the new pins."
- station 4: "TWO PEOPLE" / "PIN_CHANGE_APPROVALS=2: a pin change waits for a second admin's approval."
- station 5: "NOW AND THEN" / "Open step 1 again: until it reads 13 of 13."
- WHY strip: "Production is a process, not a moment. The dashboard measures every day; the wizard counts the same list again every time it opens."
- footer: "Afterwards"

Compose. Yerleşim: çerçeve genişliğinde yatay şerit (y ≈ 420), üstünde beş istasyon noktası (x ≈ 240, 600, 960, 1320, 1680), altlarında beş açıklama kartı (≈ 320×300, mono başlık + body-md metin).
Scene 1 (0.0–1.5s): Şerit durur (dört hücre de dolu); başlık. Zaman şeridi soldan sağa çizilir.
Scene 2 (1.5–11.5s): Beş istasyon ≈2,0 sn arayla: nokta oturur, kart gelir (başlık, 0,4 sn sonra metin). İstasyon 1'de küçük sarı rozet "UYARI" bir an yanıp söner; istasyon 2'de küçük ink düğme "Geri yükle" basılır; istasyon 4'te iki ink daire (iki yönetici) yan yana gelir.
Scene 3 (11.5–15.0s): NEDEN şeridi. Tutma.

## Frame 15 — Dört adım, tek liste

- scene: Yeşil kapanış plakası; dört adımlı şerit dolu; tek cümlelik özet ve panele yönlendirme
- voiceover:
- duration: 10s
- transition_in: crossfade
- status: animated
- src: compositions/frames/15-kapanis.html
- type: cta
- persuasion: Distillation + callback (Kare 1'deki şerit)
- beat: resolve
- blueprint: titlecard-reveal (Adapt)
- focal: dolu şerit ve özet cümlesi
- roles: yeşil zemin = background · şerit = foreground subject · özet = foreground subject · yol satırı = supporting

narrativeRole: Kare 1'deki boş şeridi dolu hâliyle geri getirir ve izleyiciyi panele yollar.
keyMessage: Hepsi hazır olmadan üretime çıkmayın.

Ekran metni:
- üst çubuk hap (krem varyant): "SON"
- şerit hücreleri (krem çerçeve, hepsi dolu): "1 · SUNUCU" "2 · SERTİFİKALAR" "3 · UYGULAMA" "4 · KOD"
- başlık (display-lg, krem): "DÖRT ADIM, TEK LİSTE."
- başlık 2 (display-head, krem): "HEPSİ HAZIR OLMADAN ÜRETİME ÇIKMAYIN."
- alt satır (mono, krem): "Panel → Kurulum Sihirbazı · Filmler: docs/animation/films.html"
- künye: "Kapanış"

English screen text:
- pill: "END"
- strip cells: "1 · SERVER" "2 · CERTIFICATES" "3 · APP" "4 · CODE"
- title: "FOUR STEPS, ONE LIST."
- title 2: "DO NOT GO TO PRODUCTION UNTIL ALL OF IT IS READY."
- bottom line: "Dashboard → Setup Wizard · Films: docs/animation/films.html"
- footer: "Closing"

Adapt: titlecard-reveal'in tek sakin hareketi korunur (başlık yukarı kayarak belirir, sonra durağan tutma); üstüne şeridin bir kez dolması eklenir.
Scene 1 (0.0–2.5s): Yeşil zemin. Ortanın üstünde krem çerçeveli dört hücreli şerit (hücreler ≈ 380×64) boş durur; hücreler soldan sağa ≈0,4 sn arayla krem dolguya döner (yazı yeşile).
Scene 2 (2.5–5.5s): Başlık yukarı kayarak belirir; 1 sn sonra başlık 2.
Scene 3 (5.5–10.0s): Alt satır belirir. Tutma; filmin tek gerçek çıkışı: son 0,8 sn'de her şey krem zemine sönümlenir.
