## Frame — İşleyen fabrika: hepsi bir arada

- scene: Bütün topoloji tek sabit sahnede; on halka ve dosya akışı, makineler arasındaki bantlarda paketler olarak sırayla akar; zincir şeridi dolar, altta her adımın tek cümlesi
- voiceover:
- duration: 70s
- transition_in: crossfade
- status: animated
- src: compositions/frames/f1-fabrika.html
- type: branding
- persuasion: Callback (bütün halkalar) + demonstration (sistemi çalışırken göstermek)
- beat: "now I get it" + mastery
- blueprint: compose
- focal: o an hareket eden paket ve iki ucundaki makine
- roles: harita (telefon, sunucu ve iç makineleri, kapılar, API sunucusu, yönetici) = background-stage, hiç yer değiştirmez · bantlar = supporting · paketler = foreground subject · zincir şeridi = supporting · alt açıklama satırı = foreground subject

narrativeRole: Filmin büyük özeti: parça parça anlatılan her şeyi tek bir çalışan sistem olarak gösterir.
keyMessage: PinVault işleyen bir fabrika gibidir: aynı harita üzerinde kurulumdan ilk isteğe ve dosyaya kadar her parça sırayla çalışır, sonra da çalışmaya devam eder.

Ekran metni:
- üst çubuk sol (mono): "PINVAULT · ÖZET"
- üst çubuk hap: "HEPSİ BİR ARADA"
- zincir hücreleri (ring karelerindeki geometriyle aynı): "1 KURULUM" "2 APK" "3 HOST" "4 KAYIT TOKEN'I" "5 TELEFONA" "6 KAYIT İSTEĞİ" "7 KART" "8 PİN LİSTESİ" "9 ATESTASYON" "10 İLK İSTEK"
- telefon: "Uygulamanız" / şerit "PinVault kütüphanesi"
- telefon içi küçük satırlar (sırayla belirir, mono): "APK: PinVault pin'leri" · "kart: tablet-07" · "liste: api.ornek.com pinli" · "PinVault-Token: 5 dk" · "dosya: saha-ayarlari"
- sunucu başlığı (mono, siyah şerit): "PinVault sunucusu"
- sunucu içi makine 1 (pembe kenar): "İstemci CA'sı" / alt (mono): "kartları imzalar"
- sunucu içi makine 2 (sarı kenar): "İmza anahtarı · HSM" / alt (mono): "listeyi mühürler"
- sunucu içi makine 3 (gri): "Depo" / alt (mono): "kayıtlar · liste · dosyalar"
- kapılar (mono): "8091 · TLS" "8092 · mTLS" "8093 · kurtarma" "8090 · yönetim"
- API kutusu: "API SUNUCUNUZ" / "api.ornek.com"
- yönetici kutusu: "YÖNETİCİ · PANEL"
- paket etiketleri (mono): "token" (sarı) · "kayıt isteği" (krem-2) · "tablet-07" (pembe kart) · "liste · İMZALI" (krem-2, sarı mühür) · "rapor" (krem-2) · "PINVAULT-TOKEN" (sarı) · "istek" (ink) · "200 OK" (yeşil) · "dosya" (krem-2, kilit)
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
  "Fabrika çalışmaya devam eder: her açılışta kart, liste, PinVault-Token; her istekte PinVault-Token."
- kapanış başlığı (display-head, son 5 sn, alt açıklama satırının yerinde): "İŞLEYEN FABRİKA."
- künye: "Hepsi bir arada"

Compose. SABİT HARİTA (1920×1080 piksel, hiç yer değiştirmez; yalnızca kenar rengi ve paketler hareket eder):
- Zincir şeridi: y = 104, 10 hücre, hücre x = 96 + i × 174, 160×40 (halka kareleriyle aynı). Başta hepsi "gelecek" (2 px kenar, %35); her adım bitince hücresi ink dolgu krem yazı olur, o anki adım krem dolgu 4 px kenar + sarı alt çizgi.
- Telefon: x 96–336, y 250–690 (240×440), telefonun içinde ekran ve altta siyah şerit; ekranın içinde küçük satırlar sırayla birikir.
- PinVault sunucusu: x 620–1240, y 220–640; üstte siyah başlık şeridi. Sol kenarında üç kapı kutusu (x 560–660, 100×44): 8091 (y 290), 8092 (y 400), 8093 (y 510). Alt kenarında 8090 kapısı (x 880–980, y 640–684).
- Sunucu içi makineler (x 720–1160, her biri 440×90): İstemci CA'sı (y 290), İmza anahtarı · HSM (y 400), Depo (y 510).
- API sunucunuz: x 1520–1824, y 290–470.
- Yönetici · panel: x 820–1040, y 712–772; 8090 kapısına kısa dikey bantla bağlı.
- Bantlar (kesik çizgili ince ink hatlar, paketler üzerlerinde kayar): telefon→8091, telefon→8092, telefon→8093 (soluk, bu sahnede kullanılmaz), telefon→API (sunucunun üstünden, y ≈ 186 hattından), yönetici→8090, yönetici→telefon (sunucunun altından, y ≈ 742 hattından, "mesaj" etiketli, PinVault'un dışından), kapılar→iç makineler (kısa yatay bantlar).
- Alt açıklama satırı: x 96–1824, y 800–870, krem-2 dolgu, 2 px ink kenar, solda siyah mono etiket "ADIM", sağında body-lg metin.

ZAMANLAMA (her adımda: ilgili iki makinenin kenarı aksan rengine döner, paket banttan kayar, adım bitince kenarlar ink'e döner; önceki paket izleri kaybolur ama telefonun içindeki satırlar kalır):
Scene 0 (0.0–4.0s): Harita kurulur: telefon, sunucu ve iç makineleri, kapılar, API, yönetici, bantlar ≈0,3 sn arayla soldan sağa belirir; zincir şeridi boş.
Scene 1 (4.0–9.0s): Adım 1. Sunucu içindeki üç makine sırayla yeşil kenar alır; İmza anahtarı · HSM makinesinin içinde küçük kilit. Zincir hücresi 1.
Scene 2 (9.0–13.5s): Adım 2. Telefonun içine küçük "APK" kutusu yukarıdan düşer; telefon satırı "APK: PinVault pin'leri" belirir. Hücre 2.
Scene 3 (13.5–19.0s): Adım 3. Yönetici kenarı turuncu değil sarı; "api.ornek.com" paketi yöneticiden 8090'a, oradan Depo'ya kayar; İmza anahtarı makinesinden Depo'ya sarı "İMZALI" mührü basılır. Hücre 3.
Scene 4 (19.0–23.0s): Adım 4. Yöneticinin yanında sarı "token" paketi belirir. Hücre 4.
Scene 5 (23.0–27.0s): Adım 5. Token, alttaki "mesaj" bandından telefona kayar. Hücre 5.
Scene 6 (27.0–32.0s): Adım 6. Telefondan 8091'e "kayıt isteği" paketi (üstünde küçük sarı token) kayar; 8091 kapısı yeşil kenar. Hücre 6.
Scene 7 (32.0–37.0s): Adım 7. Paket İstemci CA'sına gider; pembe "tablet-07" kartı çıkar, 8091'den telefona döner; telefon satırı "kart: tablet-07". Token gri olur (harcandı). Hücre 7.
Scene 8 (37.0–42.0s): Adım 8. Pembe kart telefondan 8092'ye gider (kapı yeşil), Depo'dan "liste · İMZALI" paketi telefona döner; telefon satırı "liste: api.ornek.com pinli". Hücre 8.
Scene 9 (42.0–47.0s): Adım 9. "rapor" paketi 8092'ye gider; sarı "PINVAULT-TOKEN" paketi döner (karenin tek sert gölgesi bu pakette); telefon satırı "PinVault-Token: 5 dk". Hücre 9.
Scene 10 (47.0–53.0s): Adım 10. "istek" paketi (yanında küçük sarı PinVault-Token) üst banttan API sunucusuna gider; API kutusu içinde üç küçük ✓; yeşil "200 OK" geri döner. Hücre 10.
Scene 11 (53.0–59.0s): Dosya adımı. Yöneticiden 8090 üzerinden Depo'ya "dosya" paketi (kilitli) kayar; sonra Depo'dan 8092 üzerinden telefona; telefon satırı "dosya: saha-ayarlari".
Scene 12 (59.0–65.0s): Devam vuruşu. Daha hızlı ve sessiz bir tur: pembe kart 8092'ye gidip liste döner, rapor gidip PinVault-Token döner, istek API'ye gidip 200 OK döner (her biri ≈1,5 sn). Alt satırda "Fabrika çalışmaya devam eder…".
Scene 13 (65.0–70.0s): Bütün hücreler dolu; alt açıklama satırının yerine "İŞLEYEN FABRİKA." başlığı oturur. Tutma, en çok hafif titreşim.
