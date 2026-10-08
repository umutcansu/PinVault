## Dispatch context

- PROJECT_DIR: docs/animation/video/pinvault-nasil-calisir
- Canvas: 1920×1080
- Captions: disabled (no caption track; still keep load-bearing content above y ≤ 900, the bottom mono footer chrome is the only thing below)
- Confirmed sketch: none (autonomous run; no storyboard.html)
- Audio: none. This is a fully SILENT video (music: none, no SCRIPT.md, no sfx).

### Exception to "visible text is short motion-graphics copy / never render narration"

This video has NO voiceover and NO captions. The on-screen text listed under `Ekran metni` in your frame block IS the narration and MUST be rendered, word for word, exactly as written (Turkish, including İ Ş Ğ Ü Ö Ç ı and the ellipsis "…"). Do not shorten, translate, paraphrase or re-case it. Pace reveals to READING time instead of a voice: as a guide, a line waits about 0.35 s per word (minimum 1.2 s) before the next piece arrives. Follow the Scene windows in your block.

### Video direction (verbatim from STORYBOARD.md — shared by all 13 frames)

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


### Practical notes

- Fonts: load Archivo Black, Space Grotesk and JetBrains Mono from Google Fonts with the `latin-ext` subset available (Turkish glyphs). Root element should carry `lang="tr"` where possible (e.g. on the frame root div).
- Uppercase display strings are already uppercase in the source; never apply CSS text-transform.
- The 13 frames are built in parallel by separate workers; draw the shared actors (phone, server box, port boxes, pink ID card, yellow ticket, orange attacker) exactly as Video direction describes so they match across frames.
- Your terminal action is writing `compositions/frames/<frame_id>.html`. Do not edit STORYBOARD.md, do not run the CLI.
