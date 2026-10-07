## Dispatch context

- PROJECT_DIR: /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-sunum
- Canvas: 1920×1080
- Captions: disabled (no caption track; keep load-bearing content at y ≤ 900; only the mono footer chrome sits below)
- Confirmed sketch: none (autonomous run; no storyboard.html)
- Audio: none. Fully SILENT video (music: none, no SCRIPT.md, no sfx).
- Total frames in this film: 25 (footer counter reads "NN • 25").

### Exception to "visible text is short motion-graphics copy / never render narration"

This video has NO voiceover and NO captions. The on-screen text under `Ekran metni` in your frame block IS the narration and MUST be rendered word for word as written (Turkish, including İ Ş Ğ Ü Ö Ç ı, the ellipsis "…", arrows "→", and code lines). Do not shorten, translate, paraphrase or re-case it. Pace reveals to READING time: a line waits about 0.35 s per word (minimum 1.2 s) before the next piece arrives. Follow the Scene windows in your block.

### Visual reference (optional, read-only)

A sister film in the same design already exists. For consistent drawing of the shared actors (phone, PinVault server box, port boxes, pink ID card, yellow ticket, panel-like boxes, stamps, chrome), you MAY open these finished frames read-only and match their look:
- /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-nasil-calisir/compositions/frames/09-atestasyon.html (phone, server, ticket, API box)
- /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-nasil-calisir/compositions/frames/07-kimlik-karti.html (pink card, step list)
- /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-nasil-calisir/compositions/frames/04-topoloji.html (boxes, labels, lines)
Never copy their ids: your ids must be prefixed with your own frame_id.

### Video direction (verbatim from STORYBOARD.md — shared by all frames)

## Video direction

**Dil ve yazım.** Bütün ekran metni Türkçedir. Kök öğeye `lang="tr"` koy. Archivo Black satırları büyük harftir; büyük harfli metin kaynakta zaten büyük harfle yazılmıştır (İ, Ş, Ğ, Ü, Ö, Ç dahil). CSS `text-transform` kullanma. Mono ve gövde metni yazıldığı gibi kalır. Kod satırları JetBrains Mono ile, girintisi korunarak yazılır.

**Palet (frame.md, creative-mode).** Zemin `cream`, çizgi ve yazı `ink`, ikinci yüzey `cream-2`. Vurguların anlamı bütün videoda sabittir:
- `green` = geçti, güvenli, eşleşti (✓).
- `orange` = saldırgan, ret, yanlış inanış (✗). Sert gölgenin rengi de turuncudur; bir karede en çok bir sert gölge.
- `yellow` = token ve bilet (PinVault-Token) ve imza mührü.
- `pink` = cihazın kimlik kartı (cihaz sertifikası).
Bir karede en çok üç vurgu. Yeşil zemin yalnızca son karede. Saf beyaz, degrade, bulanık gölge, parıltı yok. Köşeler kare; tek yuvarlak öğe üst çubuktaki hap etiket.

**Sabit oyuncular** (her karede aynı çizilir):
- Telefon: ink çerçeveli dikey dikdörtgen, üstte kısa hoparlör çizgisi; ekranında mono "Uygulamanız", altında siyah şerit içinde "PinVault kütüphanesi".
- PinVault sunucusu: ink çerçeveli kutu, siyah başlık şeridinde mono "PinVault sunucusu"; sol kenarında küçük kapı etiketleri (8090, 8091, 8092, 8093).
- Panel ekranı: ink çerçeveli tarayıcı benzeri kutu; üstte siyah şerit ve mono "Panel · 8090"; içinde sekmeler ve kartlar gerçek etiketleriyle; düğmeler ink çerçeveli kare kutular.
- API sunucunuz: ink çerçeveli kutu, başlık "API SUNUCUNUZ", altında mono "api.ornek.com".
- Token: sarı, kenarı ink, yatay kısa şerit; içinde mono "token".
- Kimlik kartı: pembe, kare köşeli küçük kart; üstünde mono "tablet-07".
- Bilet: sarı kart, solda "PINVAULT-TOKEN", sağda kesik çizgiyle ayrılmış "5 DK".
- Pin: krem-2 kutucuk içinde mono parmak izi ("ziA0hyMD…").

**Zincir şeridi (halka kareleri 3–12'de, kare 1'de tanıtılır, kare 14'te tamamlanır).** Üst çubuğun hemen altında, y = 104 px'ten başlayan, 40 px yüksekliğinde yatay bir şerit: 10 hücre, her biri 160 px genişlikte, x = 96 + i × 174 (i = 0…9). Hücre metni mono 15 px, büyük harf: "1 KURULUM", "2 APK", "3 HOST", "4 TOKEN", "5 TELEFONA", "6 KAYIT İSTEĞİ", "7 KART", "8 PİN LİSTESİ", "9 BİLET", "10 İLK İSTEK". Hücreler arasında 14 px'lik ince ink çizgi (zincir). Biten halkalar: ink dolgu, krem yazı. Şu anki halka: krem dolgu, 4 px ink kenar, ink yazı, altında 4 px turuncu değil sarı alt çizgi. Gelecek halkalar: 2 px ink kenar, %35 saydamlık. Şerit karenin ilk 0,6 saniyesinde zaten durur (önceki kareden devam ediyor gibi); yalnızca şu anki hücrenin dolgusu ve alt çizgisi 0,2–0,8 sn arasında oturur.

**Benzetme şeridi (halka kareleri 3–12).** Her halka karesinin altında, y ≈ 830–880 arasında, sol kenara yaslı, krem-2 dolgulu, 2 px ink kenarlı yatay kutu: solda siyah zeminli küçük mono etiket "BENZETME", sağında gövde metni (Space Grotesk, ≈26 px). Karenin son üçte birinde belirir.

**Çerçeve süsü.** Üstte mono üst çubuk: solda bölüm etiketi ("PINVAULT · 1 AMAÇ", "PINVAULT · 2 ÇÖZÜM", "PINVAULT · 3 AKIŞ", "PINVAULT · ÖZET"; karede verilir), sağda hap etiket. Altta mono künye: solda kare adı, sağda "NN • 25". Son kare krem renkli künye varyantını kullanır.

**Hareket dili.** Uzun kuyruklu yumuşak oturma (`power3`); zıplama, aşma, elastik yok. Her parça kendi okuma anında girer: sessiz video olduğu için zamanlama okuma ritmine göre yapılır. Bir satır geldikten sonra bir sonraki parça gelmeden önce kabaca kelime başına 0,35 sn (en az 1,2 sn) beklenir. Hiçbir kare ilk %25'te her şeyi dökmez. Paketler (token, kart, bilet, liste) çizgi boyunca kayan küçük kartlardır; yolun kendisi soldan sağa çizilerek belirir. Panelde bir düğmeye "basılması" düğmenin kısa bir an içe çökmesi ve ink dolguya dönmesiyle gösterilir; imleç çizilmez.

**Ritim.** Tutma (nefes) kareleri: Kare 2'nin sonu ve Kare 14. Diğerleri okuma ritmiyle açılır, son parça geldikten sonra sakin durur; tutma sırasında en çok hafif titreşim.

**Asla.** Slayt gösterisi (her şeyi başta dökmek, sonra donmak). Ekran koruyucu (bağımsız yüzen çok öğe). Döngüsel nefes alma. Arka yarıda yavaş kaydırma ya da itme. Rastgelelik. CSS transition veya keyframes. Uydurulmuş sayı: yalnızca ekran metnindeki sayılar kullanılır. Gerçek şirket logoları. Fare imleci.

**Alt bant.** Yük taşıyan içerik y ≤ 900 px içinde kalır; altında yalnızca künye.



### Practical notes

- Fonts: Archivo Black, Space Grotesk, JetBrains Mono from Google Fonts (latin-ext subset). Put `lang="tr"` on the frame root.
- Never use CSS text-transform; uppercase strings are already uppercase.
- Your frame_id starts with a letter ("p1-…"), so plain `#p1-…` selectors are fine.
- The frames you build sit between finished frames of this film; match their look. Extra read-only references for this film:
  - /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-sunum/compositions/frames/02-iki-yanlis.html (cards with ✓/✗, APK box)
  - /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-sunum/compositions/frames/03-uc-is.html (three numbered cards: krem / pembe / sarı)
  - /Users/thell/Programming/PinVault/.claude/worktrees/animasyon-topoloji-sira-33e587/docs/animation/video/pinvault-sunum/compositions/frames/05-parmak-izi.html (phone, fake server, stamps)
- Your terminal action is writing `compositions/frames/<frame_id>.html`. Do not edit STORYBOARD.md; do not run the CLI.
