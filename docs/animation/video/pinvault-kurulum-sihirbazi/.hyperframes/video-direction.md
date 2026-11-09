## Video direction

**Dil ve yazım.** Bütün ekran metni Türkçedir. Kök öğeye `lang="tr"` koy. Archivo Black satırları büyük harftir; büyük harfli metin kaynakta zaten büyük harfle yazılmıştır (İ, Ş, Ğ, Ü, Ö, Ç dahil). CSS `text-transform` kullanma. Mono ve gövde metni yazıldığı gibi kalır. Kod satırları JetBrains Mono ile, girintisi korunarak yazılır.

**Palet (frame.md, creative-mode).** Zemin `cream`, çizgi ve yazı `ink`, ikinci yüzey `cream-2`. Vurguların anlamı bütün filmde sabittir:
- `green` = HAZIR, geçti, güvenli (✓). Panel rozeti "HAZIR": yeşil kenar, yeşil yazı, krem dolgu.
- `yellow` = UYARI (eksik ama çalışır), imza mührü, token. Panel rozeti "UYARI": sarı dolgu, ink yazı.
- `orange` = EKSİK, ret, yanlış inanış (✗). Panel rozeti "EKSİK": turuncu dolgu, krem yazı. Sert gölgenin rengi de turuncudur; bir karede en çok bir sert gölge.
- `pink` = cihazın kimlik kartı (cihaz sertifikası) ve istemci CA'sı.
Bir karede en çok üç vurgu rengi baskın olur. Yeşil zemin yalnızca son karede. Saf beyaz, degrade, bulanık gölge, parıltı yok. Köşeler kare; tek yuvarlak öğe üst çubuktaki hap etiket.

**Sabit oyuncular** (her karede aynı çizilir):
- Panel ekranı: ink çerçeveli tarayıcı benzeri kutu; üstte siyah şerit ve mono "Panel · 8090 · Kurulum Sihirbazı · <adım>"; içinde kartlar ve tablolar gerçek etiketleriyle; düğmeler ink çerçeveli kare kutular; rozetler yukarıdaki üç renkte, mono 15 px, 2 px kenar.
- PinVault sunucusu: ink çerçeveli kutu, siyah başlık şeridinde mono "PinVault sunucusu"; sol kenarında küçük kapı etiketleri (8090, 8091, 8092, 8093).
- Telefon: ink çerçeveli dikey dikdörtgen, üstte kısa hoparlör çizgisi; ekranında mono "Uygulamanız", altında siyah şerit içinde "PinVault kütüphanesi".
- API sunucunuz: ink çerçeveli kutu, başlık "API SUNUCUNUZ", altında mono "api.ornek.com".
- Sertifika: krem-2 dolgulu dik küçük kart, üst köşesinde küçük ink mühür dairesi, içinde mono ad. İstemci CA'sı ve cihaz kartı pembe.
- Pin: krem-2 kutucuk içinde mono parmak izi ("ojdBCq6J…").
- İmza mührü: sarı dolgulu küçük kare, içinde mono "İMZA".

**Adım şeridi (kare 1'de tanıtılır, 3–14'te durur, 15'te tamamlanır).** Üst çubuğun hemen altında, y = 104 px'ten başlayan, 40 px yüksekliğinde yatay şerit: 4 hücre, her biri 400 px genişlikte, x = 96 + i × 432 (i = 0…3: 96, 528, 960, 1392). Hücre metni mono 17 px, büyük harf: "1 · SUNUCU", "2 · SERTİFİKALAR", "3 · UYGULAMA", "4 · KOD". Hücreler arasında 32 px'lik ince ink çizgi (y = 123). Biten adımlar: ink dolgu, krem yazı. Şu anki adım: krem dolgu, 4 px ink kenar, ink yazı, altında 4 px sarı alt çizgi (y = 148). Gelecek adımlar: 2 px ink kenar, %35 saydamlık. Şerit karenin ilk 0,6 saniyesinde zaten durur (önceki kareden devam ediyor gibi); yalnızca şu anki hücrenin dolgusu ve alt çizgisi 0,2–0,8 sn arasında oturur. Giriş ve "Neden" karelerinde (1–2) şerit yoktur; kare 1 onu büyük boy tanıtır.

**NEDEN şeridi (kare 3–14).** Her adım karesinin altında, y ≈ 830–880 arasında, sol kenara yaslı, krem-2 dolgulu, 2 px ink kenarlı yatay kutu: solda siyah zeminli küçük mono etiket "NEDEN", sağında gövde metni (Space Grotesk, ≈24–26 px; iki satıra sığmıyorsa 22 px). Karenin son üçte birinde belirir. Metin uzunsa kutu genişler (en çok 1728 px).

**Çerçeve süsü.** Üstte mono üst çubuk: solda "PINVAULT · KURULUM SİHİRBAZI", sağda hap etiket (karede verilir). Altta mono künye: solda kare adı, sağda "NN • 15". Son kare krem renkli künye varyantını kullanır.

**Hareket dili.** Uzun kuyruklu yumuşak oturma (`power3`); zıplama, aşma, elastik yok. Her parça kendi okuma anında girer: sessiz film olduğu için zamanlama okuma ritmine göre yapılır. Bir satır geldikten sonra bir sonraki parça gelmeden önce kabaca kelime başına 0,35 sn (en az 1,2 sn) beklenir. Hiçbir kare ilk %25'te her şeyi dökmez. Tablo satırları yukarıdan aşağıya ≈0,6–0,8 sn arayla gelir; rozet satırdan 0,2 sn sonra oturur. Panelde bir düğmeye "basılması" düğmenin kısa bir an içe çökmesi ve ink dolguya dönmesiyle gösterilir; imleç çizilmez. Kod satır satır yazılır (harf harf değil, satır başına ≈0,25 sn).

**Ritim.** Tutma (nefes) kareleri: Kare 2'nin sonu ve Kare 15. Diğerleri okuma ritmiyle açılır, son parça geldikten sonra sakin durur.

**Asla.** Slayt gösterisi (her şeyi başta dökmek, sonra donmak). Ekran koruyucu (bağımsız yüzen çok öğe). Döngüsel nefes alma. Arka yarıda yavaş kaydırma ya da itme. Rastgelelik. CSS transition veya keyframes. Uydurulmuş sayı: yalnızca ekran metnindeki sayılar kullanılır. Gerçek şirket logoları. Fare imleci. Ekran görüntüsü (panel her zaman çizilir).

**Alt bant.** Yük taşıyan içerik y ≤ 900 px içinde kalır; altında yalnızca künye.
