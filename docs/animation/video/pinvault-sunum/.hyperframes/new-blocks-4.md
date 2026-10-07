## Frame — Seçenek: imza anahtarı nerede durur?

- scene: Önce neden önemli olduğu (bu anahtar sahte liste mühürlerse telefonlar sahte sunucuya bağlanır); sonra üç seçenek kartı: dosya, HSM, KMS; her kartta "seçerseniz" satırı
- voiceover:
- duration: 19s
- transition_in: crossfade
- status: animated
- src: compositions/frames/h1-hsm-secenek.html
- type: feature_showcase
- persuasion: Stakes / consequence + comparison of three options
- beat: tension → control
- blueprint: compose
- focal: ortadaki HSM kartı
- roles: "neden önemli" şeridi = foreground subject (ilk üçte bir) · üç seçenek kartı = foreground subject · benzetme = supporting

narrativeRole: Kurulumda verilen en önemli güvenlik kararını, bu anahtarın neyi koruduğunu söyleyerek seçenek olarak sunar.
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

Compose. Yerleşim: başlık üstte; altında çerçeve genişliğinde "neden önemli" şeridi (krem-2 dolgu, solunda turuncu im, ≈ 1728×110); altında üç seçenek kartı yan yana (her biri ≈ 540×300; ortadaki HSM kartı yeşil kenarlı); altta benzetme. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–6.0s): "Neden önemli" şeridi: başlık, sonra satır; satırın sonunda küçük bir çizim: imzalı liste → telefon, liste turuncu "SAHTE" damgalıysa telefon sahte sunucuya bağlanır (kısa, şeridin sağ ucunda).
Scene 3 (6.0–15.0s): Üç kart soldan sağa ≈2,8 sn arayla gelir; her kartta başlık, ayar, satır, sonra "seçerseniz" satırı. HSM kartında küçük kasa çizimi: anahtar kasanın içinde kalır, dışarı yalnızca "imza" etiketli kısa bir kart çıkar (karenin tek sert gölgesi HSM kartında).
Scene 4 (15.0–19.0s): Benzetme. Tutma.

## Frame — HSM kullanırsanız

- scene: "HSM kullanırsanız" kazanç listesi; panelin İmzalama sekmesinde İmzalayıcılar tablosu (hsm · pkcs11 · birincil); sınır kutusu ve iki imzalayıcı çözümü
- voiceover:
- duration: 19s
- transition_in: push-slide LEFT
- status: animated
- src: compositions/frames/h2-hsm-kazanc.html
- type: benefit_highlight
- persuasion: Benefit enumeration + counterexample (sınır) + demonstration (panel)
- beat: confidence → foresight
- blueprint: compose
- focal: kazanç listesi
- roles: kazanç listesi = foreground subject · panel İmzalayıcılar kartı = supporting · sınır kutusu = foreground subject (son üçte bir) · iki imzalayıcı çizimi = supporting

narrativeRole: HSM seçeneğinin somut faydalarını, panelde nasıl göründüğünü ve tek başına neyi çözmediğini söyler.
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

Compose. Yerleşim: başlık üstte; solda (%52) dört kazanç satırı alt alta; sağda (%48) üstte panel "İmzalayıcılar" kartı, altta sınır kutusu; en altta not. Zincir şeridi yok.
Scene 1 (0.0–1.8s): Kicker, başlık.
Scene 2 (1.8–9.0s): Dört kazanç satırı ≈1,7 sn arayla gelir, her birinde yeşil ✓.
Scene 3 (9.0–12.0s): Sağda panel kartı açılır; tablo başlığı, satır 1 ve "birincil" rozeti.
Scene 4 (12.0–16.5s): Sınır kutusu gelir (karenin tek sert gölgesi); başlık, satır; tabloya satır 2 eklenir; kod satırı yazılır.
Scene 5 (16.5–19.0s): Not. Tutma.
