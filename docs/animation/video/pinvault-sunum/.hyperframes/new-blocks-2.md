## Frame — Panelde: atestasyon ayarı

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

## Frame — Panelden dosya yüklenir

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

## Frame — Kim alabilir: Policy ve dosya token'ı

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

## Frame — Telefon dosyayı alır

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

## Frame — Üç koruma: sunucuda şifreli, uçtan uca, ekran kilitli

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

## Frame — Telefonda: kilit, süre, iptal

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
