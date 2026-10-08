## Frame 29 — Bölüm 4: Dosyalar
compositions/frames/p6-bolum-dosyalar.html
keyMessage: Panelden eklenen dosya, seçtiğiniz cihazlara, seçtiğiniz korumayla gider.
Ekran metni:
- üst çubuk sol (mono): "PINVAULT · SUNUM"
- üst çubuk hap: "BÖLÜM 4 / 4"
- numara bloğu (Archivo, çok büyük): "4"
- kicker (mono, siyah kutu): "BÖLÜM 4"
- başlık (display-lg): "AMAÇ: SSL PINNING"
- alt satır (body-lg): "Panelden eklenen dosya, seçtiğiniz cihazlara, seçtiğiniz korumayla gider."
- bölüm şeridi hücreleri (mono): "1 AMAÇ" (bitti) · "2 ÇÖZÜM" (bitti) · "3 AKIŞ" (bitti) · "4 DOSYALAR" (şu anki)
- künye: "Bölüm 4" / sayaç "29 • 39"


## Frame 30 — Panelden dosya yüklenir
compositions/frames/d1-dosya-yukle.html
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


## Frame 31 — Kim alabilir: Policy ve dosya token'ı
compositions/frames/d2-kim-alabilir.html
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


## Frame 32 — Telefon dosyayı alır
compositions/frames/d3-telefon-alir.html
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


## Frame 33 — Üç koruma: sunucuda şifreli, uçtan uca, ekran kilitli
compositions/frames/d4-uc-koruma.html
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


## Frame 34 — Telefonda: kilit, süre, iptal
compositions/frames/d5-telefonda.html
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
