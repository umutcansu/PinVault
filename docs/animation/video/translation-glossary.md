# Turkish → English glossary for the PinVault films

Use these exact English terms. Dashboard labels are the dashboard's own English
labels (demo-server/src/main/resources/static/js/app-i18n.js, app-setup.js).

## Terms
| Turkish | English |
|---|---|
| PinVault sunucusu | PinVault server |
| API sunucunuz | your API server |
| giriş sunucunuz | your login server |
| Uygulamanız | Your app |
| PinVault kütüphanesi | PinVault library |
| kayıt token'ı | enrollment token |
| PinVault-Token | PinVault-Token |
| kart / kimlik kartı (cihaz sertifikası) | ID card (device certificate) |
| imzalı pin listesi | signed pin list |
| parmak izi (pin) | fingerprint (pin) |
| güven deposu | trust store |
| kurum (CA) | authority (CA) |
| istemci CA'sı | client CA |
| sunucu CA'sı | server CA |
| imza anahtarı | signing key |
| kasa (Android Keystore) | vault (Android Keystore) — prefer "the phone's key store" in prose |
| atestasyon | attestation |
| ret politikası | rejection policy |
| halka (zincirin halkası) | link (of the chain) |
| zincir | chain |
| kayıt | enrollment |
| kayıt isteği | enrollment request |
| sertifika isteği (CSR) | certificate signing request (CSR) |
| anahtarın donanım belgesi | key attestation (hardware) |
| yenileme | renewal |
| kurtarma | recovery |
| iptal | revocation |
| dosya token'ı | file token |
| sunucuda şifreli | encrypted on the server |
| uçtan uca | end to end |
| ekran kilitli | screen-locked |
| çevrimdışı ömür | offline lifetime |
| benzetme | analogy |
| kim / nerede | who / where |
| işleyen fabrika | the working factory |
| hepsi bir arada | all in one |
| sonrası | afterwards |
| özet | summary |
| bölüm | part |
| seçenek | option |
| panelde | in the dashboard |
| yönetici | admin |
| panel | dashboard |

## Dashboard labels (TR → EN)
Token Üret → Generate Token · Client Sertifikaları → Client Certificates · Enrollment Token → Enrollment Token ·
Client ID → Client ID · Cihaz kimliği (ANDROID_ID) → Device id (ANDROID_ID) · Yeni Host Ekle → Add New Host ·
+ Yeni Host → + New Host · URL'den Al → Fetch from URL · Elle Gir → Manual · Sertifika Üret → Generate Cert ·
Sunucu adresi → Server address · Oluştur → Create · Kurulum Sihirbazı → Setup Wizard · 1 · Sunucu → 1 · Server ·
2 · Uygulama → 2 · App · 3 · Kod → 3 · Code · Telefonların sunucuya ulaştığı adres → Address phones reach the server at ·
Port eşlemesi → Port mapping · Kaydet → Save · + Config API → + Config API · Yeni Config API → New Config API ·
TLS veya mTLS config API başlatın → Start a TLS or mTLS config API · API ID → API ID · Port → Port · Mod → Mode ·
TLS (tek yönlü) → TLS (one-way) · mTLS (çift yönlü — client cert gerekir) → mTLS (two-way — client cert required) ·
Config API Başlat → Start Config API · varsayılan → default · Genel → General · İmzalama → Signing ·
İmzalayıcılar → Signers · Ad → Name · Tür → Type · Anahtar kimliği → Key ID · birincil → primary ·
Attestation → Attestation · Red politikası → Rejection policy · Hazır ayar → Presets · Sıkı → Strict · Gevşek → Lenient ·
Bayrak → Flag · Anlamı → Meaning · Karar → Decision · reddet → reject · uyar → warn · yoksay → ignore ·
Politikayı Kaydet → Save Policy · Attestation yapan cihazlar → Attested devices · Red nedenleri → Rejection reasons ·
Vault → Vault · Vault'a Yükle → Upload to Vault · Anahtar → Key · Dosya → File · Metin → Text · Policy → Policy ·
Encryption → Encryption · Yükle → Upload · token (önerilen) → token (recommended) · token + mTLS → token + mTLS ·
public (demo) → public (demo) · api_key → api_key · user_auth — ekran kilidiyle açılır → user_auth — opens with the screen lock ·
Token Yönetimi → Token Management · + Yeni Token → + New Token · Dağıtım Geçmişi → Distribution History ·
İptal Et → Revoke · Kimliği unut → Forget identity · "Token üretildi ve panoya kopyalandı" → "Token generated and copied to clipboard"

## Fixed strings that repeat across frames (use exactly)
- Top-bar left labels: "PINVAULT · 1 AMAÇ" → "PINVAULT · 1 PURPOSE"; "PINVAULT · 2 ÇÖZÜM" → "PINVAULT · 2 SOLUTION"; "PINVAULT · 3 AKIŞ" → "PINVAULT · 3 FLOW"; "PINVAULT · 4 DOSYALAR" → "PINVAULT · 4 FILES"; "PINVAULT · ÖZET" → "PINVAULT · SUMMARY"; "PINVAULT · SUNUM" → "PINVAULT · PRESENTATION".
- Chapter-card section cells: "1 AMAÇ" → "1 PURPOSE", "2 ÇÖZÜM" → "2 SOLUTION", "3 AKIŞ" → "3 FLOW", "4 DOSYALAR" → "4 FILES"; "BÖLÜM N / 4" → "PART N / 4"; kicker "BÖLÜM N" → "PART N"; footer "Bölüm N" → "Part N".
- Chain strip cells (ring frames, the factory, the first and last frame): "1 KURULUM" → "1 SETUP", "2 APK" → "2 APK", "3 HOST" → "3 HOST", "4 KAYIT TOKEN'I" → "4 ENROLL TOKEN", "5 TELEFONA" → "5 TO THE PHONE", "6 KAYIT İSTEĞİ" → "6 ENROLLMENT", "7 KART" → "7 ID CARD", "8 PİN LİSTESİ" → "8 PIN LIST", "9 ATESTASYON" → "9 ATTESTATION", "10 İLK İSTEK" → "10 FIRST CALL". In two-line cells (number + label) use the same label words.
- Pills: "HALKA N / 10" → "LINK N / 10"; "AMAÇ" → "PURPOSE"; "ÇÖZÜM" → "SOLUTION"; "TOPOLOJİ" → "TOPOLOGY"; "CONFIG API" → "CONFIG API"; "PANELDE" → "DASHBOARD"; "SEÇENEK" → "OPTION"; "ANAHTAR" → "KEY"; "ANAHTARLAR" → "KEYS"; "GEÇMEYEN" → "REJECTED"; "DOSYA N / 5" → "FILE N / 5"; "HEPSİ BİR ARADA" → "ALL IN ONE"; "SONRASI" → "AFTERWARDS"; "ÖZET" → "SUMMARY"; "SON" → "END"; "ÖNCE BİR DÜZELTME" → "FIRST, A CORRECTION"; "GİRİŞ" → "INTRO"; "AKIŞ" → "FLOW".
- Kicker prefix "KİM: … · NEREDE: …" → "WHO: … · WHERE: …". "BENZETME" label → "ANALOGY". Bottom caption label "ADIM" → "STEP".
- Footer counters "NN • 39" stay as they are.
- The closing frame path line points to the English animation: "docs/animation/pinvault-request-flow.en.html".
