---
workflow: faceless-explainer
flow: automation
storyboard: no
message: "Sunucunun çalışması üretime hazır olduğu anlamına gelmez. Kurulum Sihirbazı dört adımda ölçer: sunucu ayarları, sertifikalar, uygulamanın korumaları, uygulamaya girecek kod; her maddede neyin neden gerektiğini söyler."
destination: embed
aspect: 1920x1080
language: tr
audience: "PinVault sunucusunu ilk kez üretime hazırlayacak yönetici ve geliştiriciler"
length: 212s
angle: how-to
---

## Intent

Kullanıcının isteği (2026-11-08): "sihirbaz kurulumu içinde kurulum videosu hazırlar mısın? … baştan sona ne için
ne yapmalıyızı detaylıca açıklayan bir video aslında … bizim videolarımız var onu nasıl hazırladıysan öyle.
İngilizce ve Türkçe yazı vardı sanırım sadece."

Önceki filmler kavramı (nasıl çalışır) ve zinciri (baştan sona) anlatır. Bu film panelin Kurulum Sihirbazı'nı
anlatır: dört adımı sırayla, her adımda hangi ekran açılır, hangi satır ne anlama gelir, neden gerekir ve
nerede düzeltilir. Sihirbazın 2.9.0 ile gelen ikinci adımı (Sertifikalar) dört kartıyla ayrıntılı gösterilir.

## Notes

- Sessiz film, ekran metni anlatımın kendisidir; aynı tasarım (creative-mode frame.md), aynı renk anlamları.
  İngilizce ikizi `../pinvault-setup-wizard/` aynı karelerin İngilizce kopyalarıdır.
- Önce panel ekranı (gerçek etiketlerle: app-setup.js i18n), sonra neden. Her adım karesinin altında "NEDEN"
  şeridi vardır (önceki filmdeki "BENZETME" şeridinin yerine).
- Kapı numaraları demo kurulumundan (PORT=8090): 8090 yönetim, 8091 TLS, 8092 mTLS, 8093 kurtarma; adres
  192.168.1.10 (önceki filmle aynı). Pin ve anahtar değerleri sample-host'un gerçek değerlerinin kısaltmasıdır.
- Doğrulanan gerçekler: sihirbaz hiçbir ayarı kendisi değiştirmez (Ayarlar kartı ve .env satırları değiştirir,
  yeniden başlatma gerekir); 1. adımda 13 kontrol (sample-host'ta 3/13 hazır), 2. adımda 21 madde (13/21);
  config API sertifikası self-signed olsa da pinli olduğu için üretimde geçerlidir; yedek anahtar yoksa anahtar
  kaybı uygulama güncellemesi ister; URL'den alınan host'un yedek pin'i çoğu zaman CA'nındır; CA değişimi bütün
  cihazların yeniden kaydı demektir; cihaz sertifikası 90 gün, üçte biri kalınca yenilenir; vault süresi yalnızca
  hatırlatmadır; pin geri alma yeni bir sürümdür; mTLS'te kayıt init'ten önce yapılır.
