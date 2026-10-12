---
workflow: faceless-explainer
flow: automation
storyboard: no
message: "Yeni bir telefon, sunucunuzla ilk güvenli isteğe kadar on halkadan geçer: sunucu kurulur, APK hazırlanır, token verilir, telefon kartını alır, listesini ve biletini alır, sonra konuşur."
destination: embed
aspect: 1920x1080
language: tr
audience: "PinVault'u ilk kez kuracak geliştirici ve yöneticiler"
length: 196s
angle: how-to
---

## Intent

Kullanıcının isteği (2026-10-07): "Tam olarak nerede ne yapıyoruz, bunu bir anlatsak. Elimizde pin yok, ilk önce
register oluyoruz token ile diyip taa en baştan anlatmak gibi. Ben token dedim ama ilk önce token verilmesinden
falan başlaman gerek. Akış diyagramının ilk halkasından başlayarak."

İlk video (pinvault-nasil-calisir) kavramı anlatır. Bu video uygulamayı anlatır: kim, nerede, hangi ekranda, hangi
sırayla ne yapar. Zincirin ilk halkası sunucunun kurulmasıdır, son halkası uygulamanın kendi API sunucusuna attığı
ilk korumalı istek.

## Notes

- Yaygın yanlış anlama düzeltilir: telefon pin'siz başlamaz. PinVault sunucusunun pin'leri APK'dadır; kayıt bile
  pinli bağlantıyla yapılır. APK'da olmayan şey token'dır ve uygulamanın kendi API sunucularının pin'leridir.
- Önce panel ve telefon ekranı (gerçek etiketlerle), protokol ikinci.
- Sessiz video, sade Türkçe ekran metni; aynı tasarım (creative-mode) ve aynı renk anlamları.
- Kapı numaraları demo uygulamasınınki (sunucu PORT=8090 ile): 8090 yönetim, 8091 TLS, 8092 mTLS, 8093 kurtarma.
- Doğrulanan sıra (kod): enroll init'ten önce; init: yenileme → imzalı liste (8092) → host pin'leri → host
  sertifikası → sağlık kontrolü → atestasyon. Kurulum sihirbazı attestation() satırını üretmez, elle eklenir.
