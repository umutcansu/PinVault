---
workflow: faceless-explainer
flow: automation
storyboard: no
message: "PinVault, telefonunuzun yalnızca gerçek sunucunuzla, sunucunuzun da yalnızca gerçek uygulamanızla konuşmasını sağlar; hepsi sizin makinenizde."
destination: embed
aspect: 1920x1080
language: tr
audience: "PinVault'u ilk kez gören Android geliştiricileri ve ekip yöneticileri"
length: 169s
angle: concept
---

## Intent

Mevcut adım adım animasyon (docs/animation/pinvault-request-flow.tr.html, 99 adım) doğru ama yoğun.
Kullanıcının isteği: "hyperframes ile animasyonu daha görsel ve insanların kolay kavrayacağı hale getir".
Bu video onun girişi olur: önce sorun, sonra benzetmelerle üç katman (pinleme, kimlik, atestasyon),
sistem topolojisi ve bir cihazın yaşam döngüsü. Ayrıntı için izleyiciyi adım adım animasyona yollar.

## Notes

- Sessiz video: Türkçe ses motoru yok (HeyGen oturumu yok, Kokoro Türkçe konuşmaz). Anlatım ekrandaki sade Türkçe yazıyla yapılır; README'de video zaten sessiz oynar.
- Türkçe sade olmalı; "kablo üstü kurcalama" gibi çeviri jargon yok. Teknik terim gerekiyorsa yanında günlük karşılığı.
- Açıklayıcılar sorundan ve benzetmelerden başlar; adım başlıkları sade; teknik ayrıntı sonda ya da animasyonda.
- Doğruluk: atestasyon pin listesini değil token'ı kapatır (pin listesi gizli değildir). Kapı numaraları demo uygulamasının (8090 yönetim, 8091 TLS, 8092 mTLS, 8093 kurtarma). Açılış sırası: yenileme → pin listesi → atestasyon.
- Kararlar (otomatik çalışma, kullanıcıya sorulmadı): yatay 1920x1080 (README/doküman gömme), ≈170 sn, kavram anlatımı, sessiz.
