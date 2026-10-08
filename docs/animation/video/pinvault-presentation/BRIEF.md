---
workflow: faceless-explainer
flow: automation
storyboard: no
message: "SSL pinning telefonu sahte sunucudan korur; PinVault pinlemenin üç eksiğini kapatır, kurulumdan ilk isteğe on halkada çalışır ve dosyaları seçtiğiniz cihaza, seçtiğiniz korumayla dağıtır."
destination: presentation
aspect: 1920x1080
language: tr
audience: "PinVault'u ilk kez görecek geliştirici ve yöneticiler"
length: 412s
angle: concept
---

## Intent

Kullanıcının isteği (2026-10-07): "Biraz karmaşa var, amaçları dolandırarak anlatıyoruz gibi. İlk önce amaç ne,
SSL pinning, bunu anlatıp sonra bizim sistem nasıl çalışıyor falan yapsan?"

İki ayrı video (kavram ve baştan sona) tek bir sunum filminde, net bir sırayla birleşir:
1 · Amaç: arada kim var, normal TLS neye güvenir, SSL pinning nedir, pinlemenin üç eksiği.
2 · PinVault ne ekler: üç eksiğe üç cevap, parçaların yeri.
3 · Baştan sona: on halka, geçmeyen telefon, sonrası, özet.

## Notes

- Kareler iki kardeş projeden aynen alınır; yalnızca üst çubuk, hap ve sayaç değişir. Yeni kareler: bölüm kartları, normal TLS, üç eksik.
- Eski iki videoda olup burada olmayanlar (mühürlü liste, kimlik kartı, kartın ömrü, atestasyon kavram kareleri, açılış sırası) üçüncü bölümün halkalarında zaten anlatıldığı için çıkarıldı.

## Update (2026-10-07)

Kullanıcı: "Dosyalar bölümünü de ekle. İlk işlemlerin panel karşılıkları yok videoda; hani panelden ekledik, şunu yaptık, şifrelendi gibi." ve "bilet yerine token daha mantıklı".
- Dördüncü bölüm "Dosyalar ve şifreleme" eklendi (panelden yükleme, Policy ve dosya token'ı, telefon alır, üç koruma, telefonda kilit/süre/iptal).
- Panel karşılıkları: "PinVault ne ekler" kartlarına PANELDE şeritleri; atestasyondan sonra "Panelde: atestasyon ayarı" karesi.
- "Bilet" yerine her yerde "PinVault-Token"; kayıttakine "kayıt token'ı".
