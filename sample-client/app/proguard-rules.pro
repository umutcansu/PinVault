# sample-client R8 kuralları: release ve e2e derlemelerinin ORTAK kuralları.
#
# Uygulamanın kendi keep kuralına ihtiyacı yok: ekranlar manifest'ten bulunur,
# kütüphanenin kuralları (model.**, Gson tipleri) AAR'ın consumer-rules.pro
# dosyasıyla kendiliğinden gelir. Buraya eklenen her kural iki derlemeyi de
# etkiler; uçtan uca testler (e2e) release ile aynı küçültülmüş kodu sınasın diye
# iki derleme bu dosyayı paylaşır.
#
# Yalnızca release'e özgü kurallar (log silme) proguard-release.pro'da.
