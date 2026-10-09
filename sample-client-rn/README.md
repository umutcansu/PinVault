# sample-client-rn

PinVault'u bir React Native uygulamasına bağlayan örnek (RN 0.87, New Architecture,
Hermes; TypeScript). Eklenti [`pinvault-react-native`](../pinvault-react-native)
bu depodan derlenir. Pin config'ini Docker'da çalışan [sample-host](../sample-host)'tan
alır; Android ve iOS örneklerinin Ana / mTLS / Vault ekranlarının sade hali.

## Ekranlar

| Ekran | Ne var |
|---|---|
| Ana | Durum ("✅ Hazır — config vN"), host başına pin sürümü, pinli istek (`PinVault.fetch`), React Native'in kendi `fetch`'i (iki platformda da PinVault'tan geçer), config'i şimdi yenile. Debug'da test kontrolleri |
| mTLS | Cihaz kimliği (panelde token'ı bu telefona bağlamak için), token ile kayıt, mTLS Config API'ye istek (`https://<host>:<mtlsPort>/health`), kaydı silme |
| Vault | Herkese açık dosya (`sample-flags`), token'lı dosya (`sample-e2e`: mTLS + token, cihaza özel şifre) ve ekran kilitli dosya (`sample-secret`: mTLS + token + ekran kilidi): indir, aç, telefondaki dosyaları sil. Açılan içerik 1 dakika sonra ya da ekrandan çıkınca silinir |

Gizli dosyalar ve mTLS bloğu yalnızca cihaz kayıtlıyken tanımlanır; kayıttan ve kayıt
silmeden sonra uygulama PinVault'u yeni yapılandırmayla yeniden başlatır.

Test kontrolleri (yalnız debug): ortam korumasının her işlemi reddetmesi (fail closed
denemesi), PinVault'u sıfırlama, React Native'in `<Image>`'ıyla hedefe bağlanma, React
Native'in `WebSocket`'iyle kendi host'umuza (pin tutar) ve pin listesinde olmayan bir
sunucuya (reddedilir) bağlanma, son bağlantı olayları. Release derlemesinde bu modül JS paketine iki kilitle girmez:
`src/generated/testControls.ts` boş yazılır, ayrıca `MainScreen.tsx` onu yalnız `__DEV__`
iken `require` eder (Metro release paketinde bu dalı atar).

## Host değerleri

Android'deki `BuildConfig` ve iOS'taki `SampleHostConfig.swift`'in karşılığı:
`sample-host.properties` (aynı biçim) derlemede `scripts/gen-host-config.js` ile
`src/generated/hostConfig.ts`'ye yazılır. Üçüncü parti paket yok (react-native-config
yerine 200 satırlık bir betik); değerler `sample-client/app/build.gradle.kts` ile aynı
biçim kurallarından geçer, uymayan değer derlemeyi durdurur.

```bash
../sample-host/scripts/client-config.sh --properties > sample-host.properties
# ya da başka bir dosya:
SAMPLE_HOST_PROPS=/yol/host.properties npm start
```

Betik `npm start / android / ios`, Gradle (`preDebugBuild` / `preReleaseBuild`,
`-PsampleHostProps=<yol>`) ve Xcode ("Bundle React Native code and images" aşaması)
öncesinde çalışır.

## Çalıştırma

Node 22.13+ (React Native 0.87'nin istediği), JDK 17, Xcode, CocoaPods.

```bash
npm install
npm start                          # Metro (port: --port 8089 gibi değiştirilebilir)

# Android
cd android && ./gradlew :app:installDebug
# iOS
cd ios && pod install && cd .. && npx react-native run-ios
```

- **PinVault kaynağı:** Android'de `android/gradle.properties` → `pinvault.localPath=../..`
  depodaki `:pinvault`'u imzasız olarak `android/build/pinvault-maven`'a yayımlar ve
  bağımlılığı oradan çözer (boşsa Maven Central). iOS'ta `ios/Podfile`
  `PINVAULT_IOS_PACKAGE_PATH`'i depoya ayarlar; `PINVAULT_IOS_PACKAGE_PATH= pod install`
  git etiketini (`v2.3.2`) kullanır.
- **Ekran görüntüsü:** Android'de ekranlar `FLAG_SECURE` alır (ekran görüntüsü yok); kanıt
  görüntüleri için yalnız debug'da `-Psample.e2eScreenshots=true`. iOS'ta uygulama arka plana
  geçerken ekranı bulanıklaştırır (uygulama değiştiricideki anlık görüntü).
- **Android 9 emülatörü:** `requireUnlockedDevice` yalnız release'te açık; o emülatörün
  yazılım keymaster'ı kilit şartlı anahtarın atestasyonunda çöküyor
  ([eklenti README'si](../pinvault-react-native/README.md#known-limits)).

## Release derlemesi

Diğer örneklerdeki kurallar: release, demo host değerleriyle derlenmez (en az 2 imza +
yedek anahtar, kurtarma anahtarı, `host.clientCaPin`, Config API kapsamları, Android'de
`host.expectedSignerSha256`; `target.requireCaTrust=false` olamaz), test kontrolleri
pakete girmez, `requireUnlockedDevice` ve `requireHardwareBackedKeys` açıktır. Sabit
noktalar (bootstrap pin'leri, imza / kurtarma anahtarları, kaç imza, kapsamlar, istemci
CA pin'i) eklentinin yerel güvenlik dosyasına da yazılır (`pinvault_security.json`;
Android'de release assets'i, iOS'ta uygulama paketi): JS paketi değişse bile uygulama
bunları paketin kendisinden alır. Android'de
gerçek imza anahtarı şart (debug anahtarına düşülmez):

```bash
cd android && ./gradlew :app:assembleRelease \
  -Psample.release.storeFile=… -Psample.release.storePassword=… \
  -Psample.release.keyAlias=… -Psample.release.keyPassword=…
```

(ya da `SAMPLE_RELEASE_STORE_FILE` … ortam değişkenleri). R8 açık; eklentinin kuralları
`consumer-rules.pro`'dan gelir.
