# sample-client-ios

PinVault'u bir iOS uygulamasına uçtan uca bağlayan örnek (SwiftUI). [sample-client](../sample-client)'ın (Android) karşılığıdır: aynı ekranlar (Ana, mTLS, Vault; test derlemelerinde Depolama ve Ayarlar), aynı görünüm kimlikleri, aynı Türkçe metinler. Pin config'ini Docker'da çalışan [sample-host](../sample-host)'tan alır. Uçtan uca testler (`sample-e2e`, `E2E_PLATFORM=ios`) bu uygulamayı simülatörde sürer.

Kütüphane depo kökündeki Swift paketinden (`Package.swift`, kaynaklar `pinvault-ios/`) yerel bağımlılık olarak gelir.

## Gerekenler

- Xcode (iOS 16+ SDK), [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- Ayakta bir sample-host (telefon ya da simülatör aynı ağda)

## Host değerleri

IP, portlar, bootstrap pin'leri ve imza anahtarı `sample-host.properties` dosyasından derlemede gömülür (Android'deki `BuildConfig` alanlarının karşılığı):

```bash
cd ../sample-host
./scripts/client-config.sh --properties > ../sample-client-ios/sample-host.properties
```

Derleme öncesi betik (`scripts/gen-host-config.sh`) dosyayı okur, her değeri Android'deki kurallarla denetler (biçime uymayan değer derlemeyi durdurur) ve `Sources/Generated/SampleHostConfig.swift`'i üretir (depoya girmez). Başka bir dosya için `SAMPLE_HOST_PROPS=/yol/dosya.properties`.

## Derleme ve çalıştırma (simülatör)

```bash
xcodegen generate
xcodebuild -project SampleClient.xcodeproj -scheme SampleClient -configuration Debug \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,id=<udid>' -derivedDataPath build build
xcrun simctl install <udid> build/Build/Products/Debug-iphonesimulator/SampleClient.app
xcrun simctl launch <udid> com.example.sampleclient
```

Ya da `SampleClient.xcodeproj`'u Xcode'da açıp çalıştır. İmza ad-hoc'tur (`-`): imzasız uygulamada simülatörün Keychain'i çalışmaz (-34018).

| Yapılandırma | Ne için |
|---|---|
| `Debug` | Geliştirme. Test kontrolleri (Depolama, Ayarlar, mod seçimi, otomatik kayıt, elle P12, E2E denetim dosyası) ve teşhis log'ları açık |
| `E2E` | Release ile aynı optimizasyon + test kontrolleri. Uçtan uca testler bunu kurar |
| `Release` | Telefona giden derleme: test kontrolü ve E2E kodu yok, uygulama arka plana geçince ekran örtülür |

Test derlemelerinde açılış modu E2E denetim dosyasından gelir (`Library/Caches/pinvault-e2e/control.json` → `"mode": "TLS" | "MTLS_CONFIG" | "CUSTOM_BACKEND" | "EMBEDDED_API" | "STATIC"`; Android'deki `--es mode`). Ayrıntı: `pinvault-ios/PORTING.md` §7–8.

## Yayın derlemesi

Release, depodaki demo değerleriyle derlenmez (Android'deki release kapısıyla aynı kurallar): config başına en az 2 imza (`host.requiredSignatures`), en az bir yedek imza anahtarı (`host.signingPublicKeys`), kurtarma anahtarı (`host.recoveryPublicKeys`), istemci CA pin'i (`host.clientCaPin`), Config API kimlikleri (`host.tlsScope`, `host.mtlsScope`) dolu ve `target.requireCaTrust=true` olmalı. Değerler sample-host'un üretim profilinden:

```bash
../sample-host/scripts/client-config.sh --properties > sample-host.properties
```
