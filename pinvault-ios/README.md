# PinVault for iOS

The iOS counterpart of the Android library: dynamic certificate pinning with a
signed, remotely updated pin config, mTLS enrollment with a Secure Enclave key,
signed and encrypted vault files, and device attestation — against the same
server and wire protocol as Android ([`SERVER_IMPLEMENTATION_GUIDE.md`](../SERVER_IMPLEMENTATION_GUIDE.md)).

- Swift 6, iOS 16+ (macOS 13+ builds too, for the tests). No third-party dependencies.
- Same names as Android: `PinVault`, `PinVaultConfig`, `ConfigApiBlock`, `VaultFileConfig`,
  `InitResult`, `ClientCertEnrollmentResult`, … Kotlin `suspend` functions are `async`.
- How each Android piece maps to iOS, and every wire addition: [`PORTING.md`](PORTING.md).

## Install

Swift Package Manager, from the repository root (`Package.swift` lives there):

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/umutcansu/PinVault.git", from: "2.3.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [.product(name: "PinVault", package: "PinVault")]),
]
```

In Xcode: *File → Add Package Dependencies…* with the same URL, product `PinVault`.
(`PinVaultE2E` is the sample app's test-control glue; apps do not link it.)

Info.plist:

| Key | Why |
|---|---|
| `BGTaskSchedulerPermittedIdentifiers` = `io.github.umutcansu.pinvault.refresh` | periodic config updates (`schedulePeriodicUpdates`) |
| `UIBackgroundModes` = `fetch` | the same |
| `NSFaceIDUsageDescription` | vault files locked behind the screen lock (`userAuth`) |

Keep App Transport Security on (no `NSAllowsArbitraryLoads`): PinVault only speaks HTTPS.
For App Attest add the *App Attest* capability (`com.apple.developer.devicecheck.appattest-environment`).

## Quick start

```swift
import PinVault

// At launch (App.init or application(_:didFinishLaunchingWithOptions:)).
PinVault.shared.registerBackgroundTask()

let config = try PinVaultConfig.Builder()
    .configApi("default-tls", url: "https://api.example.com:8081/") { block in
        block.bootstrapPins([
            HostPin(hostname: "api.example.com", sha256: [primaryPin, backupPin]),
        ])
        block.signaturePublicKeys(signingKey, backupSigningKey)
        block.serverScope("default-tls")
    }
    .build()

let result = await PinVault.shared.start(config: config)
guard case .ready(let version) = result else { /* fail closed: no pinned traffic */ return }

// Pinned requests (pin check, attestation token, pin-mismatch recovery):
let (data, response) = try await PinVault.shared.session().data(from: URL(string: "https://api.example.com/v1/me")!)
```

`start` fails closed: until it returns `.ready`, every pinned session refuses.
The panel's setup wizard writes this code with your server's values (choose *Swift (iOS)*).

### Your own URLSession configuration

```swift
let configuration = URLSessionConfiguration.ephemeral
configuration.timeoutIntervalForRequest = 15
let session = PinVault.shared.applyTo(configuration)   // pinning + token + recovery over your settings
```

Do not keep your own `URLSession` around the configuration: URLSession reuses
pooled connections without checking their certificates again, so PinVault
rebuilds its sessions whenever pins, identities or routing change. Use the
returned `PinnedSession` for every request.

### Hosts that resolve elsewhere

The counterpart of OkHttp's `Dns`: the request goes to the given address,
while the pin lookup, the hostname check and the client-certificate choice use
the original name.

```swift
PinVaultConfig.Builder().resolve(host: "api.internal.example", to: "10.0.0.12")
```

## mTLS enrollment

The identity key is a P-256 key made **in the Secure Enclave** (a software
Keychain key only where there is no Secure Enclave; `requireHardwareBackedKeys()`
refuses that). The private key never leaves the device; the CSR, the
verification code and the refusal reasons are the Android ones.

```swift
switch await PinVault.shared.enrollForResult(token: tokenFromYourBackend) {
case .enrolled(_, let level):           print("enrolled, key in", level?.wireName ?? "?")   // secure_enclave
case .pending(_, _, _, _, let code):    show(code)                                  // admin approval
case .refused(let reason, _, _, let message): show(reason, message)
case .failed(let message, _):           show(message)
}
```

The device id is `identifierForVendor` (lowercased): it survives app data and
Keychain wipes, and changes when the app is reinstalled with no other app of the
same vendor left. Renewal, the recovery door, revocation and "forget identity"
behave as on Android.

## Vault files

```swift
PinVaultConfig.Builder()
    .vaultFile("feature-flags") { file in
        file.endpoint("api/v1/vault/feature-flags")
    }
    .vaultFile("api-secret") { file in
        file.endpoint("api/v1/vault/api-secret")
        file.accessPolicy(.tokenMtls)
        file.encryption(.userAuth)
        file.userAuth(.required)
    }

_ = await PinVault.shared.fetchFile("api-secret")
let unlocked = await PinVault.shared.unlockFile(
    key: "api-secret",
    prompt: VaultFileUnlockPrompt(title: "Open the secret", description: "Face ID or passcode")
)
if case .unlocked(_, _, let bytes) = unlocked { use(bytes) }
```

- Signatures, versions, offline age and wipe-on-revocation work as on Android.
- `end_to_end` and `user_auth` files are wrapped for an RSA-2048 key in the
  Keychain (the Secure Enclave holds no RSA keys). iOS registers its keys as
  `RSA-OAEP-SHA256-MGF1-SHA256`: Apple's OAEP uses MGF1-SHA256, so the server
  wraps for iOS keys with it (Android keys stay `RSA-OAEP-SHA256`, MGF1-SHA1).
- The screen-lock key is `SecAccessControl(.userPresence)`; `unlockFile`
  evaluates `.deviceOwnerAuthentication` and opens the key with that context
  (one Face ID / passcode prompt).
- Stored files live under `Library/Application Support/pinvault/`, encrypted,
  excluded from backups; their keys are `ThisDeviceOnly` Keychain items.

## Attestation

`block.attestation()` turns it on, exactly as on Android. The report carries
`device.platform: "ios"` and iOS signals (jailbreak artefacts, simulator,
debugger, hooking libraries, app identity, installer); when the app names no
verdict provider, PinVault adds its own App Attest provider (`AppAttestVerdictProvider`).

```swift
let token = await PinVault.shared.fetchAttestationToken(host: "api.example.com")
```

For enrollment, `.integrityTokenProvider(AppAttestIntegrityTokenProvider())`
sends an App Attest attestation bound to the request.

What it does and does not prove: App Attest proves the request came from your
genuine app on genuine Apple hardware. It does not prove that the device is not
jailbroken, and the jailbreak / hooking probes run inside the app, where an
attacker with a jailbroken device can hook them. For high-value apps add a RASP
product and wire its verdict into `environmentGuard`. On the server, App Attest
also stands in for the Android Key Attestation chain under the `enforce`
settings (`ATTESTATION.md` §12).

## Platform differences

| | Android | iOS |
|---|---|---|
| Identity key | Keystore (StrongBox / TEE), key attestation chain | Secure Enclave; App Attest instead of a chain |
| Device id | `ANDROID_ID` | `identifierForVendor` |
| Encrypted stores | Keystore AES / HMAC keys, `shared_prefs` XML | Keychain keys (`ThisDeviceOnly`), plist under Application Support |
| Vault device key | Keystore RSA, OAEP MGF1-SHA1 | Keychain RSA, OAEP MGF1-SHA256 |
| Periodic updates | WorkManager | `BGTaskScheduler`; an in-process scheduler where it is unavailable (simulator) |
| 403 on mTLS listeners | read as is | URLSession hides it; the library asks for `409` + `X-PinVault-Status: 403` (`forbidden-as-409`) |
| Custom DNS | OkHttp `Dns` | `resolve(host:to:)` |

## Tests

```bash
sh pinvault-ios/scripts/test.sh <simulator udid>
```

It runs `swift test` on the Mac, the package tests on the simulator, and the
two app-hosted Keychain suites (SwiftPM's test runner has no Keychain access on
the simulator). Without a simulator id it runs the Mac suites only. The test
fixtures are throwaway keys and certificates (`Tests/PinVaultTests/Fixtures/README.md`).

End to end against the sample host, with the SwiftUI sample app
([`sample-client-ios/`](../sample-client-ios)): `cd sample-e2e && npm run test:ios`
([`sample-e2e/SETUP.md`](../sample-e2e/SETUP.md), iOS section).
