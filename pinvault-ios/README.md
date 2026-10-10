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
    .package(url: "https://github.com/umutcansu/PinVault.git", from: "2.4.1"),
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

A pinned session never continues in plain HTTP: a redirect from `https` to
`http` is not followed, the 3xx is returned and your code decides. That holds
for `session()`, `session(settings:)` and `applyTo` alike (OkHttp follows such
redirects by default; PinVault for iOS does not). A backend that must redirect
into the clear needs an explicit opt-in, which never reaches the library's own
sessions: `applyTo(configuration, followCleartextRedirects: true)` or
`HttpConnectionSettings(followCleartextRedirects: true)`.

### Pinned WebSockets

A `wss://` socket rides the same TLS machinery as `session()` — server-trust
pinning **and** mTLS (client certificate) — instead of the lower-level
`evaluateServerTrust` hook, which has no client-certificate path:

```swift
let task = try PinVault.shared.session().webSocketTask(
    for: URLRequest(url: URL(string: "wss://api.example.com/ws")!))
task.resume()
task.receive { result in /* frames; a clean close leaves task.closeCode != .invalid */ }
task.send(.string("hello")) { _ in }
```

Fail closed: before `start` (or after a failed one) the call throws, and a
`resolve(host:to:)` entry for the host refuses the socket rather than
connecting to a different address than the one the delegate pins.

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
  (one Face ID / passcode prompt). Enrolling a new face or finger does not
  retire that key; removing the passcode does.
- **Biometrics only** (MASVS L2, MASTG-TEST-0064): `PinVaultConfig.Builder()
  .userAuthBiometricOnly()` (= `.userAuthStrength(.biometricCurrentSet)`) makes
  the key with `.biometryCurrentSet` and evaluates
  `.deviceOwnerAuthenticationWithBiometrics`: no passcode fallback ("Enter
  Passcode" cancels), and the key dies with the enrolled set — a new or
  removed face or finger makes the next `unlockFile` return `.invalidated`,
  every locked copy is deleted and `fetchFile` downloads them again with a new
  key (which the server registers anew, under its replacement rules). A device
  without biometrics counts as having no screen lock for `userAuth` files
  (`.required` files are not stored); a biometric lockout makes the unlock fail
  until the user unlocks the device with the passcode. One key serves every
  locked file, so this is a config-wide choice; the default stays biometrics
  or passcode.
- Stored files live under `Library/Application Support/pinvault/`, encrypted,
  excluded from backups; their keys are `ThisDeviceOnly` Keychain items,
  wrapped by a Secure Enclave key (`SecureEnclaveKeyWrap`): a Keychain dump of
  a jailbroken phone reads only ciphertext, and the keys open on this device
  only. Keys written by earlier versions are wrapped the first time they are
  read; where no Secure Enclave key can be made they stay as they were.
  Going back to an older version of the library starts the stores empty.
- The `end_to_end` RSA key cannot be wrapped that way (the Secure Enclave holds
  no RSA keys): on a jailbroken phone a Keychain dump can copy it. Use
  `user_auth` (screen lock) for content that must not leave the device.
- **Putting an older container back** (a jailbroken phone, a restored copy of
  the app's files) would set the replay watermarks and the trusted clock back
  with it. iOS also keeps them in a `ThisDeviceOnly` Keychain item outside the
  container (`WatermarkMirror`) and reads the higher of the two, so an older
  signed config is not accepted again. Old vault copies stay readable until
  their `maxOfflineAge`, measured on that clock; set it for files where that
  matters.
- **The newest signing-key set applied** is kept in that Keychain item too, as
  a floor: below it nothing verifies (configs, stored configs, vault files)
  until a response brings a set at least as new — a container put back from
  before a rotation does not bring revoked keys back. The floor is the block's
  (it stays when the block points at another server) and holds while the
  recovery keys stay the same; an update with other recovery keys starts again
  from the set in force at its first sync. Two limits: in the moment between
  such an update and its first sync there is no floor; and blocks that share
  recovery keys should each set `serverScope`, so a set made for one block is
  never taken by another.

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
| Encrypted stores | Keystore AES / HMAC keys, `shared_prefs` XML | Keychain keys (`ThisDeviceOnly`, wrapped by the Secure Enclave), plist under Application Support |
| Replay watermarks | in the encrypted store (a restored store sets them back; the server's `config_rollback` flag sees it) | also mirrored in the Keychain, outside the container |
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

Runtimes: CI should run the simulator suites on the **oldest iOS runtime Xcode
still ships (18.0)** and on the **current one**, so that Keychain behaviour that
differs between versions is covered where it can be (iOS 16 and 17 simulators no
longer ship, so the library's calls there are checked by reading Apple's
sources rather than by running them). `PKCS12ImportKeychainTests` in the identity
host suite is the one that depends on it: it checks that opening a PKCS12
(`SecPKCS12Import`, with `kSecImportToMemoryOnly` on iOS 18+ and without it
before, as iOS 16–17 get it) leaves nothing in the Keychain and opens the same
bundle again and again. Apple's header documents memory-only as the iOS default
on every version; the test makes sure a runtime does not drift from that.

End to end against the sample host, with the SwiftUI sample app
([`sample-client-ios/`](../sample-client-ios)): `cd sample-e2e && npm run test:ios`
([`sample-e2e/SETUP.md`](../sample-e2e/SETUP.md), iOS section).
