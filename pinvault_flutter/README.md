# pinvault_flutter

Dynamic certificate pinning, mTLS identity, and vault files for Flutter — a thin,
typed bridge over the native [PinVault](https://github.com/umutcansu/PinVault)
libraries (Android `io.github.umutcansu:pinvault`, iOS `PinVault` Swift package).

Pinning, keys, signature checks and vault decryption all stay **native**. This
package only shapes inputs and outputs and runs your app's environment guard.
Nothing here stores anything, and nothing here logs outside development builds.

## Installation

```yaml
dependencies:
  pinvault_flutter: ^2.7.0
```

Flutter 3.44 or later (Dart 3.12), Android API 24, iOS 16.

### Android

`unlockFile` shows a `BiometricPrompt`, which needs a `FragmentActivity`: let
`MainActivity` extend `FlutterFragmentActivity` instead of `FlutterActivity`
(otherwise `unlockFile` fails with `E_NO_ACTIVITY`).

```kotlin
class MainActivity : FlutterFragmentActivity()
```

### iOS

iOS 16 or later. With Flutter's Swift Package Manager support (the default)
the plugin brings PinVault from its git tag. With CocoaPods, add PinVault to
the `Runner` target of the Podfile — it is not on CocoaPods trunk:

```ruby
pod 'PinVault', :git => 'https://github.com/umutcansu/PinVault.git', :tag => 'v2.7.0'
```

For `schedulePeriodicUpdates` to run in the background, list
`io.github.umutcansu.pinvault.refresh` under `BGTaskSchedulerPermittedIdentifiers`,
add `fetch` to `UIBackgroundModes` in `Info.plist`, and register the task in
`AppDelegate` before launch ends:

```swift
import pinvault_flutter

// in application(_:didFinishLaunchingWithOptions:), before `return`:
SwiftPinVaultFlutterPlugin.registerBackgroundTask()
```

Without it the update only runs while the app is in the foreground.

`unlockFile` asks for Face ID / Touch ID or the passcode: add
`NSFaceIDUsageDescription` to `Info.plist`, or the Face ID prompt ends the app.

### Native security file (required for release)

In a **release** build the trust anchors (bootstrap pins, signature keys, …)
must come from a native security file, never from the Dart bundle alone — a
Dart OTA update or an edited bundle must not be able to change them. Ship
`assets/pinvault_security.json` in the app:

- **Android:** `android/app/src/main/assets/pinvault_security.json` (the APK
  signature seals it).
- **iOS:** add it to the `Runner` target's resources (it is read from the app
  bundle as `pinvault_security.json`).

```json
{
  "configApis": [{
    "id": "default-tls",
    "url": "https://config.example.com/",
    "bootstrapPins": [{ "hostname": "api.example.com", "sha256": ["…", "…"] }],
    "signaturePublicKeys": ["…", "…"], "requiredSignatures": 2,
    "recoveryPublicKeys": ["…"], "requiredRecoverySignatures": 1,
    "serverScope": "default-tls", "clientCaPins": ["…"],
    "attestation": true, "proofOfPossession": true,
    "tokenHosts": ["api.example.com"], "clientCertHosts": ["api.example.com:443"]
  }],
  "require": {
    "requireUnlockedDevice": true, "requireHardwareBackedKeys": true,
    "requireCaTrust": ["api.example.com"], "expiredConfigGraceSeconds": 0
  },
  "vaultFiles": [{ "key": "statement", "signaturePublicKey": "…", "encryption": "USER_AUTH", "userAuth": "REQUIRED" }]
}
```

An app that deliberately accepts Dart-only anchors opts out natively — Android
`<meta-data android:name="io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE" android:value="true"/>`
in the manifest, iOS `PinVaultAllowNoNativeSecurityFile` = `YES` in `Info.plist`.
The relaxations (`allowUnsigned`, `allowUnpinnedConfigApi`,
`allowServerGeneratedKey`) are still refused from Dart in release builds; a
relaxation the native file sets for a block stays on in release builds too.
Who gets the device's token and identity is the file's call: in a release
build Dart may give `tokenHosts` and `clientCertHosts` only where the file
names them (the library's default sends `PinVault-Token` to the block's own
Config API only, so a list from Dart would add hosts).

## Quick start

```dart
final result = await PinVault.start(PinVaultConfig(
  configApis: [
    ConfigApiBlock(
      id: 'default-tls',
      url: 'https://config.example.com/',
      bootstrapPins: [HostPin(hostname: 'api.example.com', sha256: ['…', '…'])],
      signaturePublicKeys: ['…'],
    ),
  ],
  environmentGuard: (op) async => myRootDetector.isTrusted(op),
));
if (result is InitResultReady) {
  final response = await PinVault.fetch('https://api.example.com/ping');
}
```

Fail closed: until `start` returns `InitResultReady`, every pinned request is refused.

### Which requests are pinned

Only `PinVault.fetch` and `PinVaultWebSocket` go through the native pinned
client. Dart's own networking — `dart:io` `HttpClient`, `package:http`,
`dio`, `Image.network` — does **not**: it uses the platform's trust store and
none of PinVault's pins or client certificate. Send every request to a pinned
host through `PinVault.fetch`.

## API

`PinVault.` — config/status: `start`, `updateNow`, `currentVersion`,
`hostPinVersions`, `pinsForHost`, `signingStatus`, `isForceUpdate`, `reset`,
`schedulePeriodicUpdates`, `cancelPeriodicUpdates`, `enableDebugLogging`.

`PinVault.fetch(url, init)` — a request through the native pinned client (pin
check, attestation token, pin-mismatch recovery). HTTPS only; never falls back
to an unpinned path. `PinVaultRequestInit` supports method, headers, body
(text or Base64), timeouts, and a max response size.

`PinVault.` — enrollment: `deviceId`, `enrollForResult`, `autoEnrollForResult`,
`checkPendingEnrollment`, `isEnrolled`, `isEnrollmentPending`,
`enrollmentVerificationCode`, `enrolledClientCN`, `enrolledClientNotAfter`,
`unenroll`, `identityKeySecurityLevel`.

`PinVault.` — vault files: `setVaultToken`, `clearVaultTokens`, `fetchFile`,
`loadFile`, `fileStatus`, `unlockFile`, `isFileLocked`, `hasFile`,
`fileVersion`, `clearFile`, `syncAllFiles`. `TOKEN`/`TOKEN_MTLS` tokens stay in
native memory only.

`PinVault.` — attestation: `attestNow`, `fetchAttestationToken`,
`attestationStatus`, `attestationHeaderName`. Prefer `tokenHosts` +
`PinVault.fetch` (the native client adds the `PinVault-Token`) over
`fetchAttestationToken`, which hands the token to Dart. With
`proofOfPossession` the native client also adds a `PinVault-Proof` signed by
the device key, and a backend that requires it (the reference server does by
default) refuses the token alone.

`PinVault.addConnectionListener(listener)` — connection telemetry (never carries
a token, password, or file content). Returns a `StreamSubscription`; `cancel()`
it when done. Listeners are independent of each other.

`PinVaultWebSocket.connect(url, headers: …)` — a pinned `wss://` WebSocket over
the native client (OkHttp / `URLSessionWebSocketTask`); the TLS session and mTLS
identity keys stay in native memory. Only `wss://` is accepted. On both
platforms the upgrade to a token host of an attesting block carries
`PinVault-Token` (and `PinVault-Proof` with `proofOfPossession()`), attesting
first when no token is held. `messages`
carries the frames; a failure arrives once on its error handler and ends the
socket, and `done` completes on every ending.

## OWASP MASVS controls

- **MASVS-NETWORK-2 / MSTG-NETWORK-4 (pinning):** pins, signature checks and
  pin-mismatch recovery are the native library's; this bridge cannot weaken them.
- **Strict input parsing:** every structured input crosses as a JSON string and
  is parsed strictly natively — unknown keys, wrong types, out-of-range sizes and
  over-deep nesting are refused (`E_INVALID_CONFIG` / `E_INVALID_ARGUMENT`).
- **Fail closed:** unknown method arguments, oversized responses, and pre-`start`
  requests are refused, never defaulted to an unpinned path.
- **Secret hygiene:** vault access tokens and enrollment tokens live in native
  memory only and are redacted (`***`) from every string that returns to Dart.
- **Trust anchors outside the bundle:** the native security file (above) fixes
  pins, keys, relaxations and vault-file policy against OTA-updated Dart.
- **Environment guard:** an optional `environmentGuard` runs before `INIT`,
  `ENROLL`, `FETCH_FILE`, `UNLOCK_FILE`, `LOAD_FILE`; a timeout, throw, or
  non-`true` answer refuses the operation.
- **HTTPS only:** `fetch` and the WebSocket refuse non-TLS URLs and do not follow
  `https → http` redirects.

## Error model

Rejections are `PinVaultError` with a `code`
(`E_INVALID_CONFIG`, `E_INVALID_ARGUMENT`, `E_NOT_STARTED`, `E_FETCH`,
`E_NO_ACTIVITY`, `E_NATIVE`) and, where available, the native exception
(`exception.name` / `exception.message`).
