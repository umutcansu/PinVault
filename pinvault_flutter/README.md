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
  pinvault_flutter: ^2.4.0
```

### Native security file (required for release)

In a **release** build the trust anchors (bootstrap pins, signature keys, …)
must come from a native security file, never from the Dart bundle alone — a
Dart OTA update or an edited bundle must not be able to change them. Ship
`assets/pinvault_security.json` in the app:

- **Android:** `android/app/src/main/assets/pinvault_security.json` (the APK
  signature seals it).
- **iOS:** add it to the Xcode target's resources.

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

An app that deliberately accepts Dart-only anchors opts out in its manifest:
`<meta-data android:name="io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE" android:value="true"/>`.
The relaxations (`allowUnsigned`, `allowUnpinnedConfigApi`,
`allowServerGeneratedKey`) are still refused from Dart in release builds.

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
`attestationStatus`, `attestationHeaderName`.

`PinVault.addConnectionListener(listener)` — connection telemetry (never carries
a token, password, or file content).

`PinVaultWebSocket.connect(url)` — a pinned `wss://` WebSocket over the native
client (OkHttp / `URLSessionWebSocketTask`); the TLS session and mTLS identity
keys stay in native memory. Only `wss://` is accepted.

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
