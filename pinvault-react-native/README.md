# PinVault for React Native

`@umutcansu/react-native-pinvault` — dynamic certificate pinning with a signed,
remotely updated pin config, mTLS enrollment with a hardware identity key,
signed and encrypted vault files, and device attestation, for React Native
apps on Android and iOS.

It is a thin bridge over the two native libraries — Android
[`io.github.umutcansu:pinvault`](https://github.com/umutcansu/PinVault/blob/main/pinvault) and the iOS Swift package
[`PinVault`](https://github.com/umutcansu/PinVault/blob/main/pinvault-ios/README.md). Pinning, keys (Android Keystore /
Secure Enclave), signature checks and vault decryption all stay native: no
crypto runs in JavaScript, and JavaScript never sees TLS. Names are the native
ones (`InitResult`, `ClientCertEnrollmentResult`, `VaultFileResult`, …), so the
[library documentation](https://github.com/umutcansu/PinVault/blob/main/README.md) applies as it is.

- React Native **0.87+**, New Architecture only (TurboModule, codegen), Hermes.
- Android minSdk 24; iOS 16+.
- No runtime dependencies: `react` and `react-native` are peers.

## Install

```bash
npm install @umutcansu/react-native-pinvault
cd ios && pod install
```

**iOS.** The pod depends on the PinVault Swift package through React Native's
`spm_dependency` (git URL `https://github.com/umutcansu/PinVault.git`, exact
version = this package's version, product `PinVault`). Info.plist, as for the
native library:

| Key | Why |
|---|---|
| `NSFaceIDUsageDescription` | vault files behind the screen lock (`userAuth`) |
| `BGTaskSchedulerPermittedIdentifiers` = `io.github.umutcansu.pinvault.refresh`, `UIBackgroundModes` = `fetch` | `schedulePeriodicUpdates` |

Register the background task in `AppDelegate` before launch ends (the app target
does not link the Swift package itself, the pod exposes the call):

```swift
import RNPinVault
// application(_:didFinishLaunchingWithOptions:)
_ = PinVaultBridge.registerBackgroundTask()
```

**Android.** The module depends on `io.github.umutcansu:pinvault` (same version
as this package; override with the Gradle property `pinvault.version`). To pin
React Native's own networking from the first request, add one line to
`MainApplication.onCreate` (see [Networking](#networking)):

```kotlin
import io.github.umutcansu.pinvault.reactnative.PinVaultNetworking

override fun onCreate() {
  super.onCreate()
  PinVaultNetworking.install(this)   // before loadReactNative(this)
  loadReactNative(this)
}
```

## Quick start

```ts
import PinVault from '@umutcansu/react-native-pinvault';

const result = await PinVault.start({
  configApis: [{
    id: 'default-tls',
    url: 'https://api.example.com:8081/',
    bootstrapPins: [{ hostname: 'api.example.com', sha256: [primaryPin, backupPin] }],
    signaturePublicKeys: [signingKey, backupSigningKey],
    requiredSignatures: 2,
    serverScope: 'default-tls',
  }],
  requireCaTrust: ['api.example.com'],
});
if (result.type !== 'ready') {
  // Fail closed: until start() returns ready, every pinned request is refused.
  return;
}

const res = await PinVault.fetch('https://api.example.com/v1/me', { headers: { Accept: 'application/json' } });
console.log(res.status, JSON.parse(res.body));
```

`start` fails closed exactly like the native `init` / `start(config:)`. Calling
`start` again applies the new config (the bridge calls `reset()` first, as the
native samples do when they restart).

## Configuration

`start(config)` takes the builders as JSON: the keys are the builder method
names of `PinVaultConfig.Builder`, `ConfigApiBlock.Builder` and
`VaultFileConfig.Builder`, durations are `{ amount, unit }` (`TimeUnit`
names), enum values are the Kotlin constant names (`'TOKEN_MTLS'`,
`'USER_AUTH'`, …). The full shape is the `PinVaultConfig` type in
[`src/types.ts`](src/types.ts).

```ts
{
  configApis: [{ id, url, bootstrapPins, signaturePublicKeys, requiredSignatures, recoveryPublicKeys,
                 serverScope, clientCaPins, clientCertHosts, renewalUrl, attestation, tokenHosts, … }],
  vaultFiles: [{ key, endpoint, configApi, accessPolicy, encryption, userAuth, storage,
                 maxOfflineAge: { amount: 7, unit: 'DAYS' }, … }],
  requireCaTrust, requireUnlockedDevice, requireHardwareBackedKeys, expectedSignerSha256,
  wipeVaultFilesOnRevocation, vaultFileMaxOfflineAge, updateIntervalMinutes, deviceAlias, …
  environmentGuard: async (operation) => boolean,       // JS, see below
  android: { requireUnlockedDeviceAllowFallback, pinGlobalNetworking },
  ios: { resolve: { 'mock-tls.sample': '10.0.0.12' }, expectedBundleIds, expectedTeamIds, userAuthStrength },
}
```

**The native parsers are strict.** An unknown key at any level, a wrong type
(`"3"` for a number, `1` for a boolean), a value out of range, a non-`https`
Config API URL, an oversized input (256 KiB config, bounded lists and strings)
rejects `start` with `PinVaultError` code `E_INVALID_CONFIG` and a message that
names the path (`config.configApis[0]: unknown key 'bootstrapPinz'`). The
library's own builder rules still apply on top (two pins per host, a signing
key for a signed Config API, `userAuth` for `USER_AUTH` files, …). Nothing is
silently ignored; the other platform's section (`ios` on Android, `android` on
iOS) is shape-checked and left to that platform.

Not exposed, on purpose: `clientKeystore(bytes, password)` (a P12 and its
password would cross the JS bridge — enroll instead), custom
`CertificateConfigApi`, storage, integrity-token and verdict providers (native
objects; iOS adds its App Attest verdict provider by itself), and
`reportToPinVaultBackend`.

## API

All functions return promises; `PinVault.x` and the named export `x` are the same.

| Area | Functions |
|---|---|
| Start / config | `start`, `updateNow`, `currentVersion`, `hostPinVersions`, `pinsForHost`, `signingStatus`, `isForceUpdate`, `reset`, `schedulePeriodicUpdates`, `cancelPeriodicUpdates`, `enableDebugLogging` (debug builds only) |
| HTTP | `fetch(url, { method, headers, body, bodyEncoding, responseEncoding, timeoutMs, maxResponseBytes, settings })` → `{ status, url, headers, body, bodyEncoding, ok }` |
| Enrollment | `deviceId`, `enrollForResult(token)`, `autoEnrollForResult`, `checkPendingEnrollment`, `isEnrolled`, `isEnrollmentPending`, `enrollmentVerificationCode`, `enrolledClientCN`, `enrolledClientNotAfter`, `unenroll(label, { wipeVaultFiles })`, `identityKeySecurityLevel` |
| Vault | `setVaultToken(key, token)`, `clearVaultTokens`, `fetchFile(key, { token })`, `loadFile(key, encoding)`, `fileStatus`, `unlockFile(key, prompt)`, `isFileLocked`, `hasFile`, `fileVersion`, `clearFile`, `syncAllFiles` |
| Attestation | `attestNow`, `fetchAttestationToken(host)`, `attestationStatus`, `attestationHeaderName` |
| Events | `addConnectionListener(event => …)` → `{ remove() }` |

Results are plain objects with a `type` (the sealed subclass in lowerCamel):
`{ type: 'ready', version }`, `{ type: 'failed', reason, exception: { name, message } }`,
`{ type: 'refused', reason: 'INVALID_TOKEN', httpStatus, … }`, `{ type: 'updated', key, version }`, …
A refused operation is a result, not an exception — the same as natively.
Rejected promises are `PinVaultError` with `code` (`E_INVALID_CONFIG`,
`E_INVALID_ARGUMENT`, `E_NOT_STARTED`, `E_FETCH`, `E_NO_ACTIVITY`, `E_NATIVE`)
and `exception` (the native class name and message, e.g.
`SSLPeerUnverifiedException` for a pin mismatch).

## Networking

- **`PinVault.fetch`** goes through the native pinned client on both platforms
  (`PinVault.getClient()` / `PinVault.shared.session()`; `settings` →
  `getClient(settings)` / `session(settings:)`, pinning without pin-mismatch
  recovery): pin check, attestation token, pin-mismatch recovery. HTTPS only;
  a redirect from `https` into plain `http` is not followed (the 3xx comes
  back) on either platform. Request bodies ≤ 10 MiB, responses ≤ 10 MiB by
  default (`maxResponseBytes`, at most 50 MiB).
- **Android — React Native's own `fetch`, `XMLHttpRequest` and `WebSocket` are
  pinned too** (`android.pinGlobalNetworking`, default true). Two hooks of RN
  0.87, read from its sources: `NetworkingModule.setCustomClientBuilder` is
  called for every request, so it works from whenever it is installed —
  including after `start()`; each request gets the socket factory and
  interceptors of one client that `PinVault.applyTo(builder)` configured after
  `start()` (one per start, so pooled connections are reused).
  `OkHttpClientProvider.setOkHttpClientFactory` covers the clients RN builds
  once (the networking base client, the WebSocket/dev-support singleton):
  their TLS goes through a forwarding socket factory to the current pinned
  one. RN asks that factory only when it creates such a client, so a client
  created before the factory was installed stays unpinned —
  **`PinVaultNetworking.install(this)` in `MainApplication.onCreate` covers
  them all**; without it `start()` installs the hooks itself. Until `start()`
  has run, every `https` request through RN's networking fails
  (`PinVault has not started`); plain `http` (Metro in debug builds) is left
  to your network security config. Hosts without a pin entry are refused like
  everywhere else in PinVault. Not covered: images (Fresco builds its client
  at app start) and native modules with their own HTTP stack.
- **iOS — React Native's own `fetch`/`XMLHttpRequest`/`WebSocket` are NOT
  pinned** (`RCTHTTPRequestHandler` owns its `URLSession` delegate). `start`
  logs a warning saying so. Send everything that must be pinned with
  `PinVault.fetch`. Keep App Transport Security on (no
  `NSAllowsArbitraryLoads`).

## Enrollment and vault tokens

The enrollment token goes to native memory for the duration of the call only
(`enrollForResult(token)`). Vault access tokens of `TOKEN` / `TOKEN_MTLS` files
are set with `setVaultToken(key, token)` or passed to `fetchFile(key, { token })`
and kept **only in native memory**: the native `accessToken { … }` provider reads
them on every download; they are never written to disk, the Keychain or JS
state, and they are gone with the process. Forget them on a revocation:

```ts
PinVault.addConnectionListener((e) => {
  if (e.type === 'clientCertRenewal' && e.status === 'REENROLL_REQUIRED') PinVault.clearVaultTokens();
});
```

Every string the bridge hands back (reasons, messages, `lastError`) has the
tokens it holds replaced by `***`.

## Vault content

- `fetchFile` results never carry the content (`{ type: 'updated', key, version }`);
  read it with `loadFile(key, 'utf8' | 'base64')`.
- Files behind the screen lock (`USER_AUTH`) never open with `loadFile`:
  `unlockFile(key, { title, description, negativeButtonText })` shows the
  native prompt (Android `BiometricPrompt`, which needs a `FragmentActivity` —
  `ReactActivity` is one; iOS `LAContext`) and only then returns the content.
- Once the content is in JS, it is a JS string: keep it only as long as you
  need it, do not put it into state that is persisted, and never log it.

## environmentGuard

```ts
environmentGuard: async (operation) => !(await myRaspSaysCompromised()),
environmentGuardTimeoutMs: 5000,
```

Asked before `INIT`, `ENROLL`, `FETCH_FILE` and `UNLOCK_FILE`. **Fail closed:**
a timeout (native deadline 100–30 000 ms, default 5000), a thrown error, a
rejected promise or anything but `true` refuses the operation. The guard runs
in JavaScript, and code that hooks the JS runtime can answer for it: treat it
as one more signal. The decisive check is server-side attestation
(`attestation: true` on a Config API) with a strict policy.

## Security notes (OWASP MASVS)

- **NETWORK** — pinned native path only; no unpinned fallback; `https` → `http`
  redirects are not followed; Android pins RN's own networking, iOS warns.
- **STORAGE** — the plugin stores nothing in JS (no AsyncStorage); tokens live
  in native memory only; vault content leaves native code only through
  `loadFile` / `unlockFile`.
- **CRYPTO / AUTH** — no crypto in JS; screen-lock prompts are native.
- **PLATFORM** — every bridge input is validated natively (types, sizes, allowed
  keys); events and errors carry no token, password or file content; no WebView.
- **CODE** — TypeScript strict; the plugin logs only in development builds
  (`__DEV__`); R8 rules ship in `android/consumer-rules.pro`.
- **RESILIENCE** — `requireHardwareBackedKeys`, `requireUnlockedDevice` and
  `expectedSignerSha256` are config keys; turn them on in release builds.

## Privacy: what leaves the device

The same as the native libraries, to your own PinVault server only: the device
id (`ANDROID_ID` / `identifierForVendor`), manufacturer and model, the
`deviceAlias` you set, and — with `attestation` — the attestation report (app
package / bundle id, version, signer digests, installer, OS version and patch
level, key security level, and the integrity signals: root/jailbreak, emulator,
debugger, hooking framework, app integrity, cloner, installer, adb, software
key; see [`ATTESTATION.md`](https://github.com/umutcansu/PinVault/blob/main/ATTESTATION.md) §3). Vault downloads report key,
version, status, device model, device id and alias. Connection events stay on
the device unless your listener sends them somewhere.

## Tests

```bash
npm test                       # Jest: the TS layer with the native module mocked
npx tsc --noEmit
# Android JVM tests (config parsing, refusals, result mapping, RN networking hooks, fetch):
cd ../sample-client-rn/android && ./gradlew :umutcansu_react-native-pinvault:testDebugUnitTest
# iOS XCTest for the Swift core (on the Mac, against this repository's Swift package):
cd ios/Tests && swift test
```

## Development in this repository

The sample app [`sample-client-rn/`](https://github.com/umutcansu/PinVault/blob/main/sample-client-rn) builds the plugin from
source. Android: `pinvault.localPath` in its `gradle.properties` publishes the
repository's `:pinvault` (unsigned) into `android/build/pinvault-maven` at every
build and resolves `io.github.umutcansu:pinvault` only from there — a composite
build is not possible because PinVault builds with AGP 8.7 and React Native 0.87
with AGP 9. iOS: the Podfile sets `PINVAULT_IOS_PACKAGE_PATH` to the repository,
and the podspec hands `spm_dependency` that local path instead of the git tag.

## Known limits

- Android 9 **emulator** images: their software keymaster (`keymaster@3.0`)
  crashes while attesting a key made with `requireUnlockedDevice` (SIGSEGV in
  `build_auth_list`); the keystore daemon then keeps a dead connection and every
  Keystore operation fails until it is restarted. Turn `requireUnlockedDevice`
  on for release builds / real devices only (the sample does).
- iOS: RN's global networking is not pinned (above).
