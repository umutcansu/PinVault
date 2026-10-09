# PinVault for React Native

[![npm](https://img.shields.io/npm/v/@umutcansu/react-native-pinvault)](https://www.npmjs.com/package/@umutcansu/react-native-pinvault)

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
[library documentation](https://github.com/umutcansu/PinVault/blob/main/GUIDE.md) applies as it is.

- React Native **0.87+**, New Architecture only (TurboModule, codegen), Hermes.
- Android minSdk 24; iOS 16+.
- No runtime dependencies: `react` and `react-native` are peers.

## Install

From npm ([`@umutcansu/react-native-pinvault`](https://www.npmjs.com/package/@umutcansu/react-native-pinvault)):

```bash
npm install @umutcansu/react-native-pinvault
cd ios && pod install
```

The native libraries come with it, at the package's own version: npm 2.3.2
uses `io.github.umutcansu:pinvault:2.3.2` from Maven Central and the Swift
package at tag `v2.3.2`. The New Architecture must stay on (React Native
0.87's default).

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
as this package; override with the Gradle property `pinvault.version`). React
Native's own networking is pinned with no code of yours: the plugin's manifest
declares a content provider (`PinVaultNetworkingInitializer`) that installs the
hooks before `Application.onCreate` runs (see [Networking](#networking)).

**Release builds.** Put the trust anchors into the app itself, not only into
the JS bundle: [Native security file](#native-security-file).

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
                 serverScope, clientCaPins, clientCertHosts, renewalUrl, attestation, tokenHosts, proofOfPossession, … }],
  vaultFiles: [{ key, endpoint, configApi, accessPolicy, encryption, userAuth, storage,
                 maxOfflineAge: { amount: 7, unit: 'DAYS' }, … }],
  requireCaTrust, requireUnlockedDevice, requireHardwareBackedKeys, expectedSignerSha256,
  wipeVaultFilesOnRevocation, vaultFileMaxOfflineAge, updateIntervalMinutes, deviceAlias, …
  environmentGuard: async (operation) => boolean,       // JS, see below
  requirePinnedReactNativeNetworking,                    // see Networking
  android: { requireUnlockedDeviceAllowFallback, pinGlobalNetworking,
             keepReactNativeHttpCache, keepReactNativeCookies },
  ios: { resolve: { 'mock-tls.sample': '10.0.0.12' }, expectedBundleIds, expectedTeamIds, userAuthStrength,
         reactNativeMaxResponseBytes },
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
`E_INVALID_ARGUMENT`, `E_NOT_STARTED`, `E_FETCH`, `E_NO_ACTIVITY`, `E_NATIVE`,
`E_NETWORKING_NOT_PINNED`)
and `exception` (the native class name and message, e.g.
`SSLPeerUnverifiedException` for a pin mismatch).

## Native security file

The JS bundle is not a safe home for trust anchors: an OTA update (CodePush,
Expo Updates) or an edited bundle changes it without touching the app's
signature. Ship them natively as well, in `pinvault_security.json`:

- **Android:** `android/app/src/main/assets/pinvault_security.json` (or a build
  type's own `src/release/assets/`). Assets, not `res/raw`: resource shrinking
  cannot drop them and no `R` reference is needed. The APK signature seals it.
- **iOS:** a resource of the app bundle named `pinvault_security.json` (add it to
  the app target, or copy it into the bundle in a build phase that runs before
  signing). The code signature seals it.

```json
{
  "configApis": [{
    "id": "default-tls",
    "bootstrapPins": [{ "hostname": "api.example.com", "sha256": ["…", "…"] }],
    "signaturePublicKeys": ["…", "…", "…"], "requiredSignatures": 2,
    "recoveryPublicKeys": ["…"], "requiredRecoverySignatures": 1,
    "serverScope": "default-tls", "clientCaPins": ["…"],
    "url": "https://config.example.com:8081/", "attestation": true,
    "tokenHosts": ["api.example.com"], "proofOfPossession": true, "clientCertHosts": ["api.example.com:443"],
    "enrollmentUrl": "https://enroll.example.com/", "renewalUrl": "https://renew.example.com/",
    "allowUnsigned": false, "allowUnpinnedConfigApi": false, "allowServerGeneratedKey": false
  }],
  "staticPins": { "pins": [ … ], "version": 1 },
  "require": {
    "requireUnlockedDevice": true, "requireHardwareBackedKeys": true,
    "managedTrustRoots": true, "wipeVaultFilesOnRevocation": true,
    "requireCaTrust": ["api.example.com"],
    "expectedSignerSha256": ["…"],
    "expectedBundleIds": ["com.example.app"], "expectedTeamIds": ["ABCDE12345"],
    "expiredConfigGraceSeconds": 0, "vaultFileMaxOfflineAgeSeconds": 604800,
    "userAuthStrength": "BIOMETRIC_CURRENT_SET"
  },
  "vaultFiles": [
    { "key": "statement", "signaturePublicKey": "…", "encryption": "USER_AUTH", "userAuth": "REQUIRED",
      "maxOfflineAgeSeconds": 86400 }
  ]
}
```

The keys are the JS config's (a subset of `configApis[]` plus `staticPins`),
parsed as strictly; a broken file rejects `start` with `E_INVALID_CONFIG`
(fail closed). When the file is there:

- every Config API of the JS config must be declared in it (a bundle cannot add
  a block with keys of its own), and JS `staticPins` must be declared too;
- a field the file declares is the value: JS may leave it out (the native value
  applies) or repeat it (lists in any order); a different value rejects `start`
  with `E_INVALID_CONFIG` naming the field;
- `allowUnsigned`, `allowUnpinnedConfigApi` and `allowServerGeneratedKey` from
  JS are refused unless the file allows them for that block;
- a block's `url`, `enrollmentUrl`, `renewalUrl`, `tokenHosts` and
  `clientCertHosts` are fixed where the file gives them (where the block talks to, and who gets its token and identity),
  and `attestation: true` / `proofOfPossession: true` there cannot be turned off from JS;
- `require` only tightens: a protection it turns on stays on whatever JS says,
  its `requireCaTrust` hosts are added to JS's, the expected signer / bundle /
  team ids and iOS `userAuthStrength` are fixed, and `expiredConfigGraceSeconds`
  / `vaultFileMaxOfflineAgeSeconds` are the most JS may ask for (the value when
  JS asks for none)
  (Android reads `expectedSignerSha256`, iOS the bundle and team ids; one file
  can serve both);
- `vaultFiles` fixes those files' signature key, encryption and screen lock, and
  `maxOfflineAgeSeconds` is the longest offline lifetime JS may give them;
  with the section present, a JS vault file it does not name is refused.

`start` answers `nativeSecurityApplied: true` when the file was applied.

Without the file, **release builds** (Android: the app is not
`android:debuggable`; iOS: compiled without `DEBUG`) refuse to start a config
with Config APIs or static pins: its trust anchors would come from JS alone.
An app that accepts that says so natively — Android:
`<meta-data android:name="io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE" android:value="true"/>`
in the manifest's `<application>`; iOS: `PinVaultAllowNoNativeSecurityFile` =
YES in Info.plist — and the three relaxations stay refused from JS then. Debug
builds take everything as before. Whatever the file says, a release build
takes an `expiredConfigGrace` of at most 7 days. The sample app writes
the file for its release builds from `sample-host.properties`
(`scripts/gen-host-config.js --native-out`).

A repackaged app can change the file too — but only by re-signing, which the
signer check of attestation (`expectedSignerSha256`, `expectedTeamIds`) reports.

## Networking

- **`PinVault.fetch`** goes through the native pinned client on both platforms
  (`PinVault.getClient()` / `PinVault.shared.session()`; `settings` →
  `getClient(settings)` / `session(settings:)`, pinning without pin-mismatch
  recovery): pin check, attestation token, pin-mismatch recovery. HTTPS only;
  a redirect from `https` into plain `http` is not followed (the 3xx comes
  back) on either platform. Request bodies ≤ 10 MiB, responses ≤ 10 MiB by
  default (`maxResponseBytes`, at most 50 MiB) — enforced while the body is
  read on both platforms (a declared `Content-Length` over it is refused first).
- **React Native's own `fetch`, `XMLHttpRequest` and `<Image>` are pinned on
  both platforms** (WebSocket on Android only). The rules are the same on both:
  - **Before `start()`** — and after a start that failed — every `https`
    request through RN's networking fails (`PinVault has not started`): fail
    closed, as the native `getClient()` / `session()` before `init`. Plain
    `http` is not TLS and stays with RN (Metro in debug builds; ATS / the
    network security config decide).
  - Hosts without a pin entry are refused like everywhere else in PinVault.
  - No `https` → `http` redirects; no disk HTTP cache and no cookie jar (Android:
    `android.keepReactNativeHttpCache` / `keepReactNativeCookies` keep RN's own).
  - `requirePinnedReactNativeNetworking` (on by default in release builds)
    makes `start` fail with `E_NETWORKING_NOT_PINNED` when RN's networking does
    not go through PinVault (below); on Android a hook replaced after start
    then refuses RN's https too (checked every few seconds). With it off a
    warning is logged.
- **Android** (two hooks of RN 0.87, read from its sources), installed by the
  plugin's content provider before `Application.onCreate`, so every client RN
  builds is covered:
  `NetworkingModule.setCustomClientBuilder` is called for every fetch / XHR
  request; each one gets the socket factory and interceptors of one client that
  `PinVault.applyTo(builder)` configured after `start()` (one per start, so
  pooled connections are reused). `OkHttpClientProvider.setOkHttpClientFactory`
  covers the clients RN builds once — the networking base client, the
  WebSocket / dev-support singleton and Fresco's image client: their TLS goes
  through a forwarding socket factory to the current pinned one.
  Another library that calls either setter after PinVault (a network inspector,
  a crash reporter, another pinning package) replaces the hook: `start()` and
  every `PinVault.fetch` check both (`PinVaultNetworking.status()`) and log a
  warning; `requirePinnedReactNativeNetworking` turns it into a failed start.
  Opt out natively by removing the provider in the app's manifest —
  `android.pinGlobalNetworking: false` alone is refused while the hooks are in
  place, so a JS bundle cannot unpin RN's networking:

  ```xml
  <provider android:name="io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer"
      android:authorities="${applicationId}.pinvault-networking" tools:node="remove" />
  ```

  With the provider removed, `PinVaultNetworking.install(this)` in
  `MainApplication.onCreate` (before `loadReactNative`) is the explicit
  alternative; a hook installed later than that misses the clients RN already built.
- **iOS:** the plugin's `RNPinVaultURLRequestHandler` (an `RCTURLRequestHandler`)
  answers for `https` with `handlerPriority` 10; RCTNetworking picks the
  highest-priority handler, so RN's `RCTHTTPRequestHandler` (priority 0) only
  sees plain `http`. Codegen registers it (`codegenConfig.ios.
  modulesConformingToProtocol` in this package's `package.json`; `pod install`
  picks it up). Requests run on `PinVault.shared.session()` with the library's
  bounded read (`ios.reactNativeMaxResponseBytes`, default 50 MiB, at most
  256 MiB); the library hands out whole answers, so RN gets the response, the
  body in chunks and the completion after the body has been read (progress
  events arrive at the end); cancelling a request cancels it. `start` checks
  which handler RCTNetworking picks for an `https` request.
  Opt out natively with the Info.plist key `PinVaultPinReactNativeNetworking`
  = NO. **WebSocket is not pinned on iOS:** RN 0.87's `RCTWebSocketModule`
  uses SocketRocket on CFStream, not URLSession, so it cannot take PinVault's
  session or delegate; its hook (`RCTSetCustomSRWebSocketProvider` with an
  `SRSecurityPolicy` whose `evaluateServerTrust:forDomain:` decides) would need
  a public trust-evaluation API from the PinVault library, which it does not
  have. Keep secrets off `wss://` on iOS, or send them with `PinVault.fetch`.
  Keep App Transport Security on (no `NSAllowsArbitraryLoads`).

## Enrollment and vault tokens

Tokens cross the bridge once, as an argument, and the plugin keeps them on the
native side only. The enrollment token is held for the duration of the call
(`enrollForResult(token)`). Vault access tokens of `TOKEN` / `TOKEN_MTLS` files
are set with `setVaultToken(key, token)` or passed to `fetchFile(key, { token })`
and kept **in native memory only**: the native `accessToken { … }` provider
reads them on every download; the plugin never writes them to disk or the
Keychain, never hands them back to JS, and they are gone with the process.
What the plugin cannot control is the JS side: the string you pass is a JS
value until the garbage collector drops it, and if it went through React
state, a form field or a store, it lives there too. Pass it straight from where
it came from, clear the field, and never persist or log it. For an attestation
`PinVault-Token`, prefer `tokenHosts` + `PinVault.fetch` (the native client adds
it) over `fetchAttestationToken`, which hands the token to JS. With
`proofOfPossession` the native client also adds a `PinVault-Proof` signed by the
device key on every such request, and a backend that requires it refuses the
token alone — a token in JS is then of no use without the native client. Forget vault
tokens on a revocation:

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

Asked before `INIT`, `ENROLL`, `FETCH_FILE`, `UNLOCK_FILE` and `LOAD_FILE`. On iOS
the bridge asks before it calls the library (`start`: `INIT` and `ENROLL`;
enrollment calls: `ENROLL`; `fetchFile` / `syncAllFiles`: `FETCH_FILE`;
`unlockFile`: `UNLOCK_FILE`; `loadFile`: `LOAD_FILE`), so the wait for JS holds no thread; an operation the library
starts on its own (a background refresh) still waits on its own thread,
bounded by the timeout. **Fail closed:**
a timeout (native deadline 100–30 000 ms, default 5000), a thrown error, a
rejected promise or anything but `true` refuses the operation. The guard runs
in JavaScript, and code that hooks the JS runtime can answer for it: treat it
as one more signal. The decisive check is server-side attestation
(`attestation: true` on a Config API) with a strict policy.

## Security notes (OWASP MASVS)

- **NETWORK** — pinned native path only; no unpinned fallback; `https` → `http`
  redirects are not followed; RN's own fetch / XHR / images are pinned on both
  platforms (WebSocket on Android), fail closed before `start`, and a replaced
  hook is detected.
- **Trust anchors** — release builds take the relaxations only from the native
  security file; with the file, JS cannot change pins, keys or scopes.
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
- iOS: RN's WebSocket is not pinned, and RN's https answers are delivered after
  the whole (bounded) body is read (above).
- Android: the networking hooks are detected by reading two private fields of
  React Native 0.87 (`OkHttpClientProvider.factory`,
  `NetworkingModule.customClientBuilder`; the consumer R8 rules keep them). A
  React Native version that renames them reads as "could not be read", which
  counts as not pinned.
