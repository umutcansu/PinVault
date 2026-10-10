# Changelog

## Unreleased

### Fixed

- **Expo: apps with their own Android backup rules build again, with
  PinVault's excludes kept.** An app or plugin (`expo-secure-store`) that sets
  `fullBackupContent` / `dataExtractionRules` failed the manifest merge
  against the library's rules. At the end of prebuild the plugin now copies
  those rules to `res/xml/pinvault_merged_<name>.xml` with PinVault's excludes
  added (only where the app's includes reach) and points the manifest at the
  copy with `tools:replace`; rules it cannot find stop prebuild. Built with
  Expo SDK 54 + `expo-secure-store`, Android release.

## 2.4.2 — 2026-10-10

### Added

- **Expo config plugin** (`app.plugin.js`): at `expo prebuild` it sets the
  iOS deployment target to 16.0, writes the Info.plist keys
  (`faceIDPermission`, `backgroundUpdates`), adds
  `PinVaultBridge.registerBackgroundTask()` to a Swift `AppDelegate`, copies
  the native security file into Android's assets and the iOS app bundle
  (`nativeSecurityFile`), and writes the two native opt-outs only when asked
  (`allowNoNativeSecurityFile`, `pinReactNativeNetworking: false`). Built and
  run with Expo SDK 54 (React Native 0.81), Android and iOS release builds.

### Changed

- **Native libraries 2.4.2:** release builds refuse `allowUnsigned()` /
  `allowUnpinnedConfigApi()` unless the block also calls
  `allowRelaxationsInRelease()`. The bridge calls it only where the native
  security file itself allows the relaxation (`allowUnsigned` /
  `allowUnpinned`), so the native file stays the only place that decides;
  JS cannot turn it on.

## 2.4.1 — 2026-10-10

### Security

- **React Native's WebSocket is pinned on iOS.** `wss://` went through
  SocketRocket on CFStream with the platform's CA check only, so a socket.io /
  graphql-ws connection could be intercepted by anyone holding a certificate
  the device trusts (a corporate proxy, a user-installed root), and `start`
  still reported RN's networking as pinned. Every SocketRocket socket to a
  `wss` / `https` URL now gets a security policy that asks PinVault (the
  library's new `evaluateServerTrust(_:host:port:)`) before the upgrade
  request is written; subprotocols are kept. `requirePinnedReactNativeNetworking`
  covers it (`E_NETWORKING_NOT_PINNED` when the hook is not in place), and
  Info.plist `PinVaultPinReactNativeNetworking` = NO turns it off with the
  https handler. A WebSocket to a host that requires a client certificate is
  not supported on iOS yet (the handshake fails).
- **Android: every WebSocket goes through PinVault's hook of its own.** RN's
  `WebSocketModule` has a separate `setCustomClientBuilder`; up to 0.81 it
  builds each socket's client from a bare `OkHttpClient.Builder()`, outside
  `OkHttpClientProvider`, so there the socket kept the system's trust while
  `start` reported RN's networking as pinned. The plugin now installs that hook
  too and checks it with the other two (`HookStatus.webSocketBuilderIsPinVault`),
  so a library replacing it is also caught on 0.87.

- **A release build needs the anchors in the native security file:** a declared
  block must carry `bootstrapPins` (or `allowUnpinnedConfigApi`) and
  `signaturePublicKeys` (or `allowUnsigned`). A file with a bare
  `{"id": …}` satisfied the release rule while the bundle supplied the pins
  and keys; it now rejects `start` with `E_INVALID_CONFIG` naming the field.
- **`clientCertHosts` from JS only where the file names them** (release
  builds): an OTA bundle could otherwise present the device's mTLS identity
  to another pinned host. `tokenHosts` from JS is still taken: it only
  narrows the library's default.

### Changed

- **React Native 0.81+** (was 0.87+): built and run on 0.81.6 and 0.87.1,
  Android and iOS (start with `requirePinnedReactNativeNetworking`, RN `fetch`
  and `WebSocket` to a pinned and an unpinned host).

## 2.4.0 — 2026-10-09

### Breaking

- **Release builds need the native security file** when the config has Config
  APIs or static pins (Android manifest meta-data
  `io.github.umutcansu.pinvault.ALLOW_NO_NATIVE_SECURITY_FILE` / iOS Info.plist
  `PinVaultAllowNoNativeSecurityFile` = YES opts out).
- **`requirePinnedReactNativeNetworking` is on by default in release builds.**
- **`expiredConfigGrace` is at most 7 days in release builds.**
- **Vault file keys** must match `[A-Za-z0-9._-]{1,64}` (not only dots).

### Security

- The native security file may also fix a block's `url`, `tokenHosts`,
  `clientCertHosts` and `attestation`, carry a `require` section (protections
  JS cannot switch off) and `vaultFiles` (signature key, encryption, lock).
- `start` answers `nativeSecurityApplied`.
- `proofOfPossession` on a Config API (JS or the native security file, where
  it cannot be switched off): the native clients add a `PinVault-Proof` signed
  by the device key to every request that carries the token (ATTESTATION.md §5.1).
- Android: React Native's long-lived clients (WebSocket, images) run the
  current start's network interceptors (the per-request pin check) and their
  pooled connections are closed on every start and reset; a hook installed only
  by `start()` is reported as not pinned; a hook replaced after start refuses
  https while `requirePinnedReactNativeNetworking` is on.
- The JS guard of a start the native side refuses is put back.
- `LOAD_FILE` is a guarded operation (`loadFile`).

## 2.3.2 — 2026-10-08 — first release

First published version (2.3.1 was never published). Needs PinVault 2.3.2 on both platforms.

### MASVS audit fixes

- **Native security file** (`pinvault_security.json`: Android assets, iOS app
  bundle): bootstrap pins, signing / recovery keys, `requiredSignatures`,
  `serverScope`, `clientCaPins` and the three relaxations declared outside the
  JS bundle. With it, JS may only repeat them (a different value, an undeclared
  Config API or undeclared `staticPins` → `E_INVALID_CONFIG`); without it,
  release builds refuse `allowUnsigned`, `allowUnpinnedConfigApi` and
  `allowServerGeneratedKey` from JS.
- **Android networking hook installed automatically** by a content provider
  before `Application.onCreate` (`PinVaultNetworking.install` stays as the
  alternative). `start` and every `fetch` detect a replaced OkHttp factory /
  custom client builder (`PinVaultNetworking.status()`) and warn;
  `requirePinnedReactNativeNetworking: true` fails `start` with
  `E_NETWORKING_NOT_PINNED`. RN's fetch / XHR get no disk cache and no cookie
  jar by default (`android.keepReactNativeHttpCache` / `keepReactNativeCookies`),
  no `https` → `http` redirects; Fresco's image client is covered too.
  `android.pinGlobalNetworking: false` is refused while the hooks are installed
  (opt out natively). Consumer R8 rules for the release build of a React Native
  0.87 app (Error Prone annotations, WorkManager's Room database).
- **iOS: React Native's own fetch / XHR / `<Image>` pinned** by
  `RNPinVaultURLRequestHandler` (an `RCTURLRequestHandler`, priority over
  `RCTHTTPRequestHandler` for https) on `PinVault.shared.session()`: fail closed
  before `start`, bounded answers (`ios.reactNativeMaxResponseBytes`), no
  `https` → `http` redirects, cancellation. Opt out with the Info.plist key
  `PinVaultPinReactNativeNetworking` = NO. WebSocket stays unpinned on iOS
  (README).
- iOS `fetch` enforces `maxResponseBytes` while reading (needs the library's new
  `PinnedSession.data(for:maxResponseBytes:)`).
- Deep nesting refused before the JSON parsers recurse (JS, Kotlin, Swift);
  Android's `StackOverflowError` can no longer escape.
- A refused second `start` keeps the running `environmentGuard`; the iOS guard
  asks JS before the library call, so no thread waits for JS.
- README: token handling described as it is (JS values until garbage
  collection; native memory only on the plugin's side).

### Initial bridge

First release of the React Native plugin, aligned with PinVault 2.3.1
(Android `io.github.umutcansu:pinvault:2.3.1`, iOS Swift package `v2.3.1`).

- TurboModule (New Architecture, React Native 0.87+): `start`, pinned `fetch`,
  enrollment, vault files, attestation and connection events, with the native
  names and result shapes.
- Strict native config parsing (unknown keys, wrong types and oversized input are
  refused), tokens in native memory only, redacted messages.
- `environmentGuard` as an async JS callback with a native deadline (fail closed).
- Android: React Native's own `fetch` / `XMLHttpRequest` / `WebSocket` pinned with
  `PinVault.applyTo` (`PinVaultNetworking`). iOS: not pinned, warned at `start`.
