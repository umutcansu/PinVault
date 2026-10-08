# Changelog

## Unreleased — MASVS audit fixes

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

## 2.3.1

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
