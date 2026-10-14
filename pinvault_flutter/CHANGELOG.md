# Changelog

## 2.6.1 — 2026-10-15

- **iOS: without `tokenHosts`, only the block's own Config API carries
  `PinVault-Token`** (as Android has since 2.4.1). A block without
  `tokenHosts` sent the token (and `PinVault-Proof`) to every host pinned by
  its live config, so a pinned CDN or analytics host received it. Name your
  API hosts in `tokenHosts` if they need the token. Needs PinVault 2.6.1
  (`Package.swift` / the `PinVault` pod).

## 2.6.0 — 2026-10-14

- **iOS: `PinVaultWebSocket` carries the attestation token.** The upgrade to
  a token host sends `PinVault-Token` (and `PinVault-Proof` with
  `proofOfPossession()`), attesting first when none is held, as on Android.
  Frames sent before the socket is open are queued. Needs PinVault 2.6.0
  (`Package.swift` / the `PinVault` pod).
- **`fetch` and `PinVaultWebSocket.connect` refuse `PinVault-Token` /
  `PinVault-Proof` headers:** only the library sets them, for its token hosts.
- **Docs:** `expectedSignerSha256` is Android only; iOS uses
  `IosSettings.expectedBundleIds` / `expectedTeamIds`.

## 2.5.0 — 2026-10-12

First release of `pinvault_flutter`: a typed Dart bridge over the native
PinVault libraries (Android `io.github.umutcansu:pinvault`, iOS `PinVault`).

- Config, status and periodic updates (`start`, `updateNow`, …), pinned
  requests (`PinVault.fetch`) and pinned `wss://` WebSockets
  (`PinVaultWebSocket`, mTLS included), enrollment, vault files (screen-lock
  files with `unlockFile`), attestation, connection events.
- Native security file (`pinvault_security.json`): in a release build the
  trust anchors come from it, never from the Dart bundle alone; the
  relaxations it allows (`allowUnsigned`, `allowUnpinnedConfigApi`) stay on in
  release builds (`allowRelaxationsInRelease`), Dart cannot turn them on.
- Strict input parsing on both platforms, tokens kept in native memory and
  redacted from every string returned to Dart, an optional `environmentGuard`
  asked before INIT, ENROLL, FETCH_FILE, LOAD_FILE and UNLOCK_FILE.
- iOS: `SwiftPinVaultFlutterPlugin.registerBackgroundTask()` for background
  periodic updates.
- Requires Flutter 3.44 / Dart 3.12 (built-in Kotlin: the plugin does not
  apply the Kotlin Gradle plugin itself), iOS 16, Android API 24, and
  PinVault 2.5.0 on iOS (the pinned WebSocket API).
