# Changelog

## 2.5.0 — unreleased

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
