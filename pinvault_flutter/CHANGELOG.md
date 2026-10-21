# Changelog

## 2.8.2 — 2026-10-21

- No change to the plugin. Released alongside PinVault 2.8.2, whose
  reference server and dashboard say whose key the backup pin of a host
  added from a URL trusts (the issuing CA's) and take an optional second
  pin of the site instead.
- Depends on PinVault 2.8.2.

## 2.8.1 — 2026-10-15

- **iOS: a pinned session notices when its trust check was skipped.** The
  generic certificate-validation killers answer URLSession's server-trust
  challenge before the library's delegate; such a connection is now refused
  (`fetch` throws an SSL handshake error), a `wss://` socket cancelled, and
  the host reported as `hooking_framework` evidence `tls-unverified:<host>`.
- Depends on PinVault 2.8.1.

## 2.8.0 — 2026-10-15

- **Release builds take a block's addresses only from the native security
  file**: a declared block names its `url` there, and `enrollmentUrl` /
  `renewalUrl` from Dart are refused where the file names none (the device's
  identity goes to all three, its token to `url`). iOS `ios.resolve` follows the
  same rule (top-level `"ios": {"resolve": {…}}` in the file; fixed wherever the
  file gives it). Add them to `pinvault_security.json` if a release build now
  refuses to start.
- `PinVault.fetch` refuses `Host`, `Connection`, `Keep-Alive`,
  `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` and
  `Content-Length` from Dart: the HTTP client sets them.
- Depends on PinVault 2.8.0.

## 2.7.0 — 2026-10-15

- **Release builds take `tokenHosts` only from the native security file**,
  as they already did `clientCertHosts`: where `pinvault_security.json` has
  the block but names no `tokenHosts`, a `tokenHosts` from Dart is refused
  (`E_INVALID_CONFIG`, "declare tokenHosts for Config API … there"). The
  library's default sends `PinVault-Token` to the block's own Config API only,
  so a `tokenHosts` from Dart would add hosts that receive the device's token.
  Debug builds and files that name the hosts are unchanged. Move your
  `tokenHosts` into the file if a release build now refuses to start.
- Depends on PinVault 2.7.0.

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
