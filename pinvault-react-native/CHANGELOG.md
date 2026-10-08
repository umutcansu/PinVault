# Changelog

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
