# pinvault_flutter example

A small app over the plugin: **Start** (offline static pins by default,
`_remoteConfig()` for the repo's demo-server), **Fetch** and **WebSocket**.

## Tests against the demo-server

Start the repo's demo-server (`.claude/launch.json` → `demo-server-espresso`,
or `API_KEY=admin-key-123 ALLOW_DEMO_SECRETS=true ../gradlew run` in
`demo-server/`).

**End to end (debug)** — `integration_test/demo_server_test.dart`: guard,
signed config, pinned and refused requests, connection events, WebSocket
failures, enrollment with a one-time token, vault files (public, token, wrong
token). It sets up its own tokens and files over the management API and
removes them afterwards.

```sh
flutter test integration_test/demo_server_test.dart -d emulator-5554 \
  --dart-define=PINVAULT_SIGNING_KEY=$(curl -s localhost:8090/api/v1/signing-key | jq -r .publicKey)
```

On the iOS simulator add
`--dart-define=PINVAULT_HOST=192.168.1.80 --dart-define=PINVAULT_PINNED_PORT=8444 --dart-define=PINVAULT_UNPINNED_PORT=8443`
(the Mac's LAN address and the mock host its config pins).

**Release build (Android)** — `scripts/release_check.sh [serial]` builds a
release APK (R8 on) with a native security file for the local demo-server,
runs `integration_test/release_check.dart` as the app and prints its results:
Dart cannot add relaxations, change pins or add Config APIs; the signed config
loads; a relaxation the file allows stays on. Exits non-zero unless every
check passes.
