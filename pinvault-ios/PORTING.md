# PinVault for iOS — porting contract

This file is the contract every part of the iOS port follows: the Swift library
(`pinvault-ios/`), the SwiftUI sample app (`sample-client-ios/`), the E2E harness
(`sample-e2e/`, `E2E_PLATFORM=ios`) and the server changes (`demo-server/`).
The Android library (`pinvault/`) is the source of truth for behaviour: when this
file says nothing, do what the Kotlin code does.

## 1. Layout

```
Package.swift                         SwiftPM manifest at the repo root (SwiftPM resolves packages by git URL)
pinvault-ios/
  PORTING.md                          this file
  README.md                           user documentation (install, quick start, platform notes)
  Sources/PinVault/                   the library; zero third-party dependencies
    PinVault.swift                    the façade (public actor)
    Model/ API/ TLS/ Crypto/ Keys/ Store/ Internal/ Integrity/ Background/ Logging/ Util/
  Sources/PinVaultE2E/                test-control glue used only by the sample app's E2E build
  Tests/PinVaultTests/                XCTest; fixtures in Tests/PinVaultTests/Fixtures/
sample-client-ios/                    SwiftUI sample app (XcodeGen project.yml)
sample-e2e/ios-driver/                XCUITest-based UI driver (HTTP on 127.0.0.1) used by sample-e2e/lib/ios.js
```

Kotlin package → Swift folder: `model`→`Model`, `api`→`API`, `ssl`→`TLS`, `crypto`→`Crypto`,
`keystore`→`Keys`, `store`→`Store`, `internal`→`Internal`, `integrity`→`Integrity`,
`worker`→`Background`, `reporter`→`API`. One Swift file per Kotlin file unless several tiny
Kotlin files are grouped (results, small enums).

## 2. Language and API rules

- Swift 6 language mode, strict concurrency. Platforms: iOS 16+, macOS 13+ (macOS only so that
  `swift test` runs the pure-logic suites on the Mac; iOS-only APIs behind `#if os(iOS)` /
  `#if canImport(UIKit)`).
- Frameworks allowed: Foundation, Security, CryptoKit, LocalAuthentication, DeviceCheck,
  BackgroundTasks, UIKit (device info only), Network, os. No third-party packages.
- Public type and member names mirror the Android names (`PinVault`, `PinVaultConfig`,
  `ConfigApiBlock`, `VaultFileConfig`, `HostPin`, `CertificateConfig`, `InitResult`,
  `UpdateResult`, `ClientCertEnrollmentResult`, `AttestationStatus`, `VaultFileResult`,
  `KeySecurityLevel`, …). Kotlin `sealed class` → Swift `enum` with associated values;
  data class → `struct` (`Sendable`, `Equatable` where sensible, `Codable` where JSON).
- `PinVault` is `public final class PinVault: @unchecked Sendable` with `public static let shared`;
  its mutable state sits behind a lock (`Util/Locked.swift`, an `NSLock`-backed box), so the
  non-suspend Kotlin functions (`isEnrolled`, `currentVersion`, `pinsForHost`, …) stay synchronous.
  Every Kotlin `suspend fun` becomes `async` (throws only where the Kotlin function throws); callback
  overloads and `Context` parameters are dropped. Internal components with mutable state are
  either actors or lock-protected classes; never hold a lock across an `await`. Kotlin `init(context, config)` becomes
  `start(config:)` (Swift reserves `init`), `getClient()` becomes `session()` (returns a
  `PinnedSession`), `getClient(HttpConnectionSettings)` becomes `session(settings:)`,
  `applyTo(OkHttpClient.Builder)` becomes `applyTo(_ configuration: URLSessionConfiguration) -> PinnedSession`.
- `PinnedSession` is the iOS counterpart of the pinned OkHttp client: an object that owns a
  `URLSession` whose delegate is the library's `DynamicSSLManager`, and whose
  `data(for:)` / `data(from:)` run the interceptor chain of the Android client in order:
  attestation token header → send → `403 {"error":"reenroll_required"}` sniff → `401` +
  `PinVault-Token` re-attest-and-retry-once → pin-mismatch recovery (budget, circuit breaker,
  single flight, exactly as `PinRecoveryInterceptor`). URLSession reuses pooled connections
  without re-challenging, so every library-built session is rebuilt when pins change
  (the counterpart of `PinnedConnectionInterceptor`).
- Builders keep the Kotlin DSL shape:
  ```swift
  let config = try PinVaultConfig.Builder()
      .configApi("default-tls", url: "https://192.168.1.10:6651/") { block in
          block.bootstrapPins([HostPin(hostname: "192.168.1.10", sha256: [p1, p2])])
          block.signaturePublicKey(base64)
          block.serverScope("default-tls")
      }
      .vaultFile("sample-flags") { file in file.endpoint("api/v1/vault/sample-flags") }
      .build()
  ```
  Kotlin `require(...)` → `throws PinVaultError.invalidConfiguration(String)` from `build()`.
- Errors: `public enum PinVaultError: Error` mirrors `model/SSLPinningException.kt`
  (one case per exception class, same message texts).
- CF types (`SecKey`, `SecCertificate`, `SecTrust`, `SecIdentity`) are wrapped in
  `final class … : @unchecked Sendable` holders where they cross actors.

## 3. Platform mapping

| Android | iOS |
|---|---|
| ANDROID_ID | `UIDevice.current.identifierForVendor` (lowercased UUID string); stable across data wipes, changes on reinstall |
| Keystore EC P-256 identity key (`pinvault_client_identity_ec_<label>`) | Secure Enclave P-256 (`kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `AfterFirstUnlockThisDeviceOnly`, `.privateKeyUsage`), application tag = the same alias string. Fallback when the SE is unavailable: Keychain software P-256 key reporting `software`. Works on Apple-silicon simulators **only when the app is signed** (ad-hoc `CODE_SIGN_IDENTITY="-"` is enough; unsigned builds get errSecMissingEntitlement -34018) |
| Keystore key attestation chain | none (`attestationChain` omitted). App Attest is a separate, optional provider (§6) |
| `KeySecurityLevel` wire names `strongbox` / `tee` / `software` / `unknown` | add `secure_enclave` (`hardwareBacked == true`) |
| RSA-2048 device key `pinvault_vault_e2e_rsa` (end_to_end files) | Keychain RSA-2048 (software; SE holds no RSA), ThisDeviceOnly, tag = same alias |
| RSA-2048 user-auth key (screen lock) | Keychain RSA-2048 with `SecAccessControl(.userPresence)`. Use it as: `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt.description)` first, then the key with `kSecUseAuthenticationContext: thatContext` (one prompt on a device; on the simulator the key ACL is not enforced, the explicit evaluation is what shows the prompt) |
| RSA-OAEP SHA-256 + MGF1-SHA1 (server ↔ Android) | Apple's `.rsaEncryptionOAEPSHA256` is SHA-256 + **MGF1-SHA256** (verified: it cannot open MGF1-SHA1). iOS registers its keys with `"algorithm": "RSA-OAEP-SHA256-MGF1-SHA256"`; the server stores the algorithm per key and wraps with the matching MGF1 hash. Android keeps `"RSA-OAEP-SHA256"` (= MGF1-SHA1), unchanged |
| EncryptedSharedPreferences-like `SecurePreferences` (AES-256-GCM values, HMAC-SHA256 names) | same scheme; file `Library/Application Support/pinvault/<fileName>.plist` (dictionary HMAC name → Base64 value); the two 32-byte keys are Keychain generic passwords `pinvault_prefs_aes` / `pinvault_prefs_mac` (ThisDeviceOnly). Files are excluded from backup (`isExcludedFromBackup`) and get `NSFileProtectionCompleteUntilFirstUserAuthentication` (`Complete` with `requireUnlockedDevice`) |
| Vault files `files/vault_files/<key>.enc` | `Library/Application Support/pinvault/vault_files/<key>.enc`, same PVF2 layout, per-file key in Keychain |
| WorkManager periodic job | `BGTaskScheduler` identifier `io.github.umutcansu.pinvault.refresh` (`PinVault.registerBackgroundTask()` at launch, Info.plist `BGTaskSchedulerPermittedIdentifiers`). `submit` throws `.unavailable` on the simulator → an in-process scheduler takes over (states ENQUEUED / RUNNING / CANCELLED in `ScheduledTaskInfo`) |
| OkHttp `Dns` (sample's `MockDns`) | `PinVaultConfig.Builder.resolve(host:to:)` / `HttpConnectionSettings.resolve`: the request is sent to the given address, while pin lookup, hostname verification and client-certificate selection use the original (logical) host. Used by the sample app for `mock-tls.sample` / `mock-mtls.sample` |
| Timber | `os.Logger(subsystem: "io.github.umutcansu.pinvault", category: <Kotlin class name>)`; every interpolation `privacy: .public`; message texts copied verbatim from the Kotlin code (E2E tests grep them). Debug-mode lines are logged at `.notice` (persisted) when diagnostic logging is on |
| `requireUnlockedDevice` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `NSFileProtectionComplete` |
| BiometricPrompt / device credential | LocalAuthentication `.deviceOwnerAuthentication` |
| backup exclusion XML | `URLResourceValues.isExcludedFromBackup = true` on `Library/Application Support/pinvault` and everything below; Keychain items are ThisDeviceOnly (never migrate to a backup) |

## 4. Wire additions (server must accept, iOS sends)

- Device id: `identifierForVendor` (lowercased) matches the server rule `^[A-Za-z0-9._:-]{1,64}$`.
- Enrollment `keySecurityLevel` / attestation `device.keySecurityLevel`: may be `secure_enclave`.
- Vault key registration `algorithm`: `RSA-OAEP-SHA256-MGF1-SHA256` (see §3).
- Attestation report (ATTESTATION.md §3) from iOS keeps the exact shape and all 12 signal keys:
  ```json
  {
    "sdkVersion": "2.3.0", "reportTime": 1759660801234,
    "app": { "packageName": "<bundle id>", "bundleId": "<bundle id>", "teamId": "<team id or null>",
             "versionCode": <CFBundleVersion as int, else 0>, "versionName": "<CFBundleShortVersionString>",
             "signerSha256": [], "installer": "app-store|testflight|provisioned|simulator|unknown",
             "debuggable": <get-task-allow present> },
    "device": { "platform": "ios", "osVersion": "26.5", "manufacturer": "Apple", "brand": "Apple",
                "model": "<machine id, e.g. iPhone17,1>", "device": "<UIDevice.model>", "product": "<machine id>",
                "hardware": "<machine id>", "fingerprint": "iOS/<osVersion>/<build>", "sdkInt": <major>,
                "securityPatch": null, "verifiedBootState": null,
                "keySecurityLevel": "secure_enclave|software", "keyAttested": <App Attest verified> },
    "signals": { "rooted": …, "emulator": …, "debugger": …, "debuggable": …, "hooking_framework": …,
                 "app_integrity": …, "cloner": {"flag":false,"evidence":["n/a:ios"]},
                 "unknown_installer": …, "adb_enabled": {"flag":false,"evidence":["n/a:ios"]},
                 "software_key": …, "key_unattested": …, "old_patch_level": … },
    "verdictProvider": { "name": "app-attest", "token": "<JSON string, see §6>" }
  }
  ```
  iOS probes: `rooted` = jailbreak artefacts (`/Applications/Cydia.app`, `/Applications/Sileo.app`,
  `/Applications/Zebra.app`, `/var/jb`, `/private/var/lib/apt`, `/usr/sbin/sshd`, `/bin/bash`,
  `/etc/apt`, write test outside the sandbox under `/private`, `cydia://` / `sileo://` URL schemes are
  NOT queried (needs Info.plist entries)); `emulator` = `targetEnvironment(simulator)` or
  `SIMULATOR_DEVICE_NAME` env; `debugger` = `sysctl` `P_TRACED`; `debuggable` = `get-task-allow`
  entitlement (read from the embedded provisioning profile; on the simulator `#if DEBUG`);
  `hooking_framework` = loaded dyld images matching `frida|substrate|substitute|libhooker|ellekit|cycript|SSLKillSwitch|FridaGadget`,
  `DYLD_INSERT_LIBRARIES` set, frida's default port 27042 open on 127.0.0.1; `app_integrity` = bundle id /
  team id differ from the values the app gave the library (`expectedBundleId`, `expectedTeamId`);
  `unknown_installer` = not App Store / TestFlight (an embedded provisioning profile, or the simulator).
  The server (§5) treats `platform: ios` specially.
- App Attest tokens (§6).
- `X-PinVault-Features: forbidden-as-409` on every library request to a Config API, and on app
  requests to hosts where the library presents a client identity: on a connection where the server
  asked for a client certificate, URLSession turns any HTTP 403 into `URLError.clientCertificateRequired`
  (-1206) and drops the body (verified, `ReenrollRequiredDetectionTests`). The server answers such a
  request's 403 as `409` + `X-PinVault-Status: 403` with the same body; the transport hands it to the
  interceptors and the API client as a 403.

## 5. Server changes (demo-server)

1. `RSA-OAEP-SHA256-MGF1-SHA256` accepted at `POST /api/v1/vault/devices/{id}/public-key` (both
   purposes), stored per key, used when wrapping end_to_end and user_auth files; listed in the
   dashboard and openapi; Android unchanged.
2. Attestation (`AttestationService`): `device.platform == "ios"` → no Android key-attestation
   chain expected (`key_unattested` comes from App Attest instead), `old_patch_level` compares
   `device.osVersion` with `ATTESTATION_MIN_IOS_VERSION` (empty = not checked), `app_integrity`
   compares `app.bundleId` with `ATTESTATION_PACKAGE_NAMES` and `app.teamId` with
   `ATTESTATION_IOS_TEAM_IDS` (empty = not checked).
3. App Attest verifier (new): attestation objects and assertions, flags `app_attest` (verdict did not
   verify) and `app_attest_missing` (no verified App Attest verdict within the max age), both
   `warn` by default, only raised when `APP_ATTEST_APP_IDS` (`TEAMID.bundle.id`, comma separated)
   is configured. Env: `APP_ATTEST_APP_IDS`, `APP_ATTEST_ENVIRONMENT=production|development`,
   `APP_ATTEST_MAX_AGE_SECONDS`.
4. Enrollment integrity (`EnrollmentIntegrity`): an `integrityToken` that is App Attest JSON (§6) is
   verified by the App Attest verifier against the enrollment's integrity request hash.
5. Setup wizard: a Swift code snippet next to Kotlin/Java.

## 6. App Attest tokens

- Attestation rounds: `clientDataHash = SHA256(UTF8("pinvault-app-attest:v1:" + nonce + ":" + deviceId))`.
  First round (no key on record locally) generates a key and sends an attestation; later rounds send
  assertions. If the server answers with warning/reason `app_attest_unknown_key`, the client drops its
  key and attests a new one on the next round.
- Enrollment integrity: `clientDataHash = SHA256(UTF8(integrityRequestHash))` where
  `integrityRequestHash` is the 43-char string of `internal/IntegrityRequestHash.kt`. Always a fresh
  key + attestation.
- `token` (the `verdictProvider.token`, and the enrollment `integrityToken`) is a JSON string:
  `{"provider":"app-attest","keyId":"<base64>","attestation":"<base64 CBOR>"}` or
  `{"provider":"app-attest","keyId":"<base64>","assertion":"<base64 CBOR>"}`.
- `DCAppAttestService.isSupported` is false on the simulator: the provider returns nil and the
  report carries no `verdictProvider`.
- Public types (L5): `AppAttestVerdictProvider` (an `IntegrityVerdictProvider`, `init()`), and
  `AppAttestIntegrityTokenProvider` (an `IntegrityTokenProvider`, `init()`). The panel's setup wizard
  generates `.integrityTokenProvider(AppAttestIntegrityTokenProvider())` for Swift.

## 7. Sample app (sample-client-ios)

- Bundle id `com.example.sampleclient` (same as Android `APP_ID`), display name "PinVault Sample".
- Configurations: `Debug` (test controls), `E2E` (Release optimization `-O`, whole-module, test
  controls, diagnostic logs), `Release` (no test controls; refuses demo host values like the
  Android release build type). Targets: `SampleClient` (all configurations). Test controls are
  compiled in with the Swift flag `TEST_CONTROLS`; the `PinVaultE2E` product is linked only when
  `TEST_CONTROLS` is set. Signing: ad-hoc (`CODE_SIGN_IDENTITY = "-"`) for the simulator.
- Host values: `scripts/gen-host-config.sh <sample-host.properties>` → `Sources/Generated/SampleHostConfig.swift`
  (same keys and validation regexes as `sample-client/app/build.gradle.kts`); the build runs it as a
  pre-build script with `SAMPLE_HOST_PROPS` (default `sample-client-ios/sample-host.properties`).
- Screens mirror the Android activities: Main, mTLS, Vault, Settings (test controls), Storage
  (test controls). Every Android view id becomes the SwiftUI `accessibilityIdentifier` with the
  same name (`statusView`, `eventLogView`, `testButton`, `tokenInput`, `enrollButton`,
  `modeTls`, …). Text views expose their full text as the accessibility label; inputs expose
  their text as the value; toggles/radio buttons expose `1`/`0` as the value. Each screen has a
  `backButton` (iOS has no system back key).
- Every user-visible string is the Turkish text of `sample-client/app/src/main/res/values/strings.xml`
  (the E2E page object matches them with regexes), and every action result ends with the
  `#<seq> · HH:mm:ss` stamp of `ActionActivity.showResult`.

## 8. E2E control channel (E2E/Debug builds only)

The harness cannot run `am start --es`, iptables, `date -s`, `cmd jobscheduler` or `run-as` on
iOS. Instead:

- **Control file**: `<data container>/Library/Caches/pinvault-e2e/control.json`, written by the
  harness (it survives until the harness wipes the container):
  ```json
  { "mode": "TLS", "clockOffsetSeconds": 0,
    "redirects": { "192.168.1.10:6651": "127.0.0.1:6661" } }
  ```
  `mode` = initial `AppSettings` mode at launch (like `--es mode`); `clockOffsetSeconds` = added to
  the library's wall clock (`TrustedClock` wall source, certificate validity, `SecTrustSetVerifyDate`);
  `redirects` = connection-address overrides applied on top of the app's `resolve` entries
  (`host:port` → `host:port`), the counterpart of iptables DNAT/REJECT (REJECT → a closed port,
  DROP → a blackhole port the harness listens on).
- The app reads the file at launch and again whenever the Darwin notification
  `com.example.sampleclient.e2e.control` is posted (`xcrun simctl spawn <udid> notifyutil -p …`).
  New redirects/clock apply to new connections at once (library sessions are rebuilt).
- Darwin notification `com.example.sampleclient.e2e.runScheduledWork` runs the library's periodic
  job immediately (counterpart of `cmd jobscheduler run -f`).
- **Report file**: the app writes `<data container>/Library/Caches/pinvault-e2e/report.json`
  `{ "deviceId": "…", "scheduledTasks": [ScheduledTaskInfo…], "updatedAt": <ms> }` at launch and
  whenever it changes.
- The library exposes these hooks as `@_spi(PinVaultE2E)` API, used only by `Sources/PinVaultE2E`.
- **Logs**: `xcrun simctl spawn <udid> log show --start '<ts>' --predicate 'subsystem IN {"io.github.umutcansu.pinvault","com.example.sampleclient"}' --style compact`.
- **UI**: `sample-e2e/ios-driver` (XCUITest runner) serves the accessibility tree and performs taps
  / typing / swipes / system-alert buttons over HTTP on `127.0.0.1:${E2E_IOS_DRIVER_PORT:-6870}`.
  (idb's HID path does not work with Xcode 27: it looks for SimulatorKit at its pre-27 location.)
- **Screen lock**: Face ID enrolment `notifyutil -s com.apple.BiometricKit.enrollmentChanged 1` +
  `-p com.apple.BiometricKit.enrollmentChanged`; approve `-p com.apple.BiometricKit_Sim.pearl.match`;
  reject `-p com.apple.BiometricKit_Sim.pearl.nomatch`, after which SpringBoard shows a button with
  identifier `com.apple.localauthentication.ax.authentication.button.cancel` (cancel).
  The simulator always reports a device passcode (`canEvaluatePolicy(.deviceOwnerAuthentication)`
  is true even with Face ID not enrolled), so "no screen lock" cannot be simulated.
- **Data wipe** (`pm clear`): terminate, delete the data container's `Documents`, `Library`, `tmp`
  contents, `xcrun simctl keychain <udid> reset`. The app is never uninstalled between tests
  (identifierForVendor must stay stable).

## 9. Public API index

What L1a declared; later layers fill the bodies behind it (grep `TODO(L2)` … `TODO(L5)` in
`Sources/PinVault`). The public surface is meant to stay as listed here.

### Conventions

- `import PinVault`; everything is `Sendable`. Kotlin `Long` → `Int64` (epoch ms, durations),
  Kotlin `Int` → `Int`, `ByteArray` → `Data`, `TimeUnit` → the Swift `TimeUnit` enum (`.minutes`, …).
- Kotlin enum constants → lowerCamel cases whose `rawValue` is the Kotlin name
  (`VaultFileStatus.notStored.rawValue == "NOT_STORED"`), so UI texts can print the Android names.
  `GuardedOperation.INIT` is `.start`.
- Sealed classes → enums with labelled associated values (`InitResult.ready(version:)`);
  `description` mirrors Kotlin `toString()` where it matters (tokens and P12 passwords print as `***`).
- Builder methods never throw: they record the first invalid argument (Kotlin `require`) and
  `build()` throws it as `PinVaultError.invalidConfiguration(message)`, same text as Kotlin. DSL
  closures take the builder as their argument: `.configApi("id", url: "https://…") { block in … }`.
- `HostPin(...)` never throws (so the DSL needs no `try`); the Kotlin constructor rule (≥ 2 pins)
  is `HostPin.validate()`, applied by `bootstrapPins(_:)`/`build()`, `ConfigApiBlock.configurationError()`
  and, for static pins, by the pin config validator at `start`.
- Errors: `PinVaultError` (one case per Kotlin exception class + JVM families). `exceptionName` is the
  Kotlin/Java simple class name, `message` the Kotlin message → the Android sample's
  `getSimpleName() + "\n" + getMessage()` is `error.exceptionName + "\n" + error.message`.
  Result enums carry `(any Error)?`; cast with `as? PinVaultError`.
- Before `start`, synchronous getters return empty values (nil / 0 / false / `[:]`) where Kotlin throws
  `IllegalStateException`; async operations return their failure result
  (`"PinVault not initialized. Call PinVault.start() first."`); sessions fail closed.
- Listeners are closures. `OnUpdateListener` / `OnFileUpdateListener` run on the main actor;
  `PinVaultConnectionListener` runs on a background task.

### `PinVault` (`PinVault.shared`)

| Member | Kotlin | What it does |
|---|---|---|
| `static let shared` | `object PinVault` | the instance |
| `static let backgroundTaskIdentifier` | — | `io.github.umutcansu.pinvault.refresh` (Info.plist `BGTaskSchedulerPermittedIdentifiers`) |
| `typealias OnUpdateListener` / `OnFileUpdateListener` | `OnUpdateListener` / `OnFileUpdateListener` | `@MainActor @Sendable` closures |
| `setOnUpdateListener(_:)` | same | config update results |
| `setConnectionListener(_:)` | same | replace the connection listener at runtime (after start) |
| `setOnFileUpdateListener(_:)` | same | vault file sync results |
| `start(config:) async -> InitResult` | `init(context, config)` | start; `.ready(version:)` = pinned traffic may flow |
| `start(config:configApi:) async -> InitResult` | `init(context, config, configApi)` | custom `CertificateConfigApi` for the default block |
| `identityKeySecurityLevel(label:) -> KeySecurityLevel?` | same | where the mTLS identity key lives; nil = none |
| `static enableDebugLogging()` / `enableDebugLogging()` | same | debug/info logs at `.notice` (persisted) |
| `applyTo(_: URLSessionConfiguration) -> PinnedSession` | `applyTo(OkHttpClient.Builder)` | pinning + token + recovery over your configuration |
| `session() -> PinnedSession` | `getClient()` | the pinned session (pinning, token, re-attest on 401, recovery) |
| `session(settings:) -> PinnedSession` | `getClient(HttpConnectionSettings)` | custom timeouts / `resolve`; no pin-mismatch recovery |
| `attestNow(configApiId:) async -> AttestationStatus` | same | attest now |
| `fetchAttestationToken(host:) async -> AttestationTokenResult` | same | `PinVault-Token` for your own client |
| `attestationStatus(configApiId:) -> AttestationStatus` | same | last verdict, from memory |
| `attestationHeaderName() -> String` | same | `"PinVault-Token"` |
| `updateNow() async -> UpdateResult` | same | fetch + apply the latest config |
| `schedulePeriodicUpdates(intervalHours:) -> Bool` | same (callback → return value) | BGTask / in-process scheduler |
| `cancelPeriodicUpdates()` | same | |
| `scheduledTasks() async -> [ScheduledTaskInfo]` | `getScheduledWorkInfo` | ENQUEUED / RUNNING / … |
| `registerBackgroundTask() -> Bool` | — (iOS) | register the BGTask launch handler at app launch |
| `enroll(token:label:) async -> Bool` | `enroll(context, token, label)` | token / enrollment-code enrollment |
| `enrollForResult(token:label:) async -> ClientCertEnrollmentResult` | same | with the reason |
| `autoEnroll() async -> Bool`, `autoEnrollForResult()` | same | device-id enrollment (identifierForVendor) |
| `enroll(config:token:)`, `enrollForResult(config:token:)` | `enroll(context, config, token)` | before `start` (mTLS Config API) |
| `autoEnroll(config:)`, `autoEnrollForResult(config:)` | same | before `start` |
| `isEnrolled(label:) -> Bool`, `isEnrolled(config:) -> Bool` | `isEnrolled` / `isEnrolledWithConfig` | stored client certificate? |
| `enrollmentVerificationCode(label:) -> String?` | same | `4F7K-2QXM-9D3T-H6WP` for the waiting screen |
| `isEnrollmentPending(label:)`, `isEnrollmentPending(config:)` | same | waits for admin approval? |
| `checkPendingEnrollment() async`, `checkPendingEnrollment(config:) async` | same | ask again whether approved |
| `renewClientCertIfNeeded(configApiId:force:) async -> ClientCertRenewalResult` | same | renew now if due (or forced) |
| `unenroll(label:wipeVaultFiles:)` | `unenroll(context, label[, wipe])` | forget the identity (and mTLS blocks' files) |
| `enrolledClientCN(label:) -> String?`, `enrolledClientNotAfter(label:) -> Int64?` | same | stored leaf CN / expiry (epoch ms) |
| `fetchFile(_:) async -> VaultFileResult` | same | download + store a vault file |
| `loadFile(_:) -> Data?`, `loadFileAsString(_:) -> String?` | same | stored copy (checked on every read) |
| `fileStatus(_:) -> VaultFileStatus` | same | why `loadFile` would return nil |
| `unlockFile(key:prompt:) async -> VaultFileUnlockResult` | `unlockFile(activity, key, prompt)` | passcode/biometric prompt, then the content |
| `isFileLocked(_:)`, `hasFile(_:)`, `fileVersion(_:)`, `clearFile(_:)` | same | stored-copy helpers |
| `syncAllFiles() async -> [String: VaultFileResult]` | same | fetch every `updateWithPins` file |
| `currentVersion() -> Int`, `hostPinVersions() -> [String: Int]` | same | active config versions |
| `pinsForHost(_:) -> [String]?`, `currentPins: [String: [String]]` | same | active pins (Base64, no `sha256/`) |
| `signingStatus(configApiId:) -> SigningStatus?` | same | trusted key ids, m-of-n, key-set version |
| `isForceUpdate() -> Bool` | same | active config's `forceUpdate` |
| `reset()` | same | drop active pins, start over at the next `start` (watermarks kept) |
| `@_spi(PinVaultE2E)` `e2eSetClockOffset(seconds:)`, `e2eSetRedirects(_:)`, `e2eRunPeriodicWorkNow() async`, `e2eDeviceId()`, `e2eSetScheduledTasksObserver(_:)` | — | §8 hooks, used by `PinVaultE2E` only |

### Configuration (`Model/`)

| Type | What it is |
|---|---|
| `PinVaultConfig` | the config; `configApis` / `configApiIds` (ordered), `vaultFiles` / `vaultFileKeys`, `defaultConfigApi`, `orderedConfigApis`, `orderedVaultFiles`, every Kotlin field, iOS `resolvedHosts`, `expectedBundleIds`, `expectedTeamIds`; `static(_ pins: HostPin...)`; constants `defaultConfigEndpoint`, `defaultHealthEndpoint`, `defaultMaxRetry`, `defaultUpdateIntervalHours`, `defaultEnrollmentEndpoint`, `defaultClientCertEndpoint`, `defaultVaultReportEndpoint`, `defaultCertLabel` |
| `PinVaultConfig.Builder` | `configApi(_:url:_:)`, `vaultFile(_:_:)`, `maxRetryCount`, `updateIntervalHours`, `updateIntervalMinutes`, `deviceAlias`, `staticPins`, `onConnectionEvent`, `reportToPinVaultBackend(managementUrl:reportSuccessEvents:dedupWindowMs:)`, `expiredConfigGrace(_:_:)`, `requireCaTrust(_:)`, `wipeVaultFilesOnRevocation()`, `vaultFileMaxOfflineAge(_:_:)`, `requireUnlockedDevice()`, `requireHardwareBackedKeys()`, `managedTrustRoots()`, `environmentGuard(_:)` (protocol or closure), `integrityTokenProvider(_:)` (protocol or async closure), `integrityVerdictProvider(_:)`, `expectedSignerSha256(_:)` (Android parity), iOS: `resolve(host:to:)`, `expectedBundleId(_:)`, `expectedTeamId(_:)`; `build() throws` |
| `ConfigApiBlock` (+ `.Builder`) | one Config API: all Kotlin fields and builder methods (`bootstrapPins`, `signaturePublicKey(s)`, `requiredSignatures`, `recoveryPublicKeys`, `requiredRecoverySignatures`, `allowUnsigned`, `serverScope`, `allowUnpinnedConfigApi`, `clientKeystore(_:password:)`, `allowServerGeneratedKey`, `clientCaPins`, `maxClientCertLifetimeDays`, `clientCertHosts`, endpoints, `clientCertLabel`, `wantPinsFor`, `renewalUrl`, `enrollmentUrl`, `clientCertRenewalThreshold`, `disableClientCertRenewal`, `attestation`, `attestationInterval(_:_:)`, `tokenHosts`); `defaultId`, interval/threshold/lifetime constants |
| `VaultFileConfig` (+ `.Builder`) | one vault file: `endpoint`, `signaturePublicKey`, `updateWithPins`, `storage(.encryptedPrefs/.encryptedFile or a VaultStorageProvider)`, `configApi`, `accessPolicy`, `accessToken { }`, `encryption`, `userAuth`, `maxOfflineAge(_:_:)`, `wipeWhenStale()` |
| `StorageStrategy`, `VaultFileAccessPolicy` (`.public/.apiKey/.token/.tokenMtls`), `VaultFileEncryption` (`.plain/.atRest/.endToEnd/.userAuth`, `wireName`) | vault file enums |
| `HttpConnectionSettings` | timeouts etc. for `session(settings:)`; `resolve(host:to:)` returns a copy with a host mapping |
| `HostPin`, `CertificateConfig` | pins (Codable, Gson-lenient decoding; `validate()`, `computedVersion()`) |
| `SignedConfigResponse`, `SignatureEntry`, `SignedKeySet` | signed envelope wire types (Codable) |
| `EnvironmentGuard` (protocol), `ClosureEnvironmentGuard`, `GuardedOperation` | the app's device verdict before guarded operations |
| `IntegrityTokenProvider` (protocol, async), `ClosureIntegrityTokenProvider` | integrity token per enrollment request |
| `UserAuth`, `VaultFileUnlockPrompt` (`localizedReason`) | locked vault files |
| `KeySecurityLevel` | `.strongbox/.trustedEnvironment/.software/.unknown/.secureEnclave`, `wireName`, `hardwareBacked`, `fromWireName` |
| `TimeUnit` | amount + unit for the builder methods |

### Results and events

| Type | Cases / fields |
|---|---|
| `InitResult` | `.ready(version:)`, `.failed(reason:exception:)`; `isReady` |
| `UpdateResult` | `.updated(newVersion:)`, `.alreadyCurrent`, `.failed(reason:exception:)` |
| `ClientCertEnrollmentResult` | `.enrolled(alreadyEnrolled:keySecurityLevel:)`, `.refused(reason:httpStatus:serverError:message:)`, `.pending(requestId:clientId:message:retryAfterSeconds:verificationCode:)`, `.failed(message:cause:)`; `isEnrolled` |
| `EnrollmentRefusal` | `.invalidToken`, `.tokenRequired`, `.deviceAlreadyEnrolled`, `.revoked`, `.rejected`, `.limitReached`, `.expired`, `.attestationFailed`, `.csrRequired`, `.other`; `from(httpStatus:serverError:)` |
| `ClientCertRenewalResult`, `ClientCertRenewalVia`, `ClientCertRenewalResponse` | renewal outcome / door / backend answer |
| `EnrollmentResult` | P12 or PEM chain from a backend (`isCertificateChain`) |
| `AttestationStatus`, `AttestationResult`, `AttestationTokenResult` | attestation state (`hasValidToken(now:)`), `.token(value:expiresAt:)/.rejected/.failed/.unsupported` |
| `VaultFileResult` | `.updated(key:version:bytes:)`, `.alreadyCurrent(key:version:)`, `.failed(key:reason:exception:code:)`; `key`; `FailureCode` constants |
| `VaultFileUnlockResult` | `.unlocked/.notFound/.cancelled/.invalidated/.stale/.failed`; `key` |
| `VaultFileStatus` | `.available/.locked/.notStored/.stale/.needsFetch/.integrityFailed/.storageUnavailable` |
| `VaultFetchResponse`, `VaultDownloadReport` | backend download metadata / distribution report (Codable) |
| `ScheduledTaskInfo` (`State`) | scheduled update task (Codable; state raw values `ENQUEUED`, …) |
| `SigningStatus` | signature trust snapshot |
| `PinVaultConnectionEvent` | `.connection(...)`, `.configUpdate(...)`, `.clientCertRenewal(...)`, `.attestation(...)`; status enums `ConfigUpdateStatus`, `ClientCertRenewalStatus`, `AttestationEventStatus` |
| `PinVaultConnectionListener` | `@Sendable (PinVaultConnectionEvent) -> Void` |
| `PinVaultError` | see Conventions; also `isSSLPinningException`, `isCertificateException`, `refusal` |

### Integration points and helpers

| Type | What it is |
|---|---|
| `CertificateConfigApi` (protocol) | custom backend; Kotlin default bodies are protocol-extension defaults (incl. the 6/7/8-argument `enrollWithCsr` chain) |
| `SignedConfigSource` (protocol) | custom backend that hands over signed envelopes |
| `IntegrityVerdictProvider` (protocol), `IntegrityVerdict` | second opinion inside attestation reports |
| `VaultStorageProvider` (protocol) | custom vault file store (methods may throw) |
| `ClientIdentityKeyProvider` (protocol), `ClientIdentityKeys` | mTLS identity key contract; `aliasFor(_:)`, `attestationChallenge(deviceUid:)` (L3 adds the Secure Enclave / software factories) |
| `DeviceKeyProvider` (protocol), `DeviceKeys` | `end_to_end` RSA key contract; `defaultAlias`, `registrationAlgorithm` (L4 adds the Keychain factory) |
| `VaultFileDecryptor` | `decrypt(_:privateKey:)` (RSA-OAEP-SHA256/MGF1-SHA256 + AES-GCM), `decrypt(_:unwrapKey:)` |
| `PinnedSession` | `data(for:)`, `data(from:)`, `invalidateAndCancel()` |
| `PinVaultBackendReporter` | demo-server telemetry: `init(managementUrl:session:reportSuccessEvents:dedupWindowMs:)`, `init(managementUrl:pinnedSession:…)`, `listener`, `onEvent(_:)`, `pinnedClient(hostname:pins:)`, `defaultSession()` |
| `PinVaultE2E.E2EControls` | §8 control channel: `shared`, `init(controlNotification:runScheduledWorkNotification:directory:pinVault:)`, `start()`, `stop()`, `control`, `onControl`, `readControl()`, `reloadControl()`, `apply(_:)`, `writeReport()`, `Control`, `Report` |
