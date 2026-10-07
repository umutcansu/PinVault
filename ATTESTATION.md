# PinVault Attestation — protocol and design

_Status: implemented in the 2.2.0 development stream (library, reference server, dashboard). This document is the contract between the Android library and any server that speaks it; the reference server implements it in full._

PinVault's pinning protects the channel. Attestation protects what the channel
carries: it is the layer that decides **which app instances get the pins and a
short-lived token at all**, and lets your API refuse everything else. The
model follows Approov's: an SDK measures the app and the device, a service
turns the measurement into a verdict, pins and a token are released only on a
pass, the token is refreshed every few minutes, and the backend checks the
token on every request. Here the "service" is your own PinVault server.

```
Android app (PinVault)                          PinVault server (Config API port)
──────────────────────                          ─────────────────────────────────
GET  /api/v1/attest/challenge  ───────────────► nonce (HMAC-stamped, 2 min, single use)
                               ◄───────────────
measure app + device  ──┐
sign(nonce, report)     │
POST /api/v1/attest  ◄──┘  ────────────────────► verify nonce, signature, device key
                                                 (first time: Android key attestation)
                                                 evaluate rejection policy
                                                 look up device annotations
                               ◄───────────────  pass:   PinVault-Token (JWT, 5 min)
                                                         + signed pin config if changed
                                                 reject: result + ARC, no token
every request to a token host:  PinVault-Token: <jwt>  ───►  your API verifies HS256,
                                                              exp, aud, (anno), refuses the rest
re-attest at min(nextAttestIn, exp − 60 s), ≈ every 5 min while the app is alive
```

## 1. Roles and identifiers

| Term | Meaning |
|---|---|
| **Device id** | The `ANDROID_ID` the library already sends as `deviceUid` / `X-Device-Id` (iOS: `identifierForVendor`, lowercased). A claim, not a proof. |
| **Device key** | The EC P-256 identity key of the block (`ClientIdentityKeyProvider`, alias `pinvault_client_identity_ec_<label>`), generated in the Android Keystore with the existing attestation challenge `SHA-256("pinvault-identity-key:v1:<deviceId>")` (iOS: in the Secure Enclave, same alias as its tag, no attestation chain). The same key signs mTLS CSRs; a device that never enrolls for mTLS still has it. The key is what the server registers; the device id is what it indexes by. |
| **Report** | The JSON the library builds from its integrity probes (section 3). Sent as a **string** and signed as bytes, so there is no canonicalisation. |
| **Verdict** | `pass` or `reject`, with an **ARC** (attestation result code): 8 hex characters an operator can look up in the dashboard. Rejection reasons are revealed to the device only when the policy allows it. |
| **Token** | `PinVault-Token`: HS256 JWT, 5 minutes, bound to the device id and the Config API (`aud`). |
| **Policy** | Per Config API: for every flag the probes can raise, `reject`, `warn` or `ignore`. |
| **Annotations** | Per device: `forcePass`, `forceFail`, and free-form strings that travel in the token's `anno` claim (support cases, canary groups, "staff device"). |

## 2. Endpoints (device side, Config API listeners)

Both are public on the `isPublicEndpoint` allowlist, rate-limited per source
address, counted by the device refusal limiter, and capped at the 64 KB device
body limit.

### 2.1 `GET /api/v1/attest/challenge`

```json
{ "nonce": "AAABkp0…Zg", "expiresIn": 120, "serverTime": 1759660800000 }
```

The nonce is stateless: `base64url( ts(8 bytes) ‖ rand(16) ‖ HMAC-SHA256(nonceKey, ts‖rand)[0..16) )`.
The server verifies the MAC and the age (≤ 120 s) and keeps a bounded replay
cache of nonces it has accepted. `serverTime` lets the library notice a wildly
wrong device clock (it is informational; the library's trusted clock is not
moved by it).

### 2.2 `POST /api/v1/attest`

Request:

```json
{
  "v": 1,
  "nonce": "AAABkp0…Zg",
  "deviceId": "9774d56d682e549c",
  "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…",
  "attestationChain": ["MIIC…", "MIIB…"],
  "report": "{\"sdkVersion\":\"2.2.0\",…}",
  "signature": "MEUCIQ…",
  "currentConfigVersion": 7,
  "currentIssuedAt": 1759600000000,
  "hosts": ["api.example.com", "cdn.example.com"]
}
```

| Field | Rule |
|---|---|
| `v` | Protocol version, `1`. Anything else: `400 unsupported_version`. |
| `nonce` | From 2.1, unexpired, unused. |
| `deviceId` | `^[A-Za-z0-9._:-]{1,64}$`. |
| `publicKey` | Base64 DER SubjectPublicKeyInfo of the device key (EC P-256). |
| `attestationChain` | Base64 DER, leaf first. Required on **first** registration under `ATTESTATION_KEY_POLICY=enforce`; optional otherwise; ignored for a device already registered (a key cannot be re-attested). iOS sends none (the Secure Enclave has no such chain): it registers like an Android key without one — accepted under `warn` / `off`, `403 attestation_required` under `enforce` — and App Attest (§12) stands in for it in `key_unattested`. |
| `report` | The report JSON **as a string** (section 3). At most 16 KB. |
| `signature` | `SHA256withECDSA` (DER) over the UTF-8 bytes of `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>`. |
| `currentConfigVersion`, `currentIssuedAt` | What the device holds; the server embeds a fresh signed config when either differs from what it would serve. |
| `hosts` | Optional, the block's `wantPinsFor` — the same scoping the config GET applies. |

Server checks, in order (each refusal is counted by the refusal limiter):

1. `400 invalid_json` / `400 unsupported_version` / `400 report_too_large`.
2. Nonce: `400 nonce_invalid`, `400 nonce_expired`, `400 nonce_replayed`.
3. Signature over the canonical string with `publicKey`: `401 signature_invalid`.
4. Revoked device (`client_identities` / attested device marked revoked): `403 device_revoked`.
5. Device key:
   - Device known: `publicKey` must hash to the registered SPKI, else `403 key_mismatch` (an operator resets the device to let a new key in — a reinstall on the same phone generates a new key, so the dashboard shows these).
   - Device unknown: register. Under `ATTESTATION_KEY_POLICY=enforce` the chain must verify (Google hardware root, identity challenge, your package names and signer digests, verified boot) or `403 attestation_required` / `403 attestation_invalid` with the verifier's reason; under `warn` the verdict is recorded; under `off` nothing is checked (trust on first use).
6. Policy evaluation (section 4) → `pass` / `reject`, ARC, warnings.
7. Token issuance on pass; config embedding when the device is behind.

Response `200`:

```json
{
  "result": "pass",
  "arc": "7f3a9c1e",
  "warnings": ["software_key"],
  "rejectionReasons": ["rooted"],
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjYtMTAtMDUtMDEifQ…",
  "tokenExpiresAt": 1759661100000,
  "tokenTtlSeconds": 300,
  "nextAttestIn": 300,
  "configChanged": true,
  "config": { "payload": "…", "signature": "…", "signatures": [...], "signingKeys": {...} },
  "device": { "registered": true, "firstSeen": false,
              "keyAttestation": { "attested": true, "securityLevel": "StrongBox", "reason": "ok" } },
  "policyVersion": 3
}
```

- `rejectionReasons` is present only when the policy's `revealReasons` is on;
  the ARC is always present and resolvable in the dashboard.
- On `reject` there is **no** `token`. (Approov instead issues a token that
  fails verification so that app flows look identical; PinVault sends none and
  the interceptor sends no header, which a verifying backend refuses the same
  way. Apps that want identical traffic shapes can send a dummy header
  themselves.)
- `config` is the same envelope `GET /api/v1/certificate-config` serves,
  scoped by the device's host ACL, and goes through the library's normal
  verification and replay checks. A rejected device gets **no config**: it keeps
  whatever it has until it expires, exactly as if the Config API were
  unreachable.
- `nextAttestIn` is the policy's `attestIntervalSeconds` (default 300).

## 3. The report

Built by `DeviceIntegrityProbe` (library package `integrity`). Every probe is
best-effort: a probe that throws contributes `"error"` evidence, never a
crash, and never a false "clean".

```json
{
  "sdkVersion": "2.2.0",
  "reportTime": 1759660801234,
  "app": {
    "packageName": "com.example.app",
    "versionCode": 412, "versionName": "4.1.2",
    "signerSha256": ["3c:4f:…"],
    "installer": "com.android.vending",
    "debuggable": false
  },
  "device": {
    "manufacturer": "Google", "model": "Pixel 8", "brand": "google", "device": "shiba",
    "product": "shiba", "hardware": "shiba", "fingerprint": "google/shiba/…",
    "sdkInt": 35, "securityPatch": "2026-09-05",
    "verifiedBootState": "green",
    "keySecurityLevel": "strongbox",
    "keyAttested": true
  },
  "signals": {
    "rooted":            { "flag": false, "evidence": [] },
    "emulator":          { "flag": false, "evidence": [] },
    "debugger":          { "flag": false, "evidence": [] },
    "debuggable":        { "flag": false, "evidence": [] },
    "hooking_framework": { "flag": true,  "evidence": ["maps:frida-agent", "thread:gum-js-loop"] },
    "app_integrity":     { "flag": false, "evidence": [] },
    "cloner":            { "flag": false, "evidence": [] },
    "unknown_installer": { "flag": false, "evidence": [] },
    "adb_enabled":       { "flag": true,  "evidence": ["settings:adb_enabled"] },
    "software_key":      { "flag": false, "evidence": [] },
    "key_unattested":    { "flag": false, "evidence": [] },
    "old_patch_level":   { "flag": false, "evidence": [] }
  },
  "verdictProvider": { "name": "play-integrity", "token": "eyJ…" }
}
```

An iOS report (`pinvault-ios`) keeps the same shape and all twelve signal
keys, and adds what an iPhone has instead of Android's fields:

```json
{
  "app": { "packageName": "com.example.app", "bundleId": "com.example.app", "teamId": "ABCDE12345",
           "versionCode": 412, "versionName": "4.1.2", "signerSha256": [],
           "installer": "app-store", "debuggable": false },
  "device": { "platform": "ios", "osVersion": "26.5", "manufacturer": "Apple", "brand": "Apple",
              "model": "iPhone17,1", "device": "iPhone", "product": "iPhone17,1", "hardware": "iPhone17,1",
              "fingerprint": "iOS/26.5/23F79", "sdkInt": 26, "securityPatch": null, "verifiedBootState": null,
              "keySecurityLevel": "secure_enclave", "keyAttested": true },
  "signals": { "cloner": { "flag": false, "evidence": ["n/a:ios"] },
               "adb_enabled": { "flag": false, "evidence": ["n/a:ios"] }, "…": "…" },
  "verdictProvider": { "name": "app-attest", "token": "{\"provider\":\"app-attest\",…}" }
}
```

`device.platform: "ios"` switches the server's own signals to iOS rules
(below); a report without `platform` is an Android one, judged exactly as
before. The server stores the platform with the device (`platform`:
`ios`, or `android` for a report that names none) and the dashboard shows
it. `keySecurityLevel` may be `secure_enclave`: hardware, like `tee` and
`strongbox`.

The platform is the app's own claim, so the server holds a device to the
platform it is on record as: a key whose Android Key Attestation chain
verified is Android, a device with an App Attest key on record is iOS, and
otherwise the platform of its earlier verdicts stands. A report that claims
another platform is judged by the recorded one and raises `app_integrity`
(an Android device cannot call itself an iPhone to skip the signer, patch
or Play Integrity checks). An iOS device skips `play_integrity_missing` only
while App Attest is configured (`APP_ATTEST_APP_IDS`) to judge it instead.

What each probe looks at (Android, no root needed; iOS probes:
`pinvault-ios/PORTING.md` §4):

| Signal | Evidence sources |
|---|---|
| `rooted` | `su` in the usual paths; Magisk / KernelSU / APatch files (`/sbin/.magisk`, `/data/adb/magisk`, `/data/adb/ksu`, `/data/adb/ap`); `Build.TAGS` contains `test-keys`; `ro.debuggable=1`, `ro.secure=0`; a writable `/system`; root-manager packages installed (Magisk, SuperSU, KernelSU, Superuser); `which su`. |
| `emulator` | `Build.FINGERPRINT` starting with `generic`/`unknown`; `MODEL` containing `google_sdk`, `Emulator`, `Android SDK built for`; `MANUFACTURER` `Genymotion`; `HARDWARE` `goldfish`/`ranchu`/`vbox86`; `PRODUCT` `sdk_gphone*`/`vbox86p`; `ro.kernel.qemu=1`; `/dev/socket/qemud`, `/dev/qemu_pipe`. |
| `debugger` | `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, `TracerPid` ≠ 0 in `/proc/self/status`. |
| `debuggable` | `ApplicationInfo.FLAG_DEBUGGABLE`. |
| `hooking_framework` | `/proc/self/maps` entries for `frida`, `gadget`, `xposed`, `substrate`, `dobby`, `riru`, `lsposed`, `zygisk`; thread names `gmain`, `gum-js-loop`, `gdbus`, `pool-frida`; `System.getProperty("vxp")`; `de.robv.android.xposed.XposedBridge` loadable; a stack trace naming Xposed. |
| `app_integrity` | The app's signing certificate digests (`GET_SIGNING_CERTIFICATES`), compared **on the server** with `ATTESTATION_SIGNER_SHA256` / package with `ATTESTATION_PACKAGE_NAMES`; the client sets the flag itself only when the app gave it an expected digest and it differs. iOS: `app.bundleId` against `ATTESTATION_PACKAGE_NAMES` and `app.teamId` against `ATTESTATION_IOS_TEAM_IDS` (empty = not checked); the signer list is not used. |
| `cloner` | `applicationInfo.dataDir` not under `/data/user/<n>/<package>` or `/data/data/<package>`; `filesDir` naming another package; `nativeLibraryDir` outside the app's own directory. |
| `unknown_installer` | Installer package not in the allowed set (default: Play, Samsung, Huawei, Amazon stores); empty installer is `sideload`. |
| `adb_enabled` | `Settings.Global.ADB_ENABLED` / `DEVELOPMENT_SETTINGS_ENABLED`. |
| `software_key` | The device key's `KeySecurityLevel` is `software` or `unknown` (`tee`, `strongbox`, `secure_enclave` are hardware). On iOS the server reads it from the report whether or not App Attest verified: App Attest vouches for the app, not for the identity key. |
| `key_unattested` | The device key has no attestation chain (set by the server from its own records once the device is registered). iOS: no App Attest verdict verified for the device (§12) — without `APP_ATTEST_APP_IDS` every iPhone raises it. |
| `old_patch_level` | Set by the server from `device.securityPatch` and `ATTESTATION_MIN_PATCH_LEVEL`. iOS: from `device.osVersion` (dotted) and `ATTESTATION_MIN_IOS_VERSION`; not checked when that is empty (`ATTESTATION_MIN_PATCH_LEVEL` does not apply to an iPhone). |
| `play_integrity` | Set by the server (§11) when a `play-integrity` verdict the report carries does not verify or does not pass: wrong nonce, stale, another package, app not Play-recognized, device below `PLAY_INTEGRITY_DEVICE_LEVEL`. A failed verdict sticks to the device until a fresh pass. Only with the Play Console keys configured. |
| `play_integrity_missing` | Set by the server (§11) when no Play Integrity verdict was verified for the device within `PLAY_INTEGRITY_MAX_AGE_SECONDS`. Only with the Play Console keys configured; never for an iOS device. |
| `app_attest` | Set by the server (§12) when an `app-attest` attestation or assertion the report carries does not verify: another root, another challenge, another app or environment, a counter that did not rise, a key the server has no record of (then `app_attest_unknown_key` is added to `warnings`, whatever the policy does with the flag). A failed verdict sticks to the device until a fresh pass. Only with `APP_ATTEST_APP_IDS` configured. |
| `app_attest_missing` | Set by the server (§12) when an iOS device has no App Attest verdict verified within `APP_ATTEST_MAX_AGE_SECONDS` (a simulator, a device without App Attest). Only with `APP_ATTEST_APP_IDS` configured. |

On iOS the probes look for jailbreak files (Cydia, Sileo, Zebra, `/var/jb`,
apt, `sshd`, `bash`; the last two not on the simulator, which sees the Mac's
own) and a write outside the sandbox, the simulator, a tracing debugger
(`P_TRACED`), the `get-task-allow` entitlement, hooking libraries among the
loaded images, `DYLD_INSERT_LIBRARIES` and Frida's port, the bundle and team
id against the ones the app names, and where the app was installed from;
`key_unattested` and `old_patch_level` are sent down and decided by the
server (`pinvault-ios/PORTING.md` §4). All of these probes run on the device,
in the app, and can be defeated there — App Attest proves the app is genuine,
not that the device is not jailbroken — so an app whose value justifies it
should add a dedicated RASP product on top of them.

The report is a measurement by code the attacker can hook. That is true for
every RASP; what makes it useful is that (a) a hooked report still has to be
signed by a Keystore key whose attestation chain proves it was made by **your**
package on real hardware, (b) the server adds signals the client cannot
forge (attestation, patch level, key level), and (c) tampering with the
probes costs more than the generic unpinning scripts the pinning path already
defeats. Apps that want a second opinion plug a `verdictProvider`: the
library forwards its token verbatim. For Play Integrity the reference server
verifies the token itself (§11) and turns it into the `play_integrity` /
`play_integrity_missing` flags; any other provider's token is stored and
shown, not judged.

## 4. Policy

Stored per Config API (`attestation_policies`), edited in the dashboard or
with `PUT /api/v1/config-apis/{id}/attestation/policy`:

```json
{
  "version": 3,
  "flags": {
    "rooted": "reject", "emulator": "reject", "debugger": "reject", "debuggable": "reject",
    "hooking_framework": "reject", "app_integrity": "reject", "cloner": "reject",
    "unknown_installer": "warn", "adb_enabled": "ignore", "software_key": "warn",
    "key_unattested": "warn", "old_patch_level": "warn",
    "play_integrity": "warn", "play_integrity_missing": "warn",
    "app_attest": "warn", "app_attest_missing": "warn"
  },
  "revealReasons": false,
  "tokenTtlSeconds": 300,
  "attestIntervalSeconds": 300
}
```

Evaluation:

1. `forceFail` on the device → `reject`, reason `force_fail`.
2. `forcePass` on the device → `pass`, all flags demoted to warnings.
3. Otherwise every raised flag whose policy says `reject` is a rejection
   reason; `warn` flags are returned as `warnings`; `ignore` flags are dropped.
4. Server-side signals are merged before step 3: `app_integrity` from the
   signer/package check, `software_key` / `key_unattested` from the device
   record, `old_patch_level` from the report's patch level, `play_integrity`
   / `play_integrity_missing` from the Play Integrity verifier (§11; never
   raised without the Play Console keys), `app_attest` /
   `app_attest_missing` from the App Attest verifier (§12; never raised
   without `APP_ATTEST_APP_IDS`). An iOS report is held to the iOS rules of §3.
5. ARC = first 8 hex characters of `HMAC-SHA256(nonceKey, sorted reasons ‖ "|" ‖ sorted warnings)`;
   the dashboard resolves an ARC to its reasons from the device's last verdict.

Defaults: `ATTESTATION_POLICY_DEFAULT=strict` (the table above) or `lenient`
(everything `warn`; what a first rollout uses while the fleet is measured).
Changing a policy bumps `version`; tokens carry `pol` so a backend can
require a minimum policy version if it wants to.

## 5. The token

```
header  { "alg": "HS256", "typ": "JWT", "kid": "2026-10-05-01" }
payload { "iss": "pinvault", "sub": "<deviceId>", "aud": "<configApiId>",
          "iat": 1759660800, "exp": 1759661100, "jti": "…",
          "did": "<deviceId>", "arc": "7f3a9c1e", "pol": 3,
          "anno": ["staff", "canary"] }        // only when the device has annotations
```

- Secrets live in `attestation_token_secrets` (32 random bytes each,
  encrypted at rest with `VAULT_AT_REST_PASSWORD`), one **active** at a time,
  the previous ones kept for verification until an operator deletes them.
  `GET /api/v1/attestation/token-secrets` returns them (requester-run under
  two-person approval, like other secret reads); `POST …/rotate` makes a new
  active one. Backends load all listed secrets keyed by `kid`.
- A backend verifies: signature with the secret named by `kid`, `exp` (with ≤
  60 s leeway), `aud` is its Config API id, optionally `anno`. Nothing else is
  needed; there is no call back to the PinVault server on the request path.
- Reference verifier: `PinVaultTokenAuth` Ktor plugin (`plugin/PinVaultTokenAuth.kt`);
  the mock TLS/mTLS hosts install it when `MOCK_HOST_REQUIRE_TOKEN=true`.
  `SERVER_IMPLEMENTATION_GUIDE.md` has snippets for Node, Python and Java.

## 6. Admin API (management port; Config API ports when `CONFIG_API_ADMIN_ROUTES=on`)

| Method, path | Purpose |
|---|---|
| `GET /api/v1/config-apis/{id}/attestation/policy` | The policy (defaults when none stored). |
| `PUT /api/v1/config-apis/{id}/attestation/policy` | Replace it (gated: `attestation_policy`). |
| `GET /api/v1/config-apis/{id}/attestation/devices?result=&q=&page=&pageSize=` | Attested devices with last verdict, ARC, reasons, key level, annotations. |
| `GET /api/v1/config-apis/{id}/attestation/devices/{deviceId}` | One device, with its last report (trimmed to the signals and app/device blocks). |
| `PUT /api/v1/config-apis/{id}/attestation/devices/{deviceId}` | `{ "forcePass": bool, "forceFail": bool, "annotations": ["…"] }` (gated: `attestation_device`). |
| `DELETE /api/v1/config-apis/{id}/attestation/devices/{deviceId}` | Forget the device's key so it can register again (gated). |
| `GET /api/v1/config-apis/{id}/attestation/stats` | Counts for the last 24 h / 7 d: passes, rejects, by reason. |
| `GET /api/v1/attestation/token-secrets` | Active and previous secrets (requester-run gated). |
| `POST /api/v1/attestation/token-secrets/rotate` | New active secret (gated). |
| `DELETE /api/v1/attestation/token-secrets/{kid}` | Drop a previous secret (gated). |

Audit actions: `attestation_policy_updated`, `attestation_device_annotated`,
`attestation_device_forgotten`, `attestation_device_registered`,
`attestation_key_mismatch`, `attestation_rejected` (routine; not in `*`
webhooks), `attestation_token_secret_rotated`, `attestation_token_secret_deleted`.

## 7. Server settings

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTATION_ENABLED` | `true` | Serves `/api/v1/attest*`. |
| `ATTESTATION_KEY_POLICY` | `warn` (production profile: `enforce`) | What a first registration's Android key attestation must do. `enforce` needs `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256`. |
| `ATTESTATION_POLICY_DEFAULT` | `strict` | Policy for a Config API with none stored. |
| `ATTESTATION_TOKEN_TTL_SECONDS` | `300` | Token lifetime when a policy has none. |
| `ATTESTATION_INTERVAL_SECONDS` | `300` | `nextAttestIn` when a policy has none. |
| `ATTESTATION_NONCE_TTL_SECONDS` | `120` | |
| `ATTESTATION_RATE_LIMIT` | `60` | Attestations per source address per 10 minutes (`0` = off). |
| `ATTESTATION_DEVICE_RATE_LIMIT` | `30` | Per device id per 10 minutes. |
| `ATTESTATION_DEVICE_LIMIT` | `100000` | Most registered devices one Config API holds (`0` = unlimited). `POST /api/v1/attest` asks for no credential, so under `warn`/`off` invented device ids could otherwise grow the table without bound; past the cap a new device gets `503 device_limit_reached`, known devices keep attesting. |
| `ATTESTATION_REVEAL_REASONS` | `false` | Default for a policy's `revealReasons`. |
| `MOCK_HOST_REQUIRE_TOKEN` | `false` | The mock hosts refuse requests without a valid `PinVault-Token`. |
| `ATTESTATION_MIN_PATCH_LEVEL` | (existing) | Also feeds `old_patch_level`. |
| `PLAY_INTEGRITY_DECRYPTION_KEY` / `PLAY_INTEGRITY_VERIFICATION_KEY` | unset | §11. The Play Console response keys (Base64); both or neither. Set, the server verifies `play-integrity` verdicts and raises the two flags; unset, Play Integrity is off on the server. `PLAY_INTEGRITY_ENABLED=false` turns it off with the keys in place. |
| `PLAY_INTEGRITY_PACKAGE_NAMES` | `ATTESTATION_PACKAGE_NAMES` | Package names a verdict must name. Empty on both: any package (warned at start). |
| `PLAY_INTEGRITY_DEVICE_LEVEL` | `device` | `basic` / `device` / `strong`: the least `deviceRecognitionVerdict` that passes. |
| `PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED` | `true` | `appRecognitionVerdict` must be `PLAY_RECOGNIZED` (sideloaded and debug builds are not). |
| `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` | `600` | A token's `timestampMillis` may be at most this old (30–86400). |
| `PLAY_INTEGRITY_MAX_AGE_SECONDS` | `86400` | How long a verified verdict covers the device's later rounds before `play_integrity_missing` (60–2592000). |
| `ATTESTATION_MIN_IOS_VERSION` | unset | Dotted iOS version (`17.4`): an iOS report with an older (or no) `device.osVersion` raises `old_patch_level`. Unset: not checked. A malformed value is a start-up error. |
| `ATTESTATION_IOS_TEAM_IDS` | unset | Comma-separated 10-character Apple team ids: an iOS report whose `app.teamId` is not one raises `app_integrity`. Unset: not checked. The bundle id is checked against `ATTESTATION_PACKAGE_NAMES`. |
| `APP_ATTEST_APP_IDS` | unset | §12. Comma-separated `TEAMID.bundle.id`. Set, the server verifies `app-attest` verdicts (attestation rounds and enrollment) and raises the two flags; unset, App Attest is off on the server. |
| `APP_ATTEST_ROOT_CA_FILE` | unset | Path of Apple's App Attestation Root CA (PEM). Required with `APP_ATTEST_APP_IDS`: missing or unreadable, the server does not start. |
| `APP_ATTEST_ENVIRONMENT` | `production` | `production` / `development`: the aaguid an attestation must carry (the app's `appattest-environment` entitlement). |
| `APP_ATTEST_MAX_AGE_SECONDS` | `86400` | How long a verified App Attest verdict covers rounds without one before `app_attest_missing` (60–2592000). |

## 8. Library behaviour

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://config.example.com:8091/") {
        bootstrapPins(...)
        signaturePublicKey(...)
        attestation()                               // on; off by default
        attestationInterval(5, TimeUnit.MINUTES)    // default 5 min, min 1
        tokenHosts("api.example.com", "*.cdn.example.com")  // default: every pinned host of this block
    }
    .integrityVerdictProvider(PlayIntegrityVerdictProvider(context, cloudProjectNumber = 123456789012L))   // optional, §11
    .build()
```

- **Init**: after the stored config is loaded and the mTLS renewal check ran,
  each attesting block attests once. A `reject` does not fail `init` — the
  app decides what to do with `PinVault.attestationStatus()` — but no token is
  issued and no config update arrives through this channel.
- **Refresh**: a coroutine per block re-attests at `min(nextAttestIn, exp − 60 s)`
  while the process lives, with jitter; the periodic WorkManager job attests
  too, so a backgrounded app wakes with a fresh token. Failures back off
  (30 s → 5 min) and keep the last token until it expires.
- **Header**: every client the library builds or configures (`getClient()`,
  `getClient(settings)`, `applyTo`) carries an application interceptor that
  adds `PinVault-Token` to requests whose host matches a token host. If no
  valid token is held it attests synchronously once (bounded by the single
  flight), and sends the request without the header if that fails. A `401`
  whose body or `WWW-Authenticate` names `PinVault-Token` forces one
  re-attestation and one retry.
- **API**: `PinVault.attestNow(configApiId?)`, `PinVault.fetchAttestationToken(host)`
  (suspend and callback), `PinVault.attestationStatus(configApiId?)` →
  `AttestationStatus(result, arc, rejectionReasons, warnings, tokenExpiresAt, lastAttestedAt, lastError)`,
  and the event `PinVaultConnectionEvent.Attestation`.
- **Config piggyback**: a `config` in the response goes through the same
  verification, plausibility and replay checks as a fetched one
  (`SSLCertificateUpdater.applySigned`); a device that is rejected does not
  receive one.
- **Clock**: `serverTime` is compared with the device clock and surfaced as
  `clockSkewMs` in the status; the trusted clock is not touched by it.
- **Storage**: the token is held in memory only. The last status is kept in
  memory. Nothing new is written to disk.

## 9. What this does and does not give you

Gives: a verdict refreshed every five minutes by code that is harder to
bypass than the pinning path, pins withheld from rejected instances, a token
your API can require, device-level overrides, an audit trail, and a
measurement of the fleet (how many rooted, how many emulators, how many with
software keys) before you decide to enforce anything.

Does not give: Approov's closed-source SDK hardening (its probes are
obfuscated and self-checking; PinVault's are plain Kotlin — put the app
through R8 and, for high-value targets, a packer), Approov's managed
infrastructure and its continuously updated detections. A verdict that is
independent of the device is optional: §11 plugs Play Integrity in as the
verdict provider and verifies it on the server. The probes are a floor,
meant to be extended; the policy and token mechanics are the durable part.

## 10. Managed trust roots

A signed config may carry `trustRoots`: SHA-256 SPKI pins of root CAs. A
block with `managedTrustRoots()` accepts, for a host that has **no pin
entry**, a chain the platform's CAs validate **whose trust anchor's key is
one of `trustRoots`**, with the normal host-name check. Hosts with a pin
entry are unchanged. This is Approov's "managed trust roots": the device's
trust store (which a user or an attacker can add to) stops being the
authority; your signed root list is. The reference server edits the list on
each Config API's General tab and in the `PUT /api/v1/certificate-config`
body (`"trustRoots": ["…"]`, at most 64, no duplicates, each a valid pin): a
body that carries the field replaces the list (`[]` clears it), a body
without it keeps the scope's current list. The field is left out of the
payload when empty, so a client older than this section sees nothing new;
a change writes a `trust_roots_updated` history and audit entry.

## 11. Play Integrity (optional)

Google's verdict as a second opinion — the closest thing to Approov's
device-independent attestation on Android — switched on or off at three
places that do not depend on each other:

| Where | Switch | Off means |
|---|---|---|
| App | `.integrityVerdictProvider(PlayIntegrityVerdictProvider(context, cloudProjectNumber))` from the `io.github.umutcansu:pinvault-play-integrity` artifact | The report carries no `verdictProvider`; nothing of Play Services is in the APK. |
| Server | `PLAY_INTEGRITY_DECRYPTION_KEY` + `PLAY_INTEGRITY_VERIFICATION_KEY` (Play Console → App integrity → *Manage and download my response encryption keys*) | Tokens are stored with the device, never judged; `play_integrity*` is never raised. |
| Policy | `play_integrity` and `play_integrity_missing`, `reject` / `warn` / `ignore` (default `warn` in both profiles) | `ignore` records the verdict for the dashboard and changes no outcome. |

**Client.** On an attestation round the provider asks Google for a
**classic** integrity token with the round's attestation nonce as the
Play Integrity nonce (the reference server's nonces are base64url of 40
bytes, within Play Integrity's 16–500 byte URL-safe rule; a server of your
own must issue nonces of that shape) and the app's Cloud project number.
The token goes into the report as
`"verdictProvider": {"name": "play-integrity", "token": "<JWE>"}` and is
covered by the device key's signature over the report. Classic requests are
quota-limited (10 000 per app per day by default) while the library attests
every five minutes, so the provider asks at most once per `minInterval`
(default 6 hours; 0 = every round) and answers null in between — the
report then has no `verdictProvider`. `TOO_MANY_REQUESTS` waits a full
interval; a failure that will not change (no Play Store / Play Services,
invalid project number) turns the provider off for the process. A provider
failure never fails an attestation: the probe attests without it (10 s
budget), as for any provider.

**Server.** With the keys set, `POST /api/v1/attest` opens a
`play-integrity` token after the device key check and before the policy:
JWE `A256KW` + `A256GCM` under the decryption key (AAD = the protected
header), then JWS `ES256` under the verification key, then the verdict JSON.
Checks, each with a fixed reason stored in the device's `play_integrity`
summary: `malformed` / `unsupported_alg` / `decrypt_failed`,
`signature_invalid`, `payload_invalid`, `nonce_mismatch`
(`requestDetails.nonce` ≠ this round's nonce), `token_stale`
(`timestampMillis` older than `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` or
more than a minute in the future), `package_mismatch`
(`requestPackageName` / `appIntegrity.packageName` not in
`PLAY_INTEGRITY_PACKAGE_NAMES`, falling back to `ATTESTATION_PACKAGE_NAMES`),
`app_unrecognized` (`appRecognitionVerdict` ≠ `PLAY_RECOGNIZED`, unless
`PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED=false`), `device_integrity`
(`deviceRecognitionVerdict` below `PLAY_INTEGRITY_DEVICE_LEVEL`). Nothing is
sent to Google on the request path. The outcome is stored with the device
(`play_integrity_result` pass | fail, `play_integrity_at`, and a summary:
reason, device verdicts, app verdict, licensing, package, version; never
the token or the nonce — V23) and shown on the device page of the
dashboard.

Flags per round:

- token present → verified; `play_integrity` raised when it fails;
- no token, a stored verdict younger than `PLAY_INTEGRITY_MAX_AGE_SECONDS`
  → that verdict stands (`pass` raises nothing, `fail` raises
  `play_integrity`);
- no token and no fresh verdict → `play_integrity_missing`.

A device that sends a token minted for another round (a replay) fails
`nonce_mismatch`; a token made for another developer's keys fails
`decrypt_failed`; a hooked report cannot change what Google signed, and a
report that drops the token lands on `play_integrity_missing` once the
stored verdict ages out. What Play Integrity does not do is replace the
report: the two measure different things (Google: the device's integrity
and the app's provenance as Play sees them; the report: this process, now),
and the policy weighs both.

**Rollout.** Keep both flags on `warn` until the dashboard's stats show the
fleet attesting with Play Integrity; then `reject` on `play_integrity`
first, and on `play_integrity_missing` only once every supported app
version ships the provider — a build without it is `missing` for ever.
Emulators and debug builds fail `device_integrity` / `app_unrecognized` by
design; a lab server runs `PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED=false` and
`PLAY_INTEGRITY_DEVICE_LEVEL=basic`, or leaves the keys unset.

An iOS device never carries a Play Integrity verdict, so it never raises
`play_integrity_missing`; App Attest (§12) is its counterpart.

## 12. Apple App Attest (optional, iOS)

Apple's word that the request comes from **your unmodified app on a
genuine Apple device** — the iOS counterpart of §11 — verified on this
server, nothing sent to Apple. Three switches, independent of each other:

| Where | Switch | Off means |
|---|---|---|
| App | the iOS library's App Attest provider (`DCAppAttestService`; the App Attest capability, `appattest-environment` entitlement) | No `verdictProvider`; on the simulator `DCAppAttestService.isSupported` is false, so never. |
| Server | `APP_ATTEST_APP_IDS` + `APP_ATTEST_ROOT_CA_FILE` | Tokens are stored with the device, never judged; `app_attest*` is never raised; `key_unattested` stays raised on every iPhone. |
| Policy | `app_attest` and `app_attest_missing`, `reject` / `warn` / `ignore` (default `warn` in both profiles) | `ignore` records the verdict for the dashboard and changes no outcome. |

**Apple's root.** The server trusts one certificate for App Attest, Apple's
App Attestation Root CA. It is not bundled and the server never downloads
it: the operator does, once, from
<https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>
(Apple's PKI page, "Apple App Attestation Root CA"), stores it where the
server can read it (in `sample-host`: under `data/`, e.g.
`/data/apple-app-attestation-root.pem`) and sets `APP_ATTEST_ROOT_CA_FILE`.
With `APP_ATTEST_APP_IDS` set and the file missing, unreadable or without a
certificate, the server refuses to start and says so. At start it prints
the root's subject and SHA-256 fingerprint, to compare with Apple's page.

**Tokens.** `verdictProvider` is `{"name": "app-attest", "token": "<JSON
string>"}`; the token is
`{"provider":"app-attest","keyId":"<Base64>","attestation":"<Base64 CBOR>"}`
on a key's first round, `…"assertion":"<Base64 CBOR>"}` on later ones. The
client data hash of a round is
`SHA-256(UTF-8("pinvault-app-attest:v1:" + nonce + ":" + deviceId))`, so a
verdict is bound to the round's nonce and device id (and, like every
verdict, covered by the device key's signature over the report).

**Attestation** (a new key), checked as Apple's "Validating apps that
connect to your server" lays it out, each failure with a fixed reason in
the device's `app_attest` summary: CBOR `{fmt: "apple-appattest", attStmt:
{x5c, receipt}, authData}` (`malformed`, `unsupported_format`); `x5c`
(leaf, intermediate) chains to the root and is valid now (`chain_invalid`);
the leaf's extension 1.2.840.113635.100.8.2 holds
`SHA-256(authData ‖ clientDataHash)` (`nonce_mismatch`); the key id is
SHA-256 of the leaf's public key, the uncompressed point (`key_id_mismatch`);
authData's RP id hash is SHA-256 of one of `APP_ATTEST_APP_IDS`
(`app_id_mismatch`); its counter is 0 (`counter_not_zero`); its aaguid is
`appattestdevelop` (development) or `appattest` + seven zero bytes
(production), per `APP_ATTEST_ENVIRONMENT` (`environment_mismatch`); its
credential id is the key id (`credential_id_mismatch`). A pass stores the
key (key id, public key) with counter 0. The receipt is not used.

**Assertion** (later rounds): CBOR `{signature, authenticatorData}`; the
key id must be the one on record for the device, else
`app_attest_unknown_key` (forgotten, never attested, another install);
the ECDSA P-256 signature over `SHA-256(authenticatorData ‖
clientDataHash)` verifies with the stored key (`signature_invalid`); the
RP id hash names one of the apps (`app_id_mismatch`); the counter is
higher than the stored one (`counter_replay`: a cloned key, or two rounds
racing) — the new counter is stored. The outcome is kept with the device
(V24: `app_attest_result` pass | fail, `app_attest_at`, the key, its
counter and a summary — reason, attestation or assertion, app id,
environment; never the token or the nonce) and shown on the device page.

Flags per round (only with `APP_ATTEST_APP_IDS`):

- token present → verified; `app_attest` raised when it fails; a pass
  lifts `key_unattested` for the iOS device;
- an unknown key → `app_attest`, and `app_attest_unknown_key` in
  `warnings` whatever the policy says: the app drops its key and attests a
  new one next round (an operator forgetting the device has the same
  effect);
- no token, a stored verdict younger than `APP_ATTEST_MAX_AGE_SECONDS` →
  that verdict stands (`pass` raises nothing and keeps `key_unattested`
  lifted, `fail` raises `app_attest`);
- no token and no fresh verdict → `app_attest_missing` on an iOS device
  (never on an Android one).

**Enrollment.** With `INTEGRITY_VERIFICATION` on, an `integrityToken` that
is App Attest JSON with an `attestation` is verified here — a fresh key,
client data hash `SHA-256(UTF-8(integrityRequestHash))` (the 43-character
request hash of the CSR and device id) — with the same off / warn /
enforce rules; reasons are prefixed `app_attest_` (`app_attest_nonce_mismatch`
for a token made for another CSR). Any other token still goes to
`INTEGRITY_VERIFIER_COMMAND`. `enforce` starts with App Attest alone (an
iOS-only fleet needs no command), with a warning that Android tokens are
then not verified.

**Rollout.** As for §11: `warn` on both flags until the dashboard shows the
iOS fleet attesting, then `reject` on `app_attest`, and on
`app_attest_missing` only once every supported app version ships the
provider (simulators and older devices are `missing` for ever). A
development build attests with the development aaguid: a lab server runs
`APP_ATTEST_ENVIRONMENT=development`. `ATTESTATION_KEY_POLICY=enforce`
registers no iPhone (no Android chain); a mixed fleet runs `warn` and
rejects on `key_unattested` instead, which App Attest lifts.
