# PinVault Attestation — protocol and design

_Status: released in 2.3.0 (Android and iOS libraries, reference server, dashboard). This document is the contract between the Android library and any server that speaks it; the reference server implements it in full._

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
{ "nonce": "AAABkp0…Zg", "expiresIn": 120, "serverTime": 1759660800000, "verdictBinding": 2 }
```

`verdictBinding: 2` says the server takes v2 verdicts (App Attest bound to
the report, the token beside it — §12; Play Integrity bound to the device —
§11). The libraries send v2 only to a server that says so and v1 otherwise,
so an older server keeps receiving what it understands.

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
  "report": "{\"sdkVersion\":\"2.3.0\",…}",
  "signature": "MEUCIQ…",
  "currentConfigVersion": 7,
  "currentIssuedAt": 1759600000000,
  "hosts": ["api.example.com", "cdn.example.com"],
  "verdictProvider": { "name": "app-attest", "token": "{\"provider\":\"app-attest\",…}" }
}
```

| Field | Rule |
|---|---|
| `v` | Protocol version, `1`. Anything else: `400 unsupported_version`. |
| `nonce` | From 2.1, unexpired, unused. |
| `deviceId` | `^[A-Za-z0-9._:-]{1,64}$`. |
| `publicKey` | Base64 DER SubjectPublicKeyInfo of the device key (EC P-256). |
| `attestationChain` | Base64 DER, leaf first. Required on **first** registration under `ATTESTATION_KEY_POLICY=enforce`; optional otherwise; ignored for a device already registered (a key cannot be re-attested). iOS sends none (the Secure Enclave has no such chain): it registers like an Android key without one under `warn` / `off`, and App Attest (§12) stands in for it in `key_unattested`. Under `enforce` the first round's App Attest attestation registers it in place of the chain when `APP_ATTEST_APP_IDS` is configured (§12, "In place of the Android chain"); without it, `403 attestation_required`. |
| `report` | The report JSON **as a string** (section 3). At most 16 KB. |
| `signature` | `SHA256withECDSA` (DER) over the UTF-8 bytes of `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>`. |
| `currentConfigVersion`, `currentIssuedAt` | What the device holds; the server embeds a fresh signed config when either differs from what it would serve. The server also keeps the highest `currentIssuedAt` each device reported: a lower one from the same key raises `config_rollback` (§3). |
| `hosts` | Optional, the block's `wantPinsFor` — the same scoping the config GET applies. |
| `verdictProvider` | Optional, `{name, token}`: a **v2** verdict (§11, §12). A verdict bound to the report cannot sit inside it, so it travels beside it; the report then has no `verdictProvider`. A token here must be v2. Without it the report's own `verdictProvider` is read, as from older apps. |

Server checks, in order (each refusal is counted by the refusal limiter):

1. `400 invalid_json` / `400 unsupported_version` / `400 report_too_large`.
2. Nonce: `400 nonce_invalid`, `400 nonce_expired`, `400 nonce_replayed`.
3. Signature over the canonical string with `publicKey`: `401 signature_invalid`.
4. Revoked device (`client_identities` / attested device marked revoked): `403 device_revoked`.
5. Device key:
   - Device known: `publicKey` must hash to the registered SPKI, else `403 key_mismatch` (an operator resets the device to let a new key in — a reinstall on the same phone generates a new key, so the dashboard shows these).
   - Device unknown, Android report that claims `keyAttested: true` but sends no chain (a device forgotten while the app ran): `409 key_unknown`; the library sends the chain on its next round (not under `ATTESTATION_KEY_POLICY=off`).
   - Device unknown: register. Under `ATTESTATION_KEY_POLICY=enforce` the chain must verify (Google hardware root, identity challenge, your package names and signer digests, verified boot) or `403 attestation_required` / `403 attestation_invalid` with the verifier's reason; without a chain, and with `APP_ATTEST_APP_IDS` configured, the report's `app-attest` attestation for this round is verified first and registers an iPhone in its place (§12); under `warn` the verdict is recorded; under `off` nothing is checked (trust on first use).
6. Policy evaluation (section 4) → `pass` / `reject`, ARC, warnings —
   with the server's own signals from the device's record (§3, "What the
   server keeps").
7. Token issuance on pass (its `cnf` names the device key and, over mTLS,
   the client certificate, §5); config embedding when the device is behind.

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
  "sdkVersion": "2.3.0",
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
| `key_unattested` | The device key has no passing attestation chain (set by the server from its own records once the device is registered: no chain, a software-level one, one refused under `warn`). iOS: no App Attest verdict verified for the device (§12) — without `APP_ATTEST_APP_IDS` every iPhone raises it. |
| `old_patch_level` | Set by the server from the **attested** `osPatchLevel` of the registration's hardware chain when there is one, else from `device.securityPatch`, against `ATTESTATION_MIN_PATCH_LEVEL`. iOS: from `device.osVersion` (dotted) and `ATTESTATION_MIN_IOS_VERSION`; not checked when that is empty (`ATTESTATION_MIN_PATCH_LEVEL` does not apply to an iPhone). |
| `play_integrity` | Set by the server (§11) when a `play-integrity` verdict the report carries does not verify or does not pass: wrong nonce, stale, another package, app not Play-recognized, device below `PLAY_INTEGRITY_DEVICE_LEVEL`. A failed verdict sticks to the device until a fresh pass. Only with the Play Console keys configured. |
| `play_integrity_missing` | Set by the server (§11) when no Play Integrity verdict was verified for the device within `PLAY_INTEGRITY_MAX_AGE_SECONDS`. Only with the Play Console keys configured; never for an iOS device. |
| `app_attest` | Set by the server (§12) when an `app-attest` attestation or assertion the report carries does not verify: another root, another challenge, another app or environment, a counter that did not rise, a key the server has no record of (then `app_attest_unknown_key` is added to `warnings`, whatever the policy does with the flag). A failed verdict sticks to the device until a fresh pass. Only with `APP_ATTEST_APP_IDS` configured. |
| `app_attest_missing` | Set by the server (§12) when an iOS device has no App Attest verdict verified within `APP_ATTEST_MAX_AGE_SECONDS` (a simulator, a device without App Attest). A device with an App Attest key on record can assert every round, so for it a round without a token rides on the last verdict for 10 minutes only. Only with `APP_ATTEST_APP_IDS` configured. |
| `bootloader_unlocked` | Set by the server on every round when the registration's hardware chain said the bootloader is unlocked (RootOfTrust `deviceLocked` = false). See "What the server keeps" below. |
| `boot_not_verified` | Set by the server on every round when that chain said the boot was not `Verified` — `SelfSigned` with a `verifiedBootKey` in `ATTESTATION_TRUSTED_BOOT_KEYS` counts as verified (GrapheneOS, CalyxOS). |
| `key_revoked` | Set by the server when a certificate of the registration's chain is on the attestation revocation list (`ATTESTATION_REVOKED_SERIALS_FILE`) — at registration, or since: the serials are looked up again on every round. |
| `report_mismatch` | Set by the server when the report contradicts the device's record: `verifiedBootState` `green` while the chain said unlocked or not verified; a `securityPatch` more than a month older than the attested one. (A chain-less registration that claims `keyAttested: true` is answered `409 key_unknown` instead, §2.2.) |
| `config_rollback` | Set by the server when the device reports a lower `currentIssuedAt` than it reported before under the same signing-key set (restored storage, a clock set back). |

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
every RASP; what makes it useful is that (a) on Android, a hooked report
still has to be signed by a Keystore key whose attestation chain (sent at
registration, under `ATTESTATION_KEY_POLICY=enforce` required) proves it was
made by **your** package on real hardware — on iOS the identity key has no
such chain: what ties a report to the genuine app there is a v2 App Attest
verdict made over that very report (§12); (b) the server adds signals the
client cannot forge (the hardware's RootOfTrust and patch level, revocation,
key level, config watermarks; below); and (c) tampering with the probes
costs more than the generic unpinning scripts the pinning path already
defeats. Code running inside the genuine app on a rooted or jailbroken phone
can still sign whatever report it likes with the device's own key: what it
cannot change is what the hardware said at registration. Apps that want a second opinion plug a `verdictProvider`: the
library forwards its token verbatim. For Play Integrity the reference server
verifies the token itself (§11) and turns it into the `play_integrity` /
`play_integrity_missing` flags; any other provider's token is stored and
shown, not judged.

### What the server keeps (facts from the chain, config watermarks)

The chain is sent once — on the first round of every process until the
device is registered — and a key cannot be re-attested. What a chain says
about the **device** holds for the key's lifetime (unlocking or relocking
a bootloader wipes the Keystore), so the server keeps it and judges every
later round against it (V26 `key_facts`):

- **When**: only from a chain that verifies link by link up to a trusted
  root (Google's hardware roots) **and** whose attestation and KeyMint
  security levels are TEE or StrongBox. Kept under `warn` too, and when a
  later check refused the key (another package, another device id's
  challenge, an unlocked bootloader under `ATTESTATION_REQUIRE_VERIFIED_BOOT`,
  a patch below `ATTESTATION_MIN_PATCH_LEVEL`). A software-level chain — an
  emulator's — keeps nothing: it says nothing about any device, so the
  emulator baseline raises none of the flags below.
- **What**: RootOfTrust (`deviceLocked`, `verifiedBootState`,
  `verifiedBootKey`), `osVersion`, `osPatchLevel`, `vendorPatchLevel`,
  `bootPatchLevel`, and the serial of every certificate in the chain. The
  dashboard shows the first three on the device page; the admin API returns
  them as `keyFacts`.
- **Flags**: `bootloader_unlocked`, `boot_not_verified`, `key_revoked` and
  `report_mismatch` (table above); `old_patch_level` reads the attested
  patch. A stock, locked phone raises none of them, so `strict` rejects all
  of them. Root hidden from the client probes does not change them: the
  hardware said it at registration.
- **Revocation after the fact**: the chain's serials are looked up in the
  revocation list as it is on every round, so a keybox Google revokes after
  a device registered with it raises `key_revoked` from the next round on.
  Without `ATTESTATION_REVOKED_SERIALS_FILE` there is nothing to look up.
- **Patch level**: the attested `osPatchLevel` is the level when the key was
  made. A device that has been updated since still shows the older level
  until it registers a new key (an operator forgetting the device, or a
  reinstall). `ATTESTATION_MIN_PATCH_LEVEL` is off by default and
  `old_patch_level` is `warn` in `strict`; raising the minimum flags such
  devices until they re-register. A report that claims a patch more than a
  month OLDER than the attested one is `report_mismatch` (patch levels only
  rise). The libraries do not yet re-attest periodically with a fresh key;
  when they do, the server refreshes the facts at that point.
- **Config watermark**: the highest `currentIssuedAt` a device reported is
  kept with the server's signing-key set version (V26
  `config_watermark`). The library's value never goes down — a health-check
  rollback and `PinVault.reset()` keep it — except when a newer signing-key
  set resets its watermarks; the server's set version then differs from the
  stored one and the comparison starts again. 0 or absent (no config held)
  is not compared; a value more than an hour ahead of the server's clock is
  not stored. A lower report raises `config_rollback`. False positive: a
  device whose watermark reset for another reason with the same set — a
  changed compiled-in signing key or threshold in an app update — reports
  lower until it fetched a config newer than the old watermark (minutes on a
  live fleet, since every config the server signs carries the time it was
  signed). The flag catches a restored backup reported by the genuine
  library; code that controls the app can report any value.

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
    "app_attest": "warn", "app_attest_missing": "warn",
    "bootloader_unlocked": "reject", "boot_not_verified": "reject", "key_revoked": "reject",
    "report_mismatch": "reject", "config_rollback": "reject"
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
   without `APP_ATTEST_APP_IDS`), `bootloader_unlocked`,
   `boot_not_verified`, `key_revoked` and `report_mismatch` from the
   device's facts, `config_rollback` from its watermark (§3, "What the
   server keeps"). An iOS report is held to the iOS rules of §3.
5. ARC = first 8 hex characters of `HMAC-SHA256(nonceKey, sorted reasons ‖ "|" ‖ sorted warnings)`;
   the dashboard resolves an ARC to its reasons from the device's last verdict.

Defaults: `ATTESTATION_POLICY_DEFAULT=strict` (the table above) or `lenient`
(everything `warn`; what a first rollout uses while the fleet is measured).
A policy stored before a flag existed gets the default profile's action for
it: after an upgrade a stored policy rejects the five record-based flags
under a `strict` default.
Changing a policy bumps `version`; tokens carry `pol` so a backend can
require a minimum policy version if it wants to.

## 5. The token

```
header  { "alg": "HS256", "typ": "JWT", "kid": "2026-10-05-01" }
payload { "iss": "pinvault", "sub": "<deviceId>", "aud": "<configApiId>",
          "iat": 1759660800, "exp": 1759661100, "jti": "…",
          "did": "<deviceId>", "arc": "7f3a9c1e", "pol": 3,
          "anno": ["staff", "canary"],         // only when the device has annotations
          "cnf": { "jkt": "<thumbprint>",       // the device key that signed the report
                   "x5t#S256": "<thumbprint>" } } // only when the attestation came over mTLS
```

- `cnf` (RFC 7800) says what the token was issued to: `jkt` is the RFC 7638
  JWK SHA-256 thumbprint of the device key (EC P-256, base64url, what a
  DPoP library computes), `x5t#S256` the base64url SHA-256 of the DER of the
  client certificate the `POST /api/v1/attest` connection presented
  (RFC 8705). Tokens from a server before `cnf` have no such claim and
  still verify everywhere unless the backend requires the binding.
- Secrets live in `attestation_token_secrets` (32 random bytes each,
  encrypted at rest with `VAULT_AT_REST_PASSWORD`), one **active** at a time,
  the previous ones kept for verification until an operator deletes them.
  `GET /api/v1/attestation/token-secrets` returns them (requester-run under
  two-person approval, like other secret reads); `POST …/rotate` makes a new
  active one. Backends load all listed secrets keyed by `kid`.
- A backend verifies: signature with the secret named by `kid`, `iss` is
  `pinvault`, `exp` (with ≤ 60 s leeway), `aud` is its Config API id,
  optionally `anno`. Nothing else is
  needed; there is no call back to the PinVault server on the request path.
- A request that names its device (`X-Device-Id`) must name the token's
  `did` (`401` reason `device_mismatch`). Behind mTLS with the identity the
  app attested with, a backend can require the binding
  (`PINVAULT_TOKEN_REQUIRE_CERT_BINDING=true` for the reference verifier):
  the request's client certificate must be the one `cnf.x5t#S256` names, and
  a token without that claim is refused (`401` reason `cert_binding`).
- **What a rooted or jailbroken device can do with tokens.** The token is a
  bearer credential for its lifetime (5 minutes by default). Code running
  inside the genuine app on such a phone can sign reports with the device's
  own key, so it can obtain passing tokens as long as the policy passes the
  device — and a hidden root that the client probes miss passes unless the
  server's own signals (`bootloader_unlocked`, `boot_not_verified`,
  `key_revoked`, `report_mismatch`, Play Integrity at `strong`, App Attest)
  reject it. What binding changes: with the certificate binding a token
  lifted off the phone is useless elsewhere, because the request must also
  prove the device's non-exportable private key in the TLS handshake; the
  `did` check stops one device's token from being presented for another.
  What binding does not change: the phone itself, with root, can still use
  its own tokens (and its own key) for every request it makes, and act as a
  proxy for others. Bound tokens limit how far a compromised device reaches,
  not whether a compromised device that passes the policy gets in. `cnf.jkt`
  is there for a backend that adds per-request proof of possession of the
  device key (DPoP style); the libraries do not send such a proof yet.
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
| `ATTESTATION_KEY_POLICY` | `warn` (production profile: `enforce`) | What a first registration's Android key attestation must do. `enforce` needs `ATTESTATION_PACKAGE_NAMES` and `ATTESTATION_SIGNER_SHA256`, or `APP_ATTEST_APP_IDS` for an iOS-only fleet (Android devices are then refused); an iPhone gets in under it only by App Attest (§12). |
| `ATTESTATION_POLICY_DEFAULT` | `strict` (production profile: `strict`, fixed) | Policy for a Config API with none stored. |
| `ATTESTATION_TOKEN_TTL_SECONDS` | `300` | Token lifetime when a policy has none. |
| `ATTESTATION_INTERVAL_SECONDS` | `300` | `nextAttestIn` when a policy has none. |
| `ATTESTATION_NONCE_TTL_SECONDS` | `120` | |
| `ATTESTATION_RATE_LIMIT` | `60` | Attestations per source address per 10 minutes (`0` = off). |
| `ATTESTATION_DEVICE_RATE_LIMIT` | `30` | Per device id per 10 minutes. |
| `ATTESTATION_DEVICE_LIMIT` | `100000` | Most registered devices one Config API holds (`0` = unlimited). `POST /api/v1/attest` asks for no credential, so under `warn`/`off` invented device ids could otherwise grow the table without bound; past the cap a new device gets `503 device_limit_reached`, known devices keep attesting. |
| `ATTESTATION_REVEAL_REASONS` | `false` | Default for a policy's `revealReasons`. |
| `MOCK_HOST_REQUIRE_TOKEN` | `false` | The mock hosts refuse requests without a valid `PinVault-Token`. |
| `PINVAULT_TOKEN_REQUIRE_CERT_BINDING` | `false` | With `MOCK_HOST_REQUIRE_TOKEN`: the mock hosts accept a token only over mTLS with the client certificate its `cnf.x5t#S256` names (§5). A plain-TLS mock host then refuses every request. Your own backend sets the same option on `PinVaultTokenAuth` (`requireCertBinding`). |
| `ATTESTATION_TRUSTED_BOOT_KEYS` | unset | Comma-separated `verifiedBootKey` digests (64 hex characters; colons and case ignored) of operating systems you accept with a `SelfSigned` boot on a locked bootloader (GrapheneOS and CalyxOS publish theirs per device). Such a boot counts as verified for `ATTESTATION_REQUIRE_VERIFIED_BOOT` and does not raise `boot_not_verified`. A malformed value is a start-up error. |
| `ATTESTATION_MIN_PATCH_LEVEL` | (existing) | Also feeds `old_patch_level`. |
| `PLAY_INTEGRITY_DECRYPTION_KEY` / `PLAY_INTEGRITY_VERIFICATION_KEY` | unset | §11. The Play Console response keys (Base64); both or neither. Set, the server verifies `play-integrity` verdicts and raises the two flags; unset, Play Integrity is off on the server. `PLAY_INTEGRITY_ENABLED=false` turns it off with the keys in place. |
| `PLAY_INTEGRITY_PACKAGE_NAMES` | `ATTESTATION_PACKAGE_NAMES` | Package names a verdict must name. Empty on both: any package (warned at start). |
| `PLAY_INTEGRITY_DEVICE_LEVEL` | `device` | `basic` / `device` / `strong`: the least `deviceRecognitionVerdict` that passes. |
| `PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED` | `true` | `appRecognitionVerdict` must be `PLAY_RECOGNIZED` (sideloaded and debug builds are not). |
| `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` | `600` | A token's `timestampMillis` may be at most this old (30–86400). |
| `PLAY_INTEGRITY_MAX_AGE_SECONDS` | `86400` | How long a verified verdict counts (60–2592000): a failed one keeps `play_integrity` raised this long; after it, `play_integrity_missing`. |
| `PLAY_INTEGRITY_STALE_PASS_SECONDS` | `PLAY_INTEGRITY_MAX_AGE_SECONDS` | How long a stored **pass** covers rounds that carry no token (60–2592000). The provider asks Google every few hours (default 6 h) and a hooked app can drop the token; set it a little above the app's `minInterval` (e.g. `25200` for 6 h) so a dropped token turns into `play_integrity_missing` within hours, not a day. |
| `PLAY_INTEGRITY_REQUIRE_V2` | `false` (production profile: `true`) | Refuse a token asked with the round's bare nonce (v1) — `play_integrity` with reason `nonce_v1`; v2 binds it to the device id too (§11). Off, v1 passes with the warning `play_integrity_v1`. |
| `PLAY_INTEGRITY_REQUIRE_LICENSED` | `false` | `accountDetails.appLicensingVerdict` must be `LICENSED` (the user got the app from Play), else `play_integrity` with reason `app_unlicensed`. For apps sold or distributed only through Play. |
| `ATTESTATION_MIN_IOS_VERSION` | unset | Dotted iOS version (`17.4`): an iOS report with an older (or no) `device.osVersion` raises `old_patch_level`. Unset: not checked. A malformed value is a start-up error. |
| `ATTESTATION_IOS_TEAM_IDS` | unset | Comma-separated 10-character Apple team ids: an iOS report whose `app.teamId` is not one raises `app_integrity`. Unset: not checked. The bundle id is checked against `ATTESTATION_PACKAGE_NAMES`. |
| `APP_ATTEST_APP_IDS` | unset | §12. Comma-separated `TEAMID.bundle.id`. Set, the server verifies `app-attest` verdicts (attestation rounds and enrollment), raises the two flags, and takes an iPhone's App Attest attestation in place of the Android chain under `ENROLLMENT_ATTESTATION`, `USER_AUTH_ATTESTATION` and `ATTESTATION_KEY_POLICY`; unset, App Attest is off on the server and those three refuse every iPhone under `enforce` (warned at start). |
| `APP_ATTEST_ROOT_CA_FILE` | unset | Path of Apple's App Attestation Root CA (PEM). Required with `APP_ATTEST_APP_IDS`: missing or unreadable, the server does not start. |
| `APP_ATTEST_ENVIRONMENT` | `production` | `production` / `development`: the aaguid an attestation must carry (the app's `appattest-environment` entitlement). |
| `APP_ATTEST_MAX_AGE_SECONDS` | `86400` | How long a stored App Attest verdict covers rounds without one before `app_attest_missing` (60–2592000); a stored pass of a device whose key is on record covers 10 minutes at most. |
| `APP_ATTEST_REQUIRE_V2` | `false` (production profile: `true`) | Refuse an attestation round's verdict made with the v1 client data hash (nonce and device id only, not the report) — `app_attest` with reason `client_data_v1`, and `attestation_invalid` / `app_attest_client_data_v1` where it stands in for the chain. Off, v1 passes with the warning `app_attest_v1` (§12). |

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
**classic** integrity token with the app's Cloud project number and, as
the Play Integrity nonce (v2),
`base64url-nopad(SHA-256(UTF-8("pinvault-play-integrity:v2:" + nonce + ":" + deviceId)))`
— 43 characters, within Play Integrity's 16–500 URL-safe rule — so a token
is bound to this round **and** this device id. An older provider used the
round's nonce itself (v1: the reference server's nonces are base64url of
40 bytes); the server still accepts it with the warning `play_integrity_v1`
unless `PLAY_INTEGRITY_REQUIRE_V2=true`. The token goes into the report as
`"verdictProvider": {"name": "play-integrity", "token": "<JWE>"}` and is
covered by the device key's signature over the report; the request's own
`verdictProvider` (§2.2) is accepted too, for a v2 token only. Classic requests are
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
(`requestDetails.nonce` is neither this round's v2 nonce nor — for a token
in the report — its v1 nonce), `nonce_v1` (a v1 token under
`PLAY_INTEGRITY_REQUIRE_V2`, or beside the report), `token_stale`
(`timestampMillis` older than `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` or
more than a minute in the future), `package_mismatch`
(`requestPackageName` / `appIntegrity.packageName` not in
`PLAY_INTEGRITY_PACKAGE_NAMES`, falling back to `ATTESTATION_PACKAGE_NAMES`),
`app_unrecognized` (`appRecognitionVerdict` ≠ `PLAY_RECOGNIZED`, unless
`PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED=false`), `app_unlicensed`
(`appLicensingVerdict` ≠ `LICENSED` while `PLAY_INTEGRITY_REQUIRE_LICENSED=true`),
`device_integrity` (`deviceRecognitionVerdict` below
`PLAY_INTEGRITY_DEVICE_LEVEL`). Nothing is
sent to Google on the request path. The outcome is stored with the device
(`play_integrity_result` pass | fail, `play_integrity_at`, and a summary:
reason, device verdicts, app verdict, licensing, package, version; never
the token or the nonce — V23) and shown on the device page of the
dashboard.

Flags per round:

- token present → verified; `play_integrity` raised when it fails;
  `play_integrity_v1` in `warnings` when a v1 token passed;
- no token, a stored pass younger than `PLAY_INTEGRITY_STALE_PASS_SECONDS`
  → it stands (nothing raised);
- no token, a stored fail younger than `PLAY_INTEGRITY_MAX_AGE_SECONDS` →
  `play_integrity`;
- otherwise → `play_integrity_missing`.

A device that sends a token minted for another round (a replay), or with
the v2 nonce for another device id, fails `nonce_mismatch`; a token made for another developer's keys fails
`decrypt_failed`; a hooked report cannot change what Google signed, and a
report that drops the token lands on `play_integrity_missing` once the
stored pass is older than `PLAY_INTEGRITY_STALE_PASS_SECONDS` (default 24 h:
shorten it for a fleet that should not ride on a day-old pass). What Play Integrity does not do is replace the
report: the two measure different things (Google: the device's integrity
and the app's provenance as Play sees them; the report: this process, now),
and the policy weighs both.

**Rollout.** Keep both flags on `warn` until the dashboard's stats show the
fleet attesting with Play Integrity; then `reject` on `play_integrity`
first, and on `play_integrity_missing` only once every supported app
version ships the provider — a build without it is `missing` for ever.
High-value apps use `PLAY_INTEGRITY_DEVICE_LEVEL=strong` (hardware-backed,
a recent patch) and, when sold or distributed only through Play,
`PLAY_INTEGRITY_REQUIRE_LICENSED=true`; once every app version sends the v2
nonce, `PLAY_INTEGRITY_REQUIRE_V2=true`.
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
client data hash of a round, v2, is

```
SHA-256(UTF-8("pinvault-app-attest:v2:" + canonical))
canonical = "pinvault-attest:v1:" + nonce + ":" + deviceId + ":" + sha256-hex(report)
```

— `canonical` is exactly the string the identity key signs (§2.2), so
Apple's verdict is bound to the round's nonce, the device id **and the
report**. A verdict over the report cannot be inside it: the report carries
no `verdictProvider` and the token travels in the request's own
`verdictProvider` (§2.2). Older apps put the token in the report with the v1
hash `SHA-256(UTF-8("pinvault-app-attest:v1:" + nonce + ":" + deviceId))`,
bound to the round but not to the report; the server tries v2 first, then
(for a token in the report only) v1, which passes with the warning
`app_attest_v1` unless `APP_ATTEST_REQUIRE_V2=true` (`app_attest`, reason
`client_data_v1`). A token beside the report must be v2.

What v2 adds: the report and Apple's verdict now come from the same place.
On iOS the identity key has no attestation chain, so before v2 a program
outside the app that could use that key could sign a report of its own
and pair it with a genuine verdict the app had made for the round. With v2 the
verdict covers one report only. It does not stop code running **inside**
the genuine app, which asks App Attest over whatever report it built.

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
  lifts `key_unattested` for the iOS device; `app_attest_v1` in `warnings`
  when it passed with the v1 hash;
- an unknown key → `app_attest`, and `app_attest_unknown_key` in
  `warnings` whatever the policy says: the app drops its key and attests a
  new one next round (an operator forgetting the device has the same
  effect);
- no token, a stored verdict younger than `APP_ATTEST_MAX_AGE_SECONDS` →
  that verdict stands (`pass` raises nothing and keeps `key_unattested`
  lifted, `fail` raises `app_attest`); a stored `pass` of a device with its
  App Attest key on record stands for 10 minutes only (it can assert every
  round), so dropping the token does not borrow an older pass;
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

**In place of the Android chain.** Three settings ask for an Android Key
Attestation chain, and the production profile puts all three on `enforce`.
An iPhone has no such chain. With `APP_ATTEST_APP_IDS` configured, an App
Attest attestation of a **fresh** key stands in for it in each place; its
client data hash binds it to what that place registers, so one made for a
place does not pass another, and a device admitted in one place is not
admitted in the others (each needs its own):

| Where | iOS sends | Client data hash | Recorded as |
|---|---|---|---|
| Enrollment, `ENROLLMENT_ATTESTATION=warn\|enforce` (every CSR path) | body field `appAttestation`, no `attestationChain` | `SHA-256(UTF-8(integrityRequestHash))` — the 43-character hash of the CSR and the device id that is stored (`deviceUid`, else `deviceId`) | identity attestation `attested`, reason `app_attest`; the device id counts as proven, as with a passing chain |
| Screen-lock key, `USER_AUTH_ATTESTATION` (`purpose: user_auth`, first key and replacement) | body field `appAttestation`, no `attestationChain` | `SHA-256(UTF-8("pinvault-user-auth-key:v1:" + deviceId + ":" + Base64(SHA-256(SPKI DER of the key))))` | `attested`, `keyKind: app_attest` |
| Attestation registration, `ATTESTATION_KEY_POLICY=enforce` (unknown device, no chain) | the first round's `verdictProvider` `app-attest` with an `attestation` (beside the report for v2) | the round's: v2 `SHA-256(UTF-8("pinvault-app-attest:v2:" + canonical))`, or v1 `SHA-256(UTF-8("pinvault-app-attest:v1:" + nonce + ":" + deviceId))` unless `APP_ATTEST_REQUIRE_V2` | device key `attested`, reason `app_attest`; its App Attest key on record (counter 0), the device held to platform `ios` |

`appAttestation` is a JSON **string**, the token of PORTING.md §6
(`{"provider":"app-attest","keyId":"<Base64>","attestation":"<Base64 CBOR>"}`),
like `integrityToken`. The attestation is checked as above (Apple's root,
the nonce, the key id, `APP_ATTEST_APP_IDS`, counter 0, the environment's
aaguid). A failure is refused as a failing chain is, with the reason
prefixed `app_attest_` (`attestation_invalid`, e.g. `app_attest_nonce_mismatch`;
`app_attest_attestation_required` for an assertion) and recorded under
`warn`. At registration an assertion means the device was forgotten while
the app kept its key: `403 attestation_required` with reason
`app_attest_unknown_key`, and the app attests a new key. Every other rule
stays: a request with a chain is judged by the chain; replacing a
screen-lock key still needs the device's credential as well; revocation,
rate limits and limits are unchanged; Android devices still need their
chain. Without `APP_ATTEST_APP_IDS` the field is not read and every iPhone
is refused under `enforce`, as before; the server warns at start when one
of the three is on `enforce` and App Attest is not configured. An iOS-only
fleet can run the three on `enforce` with `APP_ATTEST_APP_IDS` alone
(without `ATTESTATION_PACKAGE_NAMES` / `ATTESTATION_SIGNER_SHA256`): the
server starts, warns that Android devices are refused, and refuses every
Android chain, since none can be bound to your app.

What it proves, and what it does not. App Attest proves the request came
from **your genuine app on genuine Apple hardware**. It does **not** prove
that the device is not jailbroken (Apple's attestation works on a
jailbroken phone, and a hooked genuine app can still ask for one over any
data it likes, another device id included), and it does **not** say where
the identity key or the RSA screen-lock key lives or how it is protected:
the server cannot read the key's access control, so
`USER_AUTH_REQUIRE_PER_USE` takes the library's per-use key on Apple's word
that the genuine app made the request. The dashboard shows such keys and
identities as "Apple-attested", never as "hardware-attested". For
high-value apps add a RASP product (jailbreak, hooking and tamper
detection) through `environmentGuard` and `integrityTokenProvider`.

**Rollout.** As for §11: `warn` on both flags until the dashboard shows the
iOS fleet attesting, then `reject` on `app_attest`, and on
`app_attest_missing` only once every supported app version ships the
provider (simulators and older devices are `missing` for ever). Once no
supported app version sends v1 (the dashboard counts `app_attest_v1`
warnings), set `APP_ATTEST_REQUIRE_V2=true`; the production profile of
`sample-host` sets it. A
development build attests with the development aaguid: a lab server runs
`APP_ATTEST_ENVIRONMENT=development`. Before switching an iOS fleet to
`enforce`, set `APP_ATTEST_APP_IDS` and `APP_ATTEST_ROOT_CA_FILE`: without
them `enforce` registers no iPhone. Simulators have no App Attest and are
refused under `enforce`.
