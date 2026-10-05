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
| **Device id** | The `ANDROID_ID` the library already sends as `deviceUid` / `X-Device-Id`. A claim, not a proof. |
| **Device key** | The EC P-256 identity key of the block (`ClientIdentityKeyProvider`, alias `pinvault_client_identity_ec_<label>`), generated in the Android Keystore with the existing attestation challenge `SHA-256("pinvault-identity-key:v1:<deviceId>")`. The same key signs mTLS CSRs; a device that never enrolls for mTLS still has it. The key is what the server registers; the device id is what it indexes by. |
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
| `attestationChain` | Base64 DER, leaf first. Required on **first** registration under `ATTESTATION_KEY_POLICY=enforce`; optional otherwise; ignored for a device already registered (a key cannot be re-attested). |
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

What each probe looks at (Android, no root needed):

| Signal | Evidence sources |
|---|---|
| `rooted` | `su` in the usual paths; Magisk / KernelSU / APatch files (`/sbin/.magisk`, `/data/adb/magisk`, `/data/adb/ksu`, `/data/adb/ap`); `Build.TAGS` contains `test-keys`; `ro.debuggable=1`, `ro.secure=0`; a writable `/system`; root-manager packages installed (Magisk, SuperSU, KernelSU, Superuser); `which su`. |
| `emulator` | `Build.FINGERPRINT` starting with `generic`/`unknown`; `MODEL` containing `google_sdk`, `Emulator`, `Android SDK built for`; `MANUFACTURER` `Genymotion`; `HARDWARE` `goldfish`/`ranchu`/`vbox86`; `PRODUCT` `sdk_gphone*`/`vbox86p`; `ro.kernel.qemu=1`; `/dev/socket/qemud`, `/dev/qemu_pipe`. |
| `debugger` | `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, `TracerPid` ≠ 0 in `/proc/self/status`. |
| `debuggable` | `ApplicationInfo.FLAG_DEBUGGABLE`. |
| `hooking_framework` | `/proc/self/maps` entries for `frida`, `gadget`, `xposed`, `substrate`, `dobby`, `riru`, `lsposed`, `zygisk`; thread names `gmain`, `gum-js-loop`, `gdbus`, `pool-frida`; `System.getProperty("vxp")`; `de.robv.android.xposed.XposedBridge` loadable; a stack trace naming Xposed. |
| `app_integrity` | The app's signing certificate digests (`GET_SIGNING_CERTIFICATES`), compared **on the server** with `ATTESTATION_SIGNER_SHA256` / package with `ATTESTATION_PACKAGE_NAMES`; the client sets the flag itself only when the app gave it an expected digest and it differs. |
| `cloner` | `applicationInfo.dataDir` not under `/data/user/<n>/<package>` or `/data/data/<package>`; `filesDir` naming another package; `nativeLibraryDir` outside the app's own directory. |
| `unknown_installer` | Installer package not in the allowed set (default: Play, Samsung, Huawei, Amazon stores); empty installer is `sideload`. |
| `adb_enabled` | `Settings.Global.ADB_ENABLED` / `DEVELOPMENT_SETTINGS_ENABLED`. |
| `software_key` | The device key's `KeySecurityLevel` is `software` or `unknown`. |
| `key_unattested` | The device key has no attestation chain (set by the server from its own records once the device is registered). |
| `old_patch_level` | Set by the server from `device.securityPatch` and `ATTESTATION_MIN_PATCH_LEVEL`. |

The report is a measurement by code the attacker can hook. That is true for
every RASP; what makes it useful is that (a) a hooked report still has to be
signed by a Keystore key whose attestation chain proves it was made by **your**
package on real hardware, (b) the server adds signals the client cannot
forge (attestation, patch level, key level), and (c) tampering with the
probes costs more than the generic unpinning scripts the pinning path already
defeats. Apps that want a second opinion plug a `verdictProvider` (Play
Integrity): the library forwards its token verbatim and the server stores
it; verifying it against Google is a server-side hook (`ATTESTATION_VERDICT_WEBHOOK`,
reference server: stored and shown, not verified).

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
    "key_unattested": "warn", "old_patch_level": "warn"
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
   record, `old_patch_level` from the report's patch level.
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
| `ATTESTATION_REVEAL_REASONS` | `false` | Default for a policy's `revealReasons`. |
| `MOCK_HOST_REQUIRE_TOKEN` | `false` | The mock hosts refuse requests without a valid `PinVault-Token`. |
| `ATTESTATION_MIN_PATCH_LEVEL` | (existing) | Also feeds `old_patch_level`. |

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
    .integrityVerdictProvider(myPlayIntegrityProvider)   // optional
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
infrastructure and its continuously updated detections, or a verdict that is
independent of the device (for that, plug Play Integrity in as the verdict
provider and verify it on your server). The probes are a floor, meant to be
extended; the policy and token mechanics are the durable part.

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
