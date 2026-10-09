# PinVault guide

The full reference behind the [README](README.md): every option, what each
check refuses and why, and what changed in which release (*(2.1)*, *(2.2)*,
*(2.3)*). The examples are Kotlin; the iOS and React Native libraries use the
same names and the same server, so the text applies to them too — their own
differences are in [`pinvault-ios/README.md`](pinvault-ios/README.md) and
[`pinvault-react-native/README.md`](pinvault-react-native/README.md).

**Contents**

1. [Getting started](#getting-started) — dependency, init (Kotlin and Java), the pinned client, events, logging
2. [Usage modes](#usage-modes) — one or several Config APIs, static pins, custom endpoints, your own backend
3. [Keeping pins fresh](#keeping-pins-fresh) — periodic updates, expiry, the trusted clock, what a config may contain
4. [mTLS enrollment](#mtls-enrollment) — tokens, enrollment codes, approval, the device key, renewal
5. [VaultFile](#vaultfile-remote-file-distribution) — signed files, offline lifetime, access policies, per-device encryption, screen lock, wiping
6. [Attestation](#attestation-approov-style) — the token, Play Integrity, managed trust roots
7. [Server](#server) — the reference server and building your own
8. [Requirements](#requirements)
9. [Production security checklist](#production-security-checklist)

## Getting started

### 1. Add dependency

```gradle
implementation("io.github.umutcansu:pinvault:2.4.1")
// optional: Play Integrity as the attestation's second opinion
implementation("io.github.umutcansu:pinvault-play-integrity:2.4.1")
```

### 2. Initialize (v2 DSL — Kotlin)

> **Pin format**: pass the **raw Base64 SHA-256 hash** of the
> SubjectPublicKeyInfo. **Do NOT include the `sha256/` prefix** —
> PinVault adds it internally. Producing a pin from a server cert:
> ```bash
> openssl s_client -servername HOST -connect HOST:PORT -showcerts < /dev/null 2>/dev/null \
>   | openssl x509 -pubkey -noout \
>   | openssl pkey -pubin -outform der \
>   | openssl dgst -sha256 -binary \
>   | openssl base64
> ```

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(
            HostPin(
                "api.example.com",
                listOf(
                    "AAAAprimaryBase64Hash...=",   // raw base64, no "sha256/" prefix
                    "BBBBbackupBase64Hash...="
                )
            )
        ))
        signaturePublicKey(SIGNING_KEY)   // the server's ECDSA P-256 public key, Base64 (required, see Usage modes)
    }
    .build()

// Suspend
val result = PinVault.init(context, config)

// Or callback
PinVault.init(context, config) { result ->
    if (result is InitResult.Ready) { /* ready */ }
}
```

### 2b. Initialize (v2 DSL — Java consumers)

The DSL is Kotlin-first. From Java the lambda needs to return
`kotlin.Unit.INSTANCE`, and `HostPin`'s default parameter values are
not visible to Java callers — you must supply all six positionally.

```java
import kotlin.Unit;
import io.github.umutcansu.pinvault.PinVault;
import io.github.umutcansu.pinvault.model.PinVaultConfig;
import io.github.umutcansu.pinvault.model.HostPin;
import io.github.umutcansu.pinvault.model.InitResult;
import java.util.Arrays;

PinVaultConfig config = new PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/", block -> {
        block.bootstrapPins(Arrays.asList(
            // hostname, sha256 pins (raw base64, NO "sha256/" prefix),
            // version, forceUpdate, mtls, clientCertVersion
            new HostPin(
                "api.example.com",
                Arrays.asList(
                    "AAAAprimaryBase64Hash...=",
                    "BBBBbackupBase64Hash...="
                ),
                0, false, false, null
            )
        ));
        block.signaturePublicKey(SIGNING_KEY);
        return Unit.INSTANCE;
    })
    .build();

// PinVault is a Kotlin object: Java reaches it through INSTANCE
PinVault.INSTANCE.init(context, config, result -> {
    if (result instanceof InitResult.Ready) { /* ready */ }
    return Unit.INSTANCE;
});
```

### 3. Use the pinned client

```kotlin
val response = PinVault.getClient()
    .newCall(Request.Builder().url("https://api.example.com/data").build())
    .execute()
```

If you maintain your own `OkHttpClient` (custom timeouts, interceptors,
dispatcher), call `PinVault.applyTo(builder)` on your builder instead.
Both `getClient()` and `applyTo(builder)` install the **pin-recovery
interceptor**, so a pin mismatch is automatically retried after a
config refresh.

A client built with `applyTo` also follows the device's client
certificate: after a renewal or a re-enrollment its next connection
presents the new one, without rebuilding the client. Connections it
already has open keep the certificate they were made with until they
close, so after a re-enrollment call `client.connectionPool.evictAll()`
to make sure none of them keeps using the revoked identity.

**Open connections follow the pins too** *(2.2)*. A TLS handshake
happens once per connection, so a connection kept alive (HTTP/2,
keep-alive) or a resumed TLS session used to stay trusted after its pin was
removed or the config expired. Every client PinVault builds or configures
(`getClient()`, `getClient(settings)`, `applyTo(builder)`) now checks the
connection's certificate against the live config, and the config's expiry,
before each request; a connection that no longer passes is closed and the
request fails like a failed handshake (and is retried after a config
refresh where the recovery interceptor is installed). On a pin change the
library also closes the pooled connections of its own clients and starts
new TLS sessions. An `applyTo` client keeps its own pool — the per-request
check is what protects it, so do not remove the network interceptor
`applyTo` adds.

Recovery is bounded: at most 3 failed refetches per host and 6 refetches
in 5 minutes across all hosts, one of them for hosts the config has no pin
entry for; requests that fail together share one refetch.

#### Reading the current pins (multi-module setups)

If your HTTP client lives in a separate Gradle module that doesn't depend
on PinVault — e.g. a lean `:network` module behind an interface — pass the
raw pin set across the module boundary:

```kotlin
// In :app — orchestrate PinVault, hand pins to network module
PinVault.init(this, config) {
    if (it is InitResult.Ready) NetworkModule.applyPins(PinVault.currentPins)
}
PinVault.setOnUpdateListener {   // periodic, recovery and attestation updates; not your own updateNow()
    if (it is UpdateResult.Updated) NetworkModule.applyPins(PinVault.currentPins)
}
```

```kotlin
// In :network — no PinVault dependency, accepts a plain Map
fun applyPins(pins: Map<String, List<String>>) {
    val pinner = CertificatePinner.Builder().apply {
        pins.forEach { (host, hashes) -> hashes.forEach { add(host, "sha256/$it") } }
    }.build()
    // rebuild your OkHttpClient with this pinner
}
```

Accessors:

| Accessor | Returns |
|---|---|
| `PinVault.currentPins` (property) | `Map<hostname, List<sha256-base64>>` snapshot of every host in the active config |
| `PinVault.pinsForHost(hostname)` | `List<sha256-base64>?` for a single host, or `null` if the host has no entry |

Pin values are raw Base64 (no `sha256/` prefix) — prepend `"sha256/"` when feeding OkHttp's `CertificatePinner.Builder.add(...)`.

### 4. (Optional) Subscribe to connection events

PinVault emits a `PinVaultConnectionEvent.Connection` to a registered
listener for every TLS handshake whose certificate was verified against
the configured pins — both on success and on pin mismatch. The library
itself never POSTs anywhere; what you do with the event is entirely up
to you (analytics, custom backend, log, ignore).

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(...)
        signaturePublicKey(SIGNING_KEY)
    }
    .onConnectionEvent { event ->
        when (event) {
            is PinVaultConnectionEvent.Connection -> {
                // TLS handshake outcome — fires on every handshake.
                // event.hostname, event.success, event.pinVersion,
                // event.deviceManufacturer, event.deviceModel,
                // event.actualPin, event.expectedPins
                MyAnalytics.report(event)
            }
            is PinVaultConnectionEvent.ConfigUpdate -> {
                // Config rotation outcome — fires once per WorkManager
                // refresh, recovery-driven refetch, or config delivered by
                // attestation (the same updates OnUpdateListener hears). A
                // direct PinVault.updateNow() does not emit it: read its
                // UpdateResult instead.
                // event.status (UPDATED / UNCHANGED / FAILED),
                // event.newVersion, event.failureReason
                MyAnalytics.reportRotation(event)
            }
            is PinVaultConnectionEvent.ClientCertRenewal -> Unit  // see Renewal
            is PinVaultConnectionEvent.Attestation -> Unit        // see Attestation
        }
    }
    .build()
```

If your backend is the bundled PinVault demo-server (or a fork keeping
the `/api/v1/connection-history/{client-report,config-update-report}`
schemas), there is a one-line opt-in helper:

```kotlin
import io.github.umutcansu.pinvault.reporter.reportToPinVaultBackend

PinVaultConfig.Builder()
    .reportToPinVaultBackend("http://192.168.1.10:6650/")
    .configApi("api", "https://api.example.com/") { ... }
    .build()
```

The reporter POSTs **one event per TLS handshake** by default, which
scales poorly to a production fleet. Two opt-in knobs cut that down:

```kotlin
// Heartbeat throttle — at most one healthy report per (host, version,
// cert) tuple per minute; pin mismatches always go through.
.reportToPinVaultBackend(
    managementUrl = "http://192.168.1.10:6650/",
    dedupWindowMs = 60_000L
)

// Anomalies only — drop the healthy stream entirely; only pin
// mismatches and config-update failures reach the backend.
.reportToPinVaultBackend(
    managementUrl = "http://192.168.1.10:6650/",
    reportSuccessEvents = false
)
```

The reporter's own POSTs use system trust unless you give it a pinned
client. [CONNECTION_EVENTS.md](CONNECTION_EVENTS.md) shows the three ways to
pin them (the same host as the Config API, a host of its own, or the Config
API's own certificate through `PinVaultBackendReporter.pinnedClient`) and the
listener in Java.

Listener invocations are dispatched off the TLS handshake thread, and
any exception thrown by the listener is logged and swallowed — a
misbehaving callback can never break the underlying connection.

### 5. (Optional) Enable debug logging

PinVault logs through Timber. If your app does not already plant a
Timber tree, **all of PinVault's diagnostic output (pin verification,
config updates, recovery attempts) is silently dropped** — which makes
"is recovery even running?" debugging much harder.

```kotlin
if (BuildConfig.DEBUG) PinVault.enableDebugLogging()
```

`enableDebugLogging()` plants a `Timber.DebugTree` **only if no tree is
currently planted**, so it never overrides your production logging
policy (Crashlytics tree, custom release tree, etc.). It is opt-in by
design — PinVault never plants on its own.

## Usage Modes

### Single Config API

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(HostPin("api.example.com", listOf("pin1...", "pin2..."))))
        signaturePublicKey("MFkwEwYH...")              // REQUIRED unless allowUnsigned() is called
        wantPinsFor("cdn.example.com", "api.example.com") // optional: scope request
    }
    .build()
```

`signaturePublicKey` is required — it guards against config tampering and replay attacks. The matching ECDSA P-256 private key lives on the server; the public half goes into your APK at build time. For tests or transitional setups against an unsigned endpoint, call `allowUnsigned()` instead:

```kotlin
.configApi("api", "https://api.example.com/") {
    bootstrapPins(...)
    allowUnsigned()    // opt out — disables signature, freshness, and replay checks
}
```

`allowUnsigned()` and `allowUnpinnedConfigApi()` are test relaxations: a
release build refuses them (Android: the app is not `android:debuggable`;
iOS: compiled without `DEBUG`). `init` / `start` and enrollment with that
config fail before anything is sent, naming the block. A release app that
really talks to an unsigned or unpinned Config API says so on the block with
`allowRelaxationsInRelease()`. React Native does that only where the app's
native security file allows the relaxation.

### Multi-Config-API

One app can talk to multiple Config APIs — each with its own TLS pipeline,
bootstrap pins, and (optional) mTLS keystore. Each vault file then binds to a
specific API via `configApi("<id>")`.

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("prod-tls", "https://host:8091/") {
        bootstrapPins(prodTlsPins)
        signaturePublicKey(SIGNING_KEY)
        wantPinsFor("cdn.example.com", "api.example.com")
    }
    .configApi("secure-mtls", "https://host:8092/") {
        bootstrapPins(secureMtlsPins)
        signaturePublicKey(SIGNING_KEY)
        clientKeystore(p12Bytes, devicePassword)     // mTLS client cert
        wantPinsFor("internal.acme.com")
    }
    .vaultFile("feature-flags") {
        configApi("prod-tls")                         // bind to TLS API
        endpoint("api/v1/vault/feature-flags")
    }
    .vaultFile("ml-model") {
        configApi("secure-mtls")                      // bind to mTLS API
        endpoint("api/v1/vault/ml-model")             // required
        storage(StorageStrategy.ENCRYPTED_FILE)
        accessPolicy(VaultFileAccessPolicy.TOKEN)
        accessToken { tokenStore["ml-model"] ?: "" }
        encryption(VaultFileEncryption.END_TO_END)
    }
    .build()
```

At runtime the library routes each vault fetch to the correct block's
pin-verified OkHttpClient. No cross-contamination between scopes.

### Static pins (offline, no server)

```kotlin
val config = PinVaultConfig.static(
    HostPin("api.example.com", listOf("pin1...", "pin2..."))
)
PinVault.init(context, config)
```

Static pins are checked at `init` like fetched ones (see
[What a config may contain](#what-a-config-may-contain-22)); `init`
returns `Failed` for a host name or pin that is not well-formed. A `HostPin`
with fewer than two pins never gets that far: its constructor throws
`IllegalArgumentException`. They carry no signature and no expiry.

### Custom endpoints

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://myserver.com/") {
        bootstrapPins(listOf(...))
        signaturePublicKey(SIGNING_KEY)
        configEndpoint("ssl/pins")          // default: api/v1/certificate-config
        healthEndpoint("ping")              // default: health
        enrollmentEndpoint("auth/register") // default: api/v1/client-certs/enroll
        clientCertEndpoint("certs/client")
        vaultReportEndpoint("analytics/vault")
    }
    .build()
```

### Custom `CertificateConfigApi` (bring your own backend)

If your backend doesn't match the default HTTP contract, implement
`CertificateConfigApi` and pass it to `PinVault.init`. The override is applied
to the **default (first-registered)** Config API block; for multi-API setups,
implement one `CertificateConfigApi` per block and switch inside your impl
based on the caller's block id.

```kotlin
class MyApi : CertificateConfigApi {
    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
        return myBackend.getPins(currentVersion)
    }
    override suspend fun healthCheck() = true
    override suspend fun enroll(
        token: String?, deviceId: String?,
        deviceAlias: String?, deviceUid: String?
    ) = myBackend.enroll(token)
    override suspend fun downloadHostClientCert(hostname: String) = myBackend.getCert(hostname)
    override suspend fun downloadVaultFile(endpoint: String) = myBackend.getFile(endpoint)
}

val config = PinVaultConfig.Builder()
    .configApi("api", "https://myserver.com/") {
        bootstrapPins(listOf(...))
        allowUnsigned()   // MyApi's configs are not verified — see below for signed ones
    }
    .build()

PinVault.init(context, config, MyApi()) { result -> /* ... */ }
```

**Signed configs through a custom API** *(2.2)*. `fetchConfig`
returns a parsed config, and nothing can verify that. A block with
`signaturePublicKey(...)` used to look signed while a custom API's configs
went in unchecked. Now such a block gets verified configs or none: implement
`SignedConfigSource` next to `CertificateConfigApi` and hand over the signed
envelope as your backend serves it; PinVault verifies it exactly as it does
for its own HTTP client (signatures, m-of-n, signing-key sets, `issuedAt` /
`expiresAt`, replay, `serverScope`) and keeps it with the stored config.

```kotlin
class MyApi : CertificateConfigApi, SignedConfigSource {
    override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse {
        val body = myBackend.getSignedPins(currentVersion)   // {"payload": "...", "signature": "..."}
        return SignedConfigResponse(payload = body.payload, signature = body.signature)
    }
    // fetchConfig is not called for a block with signing keys
    // … the other CertificateConfigApi methods as above
}
```

The payload is the config JSON exactly as signed (`version`, `pins`,
`forceUpdate`, `issuedAt`, `expiresAt`, and `configApiId` when the block sets
`serverScope`). A custom API that does not implement `SignedConfigSource` is
accepted for a block with signing keys only when the block also calls
`allowUnsigned()`; otherwise `init` returns `Failed` with a message that says
so. Unverified configs have no replay protection, no expiry and no integrity
check on the stored copy. `fetchScopedSignedConfig(...)` is the `wantPinsFor`
variant (default: `fetchSignedConfig`). Java implementers delegate it to
`SignedConfigSource.DefaultImpls`.

If you serve vault files through a custom API, override
`downloadVaultFileWithMeta(...)` rather than only `downloadVaultFile(...)`:
the default wrapper returns version `0` and no signature, and *(2.1)* a block
with a signing key refuses an unsigned vault file (see
[Signed vault files](#signed-vault-files-21)). Return the signature in
`VaultFetchResponse(content, version, encryption, signature = …)`. A block
that sets `serverScope` reads only the v2 fields, `signatureV2` /
`signaturesV2`; `signature` / `signatures` are ignored there.

`encryption(USER_AUTH)` files *(2.2)* need
`registerUserAuthPublicKey(deviceId, publicKeyPem, attestationChain)`
(Base64 DER certificates, leaf first; empty when the device cannot attest).
An implementation compiled against 2.1.1 or earlier does not have it: those
files then fail with a reason saying the backend does not support them.

The default implementation (`DefaultCertificateConfigApi`) speaks the HTTP
contract described in [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md)
and is sufficient for the reference server.

## Keeping pins fresh

`init` fetches the config once. To keep checking in the background, schedule a
WorkManager job after init; to refresh on demand, call `updateNow()`:

```kotlin
PinVaultConfig.Builder()
    .configApi("api", url) { /* ... */ }
    .updateIntervalHours(12)            // or updateIntervalMinutes(...) (WorkManager minimum: 15)
    .build()

PinVault.schedulePeriodicUpdates()     // uses the interval above
val result = PinVault.updateNow()      // UpdateResult.Updated / AlreadyCurrent / Failed
```

`PinVault.reset()` drops the active and stored config of every Config API;
the next `init` starts from the bootstrap pins again (clients built earlier
refuse handshakes until then — pinning never falls back to system trust).
*(2.2)* It keeps the replay watermarks (the newest `issuedAt` and
per-host versions the device has accepted), the signing-key set and the
client certificate: `reset()` is callable by the app, and by whatever can
reach the app's code, so it must not reopen the door to older signed
configs. After a reset the device accepts the newest config it has seen, or
a newer one.

**A config expires** *(2.2)*. A signed config is valid until its
`expiresAt` (the server's `CONFIG_TTL_SECONDS`, 24 hours by default). The
device keeps that date with the stored config. Past it, `init` fails with
`ConfigExpiredException` when no fresh config can be fetched, and pinned
clients refuse handshakes until one arrives. A request that hits an expired
config fetches a fresh one and retries, like a pin mismatch. So someone who
blocks the Config API cannot keep a device on old pins for longer than that.
Apps that would rather keep working through a longer outage can allow a
grace period, at the cost of that much longer on old pins:

```kotlin
PinVaultConfig.Builder()
    .expiredConfigGrace(12, TimeUnit.HOURS)   // default 0: fail closed
```

Configs without an `expiresAt` (static pins, an `allowUnsigned()` backend
that sends none) never expire. A config stored by 2.1.1 or earlier has no
saved `expiresAt`: it gets 7 days from the first start of the new version
(written down, so restarts do not extend it), whatever its `issuedAt` says —
2.1.1 did not move `issuedAt` forward while the pins stayed the same. A
successful fetch replaces the estimate.

A fetched config is also refused when its `issuedAt` is more than 1 hour
ahead of the device's clock, when its `expiresAt` has already passed (a
custom `CertificateConfigApi` can hand one over; the stored config is kept),
when it is valid for more than 30 days or expires more than 30 days from
now, when a host's version jumps by more than 1,000,000, or when a host the
device has not seen before starts above 1,000,000. A signed config must
carry both `issuedAt` and `expiresAt`. The replay checks only ever move
forward, so such values would lock out every later config. A device whose
clock runs more than an hour slow gets no new config until its clock is
corrected. A config rolled back after a failed health check no longer lowers
those checks either, and a host the server drops keeps its version
watermark: it cannot come back at a lower version.

If a signing key is stolen, its holder can still push those checks to their
limits. Revoking the key with a newer signing-key set (`recoveryPublicKeys`)
undoes that: when a device applies a newer set it clears the `issuedAt` and
version watermarks of that Config API and drops a stored config the new set
does not vouch for; the next accepted config sets them again.

**The time expiry is measured by.** Setting the device clock back does not
bring an expired config back: expiry is decided by the later of the device
clock and the highest time the library has seen (persisted, and carried
forward by the monotonic clock while the app runs). That reference goes
back in one case only, so that a clock once set far ahead by mistake does
not leave every config "expired": a config newer than every config accepted
before. The reference then becomes the later of the device clock and that
config's signed `issuedAt`; the same config served again never does it.

**What the clock cannot tell** *(2.3)*. The device cannot tell such a newer
config from a *captured* one it has never seen: someone holding a signed
config the device never received, whose `expiresAt` has passed, and the
private key of a pin it still lists, can set the device clock back (Android's
automatic time is not authenticated) and have the device trust those pins for
that config's remaining lifetime. The cost is bounded by `CONFIG_TTL_SECONDS`
(24 hours by default, 30 days at most) and needs a key the pins were rotated
away from. Keep the TTL short, and for public hosts pair pins with
`requireCaTrust`, which a leaked old key does not pass.

#### What a config may contain *(2.2)*

Every config — fetched, static, or from a custom API — is checked before it
is used, and refused as a whole if one entry fails:

- host names: letters, digits and hyphens per label, joined by dots (an IPv4
  address is fine), at most 253 characters; one optional leading `*.` for
  exactly one label; an optional `:port` (1–65535). No wildcard directly
  under a public suffix (`*.com`, `*.co.uk`), no IPv6 literals;
- pins: Base64 of a SHA-256, 44 characters, at least two distinct pins and
  at most 32 per host;
- at most 2000 hosts; no host listed twice, no negative version.

**Change detection looks at the pins, not only the versions.** A config
whose hosts, versions, pin hashes or mTLS flags differ from the stored one
is applied when it is newer (`issuedAt`), even if no version was bumped — a
pin removed without a version bump used to never reach devices.

**The stored config is checked again when it is read** *(signed blocks)*.
The signed envelope is stored with the config and its signatures are
verified at every start, against the keys trusted at that moment; the pins
used are the ones inside the envelope. A stored config that does not verify
is discarded: `init` fetches a fresh one, or fails (`NoConfigAvailableException`,
the reason says the stored config was discarded) when it cannot. Configs
stored by 2.1.x have no envelope, so the first start after the upgrade needs
the Config API once. Blocks that run unsigned, static pins and custom APIs
without `SignedConfigSource` have no envelope and no such check.

`getClient(settings)` clients (custom timeouts and pool) have no recovery
interceptor: once the config expires they refuse handshakes until something
else fetches a fresh one. Use them with `schedulePeriodicUpdates()` (or call
`updateNow()` yourself), or use `getClient()` / `applyTo(builder)`, which
refetch and retry.

## mTLS Enrollment

```kotlin
// Token-based
PinVault.enroll(context, "one-time-token")

// (2.1) An enrollment code many devices share (may wait for approval)
PinVault.enroll(context, "K7QM2-XRT9V-4NWDP-J6E8B-HC3MA")

// Automatic (device ID): ENROLLMENT_MODE=open, or (2.1) an application
// an administrator approves (applications without a code)
PinVault.autoEnroll(context)

PinVault.isEnrolled(context)           // is a client certificate stored?
PinVault.enrolledClientNotAfter(context)   // (2.1) when it expires (epoch ms), read locally
PinVault.unenroll(context)             // remove it; the next request presents no cert
```

Certificates are stored under the Config API block's `clientCertLabel(...)`;
every call above takes an optional `label` to address another one.

### Where the token comes from

The APK is the same for every device and contains no token. Each device gets
its own one-time token at runtime, the way an app receives a verification
code:

- **The server mints it.** In the dashboard: the mTLS Config API → *Client
  Certificates* → *Enrollment Token*, enter a client id (the name the device
  will carry, e.g. `tablet-07`), *Generate Token*. Or with the API key:
  `POST /api/v1/enrollment-tokens/generate` `{"clientId": "tablet-07"}` →
  `{"token": "…", "clientId": "tablet-07"}`. The token is shown once; the
  server keeps only its SHA-256 hash. It is valid for one enrollment within 24
  hours (`ENROLLMENT_TOKEN_TTL_SECONDS`).
- **The app receives it at runtime, never inside the APK.** A token baked into
  the APK would enroll only the first device (it is single-use), and anyone
  who unpacks the APK could read it. Either:
  - your backend mints it when the user signs in and returns it in the
    sign-in response; the app passes it to `enroll`. The API key stays on your
    server and the user never sees the token; or
  - for a handful of devices, send it by message or QR code and let the user
    paste it once (the demo app's *Enroll* dialog).
- **It is spent once.** From then on the device's identity is its Keystore key
  and certificate, and renewals *(2.1)* need no token. A device needs a new token only
  after a reinstall, cleared app data, or a revocation. A revoked client id
  stays revoked; *Forget identity* on its row in the dashboard (`POST
  /api/v1/client-certs/{id}/forget`) frees it for a new enrollment over a new
  key, while its old certificates and keys stay refused.

A made-up token never matches: the server looks up the hash of what it
receives and answers anything unknown, expired or used with `401`.

**Bind the token to the phone** *(2.2)*. The device id a phone sends
when it enrolls (its ANDROID_ID) is only its own claim. The reference server
believes it only when it is *proven*: the token was minted for that id, the
id equals the client id, or a key attestation with your app's package and
signer vouches for it. Only a proven device id lets the certificate stand in
for the device's own credentials: `TOKEN_MTLS` downloads, replacing the
device's end-to-end or screen-lock key over mTLS, host client-certificate
grants, and lifting a revoked device's block. In the dashboard, fill in
*Device id (ANDROID_ID)* next to the client id (the sample app shows the id on
its mTLS screen); over the API, `{"clientId": "tablet-07", "deviceUid":
"<ANDROID_ID>"}`. A phone with another id gets `403 device_uid_mismatch` and
the token stays unspent. Without a device id the token still enrolls any
phone, but that phone's files and keys stay bound to its tokens, not to its
certificate.

Per-file vault tokens (`TOKEN` / `TOKEN_MTLS` policies) travel the same way:
minted for one file and one device (the file's *Token Management* card, or
`POST /api/v1/config-apis/{configApiId}/vault/{key}/tokens`
`{"deviceId": "<ANDROID_ID>"}`), delivered at runtime, kept by the app in its
own encrypted storage and handed to the library through `accessToken { … }`.

### Enrollment codes: one code, many devices *(2.1)*

A one-time token per device is a chore for a fleet. An **enrollment policy**
gives one code to many devices, within limits:

1. In the dashboard: the mTLS Config API → *Client Certificates* →
   *Enrollment policies*. Enter a name (it prefixes the devices' ids, e.g.
   `field-tablets`), the most devices it may enroll, how many days it stays
   valid, and whether each device needs an administrator's approval (on by
   default). *Create policy* shows the code once, with a QR code, and copies
   it: `K7QM2-XRT9V-4NWDP-J6E8B-HC3MA` (25 characters, 125 bits; case, dashes
   and spaces do not matter, `O`/`I`/`L` read as `0`/`1`).
2. Every device enrolls with the same code, through the same call as a
   token: `PinVault.enroll(context, code)` (or the config overload before
   `init`). Each device gets its **own** identity, `field-tablets-7k2m9x`, and
   its own certificate over its own Keystore key — nothing about one device
   lets another one in.
3. With approval on, the device first gets
   `ClientCertEnrollmentResult.Pending(requestId, clientId, …,
   verificationCode)` and waits. It shows the verification code, made from
   its own key (`4F7K-2QXM-9D3T-H6WP`, 16 characters; also
   `PinVault.enrollmentVerificationCode(context)`). The dashboard lists the
   request under *Devices awaiting approval* with the device's model, IP
   address, time and the same code (and the webhook sends
   `enrollment_request_pending`): compare the two, then *Approve* or
   *Reject*. The device asks again by its request id with a CSR signed by
   the same key — a request id alone picks up nothing — and `init` and the
   periodic update ask on their own:

```kotlin
when (val result = PinVault.enrollForResult(context, config, code)) {
    is ClientCertEnrollmentResult.Pending -> showWaiting(result.verificationCode)
    else -> { /* Enrolled, Refused, Failed as below */ }
}

// While the "waiting for approval" screen is up:
while (PinVault.isEnrollmentPending(context, config)) {
    delay(15_000)                                        // the server's Retry-After
    when (val r = PinVault.checkPendingEnrollment(context, config)) {
        is ClientCertEnrollmentResult.Enrolled -> { PinVault.init(context, config); break }
        is ClientCertEnrollmentResult.Refused -> { showRefusal(r.reason); break }  // REJECTED: turned away
        else -> Unit                                     // still waiting, or offline
    }
}
```

A rejected device forgets the request and its key: entering the code again
is a new request. `unenroll` gives a waiting request up.

The verification code is 80 bits of the key's SHA-256 *(2.2; it was
40 bits, 8 characters — the first 8 characters are unchanged)*. It is what
ties the request the administrator approves to the device in front of them:
someone who wants their own key approved under a waiting device's code needs
a key with the same code, and with 40 bits that took minutes of key
generation. Compare all 16 characters.

**What the code costs.** It is a shared secret: whoever holds it can enroll
until the device limit or the end date — or, with approval on, only ask.
That is why it has both limits, why approval is the default, and why every
policy has *Stop*: no new devices, and the ones still waiting are turned
away (devices approved before still pick their certificates up). The rule of
one active identity per device holds: a device that is already enrolled
(a reinstall) shows the clash on its request, and the old identity has to be
revoked before it can be approved. For a sensitive device, the one-time
token above stays the tighter choice.

Codes need a CSR — the device is recognised by its key — so they work on the
Config API listeners with the 2.1 library; a P12-only client gets
`400 csr_required`. Management API: `POST /api/v1/enrollment-policies`
`{"name", "maxDevices", "validDays", "requireApproval"}` (approval defaults to on) → `{policy, code}`,
`GET /api/v1/enrollment-policies`, `POST /api/v1/enrollment-policies/{id}/stop`,
`GET /api/v1/enrollment-requests?status=pending`,
`POST /api/v1/enrollment-requests/{id}/approve` and `…/reject`.

### Applications without a code *(2.1)*

Some devices cannot be handed a code: no camera, no keyboard, a kiosk. For
them the dashboard has a switch that works like a router's MAC filter:
devices ask, and you let in the ones you recognise.

1. The mTLS Config API → *Client Certificates* → *Devices awaiting
   approval* → turn *Applications without a code* on.
2. The app calls `PinVault.autoEnroll(context)` (`autoEnrollForResult` for
   the details) — the demo app's *Apply without a code* button. Nothing is
   typed. The device gets `Pending` and shows its verification code.
3. The request appears in the list marked *without a code*, with the
   device's model, IP address, time and the same verification code. On a
   device without a screen, go by the model, address and time. *Approve*,
   and the device picks its certificate up on its own, like a device that
   came with a code.

**What it costs.** Anyone who can reach the Config API listener can ask, so
the list can fill up; nobody gets a certificate without your approval. The
server keeps the list in bounds:

- one source address may make 20 new applications per 10 minutes
  (`OPEN_ENROLLMENT_RATE_LIMIT`, `0` turns it off; beyond it
  `429 too_many_applications`);
- at most 50 wait at once (`OPEN_ENROLLMENT_MAX_PENDING`;
  `429 too_many_pending_requests`);
- a request nobody answers lapses after 24 hours
  (`ENROLLMENT_REQUEST_TTL_HOURS`; requests made with a code too): the
  device is told `410 enrollment_request_expired`
  (`EnrollmentRefusal.EXPIRED`) and forgets the request and its key, so
  applying again is a new request.

A device that asks again (a reinstall) has every one of its rows marked as
having another request waiting; approve the newest and reject the rest. A
device that is already enrolled cannot be approved until its old identity is
revoked. Turning the switch off turns new applications away (`403 Token
required`) and leaves the waiting ones to be decided. The switch takes
precedence over `ENROLLMENT_MODE=open`: while it is on, a device without a
token waits for approval instead of being enrolled outright.

Management API: `GET /api/v1/enrollment-open` →
`{enabled, maxPending, requestTtlHours, rateLimitPer10Minutes}`,
`PUT /api/v1/enrollment-open` `{"enabled": true}`. The requests are listed
and decided with the others under `/api/v1/enrollment-requests`, marked
`"openApplication": true`.

### When enrollment fails *(2.1)*

`enroll` and `autoEnroll` return `false` whatever went wrong. Their
`…ForResult` twins return a `ClientCertEnrollmentResult`, so the app can tell
its user what to do instead of "enrollment failed":

```kotlin
val message = when (val result = PinVault.enrollForResult(context, config, token)) {
    is ClientCertEnrollmentResult.Enrolled -> null
    is ClientCertEnrollmentResult.Refused -> when (result.reason) {
        EnrollmentRefusal.INVALID_TOKEN -> "The token is invalid, used or expired."
        EnrollmentRefusal.DEVICE_ALREADY_ENROLLED ->
            "This device is enrolled under another id. Retry with the same token once it is revoked."
        EnrollmentRefusal.REVOKED -> "This id was revoked. Ask for a new token."
        EnrollmentRefusal.TOKEN_REQUIRED -> "The server enrolls only with a token."
        EnrollmentRefusal.REJECTED -> "An administrator turned this device away."
        EnrollmentRefusal.LIMIT_REACHED -> "This code has no device left. Ask for a new one."
        EnrollmentRefusal.EXPIRED -> "Nobody approved the request in time. Apply again."
        EnrollmentRefusal.ATTESTATION_FAILED ->                                  // (2.2)
            "The server could not confirm this is a genuine device and app: ${result.message}"
        EnrollmentRefusal.CSR_REQUIRED -> "This device could not make its key."  // (2.2)
        EnrollmentRefusal.OTHER -> "Refused: HTTP ${result.httpStatus} ${result.serverError.orEmpty()}"
    }
    is ClientCertEnrollmentResult.Pending -> "Waiting for an administrator to approve this device."   // see above
    is ClientCertEnrollmentResult.Failed -> "Could not enroll: ${result.message}" // network, pins, key store
}
```

A refused enrollment does not spend the token. A custom `CertificateConfigApi`
reports a refusal by throwing `EnrollmentRefusedException(httpStatus,
serverError, serverMessage)`; anything else it throws becomes `Failed`.
`Failed` is also what the library answers on its own account, with the reason
in `message`: the server sent a key of its own making and the block did not
ask for one (below), or the certificate chain it issued did not pass
([what a certificate must look like](#what-an-issued-certificate-must-look-like-22)).

### The device keeps its key *(2.1)*

Enrollment generates an EC P-256 signing key in the Android Keystore and
sends the server a certificate signing request over it (`X-PinVault-Features:
csr`). The server answers with a certificate chain; the private key never
leaves the device. Custom `CertificateConfigApi` implementations take part by
overriding `enrollWithCsr` and `renewClientCert` (both have defaults; Java
implementers delegate the rest to `CertificateConfigApi.DefaultImpls`).

**The key is attested** *(2.2)*. A token proves that someone has the
token — not that the request comes from your app on a real phone. A script,
an emulator or a repackaged app holding a token used to enroll exactly like a
phone. The key is now generated with an Android key attestation challenge,
SHA-256 of `pinvault-identity-key:v1:<device id>` (the `deviceUid` the request
carries), and every enrollment request sends the key's attestation chain as
`"attestationChain": ["<base64 DER>", …]`, leaf first. A server that checks it
(the chain up to a Google hardware root, the challenge, your app's package
name and signing certificate, a locked bootloader) knows the key lives in
this device's hardware and was made by your app. The library tries StrongBox
with attestation, then the TEE with attestation, then the TEE without; a
device that cannot attest sends no chain. A server that insists answers
`403 attestation_required` or `403 attestation_invalid`
(`EnrollmentRefusal.ATTESTATION_FAILED`, the server's reason in
`Refused.message`); the token is not spent. A key an earlier version generated
has no attestation: when it is refused for that, the library makes a new key
and asks once more by itself. Emulators attest with a software root, which an
enforcing server refuses — enroll test devices against a server that only
warns.

**A key the server made is refused unless you ask for it** *(2.2)*.
An older or P12-only server answers the same request with a PKCS12: a private
key that was generated on the server and travelled over the wire. The library
used to store it without a word, and to ask for one by itself when the
Keystore could not make a key. Both now end in `Failed` with the reason. If a
server-made key is acceptable for a block, say so:

```kotlin
.configApi("legacy", "https://old-backend.example.com/") {
    allowServerGeneratedKey()      // accept a P12 answer / P12 enrollment
}
```

(The reference server answers a request without a CSR `403 csr_required`,
`EnrollmentRefusal.CSR_REQUIRED`, unless its `ENROLLMENT_P12` is on — and it
is on by default, for older apps; set `ENROLLMENT_P12=off` so the server never
makes a private key.)

**No P12 is kept on the device** *(2.2)*. Wherever the library does
accept a PKCS12 — such an enrollment, a host's client certificate downloaded
for an mTLS host, a `clientKeystore(...)` bundled with the app — it imports
the private key into the Android Keystore as a non-exportable key and stores
only the certificate chain; the P12 bytes are dropped. P12s stored by an
earlier version are moved over the first time they are loaded. Before, the
key sat in app storage under a password compiled into the app (`changeit` by
default), ready to be copied by anyone who could read the app's data. Where a
device's Keystore refuses the import, the P12 form is kept for that one key
and a warning is logged. The import cannot undo where the key has been: a
bundled keystore is still in your APK.

A device enrolls before it has a client certificate, so an mTLS Config API
would refuse the enrollment at the handshake. Give an mTLS block
`enrollmentUrl(...)` — the backend's plain-TLS listener — and enrollment goes
there; config and vault traffic stays on the mTLS URL.

On first start, enroll **before** `init` — the config overloads work without
an initialized PinVault:

```kotlin
if (!PinVault.isEnrolled(context, config)) {
    PinVault.enroll(context, config, token)   // or autoEnroll(context, config)
}
PinVault.init(context, config)                // one init, over mTLS
```

From Java, the config overload of `isEnrolled` is `PinVault.INSTANCE.isEnrolledWithConfig(context, config)`.

A block with an `enrollmentUrl` and no client certificate does not contact
its backend in `init`: it answers at once with `InitResult.Failed` carrying a
`ClientCertificateRequiredException` (or `Ready` from a stored config), instead
of retrying a handshake the server will refuse.

### Renewal *(2.1)*

A CSR-enrolled certificate is short-lived (the reference server issues 90
days) and renews itself. The library reads the stored certificate's expiry
without touching the network, at init and on every periodic update:

- with less than a third of the lifetime left, it sends a new CSR over the
  block's own connection — the current certificate is still valid and
  authenticates the request over mTLS;
- once expired, or if the server refuses the handshake, the same CSR goes to
  the block's **recovery URL** (`renewalUrl(...)`, default: the block URL): a
  plain-TLS listener that asks for no client certificate and checks the CSR
  signature against the key it registered at enrollment.

An expired certificate is never presented and never accepted. An mTLS
Config API cannot be its own recovery URL. The reference server runs a
dedicated **recovery door** (`RECOVERY_PORT`, default `PORT + 3`): renewal
only, its own certificate signed by a server CA and reissued before it
expires. Pin that CA for the door's `host:port` — a `host:port` entry applies
to that port alone, so the Config API ports keep their stricter leaf pins
while the door survives any number of certificate changes. The dashboard's
mTLS tab shows the door's port and the two CA pins to paste.

```kotlin
.configApi("secure", "https://config.example.com:8092/") {
    bootstrapPins(listOf(
        HostPin("config.example.com", listOf(leafPin, backupPin)),                 // Config API ports
        HostPin("config.example.com:8093", listOf(serverCaPin, serverCaBackupPin)) // recovery door only
    ))
    // signaturePublicKey(...) as above
    enrollmentUrl("https://config.example.com:8091/") // first enrollment: TLS, the device has no cert yet
    renewalUrl("https://config.example.com:8093/")
    clientCertRenewalThreshold(0.25)                 // default 1/3
    // disableClientCertRenewal()                    // drive it yourself
}

PinVault.renewClientCertIfNeeded(force = true)       // ClientCertRenewalResult
```

The outcome is also delivered as a `PinVaultConnectionEvent.ClientCertRenewal`
to `onConnectionEvent`. `ReenrollRequired` means the server refuses the
identity (revoked, unknown, key changed): the stored certificate is left in
place and the app should enroll again. A revoked client id stays revoked, so
the new enrollment uses a new id, or the same one after the administrator
presses *Forget identity*.

A revoked device does not wait for renewal to hear it. The server answers a
revoked identity `403 reenroll_required` on every request, and the first time
any request of a block gets that answer (config, vault file, device key
registration, report or renewal) the same `ClientCertRenewal` event arrives
with status `REENROLL_REQUIRED`. It is sent once per certificate; `init`
still returns `Ready` with the stored config. Removing the app
deletes the Keystore key, so a reinstall is a new enrollment, never a renewal.

### What an issued certificate must look like *(2.2)*

Whoever holds the TLS key of the enrollment or renewal listener can answer a
request with any certificate. Without a check, that includes a leaf valid for
fifty years, signed by a CA of their own, over the device's key — stored, never
due for renewal, never seen by your server again. So a chain is stored only
when:

- it has **at least two certificates**: the leaf and the CA certificate that
  signed it. A leaf on its own is refused (it used to be accepted, and then a
  renewal had nothing to be held to);
- the leaf is valid now, over this device's key, and signed by the next
  certificate;
- its lifetime is at most `maxClientCertLifetimeDays` (default 825). A stored
  certificate that outlives the cap is renewed at the next check;
- it comes from the right CA. **Pin your client CA** and that is checked at
  enrollment and at every renewal:

```kotlin
.configApi("secure", "https://config.example.com:8092/") {
    clientCaPins(clientCaPin, nextClientCaPin)   // Base64 SHA-256 of the CA's SubjectPublicKeyInfo
    maxClientCertLifetimeDays(120)               // default 825
}
```

  The leaf must then be signed by a certificate of the chain whose key matches
  a pin. Without pins the first chain is trusted as the pinned enrollment
  listener sent it, and a renewal must be signed by the CA of the certificate
  it replaces — a chain from any other CA is refused even if it arrives with
  its own CA attached. With two pins you can move to a new client CA without
  an app update. A chain of one stored by an earlier version cannot be renewed
  without pins (`Failed`, saying so): pin the CA or enroll again.

The pin of the reference server's client CA:
`keytool -exportcert -rfc -keystore certs/client-ca.jks -alias <alias> | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.

### Which hosts see the device's certificate *(2.2)*

A block presents its client identity only where it belongs: its own Config
API URLs (config, enrollment, renewal), hosts that have their own client
certificate, and hosts a signed config marks `mtls = true`. Any other pinned
host asks for a certificate in vain (`CERTIFICATE_REQUIRED`), so a third
party you pin cannot collect the device's identity. Other hosts that expect
this identity are named on the block:

```kotlin
.configApi("default", "https://config.example.com:8091/") {
    // bootstrapPins(...), signaturePublicKey(...) as above
    clientCertHosts("https://api.example.com:9443/", "files.example.com:443")  // port required, https only
}
```

Once `clientCertHosts` is set, it is the whole list: an `mtls = true` pin in
a signed config no longer adds a host, so even the config signer cannot send
the identity elsewhere. Without it, `mtls = true` pins work as before.

## VaultFile (Remote File Distribution)

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(...))
        signaturePublicKey(SIGNING_KEY)
    }
    .vaultFile("ml-model") {
        configApi("api")                             // which Config API to use
        endpoint("api/v1/vault/ml-model")
        storage(StorageStrategy.ENCRYPTED_FILE)
    }
    .vaultFile("feature-flags") {
        configApi("api")
        endpoint("api/v1/vault/feature-flags")
        updateWithPins(true)                         // auto-sync on pin update
    }
    .deviceAlias("Warehouse Tablet #3")              // the name the server dashboard shows
    .build()

// Fetch
val result = PinVault.fetchFile("ml-model")

// Load cached
val bytes = PinVault.loadFile("ml-model")
val json = PinVault.loadFileAsString("feature-flags")

// Housekeeping
PinVault.syncAllFiles()               // fetch every file with updateWithPins(true)
PinVault.hasFile("ml-model")          // cached copy present?
PinVault.fileVersion("ml-model")      // cached version (0 = none)
PinVault.fileStatus("ml-model")       // (2.2) why loadFile returned null
PinVault.clearFile("ml-model")        // drop the cached copy
```

`storage(...)` also accepts your own `VaultStorageProvider` instead of a
`StorageStrategy`.

### Signed vault files *(2.1)*

A vault file is saved only after its signature checks out. The server signs
`pinvault-vault-file:v1:<key>:<version>:<sha256-hex of the content>` with the
Config API's signing key and sends it in `X-Vault-Signature` (several signers:
`X-Vault-Signatures`). The device verifies it with the same keys it trusts for
configs — including a rotated key set and `requiredSignatures(n)` — after any
per-device decryption, and refuses a validly signed but older version.

- A file with no signature, or a bad one, ends as `VaultFileResult.Failed` and
  nothing is written. The reference server signs every file; **a backend of
  your own must send the header** once the block has a signing key.
- `signaturePublicKey(...)` inside `.vaultFile { }` checks that one file
  against exactly that key instead.
- The check is skipped (with a logged warning) only when there is no key to
  check with: a block with no signing key (`allowUnsigned()` and no
  `signaturePublicKey`) and no per-file key. `allowUnsigned()` next to a
  signing key does not turn it off: that block's vault files must still be
  signed.

**Signatures that name the Config API** *(2.2)*. The v1 string above
does not say which Config API a file belongs to, so with one signing key for
several Config APIs a file of one verifies for another. The server now also
sends `X-Vault-Signature-V2` (several signers: `X-Vault-Signatures-V2`, the
same `keyId:signature` list), a signature over
`pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256-hex of the content>`.
A block that names its server-side Config API with
[`serverScope(id)`](#4-enable-ecdsa-signature-verification-on-configs) **requires** the
v2 signature and verifies it with that id — at download, at unlock, and
whenever the stored copy is read. A block without `serverScope` verifies v1
as before. Set `serverScope` on every block that shares its signing key.

**The stored copy is verified every time it is read** *(2.2)*. A
file used to be checked when it was downloaded and then trusted for as long
as it sat in the app's storage. Now the signatures a file was accepted with
are stored with it, and `loadFile` / `unlockFile` verify the copy again with
the keys trusted at that moment. A copy that fails — rewritten, swapped with
another file's, given another version, or signed by a key revoked since — is
deleted and not returned. The stored forms also bind the file's name and
version into their encryption, so a blob moved under another name or version
does not even decrypt.

```kotlin
val bytes = PinVault.loadFile("trusted-hosts")
if (bytes == null) when (PinVault.fileStatus("trusted-hosts")) {
    VaultFileStatus.NOT_STORED          -> PinVault.fetchFile("trusted-hosts")   // never fetched
    VaultFileStatus.NEEDS_FETCH         -> PinVault.fetchFile("trusted-hosts")   // stored by an earlier version, see below
    VaultFileStatus.INTEGRITY_FAILED    -> { report(); PinVault.fetchFile("trusted-hosts") }  // the copy was tampered with; deleted
    VaultFileStatus.STALE               -> PinVault.fetchFile("trusted-hosts")   // past maxOfflineAge, see below
    VaultFileStatus.LOCKED              -> /* PinVault.unlockFile(...) */ Unit
    VaultFileStatus.STORAGE_UNAVAILABLE -> Unit                                  // Keystore busy / device locked: try later
    VaultFileStatus.AVAILABLE           -> Unit
}
```

A deleted copy is also reported to the `OnFileUpdateListener` as
`VaultFileResult.Failed` with the reason. **Upgrade:** a copy a signed block
stored with 2.1.x has no signature on record; `loadFile` returns `null` for
it (`NEEDS_FETCH`) until the next `fetchFile` / `syncAllFiles` has downloaded
it again — one fetch per file after the upgrade. Nothing is deleted meanwhile.
Files of `allowUnsigned()` blocks are read as before. What this cannot stop:
someone with root putting the whole of the app's storage back to an earlier
state — an older file with its older, valid signature. Nothing kept on a
device can; the offline lifetime below bounds it and the next fetch replaces
the copy.

### How long a file stays readable offline *(2.2)*

A device the server has revoked learns of it from the server. One that stays
offline never hears it and keeps every cached file. Give a file — or all of
them — an offline lifetime:

```kotlin
PinVaultConfig.Builder()
    .vaultFileMaxOfflineAge(30, TimeUnit.DAYS)       // default for every file
    .vaultFile("customer-keys") {
        endpoint("api/v1/vault/customer-keys")
        maxOfflineAge(72, TimeUnit.HOURS)            // this file: three days
        wipeWhenStale()                              // and delete it once they are over
    }
```

`loadFile` returns `null` (`fileStatus` = `STALE`) and `unlockFile` returns
`VaultFileUnlockResult.Stale` once the last successful fetch of the file — a
download, or the server's "you have the current version" — is longer ago than
that. (An `encryption(USER_AUTH)` download beside a stored copy counts from
the moment `unlockFile` has verified it, backdated to the download.) A
successful fetch makes the copy readable again; with `wipeWhenStale()`
the copy is deleted instead, at the next read, at `init` and on every periodic
update, whether or not the app asks for it. The time is the library's own
clock, the one config expiry uses: setting the device clock back does not
extend it.

**The default is no limit**, as before. For files that would hurt in the
hands of a revoked device, set one: a few days for secrets (long enough for a
weekend without signal, short enough to matter), with `wipeWhenStale()`; and
run `schedulePeriodicUpdates()` with `updateWithPins(true)` on those files so
a device that is online keeps confirming them. A copy stored before a limit
was set has no confirmation on record and is stale until its next fetch.

### Per-file access policies (v2)

```kotlin
.vaultFile("private-doc") {
    configApi("api")
    endpoint("api/v1/vault/private-doc")
    accessPolicy(VaultFileAccessPolicy.TOKEN)         // public | api_key | token | token_mtls
    accessToken { secureTokenStore["private-doc"] ?: "" }   // lazy token provider
}
```

| Policy | What the device sends | Use for |
|---|---|---|
| `PUBLIC` | nothing | genuinely public files; demo/test |
| `API_KEY` | **nothing — not usable from a device** | server-side tooling only (see below) |
| `TOKEN` | `X-Device-Id` + `X-Vault-Token` | per-device, per-file access (recommended) |
| `TOKEN_MTLS` | the above, over a client-authenticated TLS connection | highest assurance |

> **⚠️ `API_KEY` cannot be satisfied from a device.** That policy is enforced
> with the server's admin `X-API-Key`, and PinVault deliberately never sends it
> from a device: an admin key inside an APK is an admin key for everyone who
> downloads the app. A file declared with `API_KEY` therefore **fails with
> HTTP 401 on every fetch**, and the only trace is a `failed` row in the
> server's distribution history. `build()` logs a warning when it sees one.
> Use it to mark files only your build pipeline or ops scripts may read; for
> device-facing files use `TOKEN` / `TOKEN_MTLS`.

`accessToken { … }` is read on every fetch. Returning `""` (no token issued
yet) is fine — the library omits the header entirely so the server answers
"X-Vault-Token header required" rather than "invalid or revoked token".
How a device gets its token: [Where the token comes from](#where-the-token-comes-from).

### Per-device encryption (v2)

```kotlin
.vaultFile("ml-model") {
    configApi("secure-mtls")
    endpoint("api/v1/vault/ml-model")
    encryption(VaultFileEncryption.END_TO_END)        // RSA-OAEP + AES-256-GCM
}
```

The device's RSA public key is registered with every Config API at `init`;
the server encrypts each response with that key. Private key never leaves the
device's Android Keystore.

Who may set that key: over **mTLS** only a client certificate that belongs to
the device. Over **TLS** the first key a device registers is kept; a new one
(the app's data was cleared, so the Keystore key is new) replaces it only when
the request carries the device's token for one of that API's `end_to_end`
files — the library *(2.1)* adds it on its own when the app has one. Otherwise the
server answers `409` and keeps the old key, and an administrator can free the
slot: `DELETE /api/v1/config-apis/{configApiId}/vault/devices/{deviceId}/public-key`.
Since TLS asks for no credential, the server only stores RSA keys of
2048–4096 bits and limits how many a source address writes
(`DEVICE_KEY_RATE_LIMIT`) and a Config API holds (`DEVICE_KEY_LIMIT`). Files
that matter belong on an mTLS Config API, where `X-Device-Id` must also belong
to the device's certificate.

This is not end-to-end in the strict sense, despite the `END_TO_END` name: the
server performs the encryption, so it sees the content (the reference server
keeps it encrypted on disk). Relays, caches and other devices cannot read a
download. To hide a file from the server too, encrypt it before upload.

### Locked behind the screen lock *(2.2)*

Every vault file is stored encrypted with a Keystore key, but the app itself
can use that key at any time, so a rooted phone or a hooked app can read the
file through it. `userAuth` adds a key the hardware (TEE/StrongBox) uses only
after the user has passed the screen lock (PIN, pattern, password) or a strong
biometric. There is one such key per device.

```kotlin
.vaultFile("statement") {
    endpoint("api/v1/vault/statement")
    encryption(VaultFileEncryption.USER_AUTH)   // sealed by the server; recommended
    userAuth(UserAuth.REQUIRED)                 // or UserAuth.IF_SCREEN_LOCK
}
```

What is protected depends on who seals the file. With
`encryption(USER_AUTH)` the server seals it for the device's key, and the
content reaches the app only through `unlockFile`, after the prompt: not in
the fetch result, not in the update listener, not in storage. Against root
running as the app this holds only when the server enforces key attestation
(`USER_AUTH_ATTESTATION=enforce`). Without `encryption(USER_AUTH)` the
library seals the file after download, which protects the copy at rest
only. How a newer download waits until it is verified, and what trust on
first use leaves open: [SCREEN_LOCK.md](SCREEN_LOCK.md).

```kotlin
when (val r = PinVault.unlockFile(activity, "statement", VaultFileUnlockPrompt("Open your statement"))) {
    is VaultFileUnlockResult.Unlocked    -> show(r.bytes)
    is VaultFileUnlockResult.Cancelled   -> Unit
    is VaultFileUnlockResult.Invalidated -> PinVault.fetchFile("statement")   // key retired, download again
    is VaultFileUnlockResult.NotFound    -> PinVault.fetchFile("statement")
    is VaultFileUnlockResult.Stale       -> PinVault.fetchFile("statement")   // past maxOfflineAge, see above
    is VaultFileUnlockResult.Failed      -> showError(r.reason)
}
```

- Fetching and storing need no prompt, so periodic sync keeps working;
  `loadFile` returns `null` for a locked file, and `unlockFile` (a
  `FragmentActivity`, callback overload for Java) shows the system prompt.
  It works for unlocked files too, without a prompt.
- **No fingerprint or face:** the screen lock alone is enough.
- **No screen lock at all:** `REQUIRED` stores nothing and the fetch fails
  with `ScreenLockRequiredException` (send the user to the security
  settings); `IF_SCREEN_LOCK` stores the file as before and seals it as soon
  as a screen lock exists. A `USER_AUTH` file cannot be received without a
  screen lock under either policy.
- **Android versions.** Android 11+ asks on every unlock, for a strong
  biometric or the screen lock. Android 7–10 cannot tie the screen lock to
  a single use, so the key depends on whether a fingerprint is enrolled when
  it is made. Decide, before you ship `userAuth` files, whether a time-bound
  key is acceptable for them; the table is what the platform allows, not a
  library choice.

  | Android | Key | Opened by | Prompt offers |
  |---|---|---|---|
  | 11+ (API 30+) | per use (`PER_USE`) | every use: strong biometric or screen lock, bound to the operation | strong biometric + screen lock |
  | 7–10, a strong fingerprint enrolled when the key is made | per use, fingerprint only (`PER_USE_BIOMETRIC`) | every use: the fingerprint, bound to the operation | fingerprint only |
  | 7–10, no strong fingerprint then | time-bound (`TIME_BOUND`) | the screen lock or a fingerprint, for **5 s** after it is passed — in the prompt, or by unlocking the phone | Android 7–8: strong biometric + screen lock; Android 9–10: any biometric + screen lock |

  `PinVault.userAuthKeyKind()` reads this device's kind. Why the window is
  5 seconds, what retires each key, and how a server refuses time-bound keys
  (`USER_AUTH_REQUIRE_PER_USE=true`): [SCREEN_LOCK.md](SCREEN_LOCK.md).
- **Key retired:** `unlockFile` deletes the stored copy and returns
  `Invalidated`; the next fetch makes a new key, registers it and downloads
  the file again. Any other Keystore error returns `Failed` and keeps the
  copy and the key; try again.
- **Past its offline lifetime** (`maxOfflineAge`, above): `unlockFile`
  returns `Stale` without showing the prompt.

### Wiping files when a device is revoked *(2.2)*

Files already on a device stay there when the server revokes it. To remove
them when the Config API answers `403 reenroll_required` (the
`REENROLL_REQUIRED` event):

```kotlin
PinVaultConfig.Builder()
    .wipeVaultFilesOnRevocation()
```

Every file bound to the Config API that refused the device is deleted, locked
copies included; the device's user-auth key goes too once no locked file is
left. Vault access tokens belong to the app (`accessToken { … }`): forget them
when the event arrives.

The answer is a plain `403` — nothing in it is signed — so it deletes files
only when it was about this device's identity *(2.2)*: it arrived on
a connection that presented the client certificate the block has loaded, or
it is the answer to that certificate's own renewal request. A
`reenroll_required` on a connection without a client certificate (a TLS-only
block, a request before enrollment) still raises the event, and wipes
nothing. A device that is revoked while offline never gets the answer at
all: give its files an [offline lifetime](#how-long-a-file-stays-readable-offline-22). `PinVault.unenroll(context, label, wipeVaultFiles = true)`
does the same on demand, after `init`, for the Config APIs that use that
client certificate for mTLS (the label matches and the block names an
`enrollmentUrl` or `renewalUrl`, bundles a `clientKeystore`, or has a
`token_mtls` file); a TLS-only block that shares the default label keeps
its files.

## Attestation (Approov-style)

Pinning protects the channel. Attestation decides **which app instances get
the pins and a short-lived token at all**, so your API can refuse everything
else. The model is Approov's: the library measures the app and the device,
your PinVault server turns the measurement into a verdict, pins and a token
are released only on a pass, the token is refreshed every few minutes, and
your backend checks the token on every request. The full protocol is in
[`ATTESTATION.md`](ATTESTATION.md); the reference server implements it.

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://config.example.com:8091/") {
        bootstrapPins(...)
        signaturePublicKey(...)
        attestation()                                        // on; off by default
        attestationInterval(5, TimeUnit.MINUTES)             // ceiling; default 5 min, at least 1
        tokenHosts("api.example.com", "*.cdn.example.com")   // default: every pinned host of this block + its own Config API
        proofOfPossession()                                  // optional: a PinVault-Proof per request (ATTESTATION.md §5.1)
    }
    .expectedSignerSha256("3c:4f:…")                         // optional: your release signer
    .integrityVerdictProvider(                               // optional: Google's second opinion
        PlayIntegrityVerdictProvider(context, cloudProjectNumber = 123456789012L))
    .build()
```

What happens:

- **At `init`**, after the stored config is loaded and the mTLS renewal check
  ran, each attesting block asks `GET api/v1/attest/challenge` for a nonce,
  builds the report (`sdkVersion`, `app`, `device`, twelve `signals` the
  device measures — the server adds `play_integrity` / `play_integrity_missing` —
  `rooted`, `emulator`, `debugger`, `debuggable`, `hooking_framework`,
  `app_integrity`, `cloner`, `unknown_installer`, `adb_enabled`,
  `software_key`, `key_unattested`, `old_patch_level`), signs
  `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>` with the
  block's device key (the same Keystore key that signs mTLS CSRs; made here
  if the device never enrolled) and posts it to `api/v1/attest`. The first
  request carries the key's Android key attestation chain, so a server with
  `ATTESTATION_KEY_POLICY=enforce` can bind the key to your package on real
  hardware.
- **A pass** yields a `PinVault-Token` (ES256 JWT by default, 5 minutes) held in memory,
  and — when the device is behind — a signed pin config that goes through
  exactly the checks a fetched one gets (`SSLCertificateUpdater.applySigned`:
  signatures, scope, freshness, replay, plausibility). **A reject** yields
  neither; `init` still succeeds, and the app decides what to do with
  `PinVault.attestationStatus()` (result, ARC, the reasons the policy
  reveals, warnings, `tokenExpiresAt`, `nextAttestAt`, `clockSkewMs`,
  `lastError`). A failure (network, a refused key) is retried with backoff
  (30 s → 5 min) and the last token is kept until it expires.
- **Refresh**: a coroutine per block re-attests at
  `min(nextAttestIn, attestationInterval, tokenExpiry − 60 s)` with ±10 %
  jitter while the process lives; the periodic WorkManager job attests too,
  so a backgrounded app wakes with a fresh token.
- **The header**: every client the library builds or configures
  (`getClient()`, `getClient(settings)`, `applyTo`) adds `PinVault-Token` to
  HTTPS requests whose host matches a token host — with `proofOfPossession()`
  also a `PinVault-Proof` made for each request (ATTESTATION.md §5.1), which
  only these clients can make. Without a valid token it attests
  once, synchronously (bounded by the single flight and the backoff), and
  sends the request bare when that fails. A `401` whose `WWW-Authenticate`
  names `PinVault-Token`, or whose body says `invalid_token`, forces one
  re-attestation and one retry (never for a request body that can be sent
  once only). For a client of your own, `PinVault.fetchAttestationToken(host)`
  (suspend and callback) returns `AttestationTokenResult.Token | Rejected |
  Failed | Unsupported`; put it in `PinVault.attestationHeaderName()` (a
  backend that requires proofs refuses such a request: route it through
  `applyTo` instead).
- **Events**: `PinVaultConnectionEvent.Attestation(configApiId, status,
  arc, rejectionReasons, warnings, tokenExpiresAt, deviceManufacturer,
  deviceModel, failureReason)` on the
  connection listener, once per attempt. `PinVault.attestNow(configApiId?)`
  (suspend and callback) attests on demand.
- **Storage**: nothing. The token and the status live in memory only.

What this does **not** give you: Approov's hardened, obfuscated probes — the
library's are plain Kotlin, so put the app through R8 and, for high-value
targets, a packer. A verdict independent of the device is the optional Play
Integrity layer below. The report is a measurement by code an attacker can
hook; what makes it worth having is that a hooked report must still be
signed by a Keystore key whose attestation chain names your package on real
hardware, that the server adds signals the device cannot forge, and that
the policy — `reject`, `warn` or `ignore` per flag, device overrides, an
audit trail — is the server's.

### Play Integrity, optional *(2.3)*

Google's verdict as a second opinion, in the same report and under the
same policy. Three independent switches, so nothing changes until you turn
all of them:

1. **App** — add `io.github.umutcansu:pinvault-play-integrity` and register
   `PlayIntegrityVerdictProvider(context, cloudProjectNumber)` (the project
   number from Play Console → App integrity). Without the artifact nothing of
   Play Services is in the APK. The provider asks Google for a classic token
   bound to the attestation nonce at most once per 6 hours (classic requests
   are quota-limited; `minInterval` sets it, 0 = every round), and a failure
   never fails an attestation.
2. **Server** — set `PLAY_INTEGRITY_DECRYPTION_KEY` and
   `PLAY_INTEGRITY_VERIFICATION_KEY` (Play Console → *Manage and download my
   response encryption keys*). The reference server opens the token itself
   (JWE A256KW/A256GCM, JWS ES256), checks nonce, age, package, app
   recognition and device level, stores Google's summary with the device
   and shows it in the dashboard. Nothing goes to Google on the request path.
3. **Policy** — `play_integrity` (the verdict failed, or the token did not
   verify) and `play_integrity_missing` (no verdict within
   `PLAY_INTEGRITY_MAX_AGE_SECONDS`, 24 h) are `warn` by default; `reject`
   when the fleet is ready, `ignore` to only record.

Details, reasons and the rollout order are in
[ATTESTATION.md §11](ATTESTATION.md#11-play-integrity-optional).

### Managed trust roots *(2.3)*

Approov's "managed trust roots", in PinVault terms: the signed config may
carry `trustRoots`, SHA-256 SPKI pins of root CAs (the same form as pins).
With `managedTrustRoots()` on the config, a host that has **no pin entry** is
accepted when the platform's CAs validate its chain **and** the chain the
platform validated contains a listed root, and the leaf names the host.
The device's trust store stops being the authority for such hosts: a CA a
user or an attacker added to the device is not in the list, and a root you
stop listing stops being trusted on the next config, without an app update.
Hosts with a pin entry are unchanged; pins stay the stricter choice.

```kotlin
PinVaultConfig.Builder()
    .managedTrustRoots()
```

The reference server's pin-config form and `PUT /api/v1/certificate-config`
take the list (`"trustRoots": ["…"]`); it is part of the signed payload, so a
change rolls out like a pin change. A refusal is `ManagedTrustRootException`
in the handshake error's cause and earns the recovery interceptor's
"unknown host" budget (one refetch per window), since a fresh config may
list the root.

## Server

### Reference implementation (Docker)

```bash
cd demo-server
API_KEY=your-secret SIGNING_KEY_PASSWORD=second-secret KEYSTORE_PASSWORD=third-secret \
  VAULT_AT_REST_PASSWORD=fourth-secret docker compose up
```

Dashboard: `http://localhost:8080`
API docs (Swagger): `http://localhost:8080/docs`
Config API (TLS): `https://localhost:8081`

`API_KEY` is required. In production also set `KEYSTORE_PASSWORD`,
`SIGNING_KEY_PASSWORD` and `VAULT_AT_REST_PASSWORD`: unset, their defaults
are public or leave keys in plain text. Every variable (enrollment, rate
limits, attestation, Play Integrity, the setup wizard) and where the data
lives: [demo-server/README.md](demo-server/README.md).

The dashboard's *Setup Wizard* *(2.3)* lists what a production server still
lacks and writes the app's PinVault configuration from the server's own
pins and keys. The optional signing and governance layers (named admins,
two-person approval, the live-certificate check, webhooks, HSM/KMS signers,
signing-key sets) are off by default and documented in
[SECURE_OPERATIONS.md](SECURE_OPERATIONS.md).

### Build your own server

See [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md) for the API contract. Pinning alone needs 2 endpoints:

1. `GET /health` — return `{"status":"ok"}`
2. `GET /api/v1/certificate-config` — return a signed envelope `{payload, signature}` whose payload includes `issuedAt`/`expiresAt` (ECDSA-SHA256 with a P-256 key). The library refuses unsigned/missing-freshness responses unless the caller explicitly opts in via `allowUnsigned()`.

Add these for the features you use:

3. mTLS — `POST /api/v1/client-certs/enroll`. With `X-PinVault-Features: csr` and a `csr` field *(2.1, the default)*: sign the device's own key and answer with the certificate chain — leaf, then the CA certificate that signed it — as JSON (`X-PinVault-Cert-Format: pem-chain`); renew at `POST /api/v1/client-certs/renew`. *(2.2)* Verify the request's `attestationChain` (challenge SHA-256 of `pinvault-identity-key:v1:<deviceUid>`), and answer a request without a `csr` `403 csr_required`: a PKCS12 answer (with `X-P12-SHA256`, optionally `X-P12-Password`) is taken only by apps that call `allowServerGeneratedKey()`. To make a device wait for an administrator, answer `202` with a `requestId` *(2.1)*; the code to show next to it is 16 characters *(2.2)*. Details in [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md).
4. VaultFile — `GET /<your vault endpoint>`: the file bytes with `X-Vault-Version` and, for signed blocks, `X-Vault-Signature` *(2.1, see [Signed vault files](#signed-vault-files-21))* and `X-Vault-Signature-V2`, which names the Config API *(2.2; required by blocks that set `serverScope`)*.
5. Per-device encryption — `POST /api/v1/vault/devices/{deviceId}/public-key` to register the device key, then encrypt responses with it. Decide who may replace a registered key: the reference server takes a client certificate bound to the device, or over TLS the first key plus `X-Vault-Key` / `X-Vault-Token` (the device's token for an `end_to_end` file) for a replacement. Without a credential, bound what a caller can store: the reference server takes only RSA 2048–4096 keys, a quota per source address and a cap per Config API.

On a client-authenticated listener, treat `X-Device-Id` as a claim to check against the certificate (the device it enrolled as), not as the identity: it selects per-device pins and token checks.

Works with any language: Python, Node.js, Go, .NET, etc.

## Requirements

| Tool                  | Minimum |
| --------------------- | ------- |
| Android `minSdk`      | 24 (Android 7.0+) |
| Kotlin (consumer)     | 1.9.0   |
| Android Gradle Plugin | 8.2     |
| Gradle                | 8.2     |
| JDK                   | 17      |
| OkHttp                | 4.x     |

iOS: iOS 16+, Swift 6 toolchain (Xcode 16 or newer), no third-party dependencies.

PinVault `2.0.0+` is compiled with Kotlin 2.1 but emits Kotlin 1.9
metadata, so projects on Kotlin 1.9.x through 2.x can depend on it without
metadata-version errors.

Build errors such as `Unable to read Kotlin metadata`, Java code that stops
compiling after an upgrade from 1.x, and the notes for every upgrade since
2.0 are in [MIGRATION.md](MIGRATION.md).

## Production Security Checklist

PinVault is built around OWASP MASVS guidelines (NETWORK, CRYPTO, STORAGE).
Before shipping to production, verify the following:

### 1. Never ship a server-side keystore password
*(2.1)* Enrollment and host client certificate downloads ask for a one-off P12
password (`X-PinVault-Features: p12password`). A backend that returns it in
`X-P12-Password` (the reference server does) never needs the app to know a
password of its own: the library opens the bundle with it.
Do not wrap device P12s with the password protecting your server's keystores.

*(2.2)* The key in such a bundle is then imported into the Android
Keystore as a non-exportable key and only the certificate chain is stored;
no P12 stays in app storage (see
[The device keeps its key](#the-device-keeps-its-key-21)). Prefer not to
receive private keys at all: enroll with the default CSR flow, and leave
`allowServerGeneratedKey()` off.

For a P12 you hand over yourself (`clientKeystore(bytes, password)`), the
`"changeit"` default is a development placeholder: use a unique high-entropy
password per device, delivered out of band — never hard-code it in the APK.

```kotlin
// ❌ Don't
.configApi("api", url) { clientKeystore(p12Bytes) }

// ✅ Do
val devicePassword = backend.fetchKeystorePassword(deviceId) // ≥ 16 random chars
.configApi("api", url) {
    bootstrapPins(bootstrap)
    signaturePublicKey(SIGNING_KEY)
    clientKeystore(p12Bytes, devicePassword)
}
```

### 2. Keep debug logging out of release builds
The library logs every pin verification, enrollment and vault file operation
through [Timber](https://github.com/JakeWharton/timber), which stays silent
until a tree is planted. Plant one (or call `PinVault.enableDebugLogging()`,
see Getting started step 5) only when `BuildConfig.DEBUG` is true.

### 3. Always use bootstrap pins for the first connection
Without bootstrap pins, the first config fetch is unpinned (vulnerable to MITM
on first install). *(2.2)* `init` enforces it, however the config
object was built: a Config API block must use `https://` (also for
`enrollmentUrl` / `renewalUrl`) and carry bootstrap pins, or `init` returns
`Failed` and the block's client refuses to connect. Tests against a local
plain-HTTP server opt out with `allowUnpinnedConfigApi()` on the block (a
release build refuses it unless the block also calls `allowRelaxationsInRelease()`).
Hardcode at least 2 SHA-256 SPKI hashes in the APK:

```kotlin
.configApi("api", "https://api.example.com/") {
    bootstrapPins(listOf(
        HostPin("api.example.com", listOf("primary...", "backup..."))
    ))
    signaturePublicKey(SIGNING_KEY)   // see 4.
}
```

### 4. Enable ECDSA signature verification on configs
Without `signaturePublicKey()`, a compromised backend can serve any pins it
wants. Sign your configs server-side with ECDSA P-256 and ship the public key
in the APK:

```kotlin
.configApi("api", url) {
    bootstrapPins(...)
    signaturePublicKey("MFkwEwYHKoZI...") // X.509 public key, Base64
}
```

See `SERVER_IMPLEMENTATION_GUIDE.md` for the signing protocol.

**Name the Config API the configs are for** *(2.2)*. One signing
key often signs for several Config APIs, and a config signed for another of
them has a valid signature here too. With `serverScope("default-tls")` on
the block (the server-side Config API id), a signed config must carry
`"configApiId": "default-tls"` in its signed payload or it is refused. Not
set: the field is ignored. Needs a server that writes the field (the
reference server does).

```kotlin
.configApi("api", url) {
    bootstrapPins(...)
    signaturePublicKey("MFkwEwYHKoZI...")
    serverScope("default-tls")
}
```

What a block that runs unsigned (`allowUnsigned()`) gives up: the signature,
replay protection and expiry (unless its configs carry `issuedAt` /
`expiresAt` anyway), `serverScope`, and the integrity check on the stored
config. Host-name and pin validation, the version checks and the
per-request connection check apply in every mode. Vault file signatures are
checked whenever a key is configured (on the block or the file), with or
without `allowUnsigned()`; only a block with no key at all skips them.

Optional, stronger setups *(2.1)* — each off by default, pick what your team can run
(details and runbooks in [`SECURE_OPERATIONS.md`](SECURE_OPERATIONS.md)):

```kotlin
.configApi("api", url) {
    bootstrapPins(...)
    signaturePublicKeys(SERVER_KEY, OFFLINE_BACKUP_KEY) // switch keys without an app update
    requiredSignatures(2)                                // m-of-n: no single signer can publish
    recoveryPublicKeys(RECOVERY_KEY)                     // rotate / revoke signing keys over the air
}
```

`PinVault.signingStatus()` reports what a device currently trusts (key ids,
required count, applied key-set version, who signed the last config).

**Pins and a CA** *(2.2)*. Whoever holds the config signing key
decides the pins, so a stolen signing key can pin an attacker's certificate
for any host. For hosts with certificates from a public CA, ask for both:

```kotlin
PinVaultConfig.Builder()
    .requireCaTrust("api.example.com", "*.cdn.example.com", "pay.example.com:8443")
```

For a listed host the chain must match a pin AND be trusted by the
platform's CAs (the system store, as your network security config shapes
it). The setting is compiled into the app; nothing the server sends turns it
off. Patterns follow the pin syntax; a wildcard may carry a port
(`*.example.com:443` covers that port only), for pins as well. Don't list hosts with self-signed or
private-CA certificates (such as the reference server's own listeners): they
would fail. A refusal surfaces as `CaTrustException` in the handshake error's
cause, and is not retried with a fresh config.

The reference server adds HSM (PKCS#11) and KMS signers, sign-once-per-publish,
named admins with a hash-chained audit log, webhook alerts, two-person
approval for pin changes and a live-certificate gate that refuses pin sets the
host would fail — all switched on with environment variables.

### 5. Backup exclusion — automatic

Client certificates, the vault file store, signing-key sets and the stored pin
configs are excluded from cloud backup and device-to-device transfer via
`pinvault_backup_rules.xml` and `pinvault_data_extraction_rules.xml`. The
manifest merger pulls both in automatically.

From 2.1 every store lives in one of four fixed files (`pinvault_secure_config.xml`,
`pinvault_secure_client_cert.xml`, `pinvault_secure_signing_keys.xml`,
`pinvault_secure_vault_files.xml`), so the rules cover any Config API id.
PinVault 2.0.x kept each block's config in its own
`ssl_cert_config_<configApiId>.xml`, which the rules could only name for the
library's own ids; those files are moved and deleted on the first start of the
new version.

### 6. Verify TLS configuration on your backend
- TLS 1.2 or higher (1.3 preferred). *(2.2)* The library enables
  TLS 1.2 and 1.3 only, whatever the client's `ConnectionSpec` says, and no
  longer caps connections at 1.2: with TLS 1.3 (Android 10+) the device's
  client certificate, whose subject names the device, is no longer sent in
  the clear
- *(2.2)* The device's client certificate is presented to the
  Config API's own listeners (config, enrollment and renewal URLs), to hosts
  whose pin entry has `mtls: true`, and — their own certificate — to hosts
  with a host-specific client certificate. Any other pinned host that asks
  for a client certificate gets none
- Server certificate matches at least one pinned SHA-256(SPKI) hash
- mTLS endpoints reject unknown client certs
- HTTP-only endpoints are off (the library refuses cleartext HTTPS hosts)

### 7. Rotate pins ahead of expiry
Configure at least 2 different pins per host (primary + backup; *(2.3)* the
same hash twice is refused). From 2.1 a pin
may be the leaf's key or the key of a CA the leaf chains to (checked on the device), so
pinning your CA survives leaf renewals. *(2.3)* An issuer pin also
requires the leaf to be issued for the host (a matching `subjectAltName`),
checked by the library itself: a pin on a public CA's key would otherwise
accept any site's certificate, and an app that relaxed its own
`HostnameVerifier` would not notice. A leaf pin needs no name — the key is
the identity. Add the new pin to the
config 30+ days before the old certificate expires. Set `forceUpdate: true`
on the host entry to force clients to refresh immediately.

There are two flags. `forceUpdate` on a host entry makes the device apply the
config even when nothing else changed (same pins, same versions). The
config-level `forceUpdate` (the top-level field of the payload) is the one the
device keeps and checks at start, as described next. The reference server
sets the config-level flag whenever any host entry has one, so with it the
two go together; a backend of your own decides each separately.

**`forceUpdate=true` availability trade-off.** A client that holds a
config with the config-level `forceUpdate=true` refuses to initialize when
the backend is unreachable — the previously cached config is treated as untrusted
because the server already declared it superseded. This is intentional:
the flag exists to revoke compromised pin sets and must not silently
fall back to the very config it is trying to revoke. The cost is
availability: an attacker who can sustainably DoS the Config API can
prevent affected devices from coming up. Mitigate by keeping the
Config API behind diverse routes (multiple regions / CDN cache) and
reserving `forceUpdate=true` for genuine revocation events rather than
routine rotations.

### 8. Bind the identity to real devices *(2.2)*

- On the server, **enforce the enrollment key attestation** with your app's
  package name and signing certificate. Until you do, a token is enough to
  enroll from anything that can make an HTTPS request.
- **Pin the client CA** (`clientCaPins(...)`), so nobody who gets hold of the
  enrollment or renewal listener's TLS key can hand devices certificates of
  their own.
- Give files that matter an **offline lifetime** (`maxOfflineAge`,
  `wipeWhenStale()`) and turn on `wipeVaultFilesOnRevocation()`.
- Set `serverScope(...)` on every block, so configs and vault files signed
  for one Config API are not accepted by another.
- **Mint each enrollment token for one phone** (its device id), so a token
  that leaks cannot be used to pose as another device.
- Name the hosts that may see the client certificate with
  `clientCertHosts(...)`.
- **iOS fleets: configure App Attest before you enforce.** An iPhone has no
  Android Key Attestation chain, so a server that enforces one (enrollment,
  screen-lock keys, attestation registration) refuses every iPhone until
  App Attest is configured (`APP_ATTEST_APP_IDS`, `APP_ATTEST_ROOT_CA_FILE`
  with Apple's App Attestation Root CA, `APP_ATTEST_ENVIRONMENT=production`);
  the reference server warns at start. App Attest then stands in for the
  chain, verified separately for each request. It proves your genuine app on
  genuine Apple hardware — not that the phone is not jailbroken, and not
  where the keys live; for high-value apps add a RASP product
  ([ATTESTATION.md §12](ATTESTATION.md#12-apple-app-attest-optional-ios)).

### 8b. Know — or require — where the keys live *(2.3)*

The library asks the Keystore for StrongBox first and the TEE next, but
where the key ends up is the Keystore's decision; a ROM that can do neither
hands out a software key a rooted device can copy. Every key the library
makes is now read back (`KeyInfo`) and its level logged. It is reported as
`KeySecurityLevel` (`STRONGBOX`, `TRUSTED_ENVIRONMENT`, `SOFTWARE`,
`UNKNOWN`) on `ClientCertEnrollmentResult.Enrolled.keySecurityLevel`, from
`PinVault.identityKeySecurityLevel()`, and in the attestation report the
server sees. To refuse anything but hardware:

```kotlin
PinVaultConfig.Builder()
    .requireHardwareBackedKeys()
```

A `SOFTWARE` or `UNKNOWN` key is then deleted again and the operation fails
with `HardwareBackedKeyRequiredException`: enrollment, vault-file and
imported keys, the user-auth key, and the store keys made on first use
(`init` returns `Failed`). Keys that already exist are used as they are.
Emulators have no secure hardware, so leave this off in emulator builds.

### 9. (Optional) Keys that work only while the phone is unlocked *(2.2)*

```kotlin
PinVaultConfig.Builder()
    .requireUnlockedDevice()
```

The Keystore keys the library generates from then on — the mTLS identity
key, the per-device vault key, the keys of the encrypted stores and of
`ENCRYPTED_FILE` vault files, keys imported from a P12 — are usable only
while the device is unlocked (`setUnlockedDeviceRequired(true)`, Android 9+;
ignored on 7 and 8). A phone that is locked, lost or lying on a desk then
decrypts nothing PinVault stored and cannot present its client certificate,
whoever runs code on it.

What it costs: **background work behind a locked screen fails** until the
user unlocks the phone, and the library reports it like any other failure —
nothing is deleted, and the next run after an unlock works:

| What runs while locked | What you get |
|---|---|
| periodic update (WorkManager) | `UpdateResult.Failed` to `OnUpdateListener`, a `ConfigUpdate` event with `FAILED`; the worker retries |
| `syncAllFiles()` / `fetchFile()` | `VaultFileResult.Failed` |
| `init` in a process started while locked | `InitResult.Failed` ("storage is locked while the device is locked"); call `init` again after `ACTION_USER_PRESENT` |
| `loadFile()` | `null`, `fileStatus()` = `STORAGE_UNAVAILABLE` |
| a request through `getClient()` to an mTLS host | the handshake fails (`SSLHandshakeException`) |

It applies to keys generated after you turn it on. Existing installs keep
the keys they have (usable while locked) until those are replaced: the
identity key at the next enrollment, the store keys when the app's data is
cleared. A phone without a screen lock has nothing to unlock, so the option
changes nothing there. Call `init` (or the config overloads of `enroll` /
`isEnrolled`) with this config before anything else touches PinVault, since
the first use creates the keys.

**When the Keystore refuses such a key** (a ROM that does not support
`setUnlockedDeviceRequired`), the operation that needed the key fails with
`UnlockedDeviceKeyRequiredException` — `init` returns `Failed` for the
store keys, enrollment and vault files report `Failed` with that cause —
and the error is logged. You asked for keys that work only while the
device is unlocked; a key made without that requirement would not be what
you asked for, and until 2.3.0 the library made one anyway with only a
warning. To keep that behaviour, opt into it:

```kotlin
PinVaultConfig.Builder()
    .requireUnlockedDevice(allowFallback = true)   // Java: requireUnlockedDevice(true)
```

The key is then made without the requirement and a warning is logged, as
before. Decide per app: a device whose Keystore cannot make the key is a
device on which the option protects nothing.

### 10. Bypass protection *(2.3)*

Pinning stops an attacker on the network. On a device the attacker controls
(root, Frida, Xposed, a repackaged app) code inside the app can switch the
pin check off. PinVault answers that in three layers:

1. **Your detection, asked at the right moments.** PinVault detects nothing
   itself; wire your RASP product's or RootBeer's verdict into
   `environmentGuard`. It is asked before every `GuardedOperation` and a `false`
   refuses that operation (`Failed` with `UntrustedEnvironmentException`;
   nothing sent, no token spent). A guard that throws refuses.

   ```kotlin
   PinVaultConfig.Builder()
       .environmentGuard { operation ->
           // Keep pinned traffic working; no enrollment, downloads or unlocks on a compromised device.
           operation == GuardedOperation.INIT || !shield.isCompromised()
       }
   ```

   | Operation | Asked before | Refused as |
   |---|---|---|
   | `INIT` | `init` | `InitResult.Failed` |
   | `ENROLL` | every enroll / autoEnroll / checkPendingEnrollment, the pending pick-up at init and on updates | `ClientCertEnrollmentResult.Failed` |
   | `FETCH_FILE` | `fetchFile`, `syncAllFiles`, the periodic sync | `VaultFileResult.Failed` (reported to the server like any failed fetch) |
   | `UNLOCK_FILE` | `unlockFile`, before the prompt | `VaultFileUnlockResult.Failed` |
   | `LOAD_FILE` | `loadFile` (reading a stored copy, no network) | `null`; the copy is not decrypted and stays stored |

   A guard can be bypassed on a device the attacker controls: keep files
   that matter behind `userAuth` as well, so their content is only handed
   out by `unlockFile`. The sample app wires
   all of this (`sample-client/.../App.java`, `harden`): a small in-app
   check (`DeviceShield`) as the guard, `expectedSignerSha256` from its
   host properties, and `requireUnlockedDevice()` /
   `requireHardwareBackedKeys()`, always on in its release build.

2. **A verdict the device cannot forge, judged by the server.** A check inside
   the app can be hooked too. `integrityTokenProvider` sends a Google Play
   Integrity token (or a RASP product's attestation) with every enrollment,
   bound to that request's CSR and device id. The reference server decodes it
   with `INTEGRITY_VERIFIER_COMMAND` (`scripts/play-integrity-verify.sh`) and,
   under `INTEGRITY_VERIFICATION=enforce`, issues no certificate to a rooted
   device or an app that did not come from Play. A refusal is
   `EnrollmentRefusal.ATTESTATION_FAILED` with `serverError`
   `integrity_required` or `integrity_invalid`.

   ```kotlin
   val integrity = IntegrityManagerFactory.createStandard(context)
   // prepare once at app start (Tasks.await on a background thread, or a callback)
   val provider = Tasks.await(integrity.prepareIntegrityToken(
       PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(CLOUD_PROJECT_NUMBER).build()))

   PinVaultConfig.Builder()
       .integrityTokenProvider { requestHash ->   // called on a background thread
           Tasks.await(
               provider.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()),
               10, TimeUnit.SECONDS
           ).token()
       }
   ```

   The request hash is `base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))`
   (unpadded, 43 characters), where `deviceId` is the request's `deviceUid`,
   else its `deviceId`. A server built from scratch recomputes it from the
   request ([SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md)).

3. **Less to take when it is bypassed.** Keys stay in the Keystore and are
   attested at enrollment (§8), files can need the screen lock (§9,
   `userAuth`), a revoked device loses its files, and configs expire.

### What PinVault does NOT do
- **Hardened, self-checking probes.** The attestation report *(2.3)*
  does look for root, emulators, debuggers, Frida/Xposed-style hooking,
  cloners and a changed signer — but with plain Kotlin an attacker can hook.
  What holds it up is the server side: the report must be signed by a
  hardware-attested Keystore key, the server adds signals the device cannot
  forge, and Play Integrity can be verified as a second opinion. For
  high-value targets add a packer or a dedicated RASP on top.
  (`userAuth` vault files with `encryption(USER_AUTH)` stay sealed on a
  rooted phone until the user unlocks them, but what the app then reads is
  in its memory.)
- **A detector of its own beyond those probes** — a RASP product or RootBeer
  can veto init, enrollment, downloads and unlocks through `environmentGuard`
  *(2.3)*, and `integrityTokenProvider` sends a Play Integrity token
  with every enrollment for the server to enforce
- **Code obfuscation** — enable R8/ProGuard in your app (`isMinifyEnabled = true`)
- **Network anomaly detection** — pair with your APM/SIEM
- **A verdict without Google or a server of your own** — the device alone
  cannot prove its integrity; the policy, the token and Play Integrity all
  live on the server.

