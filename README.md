# PinVault

Dynamic SSL certificate pinning library for Android. Manage pins remotely, support mTLS, distribute versioned files — all with encrypted storage.

> **Latest release: 2.0.9.** This README follows the `main` branch, which is
> heading for **2.1**. Anything marked *(2.1)* is not in 2.0.9 yet — using it
> against the 2.0.9 artifact fails to compile. See [CHANGELOG.md](CHANGELOG.md)
> ("Unreleased") for the full list and [MIGRATION.md](MIGRATION.md) for the
> DSL reference.

## Features

- **Dynamic pin management** — fetch pins from your server, per-host versioning, force update
- **Bootstrap pinning** — hardcoded pins for initial connection security
- **mTLS support** — mutual TLS with token-based or automatic device enrollment
- **Device-held client keys** *(2.1)* — the mTLS key is generated in the Android Keystore and never leaves it; certificates come from a CSR and renew themselves, through a recovery door once expired
- **Fleet enrollment** *(2.1)* — one enrollment code for many devices, optional administrator approval with a verification code shown on both sides, applications without a code (like a router's MAC filter), and forgetting a revoked identity so its client id can enroll again
- **Pin mismatch recovery** — automatic config refresh and retry on pin failure
- **Multi-Config-API** *(v2)* — register N Config APIs, bind each vault file to a specific one
- **Server-side pin scoping** *(v2)* — `wantPinsFor(...)` + per-device ACL, least-privilege
- **VaultFile** — remote versioned file distribution (ML models, configs, feature flags)
- **Per-file access policies** *(v2)* — `public` / `api_key` / `token` / `token_mtls`
- **Per-device encryption** *(v2)* — RSA-OAEP-SHA256 + AES-256-GCM, Android Keystore-backed: only the target device opens a download (the server encrypts it, so it sees the content)
- **Encrypted storage** — values AES-256-GCM, names HMAC-SHA256, both keys generated in the Android Keystore (hardware-backed) and never leaving it *(2.1; 2.0.x uses EncryptedSharedPreferences)*
- **Server-agnostic** — works with any backend, or offline with static pins
- **ECDSA signed configs** — verify config integrity with SHA256withECDSA
- **Signed vault files** *(2.1)* — every downloaded file is checked against the Config API's signing keys before it is saved
- **Issuer pins** *(2.1)* — pin your CA's key and survive leaf renewals
- **Optional signing layers** *(2.1)* — backup keys, m-of-n signatures, signing-key rotation/revocation over the air ([SECURE_OPERATIONS.md](SECURE_OPERATIONS.md))

## Quick Start

### 1. Add dependency

```gradle
implementation("io.github.umutcansu:pinvault:2.0.9")
```

> Kotlin 1.9.x consumer projects: use `2.0.3` or later — older 2.0.x
> versions emit Kotlin 2.1 metadata in their POM and trigger
> `Unable to read Kotlin metadata due to unsupported metadata version`.

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
import io.github.umutcansu.pinvault.PinVaultConfig;
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
        return Unit.INSTANCE;
    })
    .build();

PinVault.init(context, config, result -> {
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

#### Reading the current pins (multi-module setups)

If your HTTP client lives in a separate Gradle module that doesn't depend
on PinVault — e.g. a lean `:network` module behind an interface — pass the
raw pin set across the module boundary:

```kotlin
// In :app — orchestrate PinVault, hand pins to network module
PinVault.init(this, config) {
    NetworkModule.applyPins(PinVault.currentPins)
}
PinVault.setOnUpdateListener {
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
                // Config rotation outcome — fires once per updateNow /
                // WorkManager refresh / recovery-driven swap.
                // event.status (UPDATED / UNCHANGED / FAILED),
                // event.newVersion, event.failureReason
                MyAnalytics.reportRotation(event)
            }
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
    .reportToPinVaultBackend("http://192.168.1.80:6650/")
    .configApi("api", "https://api.example.com/") { ... }
    .build()
```

The reporter POSTs **one event per TLS handshake** by default, which
scales poorly to a production fleet. Two opt-in knobs cut that down:

```kotlin
// Heartbeat throttle — at most one healthy report per (host, version,
// cert) tuple per minute; pin mismatches always go through.
.reportToPinVaultBackend(
    managementUrl = "http://192.168.1.80:6650/",
    dedupWindowMs = 60_000L
)

// Anomalies only — drop the healthy stream entirely; only pin
// mismatches and config-update failures reach the backend.
.reportToPinVaultBackend(
    managementUrl = "http://192.168.1.80:6650/",
    reportSuccessEvents = false
)
```

#### Pinning the reporter's own HTTP traffic

`reportToPinVaultBackend(...)` and the bare `PinVaultBackendReporter(...)`
constructor both default to an `OkHttpClient` with **system trust** — no
pinning on the telemetry POSTs themselves. For production fleets an
attacker on path could drop the pin-mismatch reports (silencing your
detection channel) or tamper with healthy-handshake payloads.

There are two ways to pin the reporter. Pick by where the management
endpoint lives relative to the Config API.

**Option A — Same host as the Config API.** If the reporter's URL
shares its hostname with the Config API (only the port differs), the
server is already returning a pin entry for that host in its
`/api/v1/certificate-config` response. Reuse PinVault's dynamic trust
manager by passing a builder it pinned, attaching the reporter once
init has loaded the config:

```kotlin
PinVault.init(context, config) { result ->
    if (result !is InitResult.Ready) return@init

    val pinnedClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .also { PinVault.applyTo(it) }   // dynamic TM + recovery interceptor
        .build()

    PinVault.setConnectionListener(
        PinVaultBackendReporter(
            managementUrl = "https://management.example.com/",
            httpClient = pinnedClient,
            reportSuccessEvents = false,
            dedupWindowMs = 60_000L
        )
    )
}
```

Prerequisite: the active config must contain a pin entry for the
management hostname. If it doesn't, the trust manager fails closed and
every reporter POST throws `CertificateException: No pin entry for
hostname 'management.example.com'`. Confirm with
`curl https://management.example.com:.../api/v1/certificate-config?currentVersion=0`
and look for the host under `pins`.

**Option B — Management endpoint is a separate host with its own cert.**
PinVault's per-host pin scoping won't cover this hostname, so the
reporter can't piggyback on `PinVault.applyTo`. Use OkHttp's built-in
`CertificatePinner` with a build-time pin instead:

```kotlin
val managementPin = "sha256/xyzABC..."   // extract with openssl, hardcoded

val pinnedClient = OkHttpClient.Builder()
    .connectTimeout(5, TimeUnit.SECONDS)
    .readTimeout(5, TimeUnit.SECONDS)
    .certificatePinner(
        CertificatePinner.Builder()
            .add("management.example.com", managementPin)
            .build()
    )
    .build()                              // no PinVault.applyTo on this builder

PinVault.setConnectionListener(
    PinVaultBackendReporter(
        managementUrl = "https://management.example.com/",
        httpClient = pinnedClient,
        reportSuccessEvents = false
    )
)
```

Extract the pin with:

```bash
openssl s_client -servername management.example.com -connect management.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Do **not** chain `PinVault.applyTo` on the same builder as
`certificatePinner`: PinVault installs a custom `X509ExtendedTrustManager`
to work around the Android/Conscrypt empty-`getPeerCertificates` issue,
and OkHttp's `CertificatePinner` reads from that same source — so the
two pinning paths are mutually exclusive on a single client. Pick one.
Option B trades dynamic pin rotation (no longer driven by PinVault
config swaps) for not needing the management host in the server's pin
response.

**Option C *(2.1)* — the endpoint shares a certificate you already pin.** When the
report endpoint is served with the Config API's own certificate (the
reference server's `MANAGEMENT_HTTPS_PORT` does exactly that), pin it with the
bootstrap pins you already ship. `pinnedClient` works with self-signed
certificates (`CertificatePinner` needs system trust first), and its
handshakes raise no connection events, so the reporter never reports its
own traffic:

```kotlin
PinVault.setConnectionListener(
    PinVaultBackendReporter(
        managementUrl = "https://192.168.1.80:6655/",
        httpClient = PinVaultBackendReporter.pinnedClient("192.168.1.80", listOf(primaryPin, backupPin)),
        reportSuccessEvents = false
    )
)
```

For Java consumers the event subtype check looks like:

```java
.onConnectionEvent(event -> {
    if (event instanceof PinVaultConnectionEvent.Connection) {
        PinVaultConnectionEvent.Connection c = (PinVaultConnectionEvent.Connection) event;
        myAnalytics.report(c.getHostname(), c.getSuccess(),
                           c.getPinVersion(), c.getDeviceManufacturer(),
                           c.getDeviceModel());
    } else if (event instanceof PinVaultConnectionEvent.ConfigUpdate) {
        PinVaultConnectionEvent.ConfigUpdate u = (PinVaultConnectionEvent.ConfigUpdate) event;
        myAnalytics.reportRotation(u.getStatus(), u.getNewVersion(),
                                   u.getFailureReason());
    }
})
```

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

### Multi-Config-API

One app can talk to multiple Config APIs — each with its own TLS pipeline,
bootstrap pins, and (optional) mTLS keystore. Each vault file then binds to a
specific API via `configApi("<id>")`.

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("prod-tls", "https://host:8091/") {
        bootstrapPins(prodTlsPins)
        wantPinsFor("cdn.example.com", "api.example.com")
    }
    .configApi("secure-mtls", "https://host:8092/") {
        bootstrapPins(secureMtlsPins)
        clientKeystore(p12Bytes, devicePassword)     // mTLS client cert
        wantPinsFor("internal.acme.com")
    }
    .vaultFile("feature-flags") {
        configApi("prod-tls")                         // bind to TLS API
        endpoint("api/v1/vault/feature-flags")
    }
    .vaultFile("ml-model") {
        configApi("secure-mtls")                      // bind to mTLS API
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

### Custom endpoints

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://myserver.com/") {
        bootstrapPins(listOf(...))
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
    }
    .build()

PinVault.init(context, config, MyApi()) { result -> /* ... */ }
```

If you serve vault files through a custom API, override
`downloadVaultFileWithMeta(...)` rather than only `downloadVaultFile(...)`:
the default wrapper returns version `0` and no signature, and *(2.1)* a block
with a signing key refuses an unsigned vault file (see
[Signed vault files](#signed-vault-files-21)). Return the signature in
`VaultFetchResponse(content, version, encryption, signature = …)`.

The default implementation (`DefaultCertificateConfigApi`) speaks the HTTP
contract described in [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md)
and is sufficient for the reference server.

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
   verificationCode)` and waits. It shows the verification code, a short
   code made from its own key (`4F7K-2QXM`; also
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
        EnrollmentRefusal.OTHER -> "Refused: HTTP ${result.httpStatus} ${result.serverError.orEmpty()}"
    }
    is ClientCertEnrollmentResult.Pending -> "Waiting for an administrator to approve this device."   // see above
    is ClientCertEnrollmentResult.Failed -> "Could not enroll: ${result.message}" // network, pins, key store
}
```

A refused enrollment does not spend the token. A custom `CertificateConfigApi`
reports a refusal by throwing `EnrollmentRefusedException(httpStatus,
serverError, serverMessage)`; anything else it throws becomes `Failed`.

### The device keeps its key *(2.1)*

Enrollment generates an EC P-256 signing key in the Android Keystore and
sends the server a certificate signing request over it (`X-PinVault-Features:
csr`). The server answers with a certificate chain; the private key never
leaves the device. A server that does not understand CSRs answers the same
request with a P12, which is stored as before — one request either way, so a
one-time token is never spent twice. Custom `CertificateConfigApi`
implementations take part by overriding `enrollWithCsr` and
`renewClientCert` (both have defaults; Java implementers delegate the rest to
`CertificateConfigApi.DefaultImpls`).

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
place and the app should enroll again with a fresh token. A renewed
certificate must come from the CA that issued the current one; a chain from
any other CA is refused even if it arrives with its own CA attached. Removing the app
deletes the Keystore key, so a reinstall is a new enrollment, never a renewal.

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

`PinVault.reset()` drops the active and stored config; the next `init` starts
from the bootstrap pins again (clients built earlier refuse handshakes until
then — pinning never falls back to system trust).

## VaultFile (Remote File Distribution)

```kotlin
val config = PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") {
        bootstrapPins(listOf(...))
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
    .deviceAlias("Warehouse Tablet #3")
    .build()

// Fetch
val result = PinVault.fetchFile("ml-model")

// Load cached
val bytes = PinVault.loadFile("ml-model")
val json = PinVault.loadFileAsString("feature-flags")

// Housekeeping
PinVault.syncAllFiles()               // fetch every registered file
PinVault.hasFile("ml-model")          // cached copy present?
PinVault.fileVersion("ml-model")      // cached version (0 = none)
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
- Blocks with `allowUnsigned()` skip the check (and log a warning).

### Per-file access policies (v2)

```kotlin
.vaultFile("private-doc") {
    configApi("api")
    endpoint("api/v1/vault/private-doc")
    accessPolicy(VaultFileAccessPolicy.TOKEN)         // public | api_key | token | token_mtls
    accessToken { secureTokenStore["private-doc"] }   // lazy token provider
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

## Device Tracking

```kotlin
PinVaultConfig.Builder()
    .configApi("api", "https://api.example.com/") { bootstrapPins(listOf(...)) }
    .deviceAlias("Warehouse Tablet #3")              // shown in server dashboard
    .build()
```

Server dashboard shows which device has which certificate and vault file version.

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

Data lives under `demo-server/data/` (`db/`, `certs/`, `keys/signing-key.pem`).
The compose file passes through the variables in the two tables below; add any
other one to its `environment:` list. Upgrading from a checkout that mounted
`./data/signing-key.pem`: move that file to `./data/keys/signing-key.pem`
before starting, or the server generates a new key and every device rejects
its configs.

#### Required env vars

| Variable | Required? | Purpose |
|---|---|---|
| `API_KEY` | Required | X-API-Key header value for management endpoints. Server refuses to start when unset — pass `ALLOW_ANONYMOUS_ADMIN=true` to opt out (dev only). |

#### Optional env vars

| Variable | Default | Purpose |
|---|---|---|
| `SIGNING_KEY_PASSWORD` | unset | AES-256-GCM encrypts the ECDSA signing key on disk (PBKDF2-SHA256). When unset, the key is written plaintext + chmod 600 + warning logged. Existing plaintext keys are auto-migrated on startup. |
| `KEYSTORE_PASSWORD` | `changeit` | Protects the server's own keystores (TLS key, backup keys, truststore, stored host client certs). Never leaves the server. **Set it in production** — the default is public. |
| `KEYSTORE_PASSWORD_PREVIOUS` | unset | Old password when changing `KEYSTORE_PASSWORD`: keystores are re-encrypted at startup. Remove afterwards. |
| `VAULT_AT_REST_PASSWORD` | demo key | Encrypts uploaded vault files on disk. Unset uses a key that is in the source code, so the encryption is cosmetic. `VAULT_AT_REST_PASSWORD_PREVIOUS` re-encrypts after a change. |
| `CLIENT_P12_PASSWORD` | `changeit` | Password on device P12s for clients that don't negotiate a one-off one (`X-PinVault-Features: p12password`, library 2.1+). |
| `CONFIG_TTL_SECONDS` | `86400` (24h) | How long a signed config response stays valid before clients reject it as replayed. Lower = tighter replay window; too low risks rejecting cached configs from offline devices. |
| `ENROLLMENT_MODE` | `token` | `token` (production) requires an enrollment token; `open` allows deviceId-only enrollment (demo only). |
| `ENROLLMENT_TOKEN_TTL_SECONDS` | `86400` | Lifetime of a one-time enrollment token. |
| `ENROLLMENT_REQUEST_TTL_HOURS` | `24` | How long a device's request may wait for approval (enrollment codes and applications without a code); unanswered, it lapses and the device is told `410`. 1–720. |
| `OPEN_ENROLLMENT_RATE_LIMIT` | `20` | New applications without a code one source address may make per 10 minutes (`429` beyond it). Behind one NAT or proxy every device shares it; `0` turns it off. |
| `OPEN_ENROLLMENT_MAX_PENDING` | `50` | Most applications without a code waiting at once (`429` beyond it). |
| `CLIENT_CERT_TTL_DAYS` | `90` | Lifetime of certificates issued over device-held keys (CSR enrollment, library 2.1+). They renew themselves at a third of the lifetime; `KEYSTORE_PASSWORD` also protects the client CA (`client-ca.jks`). |
| `RECOVERY_PORT` | `PORT+3` | Certificate-renewal door for devices whose client certificate expired: TLS without client auth, serves only `POST /api/v1/client-certs/renew` and `/health`. Its certificate is signed by the server CA (`server-ca.jks` + `server-ca.backup.jks`) and reissued 30 days before expiry. `0` turns it off. In Docker it is 8083. |
| `ALLOW_TEST_HOOKS` | unset | `true` enables `POST /api/v1/test-hooks/client-cert-ttl` (API key), which arms a short lifetime for a client id's next certificate so tests can watch it expire. Never in production. |
| `DEVICE_KEY_RATE_LIMIT` | `30` | E2E keys a source address may write per 10 minutes over a TLS Config API, where key registration asks for no credential (`429` beyond it; a device repeating its own key is not counted). The address is the TCP peer: behind a reverse proxy, or Docker Desktop's port forwarding, every device shares one quota. Raise it for a first rollout behind one NAT or proxy; `0` turns it off. |
| `DEVICE_KEY_LIMIT` | `100000` | Most E2E keys one Config API stores; a new device beyond it gets `503`, known devices keep working. |
| `EXTRA_CERT_SANS` | unset | Comma-separated IPv4 addresses / DNS names added to every TLS certificate the server generates. Set it to the Docker host's LAN IP when running in a container — the server only sees the container's own address, and Android clients reject a certificate that does not name the IP they connect to. Applies when a certificate is (re)generated. |
| `CERT_EXPIRY_WARN_DAYS` | `30` | When `/api/v1/cert-expiry` and the dashboard start warning. |
| `MANAGEMENT_HTTPS_PORT` | unset | Also serve the management API over TLS with the Config API's certificate (the one apps already pin), so device reports and remote admins don't cross the network in the clear. Not in the compose file — add it and a port mapping. |
| `PORT` / `HTTPS_PORT` | `8080` / `PORT+1` | Management HTTP / Config API TLS ports. In Docker, change the host side instead (`PORT=9000 docker compose up`). |
| `ALLOW_ANONYMOUS_ADMIN` | unset | Set to `true` to allow startup with no `API_KEY` (anonymous admin). Logs a warning. Do not use on any network you don't control. |

The optional signing and governance layers — named admins (`ADMIN_KEYS`),
two-person approval (`PIN_CHANGE_APPROVALS`), live-certificate check
(`PIN_LIVE_CHECK`), webhooks (`NOTIFY_WEBHOOK_URL`), HSM/KMS signers
(`CONFIG_SIGNERS`, `PKCS11_*`, `SIGNER_*`), signature cache and signing-key
sets (`RECOVERY_PUBLIC_KEYS`) — are all off by default and documented with
their variables in [SECURE_OPERATIONS.md](SECURE_OPERATIONS.md).

### Build your own server

See [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md) for the API contract. Pinning alone needs 2 endpoints:

1. `GET /health` — return `{"status":"ok"}`
2. `GET /api/v1/certificate-config` — return a signed envelope `{payload, signature}` whose payload includes `issuedAt`/`expiresAt` (ECDSA-SHA256 with a P-256 key). The library refuses unsigned/missing-freshness responses unless the caller explicitly opts in via `allowUnsigned()`.

Add these for the features you use:

3. mTLS — `POST /api/v1/client-certs/enroll`. With `X-PinVault-Features: csr` and a `csr` field *(2.1, the default)*: sign the device's own key and answer with the certificate chain as JSON (`X-PinVault-Cert-Format: pem-chain`); renew at `POST /api/v1/client-certs/renew`. Otherwise PKCS12 bytes **plus** an `X-P12-SHA256` response header so the library can verify integrity (optionally `X-P12-Password`, see checklist item 1). To make a device wait for an administrator, answer `202` with a `requestId` *(2.1)*. Details in [SERVER_IMPLEMENTATION_GUIDE.md](SERVER_IMPLEMENTATION_GUIDE.md).
4. VaultFile — `GET /<your vault endpoint>`: the file bytes with `X-Vault-Version` and, for signed blocks, `X-Vault-Signature` *(2.1, see [Signed vault files](#signed-vault-files-21))*.
5. Per-device encryption — `POST /api/v1/vault/devices/{deviceId}/public-key` to register the device key, then encrypt responses with it. Decide who may replace a registered key: the reference server takes a client certificate bound to the device, or over TLS the first key plus `X-Vault-Key` / `X-Vault-Token` (the device's token for an `end_to_end` file) for a replacement. Without a credential, bound what a caller can store: the reference server takes only RSA 2048–4096 keys, a quota per source address and a cap per Config API.

On a client-authenticated listener, treat `X-Device-Id` as a claim to check against the certificate (the device it enrolled as), not as the identity: it selects per-device pins and token checks.

Works with any language: Python, Node.js, Go, .NET, etc.

## Samples

Three projects next to the library show PinVault end to end (their READMEs are in Turkish):

| Directory | What it is |
|---|---|
| [`sample-host/`](sample-host) | The demo server in Docker, set up for phones on the LAN: `./scripts/setup.sh`, then `docker compose up -d --build`. With `PINVAULT_SERVER_SRC=../demo-server` it builds the server from this checkout. |
| [`sample-client/`](sample-client) | An Android app (Java) that uses every PinVault feature against the sample host. It builds the library from this checkout (`pinvault.localPath=..`). |
| [`sample-e2e/`](sample-e2e) | Playwright end-to-end tests: an action in the host's dashboard is checked on the phone, or the other way round, with a one-file evidence page of screenshots. Setting everything up from scratch: [`sample-e2e/SETUP.md`](sample-e2e/SETUP.md). |

## Architecture

```
Android App                           Your Server
───────────                           ───────────
PinVault.init()              ───→     GET /certificate-config
  Pin config received        ←───     {pins: [{hostname, sha256[]}]}
  Stored encrypted (AES-GCM)

PinVault.getClient()         ───→     Your API endpoints
  Every request pinned                (TLS certificate verified)

PinVault.enroll()            ───→     POST /client-certs/enroll
  CSR (key stays in Keystore)         token, enrollment code or nothing
  Certificate chain          ←───     signed by the client CA
                                      (or 202: wait for approval)
  Stored encrypted

PinVault.fetchFile("key")   ───→     GET /vault/{key}
  File cached encrypted      ←───     Binary bytes
```

## Requirements

| Tool                  | Minimum |
| --------------------- | ------- |
| Android `minSdk`      | 24 (Android 7.0+) |
| Kotlin (consumer)     | 1.9.0   |
| Android Gradle Plugin | 8.2     |
| Gradle                | 8.2     |
| JDK                   | 17      |
| OkHttp                | 4.x     |

PinVault `2.0.0+` is compiled with Kotlin 2.1 but emits Kotlin 1.9
metadata, so projects on Kotlin 1.9.x through 2.x can depend on it without
metadata-version errors.

### Troubleshooting: "Unable to read Kotlin metadata"

If you see one of these errors when adding PinVault to your project:

```
warning: Unable to read Kotlin metadata due to unsupported metadata version.
error: Unable to read Kotlin metadata due to unsupported metadata kind: null.
```

it means a Kotlin compiler in your build pipeline is older than the
metadata it's trying to read. Try in this order:

1. **Use PinVault `2.0.0` or later** — earlier versions only support
   Kotlin 2.1+ consumers.
2. **Upgrade your project to Kotlin `1.9.25+`** — Kotlin 1.8 and below
   cannot read 1.9 metadata.
3. **If you use Hilt / Dagger / kapt**: upgrade Hilt to `2.51+` or Dagger
   to `2.51+`. Older versions bundle a pre-K2 `kotlin-metadata-jvm` that
   stumbles on transitive dependencies. Migrating from `kapt` to `KSP` is
   the long-term fix.
4. **Last resort**: add `kotlin.suppressKotlinVersionCompatibilityCheck=true`
   to your `gradle.properties`. This silences the warning, but the
   underlying issue may still surface elsewhere.

### Troubleshooting: compile errors after upgrading from 1.x to 2.x

If you upgraded from PinVault `1.x` to `2.x` and now see compile errors
like:

```
error: constructor Builder in class Builder cannot be applied to given types;
       new PinVaultConfig.Builder("https://...")
       required: no arguments

error: constructor HostPin in class HostPin cannot be applied to given types;
       new HostPin("host", Arrays.asList(...))
       required: String,List<String>,int,boolean,boolean,Integer
```

these are **API breaking changes** introduced in `2.0`, not metadata
errors. v2 replaced the single-URL constructor with a multi-Config-API
DSL, and `HostPin` gained four optional fields. Update your Java code
following the patterns in section **2b** above, or read
[MIGRATION.md](MIGRATION.md) for the full DSL reference. If migrating
to v2 isn't an option right now, pin the dependency to the latest
`1.x` release.

### Upgrading from 2.0.x to 2.1

No app code changes are needed from 2.0.9. A backend of your own that serves
vault files to a signed block must start sending `X-Vault-Signature`
([Signed vault files](#signed-vault-files-21)); the reference server does.
On the first start 2.1 moves the 2.0.x
EncryptedSharedPreferences files (configs, client certificates, cached vault
files) into its Keystore-backed store and deletes them. Going back to 2.0.x
afterwards starts from scratch: bootstrap pins, re-enrollment, re-download.
Details in [MIGRATION.md](MIGRATION.md).

## Production Security Checklist

PinVault is built around OWASP MASVS guidelines (NETWORK, CRYPTO, STORAGE).
Before shipping to production, verify the following:

### 1. Never ship a server-side keystore password
*(2.1)* Enrollment and host client certificate downloads ask for a one-off P12
password (`X-PinVault-Features: p12password`). A backend that returns it in
`X-P12-Password` (the reference server does) never needs the app to know a
password of its own: the library checks the bundle with it and re-wraps it
with `clientKeyPassword` before storing it in Keystore-encrypted storage.
Do not wrap device P12s with the password protecting your server's keystores.

For a P12 you hand over yourself (`clientKeystore(bytes, password)`), the
`"changeit"` default is a development placeholder: use a unique high-entropy
password per device, delivered out of band — never hard-code it in the APK.

```kotlin
// ❌ Don't
.configApi("api", url) { clientKeystore(p12Bytes) }

// ✅ Do
val devicePassword = backend.fetchKeystorePassword(deviceId) // ≥ 16 random chars
.configApi("api", url) { clientKeystore(p12Bytes, devicePassword) }
```

### 2. Keep debug logging out of release builds
The library logs every pin verification, enrollment and vault file operation
through [Timber](https://github.com/JakeWharton/timber), which stays silent
until a tree is planted. Plant one (or call `PinVault.enableDebugLogging()`,
see Quick Start step 5) only when `BuildConfig.DEBUG` is true.

### 3. Always use bootstrap pins for the first connection
Without bootstrap pins, the first config fetch is unpinned (vulnerable to MITM
on first install). Hardcode at least 2 SHA-256 SPKI hashes in the APK:

```kotlin
.configApi("api", "https://api.example.com/") {
    bootstrapPins(listOf(
        HostPin("api.example.com", listOf("primary...", "backup..."))
    ))
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
- TLS 1.2 or higher (1.3 preferred)
- Server certificate matches at least one pinned SHA-256(SPKI) hash
- mTLS endpoints reject unknown client certs
- HTTP-only endpoints are off (the library refuses cleartext HTTPS hosts)

### 7. Rotate pins ahead of expiry
Configure at least 2 different pins per host (primary + backup). From 2.1 a pin
may be the leaf's key or the key of a CA the leaf chains to (checked on the device), so
pinning your CA survives leaf renewals. Add the new pin to the
config 30+ days before the old certificate expires. Set `forceUpdate: true`
on the host entry to force clients to refresh immediately.

**`forceUpdate=true` availability trade-off.** A client that holds a
`forceUpdate=true` config refuses to initialize when the backend is
unreachable — the previously cached config is treated as untrusted
because the server already declared it superseded. This is intentional:
the flag exists to revoke compromised pin sets and must not silently
fall back to the very config it is trying to revoke. The cost is
availability: an attacker who can sustainably DoS the Config API can
prevent affected devices from coming up. Mitigate by keeping the
Config API behind diverse routes (multiple regions / CDN cache) and
reserving `forceUpdate=true` for genuine revocation events rather than
routine rotations.

### What PinVault does NOT do
- **Root/jailbreak detection** — combine with libraries like RootBeer if needed
- **Code obfuscation** — enable R8/ProGuard in your app (`isMinifyEnabled = true`)
- **Network anomaly detection** — pair with your APM/SIEM
- **Frida/Xposed hooking detection** — out of scope; consider a dedicated
  RASP solution for high-value targets

## License

Apache 2.0
