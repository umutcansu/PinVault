# Connection events and the backend reporter

The basics — `onConnectionEvent { … }` and `reportToPinVaultBackend(...)` —
are in the [guide](GUIDE.md#4-optional-subscribe-to-connection-events).
This page covers pinning the reporter's own traffic and the Java form of the
listener.

## Pinning the reporter's own HTTP traffic

`reportToPinVaultBackend(...)` and the bare `PinVaultBackendReporter(...)`
constructor both default to an `OkHttpClient` with **system trust** — no
pinning on the telemetry POSTs themselves. For production fleets an
attacker on path could drop the pin-mismatch reports (silencing your
detection channel) or tamper with healthy-handshake payloads.

There are three ways to pin the reporter. Pick by where the management
endpoint lives and which certificate it serves.

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
        .also { PinVault.applyTo(it) }   // live pins + client cert, recovery interceptor
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
hostname 'management.example.com'` (unless `managedTrustRoots()` is on and
the config lists the host's root CA: then it is accepted without a pin). Confirm with
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
        managementUrl = "https://192.168.1.10:6655/",
        httpClient = PinVaultBackendReporter.pinnedClient("192.168.1.10", listOf(primaryPin, backupPin)),
        reportSuccessEvents = false
    )
)
```

## Java consumers

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
