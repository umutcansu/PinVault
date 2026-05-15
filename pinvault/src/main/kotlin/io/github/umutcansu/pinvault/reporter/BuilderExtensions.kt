@file:JvmName("PinVaultBuilderExtensions")

package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.model.PinVaultConfig

/**
 * One-line opt-in for the canonical PinVault demo-server telemetry POST.
 *
 * Use this when your backend is the bundled demo-server (or a fork of it
 * that keeps the `/api/v1/connection-history/client-report` schema).
 * For any other backend, register a custom [PinVaultConnectionListener]
 * via [PinVaultConfig.Builder.onConnectionEvent] and write your own POST
 * — the library imposes no convention on the wire format.
 *
 * From Java: `PinVaultBuilderExtensions.reportToPinVaultBackend(builder, url, …)`.
 *
 * @param managementUrl e.g. `"http://192.168.1.80:6650/"`. The reporter
 *   appends the endpoint path itself.
 * @param reportSuccessEvents Pass `false` to suppress healthy-handshake
 *   reports entirely and POST only pin mismatches. Default `true`.
 * @param dedupWindowMs Minimum interval between duplicate "healthy" POSTs
 *   for the same host/version/cert (mismatch events always go through).
 *   Default 0 = every handshake produces a report; production deployments
 *   that want heartbeats should pass at least 60_000. Ignored when
 *   [reportSuccessEvents] is `false`.
 */
@JvmOverloads
fun PinVaultConfig.Builder.reportToPinVaultBackend(
    managementUrl: String,
    reportSuccessEvents: Boolean = true,
    dedupWindowMs: Long = 0L
): PinVaultConfig.Builder = onConnectionEvent(
    PinVaultBackendReporter(
        managementUrl,
        reportSuccessEvents = reportSuccessEvents,
        dedupWindowMs = dedupWindowMs
    )
)
