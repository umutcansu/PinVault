@file:JvmName("PinVaultBuilderExtensions")

package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.model.PinVaultConfig

/**
 * One-line opt-in for the canonical PinVault demo-server telemetry POST.
 *
 * Equivalent to:
 * ```
 * onConnectionEvent(PinVaultBackendReporter(managementUrl))
 * ```
 *
 * Use this when your backend is the bundled demo-server (or a fork of it
 * that keeps the `/api/v1/connection-history/client-report` schema).
 * For any other backend, register a custom [PinVaultConnectionListener]
 * via [PinVaultConfig.Builder.onConnectionEvent] and write your own POST
 * — the library imposes no convention on the wire format.
 *
 * From Java: `PinVaultBuilderExtensions.reportToPinVaultBackend(builder, url)`.
 *
 * @param managementUrl e.g. `"http://192.168.1.80:6650/"`. The reporter
 *   appends the endpoint path itself.
 */
fun PinVaultConfig.Builder.reportToPinVaultBackend(
    managementUrl: String
): PinVaultConfig.Builder = onConnectionEvent(PinVaultBackendReporter(managementUrl))
