package io.github.umutcansu.pinvault.api

/**
 * Connection-level events emitted by PinVault during pinned TLS handshakes.
 *
 * Subscribe to these via [PinVaultConfig.Builder.onConnectionEvent]
 * (`io.github.umutcansu.pinvault.model.PinVaultConfig`).
 *
 * The library never sends events to a remote endpoint on its own — it only
 * hands the structured event to whatever listener the consumer registered.
 * For the canonical "POST to demo-server" flow, see
 * [io.github.umutcansu.pinvault.reporter.PinVaultBackendReporter].
 *
 * This is a [sealed class]; `when` expressions over the event will keep
 * compiling when new event types are added in future releases as long as
 * an `else` branch (or exhaustive handling) is present.
 */
sealed class PinVaultConnectionEvent {

    /**
     * Result of a single TLS handshake whose server certificate was checked
     * against the configured pins.
     *
     * Emitted both on success ([success] = `true`) and on pin mismatch
     * ([success] = `false`). When `success` is false, [actualPin] holds the
     * SHA-256 SPKI hash the server actually presented and [expectedPins]
     * lists the configured hashes that did not match.
     *
     * Device fields are populated by the library from
     * `android.os.Build.MANUFACTURER` and `android.os.Build.MODEL` — the
     * consumer never supplies them. They are included so that listeners
     * (telemetry, "connected devices" panels, anomaly detection) have
     * everything they need without round-tripping back to the app.
     */
    data class Connection(
        /** Hostname the TLS handshake was performed against, e.g. `"api.example.com"`. May be empty when SNI is unavailable. */
        val hostname: String,

        /** `true` if the server's leaf-cert SPKI hash matched one of the configured pins. */
        val success: Boolean,

        /** Active pin config version at the moment of the handshake. `0` if no config has been loaded yet. */
        val pinVersion: Int,

        /** Static device label, mirrors `android.os.Build.MANUFACTURER`. */
        val deviceManufacturer: String,

        /** Static device label, mirrors `android.os.Build.MODEL`. */
        val deviceModel: String,

        /** Server cert SPKI hash that was actually presented. Always populated; useful even on success for downstream auditing. */
        val actualPin: String,

        /** SPKI hashes the host's [HostPin] config currently accepts. Always populated. */
        val expectedPins: List<String>
    ) : PinVaultConnectionEvent()

    /**
     * Result of a config update attempt — either a periodic WorkManager
     * refresh or a `PinVault.updateNow()` call, plus the on-the-fly retry
     * the recovery interceptor performs after a pin mismatch.
     *
     * Fired alongside the legacy `PinVault.OnUpdateListener` so that
     * consumers who subscribe via [PinVaultConfig.Builder.onConnectionEvent]
     * receive both handshake outcomes and config-rotation outcomes on a
     * single pipe — convenient for telemetry that needs to correlate the
     * two streams.
     */
    data class ConfigUpdate(
        /** Whether the update changed the active config, was a no-op, or failed. */
        val status: ConfigUpdateStatus,

        /**
         * Config version after the update. For [ConfigUpdateStatus.UPDATED]
         * this is the freshly fetched version; for [ConfigUpdateStatus.UNCHANGED]
         * the previously persisted version that the server confirmed; for
         * [ConfigUpdateStatus.FAILED] the version still in use (may be 0 if
         * no config has ever been loaded).
         */
        val newVersion: Int,

        /** Static device label, mirrors `android.os.Build.MANUFACTURER`. */
        val deviceManufacturer: String,

        /** Static device label, mirrors `android.os.Build.MODEL`. */
        val deviceModel: String,

        /** Failure detail. Null for non-failure statuses. */
        val failureReason: String? = null
    ) : PinVaultConnectionEvent()
}

/** Outcome categories for [PinVaultConnectionEvent.ConfigUpdate]. */
enum class ConfigUpdateStatus {
    /** Backend returned a new config and the client swapped to it. */
    UPDATED,

    /** Backend confirmed the client's current version — no swap. */
    UNCHANGED,

    /** Update attempt failed (network, signature, freshness, etc.). */
    FAILED
}
