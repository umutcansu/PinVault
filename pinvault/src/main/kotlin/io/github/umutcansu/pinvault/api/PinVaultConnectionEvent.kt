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

    /**
     * Result of a client-certificate renewal check — run at init, on every
     * periodic update, and by `PinVault.renewClientCertIfNeeded`. Only
     * emitted for CSR-enrolled identities (a device key in the Keystore);
     * P12 enrollments have nothing to renew with and stay silent.
     */
    data class ClientCertRenewal(
        val status: ClientCertRenewalStatus,

        /** Expiry of the certificate in use after the check, epoch ms. `0` when unknown. */
        val notAfterEpochMs: Long,

        /** Which door the renewal went through. Null unless a renewal was attempted. */
        val via: io.github.umutcansu.pinvault.model.ClientCertRenewalVia?,

        /** The Config API block whose identity was checked. */
        val configApiId: String,

        /** Static device label, mirrors `android.os.Build.MANUFACTURER`. */
        val deviceManufacturer: String,

        /** Static device label, mirrors `android.os.Build.MODEL`. */
        val deviceModel: String,

        /** Failure detail, or the server's reason for [ClientCertRenewalStatus.REENROLL_REQUIRED]. */
        val failureReason: String? = null
    ) : PinVaultConnectionEvent()

    /**
     * Result of an attestation of a Config API block (`attestation()` on the
     * block): at init, on every refresh of the token, on the periodic update
     * and on `PinVault.attestNow`. See `ATTESTATION.md`.
     *
     * The token itself is never in an event; `PinVault.attestationStatus`
     * and `fetchAttestationToken` are for that.
     */
    data class Attestation(
        /** The Config API block that attested. */
        val configApiId: String,

        /** Pass, reject, or an attempt that could not be completed. */
        val status: AttestationEventStatus,

        /** The attestation result code of the verdict; null when no verdict was reached. */
        val arc: String?,

        /** The server's rejection reasons, when its policy reveals them (else empty). */
        val rejectionReasons: List<String>,

        /** Flags the policy marked `warn`. */
        val warnings: List<String>,

        /** When the issued token expires (epoch ms, device clock); null without a token. */
        val tokenExpiresAt: Long?,

        /** Static device label, mirrors `android.os.Build.MANUFACTURER`. */
        val deviceManufacturer: String = android.os.Build.MANUFACTURER ?: "",

        /** Static device label, mirrors `android.os.Build.MODEL`. */
        val deviceModel: String = android.os.Build.MODEL ?: "",

        /** Why the attempt failed, for [AttestationEventStatus.FAILED]; null otherwise. */
        val failureReason: String? = null
    ) : PinVaultConnectionEvent()
}

/** Outcome categories for [PinVaultConnectionEvent.Attestation]. */
enum class AttestationEventStatus {
    /** The server passed the device and issued a token. */
    PASS,

    /** The server rejected the device: no token, no config through this channel. */
    REJECT,

    /** The attestation could not be completed; retried with backoff. */
    FAILED
}

/** Outcome categories for [PinVaultConnectionEvent.ClientCertRenewal]. */
enum class ClientCertRenewalStatus {
    /** A new certificate was issued and is presented from now on. */
    RENEWED,

    /** Enough lifetime left — nothing was sent. */
    NOT_NEEDED,

    /** The server refuses this identity; the host app must enroll again. */
    REENROLL_REQUIRED,

    /** Renewal was attempted and failed; it is retried on the next check. */
    FAILED
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
