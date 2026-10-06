package io.github.umutcansu.pinvault.model

/**
 * Where a Keystore key the library generated actually lives — what the
 * Android Keystore reports about it after the fact (`KeyInfo`), not what was
 * asked for. The library asks for StrongBox first, then the TEE; a ROM may
 * refuse both and hand out a software key, and nothing used to say so.
 *
 * Reported on [ClientCertEnrollmentResult.Enrolled.keySecurityLevel], in the
 * enrollment request (`keySecurityLevel`) and in the attestation report, and
 * enforced by [PinVaultConfig.Builder.requireHardwareBackedKeys].
 */
enum class KeySecurityLevel(
    /** The value on the wire and in logs. */
    val wireName: String
) {
    /** A dedicated secure element (`setIsStrongBoxBacked`). */
    STRONGBOX("strongbox"),

    /** The trusted execution environment (TEE) of the main processor. */
    TRUSTED_ENVIRONMENT("tee"),

    /** The key is held by software only; a rooted device can copy it. */
    SOFTWARE("software"),

    /**
     * The Keystore did not say (a provider without `KeyInfo`, an error while
     * asking, or a test key). Treated like [SOFTWARE] where hardware is required.
     */
    UNKNOWN("unknown");

    /** True for [STRONGBOX] and [TRUSTED_ENVIRONMENT]. */
    val hardwareBacked: Boolean get() = this == STRONGBOX || this == TRUSTED_ENVIRONMENT

    companion object {
        /** The level named by [wireName] (case-insensitive), or [UNKNOWN]. */
        @JvmStatic
        fun fromWireName(name: String?): KeySecurityLevel =
            entries.firstOrNull { it.wireName.equals(name?.trim(), ignoreCase = true) } ?: UNKNOWN
    }
}
