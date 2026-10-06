package io.github.umutcansu.pinvault.model

/**
 * What the last attestation of a Config API block came to.
 *
 * See `ATTESTATION.md` and [io.github.umutcansu.pinvault.PinVault.attestationStatus].
 */
enum class AttestationResult {
    /** The server passed the device and issued a `PinVault-Token`. */
    PASS,

    /** The server refused the device: no token, no config through this channel. */
    REJECT,

    /** The attestation could not be completed (network, server error, a refused key). Retried with backoff. */
    FAILED,

    /** No attestation has run yet for this block. */
    NOT_ATTESTED,

    /**
     * This block cannot attest: `attestation()` was not called on it, or it
     * uses a custom [io.github.umutcansu.pinvault.api.CertificateConfigApi]
     * (the attest endpoints are reached through the library's own client only).
     */
    UNSUPPORTED
}

/**
 * The state of attestation for one Config API block: the last verdict, the
 * token's expiry, when the next attestation is due, and why the last attempt
 * failed. Held in memory only; `PinVault.attestationStatus(configApiId)`.
 *
 * @property configApiId the block.
 * @property result the last outcome.
 * @property arc the attestation result code of the last verdict (8 hex
 *   characters an operator resolves in the dashboard), or null without one.
 * @property rejectionReasons the server's reasons for a `REJECT` — only when
 *   the policy reveals them; otherwise empty, and [arc] is what to look up.
 * @property warnings flags the policy marked `warn` on the last verdict.
 * @property tokenExpiresAt when the held token expires, epoch ms by the
 *   device clock; null without a token.
 * @property lastAttestedAt when the server last answered (pass or reject), epoch ms; null if never.
 * @property nextAttestAt when the library re-attests next, epoch ms; null when no refresh is scheduled.
 * @property clockSkewMs `serverTime − device time` from the last challenge, ms; informational.
 * @property lastError why the last attempt failed, or null.
 * @property policyVersion the server policy version the last verdict was made under, or null.
 */
data class AttestationStatus(
    val configApiId: String,
    val result: AttestationResult,
    val arc: String? = null,
    val rejectionReasons: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val tokenExpiresAt: Long? = null,
    val lastAttestedAt: Long? = null,
    val nextAttestAt: Long? = null,
    val clockSkewMs: Long? = null,
    val lastError: String? = null,
    val policyVersion: Int? = null
) {
    /** True when the last verdict was a pass and the token has not expired by [now]. */
    fun hasValidToken(now: Long = System.currentTimeMillis()): Boolean =
        result == AttestationResult.PASS && (tokenExpiresAt ?: 0L) > now
}

/**
 * Outcome of [io.github.umutcansu.pinvault.PinVault.fetchAttestationToken]:
 * the token to put in the `PinVault-Token` header, or why there is none.
 */
sealed class AttestationTokenResult {
    /** A token that is valid until [expiresAt] (epoch ms, device clock). */
    data class Token(val value: String, val expiresAt: Long) : AttestationTokenResult() {
        /** Never prints the token. */
        override fun toString() = "Token(expiresAt=$expiresAt, value=***)"
    }

    /** The server rejected the device; [status] carries the ARC and the reasons the policy reveals. */
    data class Rejected(val status: AttestationStatus) : AttestationTokenResult()

    /** The attestation could not be completed; retried later. */
    data class Failed(val message: String) : AttestationTokenResult()

    /** The block does not attest (see [AttestationResult.UNSUPPORTED]). */
    object Unsupported : AttestationTokenResult() {
        override fun toString() = "Unsupported"
    }
}
