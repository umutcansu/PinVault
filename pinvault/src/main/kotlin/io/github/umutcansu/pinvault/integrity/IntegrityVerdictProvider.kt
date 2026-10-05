package io.github.umutcansu.pinvault.integrity

/**
 * A second opinion on the device's integrity from a service of the app's
 * choosing — Play Integrity, typically — forwarded verbatim inside the
 * attestation report (`verdictProvider` in `ATTESTATION.md` §3). The library
 * does not read or verify the token: the server stores it and may hand it
 * to a verifier of its own (`ATTESTATION_VERDICT_WEBHOOK`).
 *
 * Register one with
 * [io.github.umutcansu.pinvault.model.PinVaultConfig.Builder.integrityVerdictProvider].
 *
 * ```kotlin
 * class PlayIntegrityProvider(private val manager: IntegrityManager) : IntegrityVerdictProvider {
 *     override suspend fun verdict(nonce: String): IntegrityVerdict? {
 *         val token = manager.requestIntegrityToken(
 *             IntegrityTokenRequest.builder().setNonce(nonce).build()
 *         ).await().token()
 *         return IntegrityVerdict("play-integrity", token)
 *     }
 * }
 * ```
 */
interface IntegrityVerdictProvider {

    /**
     * Asks the service for a verdict bound to [nonce] — the attestation
     * nonce of this round, so the server can tie the two together. Called
     * on a background thread, once per attestation, with a 10 second budget;
     * it may suspend. Return null (or throw) when no verdict is available:
     * the report then carries no `verdictProvider` and the attestation goes
     * on without it.
     */
    suspend fun verdict(nonce: String): IntegrityVerdict?
}

/**
 * What an [IntegrityVerdictProvider] hands over.
 *
 * @property name which service, e.g. `"play-integrity"`; the server records it with the token.
 * @property token the service's token, as issued; sent verbatim.
 */
data class IntegrityVerdict(val name: String, val token: String) {
    /** Never prints the token. */
    override fun toString() = "IntegrityVerdict(name=$name, token=***)"
}
