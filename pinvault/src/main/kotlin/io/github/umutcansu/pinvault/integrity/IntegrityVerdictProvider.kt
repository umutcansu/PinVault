package io.github.umutcansu.pinvault.integrity

/**
 * A second opinion on the device's integrity from a service of the app's
 * choosing — Play Integrity, typically — forwarded verbatim inside the
 * attestation report (`verdictProvider` in `ATTESTATION.md` §3). The library
 * does not read or verify the token: the server does. The reference server
 * verifies Play Integrity tokens itself when it holds the Play Console
 * response keys (`ATTESTATION.md` §11) and raises `play_integrity` /
 * `play_integrity_missing` for the policy; any other provider's token is
 * stored for a verifier of your own.
 *
 * Register one with
 * [io.github.umutcansu.pinvault.model.PinVaultConfig.Builder.integrityVerdictProvider].
 * The ready-made Play Integrity provider lives in the optional
 * `io.github.umutcansu:pinvault-play-integrity` artifact
 * (`PlayIntegrityVerdictProvider(context, cloudProjectNumber)`), so an app
 * that does not want Google's client in its APK does not get it. Writing
 * one by hand is this:
 *
 * ```kotlin
 * class PlayIntegrityProvider(private val manager: IntegrityManager, private val project: Long) : IntegrityVerdictProvider {
 *     override suspend fun verdict(nonce: String): IntegrityVerdict? {
 *         val token = manager.requestIntegrityToken(
 *             IntegrityTokenRequest.builder().setNonce(nonce).setCloudProjectNumber(project).build()
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
