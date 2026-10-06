package io.github.umutcansu.pinvault.crypto

import com.google.gson.Gson
import com.google.gson.JsonParser
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.ssl.PinConfigValidator
import io.github.umutcansu.pinvault.store.StoredEnvelope
import timber.log.Timber

/**
 * Turns a signed config envelope into a config that may be used, for one
 * Config API block. The same checks apply whoever fetched the envelope — the
 * library's HTTP client or a custom API that implements
 * [io.github.umutcansu.pinvault.api.SignedConfigSource] — and, minus the
 * freshness window, when a stored envelope is read back.
 *
 * @param serverScope the block's `serverScope`: when set, the signed payload
 *   must carry exactly this `configApiId`. One signing key often serves
 *   several Config APIs; without the check an envelope signed for another of
 *   them is accepted here.
 */
internal class SignedConfigVerifier(
    private val trust: SignatureTrust,
    private val serverScope: String? = null,
    /**
     * The time a config's expiry is judged by: [clock], or the later of it
     * and the block's trusted clock ([expiryNow]). Null = [clock].
     */
    private val trustedNow: (() -> Long)? = null,
    /** The highest `issuedAt` this block has accepted (0 = none); see [expiryNow]. */
    private val issuedAtWatermark: () -> Long = { 0L },
    /** Wall clock (last, so tests can pass it as a trailing lambda). */
    private val clock: () -> Long = System::currentTimeMillis
) {
    private val gson = Gson()

    /** A config whose envelope verified, with the envelope to store next to it. */
    class Verified(val config: CertificateConfig, val envelope: StoredEnvelope)

    /** Version of the signing-key set in force (0 = the compiled-in keys). */
    fun keySetVersion(): Int = trust.keySetVersion()

    /** See [SignatureTrust.anchorsFingerprint]. */
    fun anchorsFingerprint(): String = trust.anchorsFingerprint()

    /**
     * Applies a signing-key set riding along with [signed], if it is newer.
     * FIRST, before [verifyFetched]: the config in the same response may
     * already be signed by a key that set introduces. A set that fails its
     * own checks throws and fails the whole response; a valid one stays
     * applied even if the config then fails, so a revocation sticks.
     *
     * @return true when a newer set was applied.
     */
    fun applyKeySet(signed: SignedConfigResponse): Boolean = trust.applyKeySetUpdate(signed.signingKeys)

    /**
     * Checks a freshly fetched envelope: signatures, the scope it was signed
     * for, and its freshness — `issuedAt` and `expiresAt` must both be there
     * and `expiresAt` must not have passed. Throws [SecurityException]
     * otherwise; [failureMessage] words a signature failure.
     */
    fun verifyFetched(
        signed: SignedConfigResponse,
        failureMessage: (detail: String) -> String = { DEFAULT_FAILURE + it }
    ): Verified {
        val envelope = envelopeOf(signed) ?: throw SecurityException(failureMessage(" The envelope has no payload."))
        val verification = trust.verifyConfig(envelope.payload, envelope.signatures)
        if (!verification.ok) throw SecurityException(failureMessage(verification.detail))
        Timber.d("Config signature verified ✓ — signed by %s", verification.signedBy)

        checkScope(envelope.payload)
        val config = parse(envelope.payload)
        enforceFreshness(config)
        return Verified(config, envelope)
    }

    /**
     * The config inside a stored [envelope] when its signatures still verify
     * against the keys trusted NOW (a revoked key no longer counts), it was
     * signed for this block's scope and its content is well-formed; null
     * otherwise. Expiry is left to the caller: an expired stored config has
     * its own handling (grace, refetch).
     *
     * @throws StoreUnreadableException when the signing-key set cannot be
     *   read right now — that is "cannot tell", not "does not verify".
     */
    fun verifyStored(envelope: StoredEnvelope): CertificateConfig? = try {
        if (!trust.verifyStoredConfig(envelope.payload, envelope.signatures).ok) {
            null
        } else {
            checkScope(envelope.payload)
            parse(envelope.payload).also { PinConfigValidator.validate(it) }
        }
    } catch (e: StoreUnreadableException) {
        throw e
    } catch (e: Exception) {
        Timber.w("Stored config envelope rejected: %s", e.message)
        null
    }

    /** `signatures` (several signers) wins over the single legacy field. */
    private fun envelopeOf(signed: SignedConfigResponse): StoredEnvelope? {
        // Gson leaves absent fields null whatever their Kotlin type says.
        @Suppress("USELESS_CAST")
        val payload = (signed.payload as String?) ?: return null
        @Suppress("USELESS_CAST")
        val single = (signed.signature as String?)?.let { SignatureEntry(signed.keyId, it) }
        @Suppress("USELESS_CAST")
        val entries = (signed.signatures?.takeIf { it.isNotEmpty() } ?: listOfNotNull(single)) as List<SignatureEntry?>
        // Only what can be stored and read back: entries that carry a signature.
        @Suppress("USELESS_CAST")
        val usable = entries.filterNotNull().filter { !(it.signature as String?).isNullOrBlank() }.take(MAX_STORED_SIGNATURES)
        return StoredEnvelope(payload, usable)
    }

    private fun parse(payload: String): CertificateConfig =
        PinConfigValidator.normalized(
            gson.fromJson(payload, CertificateConfig::class.java)
                ?: throw SecurityException("Signed config payload is empty.")
        )

    /** The audience check behind `serverScope`. The field is inside the signed payload, so it cannot be swapped. */
    private fun checkScope(payload: String) {
        val expected = serverScope ?: return
        val actual = try {
            JsonParser.parseString(payload).asJsonObject.get(SCOPE_FIELD)?.takeUnless { it.isJsonNull }?.asString
        } catch (e: Exception) {
            null
        }
        if (actual == null) {
            throw SecurityException(
                "Signed config rejected: its payload names no '$SCOPE_FIELD', and this block accepts only configs " +
                    "signed for Config API '$expected' (serverScope). The server must write the field into every " +
                    "signed config."
            )
        }
        if (actual != expected) {
            throw SecurityException(
                "Signed config rejected: it was signed for Config API '${actual.take(64)}', this block accepts " +
                    "only '$expected' (serverScope)."
            )
        }
    }

    /**
     * Rejects signed configs that fall outside the server-controlled freshness
     * window. Guards against replay of older signed payloads even when the
     * signature is still cryptographically valid: a captured config becomes
     * unusable once the clock ([expiryNow]: the trusted clock where there is
     * one) crosses [CertificateConfig.expiresAt].
     *
     * A missing `expiresAt` or `issuedAt` (= 0) is an error rather than
     * silently accepted — a server that returns signed configs MUST populate
     * both. Without `issuedAt` the replay check and the validity-window cap
     * have nothing to compare, and a holder of a signing key could publish a
     * config that never ages.
     *
     * Replay against the stored `issuedAt` is caught by the updater — this
     * method only enforces the fields and the absolute expiry.
     */
    private fun enforceFreshness(config: CertificateConfig) {
        val now = expiryNow(config, clock, trustedNow, issuedAtWatermark)
        if (config.expiresAt <= 0L) {
            throw SecurityException(
                "Signed config missing expiresAt — refusing to apply. " +
                "Server must populate expiresAt (Unix epoch ms) to enable replay protection."
            )
        }
        if (config.issuedAt <= 0L) {
            throw SecurityException(
                "Signed config missing issuedAt — refusing to apply. " +
                "Server must populate issuedAt (Unix epoch ms) to enable replay protection."
            )
        }
        if (config.expiresAt <= now) {
            throw SecurityException(
                "Signed config expired: expiresAt=${config.expiresAt}, now=$now " +
                "(stale by ${now - config.expiresAt}ms). Possible replay attack."
            )
        }
    }

    companion object {
        /** The payload field that names the Config API a config was signed for. */
        const val SCOPE_FIELD = "configApiId"

        /**
         * The time against which "already expired" is judged for a fetched
         * [config]. Normally the trusted clock (the later of the wall clock
         * and the highest time seen), so setting the device clock back does
         * not let an expired config in again. Not for a config newer than
         * every config accepted before: that is the one config that may move
         * a trusted clock that ran ahead back again (`TrustedClock.resetTo`),
         * and judging it by that clock would leave a device whose clock was
         * once far ahead unable ever to accept a config. Its `issuedAt` is
         * checked against the watermark anyway.
         */
        internal fun expiryNow(
            config: CertificateConfig,
            wall: () -> Long,
            trustedNow: (() -> Long)?,
            issuedAtWatermark: () -> Long
        ): Long {
            val wallNow = wall()
            val trusted = trustedNow ?: return wallNow
            if (config.issuedAt > issuedAtWatermark()) return wallNow
            return maxOf(wallNow, trusted())
        }

        private const val DEFAULT_FAILURE =
            "Config signature verification failed — possible tampering detected. Keeping previous safe config."

        /** Signature entries kept with a stored config; verification looks at no more either. */
        private const val MAX_STORED_SIGNATURES = 16
    }
}
