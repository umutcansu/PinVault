package io.github.umutcansu.pinvault.crypto

import com.google.gson.Gson
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedKeySet
import io.github.umutcansu.pinvault.model.SigningKeySetPayload
import io.github.umutcansu.pinvault.model.SigningStatus
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.store.SigningKeyStore
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

/**
 * Which keys a Config API block trusts to sign its configs and vault files,
 * how many of them have to sign, and how that list changes over the air.
 *
 * Three layers, each optional and off unless the block configures it:
 *
 * 1. **Several trusted keys** (`signaturePublicKeys`). One valid signature is
 *    enough. Ship an offline backup key in the app and the backend can switch
 *    to it — after the primary is lost or stolen — without an app update.
 * 2. **m-of-n** (`requiredSignatures`). A config needs valid signatures from
 *    that many DISTINCT trusted keys. With the keys held by different people
 *    or systems, none of them can publish pins alone.
 * 3. **Signing-key sets** (`recoveryPublicKeys`). Offline recovery keys sign
 *    a versioned list of signing keys. A device applies a list newer than the
 *    one it holds and from then on trusts exactly that list, which is how a
 *    signing key is rotated or REVOKED without an app update. Recovery keys
 *    never sign configs, a set may not name one as a signing key, and a stolen
 *    signing key cannot produce a set.
 *
 * Keys are compared in canonical form (parsed and re-encoded), never as the
 * text they were configured with: two spellings of one key must not count as
 * two signers.
 *
 * With none of the layers configured this behaves exactly like the single
 * `signaturePublicKey` check it replaces.
 */
internal class SignatureTrust(
    val configApiId: String,
    builtInKeys: List<String>,
    builtInThreshold: Int,
    recoveryKeys: List<String>,
    recoveryThreshold: Int,
    /**
     * The block's `serverScope`. A signing-key set whose payload names a
     * `configApiId` is applied only when it names this one: one recovery key
     * set may serve several Config APIs, and a set made for another of them
     * must not replace this block's keys. A set that names none is accepted
     * as before (the field is optional; older sets do not carry it).
     */
    private val serverScope: String? = null,
    storeProvider: () -> SigningKeyStore?
) {
    /** Convenience for tests and callers that already hold the store. */
    constructor(
        configApiId: String,
        builtInKeys: List<String>,
        builtInThreshold: Int,
        recoveryKeys: List<String>,
        recoveryThreshold: Int,
        store: SigningKeyStore?,
        serverScope: String? = null
    ) : this(configApiId, builtInKeys, builtInThreshold, recoveryKeys, recoveryThreshold, serverScope, { store })

    private val builtInKeys: List<String> = canonicalize(builtInKeys, "signing")
    private val builtInThreshold = builtInThreshold.coerceAtLeast(1)
    private val recoveryKeys: List<String> = canonicalize(recoveryKeys, "recovery").filter { key ->
        (key !in this.builtInKeys).also { distinct ->
            if (!distinct) Timber.e("Config API '%s': a recovery key is also a signing key — ignoring it as a recovery key", configApiId)
        }
    }
    private val recoveryThreshold = recoveryThreshold.coerceAtLeast(1)

    /**
     * SHA-256 (hex) over what this build trusts by itself: the compiled-in
     * signing keys and how many must sign, the recovery keys and their
     * threshold, in canonical form and order. It changes only with an app
     * update that rotates them; see `SSLCertificateUpdater.syncTrustAnchors`.
     */
    fun anchorsFingerprint(): String {
        val text = buildString {
            append("pinvault-trust-anchors:v1\n")
            append("signing:").append(builtInThreshold).append('\n')
            builtInKeys.sorted().forEach { append(it).append('\n') }
            append("recovery:").append(recoveryThreshold).append('\n')
            recoveryKeys.sorted().forEach { append(it).append('\n') }
        }
        return java.security.MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    /**
     * Opened on first use, off the init path. A store that fails to open is
     * NOT "no persisted set": the set may hold a revocation, and falling back
     * to the compiled-in keys would trust the revoked key again for the rest
     * of the process. The failure is thrown as [StoreUnreadableException] to
     * whoever asked (nothing verifies for that attempt) and opening is tried
     * again on the next use — `lazy` does not keep a failed result.
     */
    private val store: SigningKeyStore? by lazy {
        try {
            storeProvider()
        } catch (e: StoreUnreadableException) {
            throw e
        } catch (e: Exception) {
            Timber.e(e, "Config API '%s': signing-key store unavailable — nothing is verified until it opens", configApiId)
            throw StoreUnreadableException(
                "Config API '$configApiId': the signing-key store cannot be opened right now (${e.javaClass.simpleName})", e
            )
        }
    }

    private val gson = Gson()
    private val lock = Any()
    private val keyIds = ConcurrentHashMap<String, String>()

    /** Verified copy of the stored key set; `null` = the compiled-in keys apply. */
    @Volatile private var activeSet: KeySet? = null
    @Volatile private var activeSetLoaded = false
    @Volatile private var lastSignedBy: List<String> = emptyList()

    // From the keys as configured, not as parsed: a block whose keys are all
    // malformed must fail closed (nothing verifies), not look unsigned.
    private val configured = builtInKeys.any { it.isNotBlank() }

    /** False only when the block has no signing key configured at all (`allowUnsigned()`). */
    val isEnabled: Boolean get() = configured

    fun trustedKeys(): List<String> = currentSet()?.keys ?: builtInKeys

    fun requiredSignatures(): Int = currentSet()?.requiredSignatures ?: builtInThreshold

    fun keySetVersion(): Int = currentSet()?.version ?: 0

    fun status(): SigningStatus = SigningStatus(
        configApiId = configApiId,
        trustedKeyIds = trustedKeys().map(::keyId),
        requiredSignatures = requiredSignatures(),
        keySetVersion = keySetVersion(),
        recoveryKeyIds = recoveryKeys.map(::keyId),
        lastConfigSignedBy = lastSignedBy
    )

    /**
     * Applies a signing-key set delivered with a config, if it is newer than
     * the one this block holds.
     *
     * Throws [SecurityException] when the set is present but does not carry
     * enough valid recovery signatures or is malformed: a backend that sends a
     * set means it, and silently keeping the old keys would hide a forged or
     * broken rotation. A set that is merely older or equal is ignored — it is
     * what every response carries once the rotation has reached this device.
     *
     * @return true when [incoming] was newer and is now the set in force.
     * @throws StoreUnreadableException when the set applied so far cannot be
     *   read right now; nothing is applied then.
     */
    fun applyKeySetUpdate(incoming: SignedKeySet?): Boolean {
        if (incoming == null) return false
        if (recoveryKeys.isEmpty()) {
            Timber.w(
                "Config API '%s': the response carries a signing-key set but no recoveryPublicKeys " +
                    "are configured — ignoring it and keeping the compiled-in keys",
                configApiId
            )
            return false
        }
        val candidate = check(incoming)
        synchronized(lock) {
            val current = currentSet()
            val currentVersion = current?.version ?: 0
            when {
                candidate.version > currentVersion -> {
                    store?.save(configApiId, incoming)
                    activeSet = candidate
                    activeSetLoaded = true
                    Timber.i(
                        "Config API '%s': signing-key set v%d applied — %d trusted key(s), %d signature(s) required",
                        configApiId, candidate.version, candidate.keys.size, candidate.requiredSignatures
                    )
                    return true
                }
                candidate.version == currentVersion && current != null &&
                    candidate.keys.toSet() != current.keys.toSet() ->
                    Timber.w(
                        "Config API '%s': a different signing-key set with the same version v%d was " +
                            "offered — keeping the one already applied",
                        configApiId, currentVersion
                    )
                else -> Timber.d(
                    "Config API '%s': signing-key set v%d is not newer than v%d — nothing to apply",
                    configApiId, candidate.version, currentVersion
                )
            }
        }
        return false
    }

    /**
     * Checks [payload] against the signatures in [entries]. The result is ok
     * when at least [requiredSignatures] distinct trusted keys produced one of
     * them; [Verification.detail] explains a failure in words fit for a log or
     * an `UpdateResult.Failed` reason.
     */
    fun verifyConfig(payload: String, entries: List<SignatureEntry>): Verification {
        val result = evaluate(payload, entries)
        if (result.ok) lastSignedBy = result.signedBy
        return result
    }

    /**
     * [verifyConfig] for a config envelope read back from storage: the same
     * check against the keys trusted now, without recording its signers as
     * "the last accepted config".
     */
    fun verifyStoredConfig(payload: String, entries: List<SignatureEntry>): Verification = evaluate(payload, entries)

    /**
     * Same as [verifyConfig] for a vault file's canonical content string:
     * v1 when [serverScope] is null, v2 (which names that Config API) when
     * the block set one. [entries] must be the signatures of that scheme.
     */
    fun verifyVaultFile(
        key: String,
        version: Int,
        plaintext: ByteArray,
        entries: List<SignatureEntry>,
        serverScope: String? = null
    ): Verification = evaluate(
        if (serverScope == null) ConfigSignatureVerifier.vaultCanonical(key, version, plaintext)
        else ConfigSignatureVerifier.vaultCanonicalV2(serverScope, key, version, plaintext),
        entries
    )

    private fun evaluate(payload: String, entries: List<SignatureEntry>): Verification {
        // One snapshot for the keys AND the count: a key-set update landing
        // between two separate reads could pair the old keys with a new count.
        val set = currentSet()
        val keys = set?.keys ?: builtInKeys
        val required = set?.requiredSignatures ?: builtInThreshold
        val signers = validSigners(payload, entries, keys)
        if (signers.size >= required) {
            return Verification(ok = true, signedBy = signers.map(::keyId), required = required, detail = "")
        }
        val detail = buildString {
            if (required > 1) append(" ${signers.size} of $required required signatures valid.")
            // Name the reason an operator will want first: the signature is
            // genuine, but from a key the applied set no longer trusts.
            if (set != null && signers.isEmpty()) {
                val revoked = validSigners(payload, entries, builtInKeys.filter { it !in set.keys })
                if (revoked.isNotEmpty()) {
                    append(
                        " Signed by a key revoked by signing-key set v${set.version} " +
                            "(${revoked.joinToString { keyId(it) }})."
                    )
                }
            }
        }
        return Verification(ok = false, signedBy = signers.map(::keyId), required = required, detail = detail)
    }

    /**
     * Distinct keys from [keys] (canonical) that produced a valid signature in
     * [entries]. An entry's `keyId` only decides which key is tried first — it
     * is not signed, so a missing or wrong hint must not turn a good signature
     * bad. At most [MAX_ENTRIES] entries are looked at: each one may cost a
     * verification per trusted key.
     */
    private fun validSigners(payload: String, entries: List<SignatureEntry>, keys: List<String>): List<String> {
        if (keys.isEmpty()) return emptyList()
        val verified = LinkedHashSet<String>()
        // Gson fills absent fields — and `null` array elements — with null
        // regardless of the Kotlin types, so both are treated as nullable here.
        @Suppress("USELESS_CAST")
        for (entry in (entries as List<SignatureEntry?>).take(MAX_ENTRIES)) {
            if (entry == null) continue
            @Suppress("USELESS_CAST")
            val signature = (entry.signature as String?)?.takeIf { it.isNotBlank() } ?: continue
            val hinted = entry.keyId?.let { id -> keys.filter { keyId(it) == id } }.orEmpty()
            for (key in hinted + keys.filter { it !in hinted }) {
                if (key in verified) continue
                if (ConfigSignatureVerifier.verifyQuietly(payload, signature, key)) {
                    verified += key
                    break
                }
            }
            if (verified.size == keys.size) break
        }
        return verified.toList()
    }

    /**
     * The applied key set, read from the store on first use. A read that
     * fails ([StoreUnreadableException]) leaves it unloaded — never "loaded,
     * none" — so the caller's check fails now and the read is tried again.
     */
    private fun currentSet(): KeySet? {
        if (recoveryKeys.isEmpty()) return null
        if (!activeSetLoaded) {
            synchronized(lock) {
                if (!activeSetLoaded) {
                    activeSet = store?.load(configApiId)?.let { stored ->
                        try {
                            check(stored)
                        } catch (e: SecurityException) {
                            // Only possible when this build ships different
                            // recovery keys than the one that stored the set.
                            Timber.w(
                                "Config API '%s': the stored signing-key set no longer verifies against " +
                                    "this build's recovery keys — using the compiled-in keys (%s)",
                                configApiId, e.message
                            )
                            null
                        }
                    }
                    activeSetLoaded = true
                }
            }
        }
        return activeSet
    }

    private fun check(keySet: SignedKeySet): KeySet {
        @Suppress("USELESS_CAST")
        val entries = (keySet.signatures as List<SignatureEntry>?).orEmpty()
        @Suppress("USELESS_CAST")
        val payload = (keySet.payload as String?)
            ?: throw SecurityException("Signing-key set rejected — it has no payload.")
        val signers = validSigners(payload, entries, recoveryKeys)
        if (signers.size < recoveryThreshold) {
            throw SecurityException(
                "Signing-key set rejected — ${signers.size} of $recoveryThreshold required recovery " +
                    "signature(s) valid. Keeping the current signing keys."
            )
        }
        val parsed = try {
            gson.fromJson(payload, SigningKeySetPayload::class.java)
        } catch (_: Exception) {
            null
        } ?: throw SecurityException("Signing-key set rejected — the payload is not a key set.")
        if (parsed.type != KEY_SET_TYPE) {
            throw SecurityException("Signing-key set rejected — type '${parsed.type}' is not '$KEY_SET_TYPE'.")
        }
        if (parsed.version <= 0) {
            throw SecurityException("Signing-key set rejected — version must be positive.")
        }
        // Inside the recovery-signed payload, so it cannot be swapped.
        val scopedTo = parsed.configApiId?.takeIf { it.isNotBlank() }
        if (scopedTo != null && serverScope != null && scopedTo != serverScope) {
            throw SecurityException(
                "Signing-key set rejected — it was made for Config API '${scopedTo.take(64)}', this block is '$serverScope' (serverScope)."
            )
        }
        val raw = parsed.keys.orEmpty().filterNotNull().filter { it.isNotBlank() }
        if (raw.size > MAX_SET_KEYS) {
            throw SecurityException("Signing-key set rejected — more than $MAX_SET_KEYS keys.")
        }
        val keys = raw.map { key ->
            ConfigSignatureVerifier.canonicalKey(key)
                ?: throw SecurityException("Signing-key set rejected — not an EC public key: ${key.take(16)}…")
        }.distinct()
        if (keys.isEmpty()) {
            throw SecurityException("Signing-key set rejected — it lists no signing keys.")
        }
        if (keys.any { it in recoveryKeys }) {
            throw SecurityException("Signing-key set rejected — a recovery key may not be a signing key.")
        }
        // A set can raise the number of signatures a config needs, never lower
        // it below what the app itself demands.
        val required = maxOf(builtInThreshold, parsed.requiredSignatures ?: 1)
        if (required > keys.size) {
            throw SecurityException(
                "Signing-key set rejected — it requires $required signatures but lists only ${keys.size} key(s)."
            )
        }
        return KeySet(parsed.version, keys, required)
    }

    private fun keyId(key: String): String =
        keyIds.getOrPut(key) { ConfigSignatureVerifier.keyIdOf(key) ?: "invalid-key" }

    private fun canonicalize(keys: List<String>, role: String): List<String> =
        keys.mapNotNull { key ->
            ConfigSignatureVerifier.canonicalKey(key).also {
                if (it == null) Timber.e("Config API '%s': ignoring a %s key that is not an EC public key (%s…)", configApiId, role, key.take(16))
            }
        }.distinct()

    /** Outcome of a signature check. */
    data class Verification(
        val ok: Boolean,
        /** Key ids whose signatures verified. */
        val signedBy: List<String>,
        val required: Int,
        /** Empty when [ok]; otherwise a sentence (with a leading space) explaining why. */
        val detail: String
    )

    private data class KeySet(val version: Int, val keys: List<String>, val requiredSignatures: Int)

    companion object {
        const val KEY_SET_TYPE = "pinvault-signing-keys"

        /** Signature entries looked at per document; the rest are ignored. */
        private const val MAX_ENTRIES = 16

        /** Keys a signing-key set may list. */
        private const val MAX_SET_KEYS = 32

        /** The trust a block's configuration asks for, or `null` when it runs unsigned. */
        fun forBlock(block: ConfigApiBlock, storeProvider: () -> SigningKeyStore?): SignatureTrust? {
            val keys = block.effectiveSignatureKeys()
            if (keys.isEmpty()) return null
            return SignatureTrust(
                configApiId = block.id,
                builtInKeys = keys,
                builtInThreshold = block.requiredSignatures,
                recoveryKeys = block.recoveryPublicKeys,
                recoveryThreshold = block.requiredRecoverySignatures,
                storeProvider = storeProvider,
                serverScope = block.serverScope
            )
        }

        fun forBlock(block: ConfigApiBlock, store: SigningKeyStore?): SignatureTrust? = forBlock(block) { store }

        /** A single fixed key: one signature from it is required, no rotation. */
        fun single(configApiId: String, key: String) =
            SignatureTrust(configApiId, listOf(key), 1, emptyList(), 1) { null }
    }
}
