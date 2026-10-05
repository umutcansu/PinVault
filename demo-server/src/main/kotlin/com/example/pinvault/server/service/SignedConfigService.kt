package com.example.pinvault.server.service

import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.SignatureEntry
import com.example.pinvault.server.model.SignedConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong

/**
 * Turns the config a device may see into the signed envelope it receives.
 *
 * ## Per request (default, local key file only)
 * `issuedAt` / `expiresAt` are stamped and the payload signed on every
 * request, exactly as before.
 *
 * ## Signature cache (`CONFIG_SIGNATURE_CACHE=true`; always on with an external signer)
 * The same content is signed ONCE and the identical envelope served until
 * half its lifetime has passed, then re-signed. A pin change produces new
 * content and therefore a new signature — and [prewarm] produces it at
 * publish time, so the signer (HSM, KMS, remote service) is called when the
 * operator publishes, not when devices poll. Fewer signer calls, a signer
 * that may be slow or rate-limited, and every signature traceable to a
 * publish. Only clients that announce `X-PinVault-Features: redelivery`
 * (library 2.1+) get cached envelopes; older clients, which would reject the
 * repeat as a replay, keep getting a fresh signature per request.
 *
 * ## External signers (`CONFIG_SIGNERS=command|pkcs11`)
 * The config endpoint asks for no credential, so "one signature per
 * request" would let anyone who reaches a device port run the signer command
 * — up to its timeout each — or spend HSM/KMS calls at will. With any signer
 * that is not a local key file the cache is therefore ON whatever
 * `CONFIG_SIGNATURE_CACHE` says, and EVERY client is served the cached
 * envelope: one signing per distinct content, however many requests ask for
 * it, and at most a few signings at a time ([ConfigSigningService] bounds
 * them). Apps older than 2.1 then see a repeated envelope as a replay while
 * nothing changed; they keep the config they have.
 *
 * Either way the latest signing-key set is attached to every envelope.
 */
class SignedConfigService(
    private val signing: ConfigSigningService,
    private val keySets: SigningKeySetService? = null,
    val ttlMs: Long = ttlFromEnv(),
    cacheEnabled: Boolean = System.getenv("CONFIG_SIGNATURE_CACHE") == "true",
    private val clock: () -> Long = System::currentTimeMillis
) {
    /** Whether signatures are cached per content: asked for, or required by an external signer. */
    val cacheEnabled: Boolean = cacheEnabled || signing.external

    /** True when the cache was not asked for but an external signer made it necessary. */
    val cacheForced: Boolean = !cacheEnabled && signing.external

    private val json = Json { encodeDefaults = true }

    private data class Cached(val issuedAt: Long, val envelope: SignedConfig)

    private val cache = object : LinkedHashMap<String, Cached>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Cached>?) = size > MAX_ENTRIES
    }
    private val vaultCache = object : LinkedHashMap<String, VaultSignatures>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, VaultSignatures>?) = size > MAX_ENTRIES
    }

    /** A vault file's signatures in both schemes, one entry per signer, primary first. */
    data class VaultSignatures(
        /** Over `pinvault-vault-file:v1:<key>:<version>:<sha256>` (older clients). */
        val v1: List<SignatureEntry>,
        /** Over `pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256>`. */
        val v2: List<SignatureEntry>
    )

    val cacheHits = AtomicLong()

    /**
     * Bumped by every admin write (see [invalidate]). Part of every cache key,
     * so a cached envelope never outlives a change — also a change that brings
     * a view back to content it had before (force on, force off): re-serving
     * that earlier envelope would carry an OLDER issuedAt than what devices
     * applied in between, and they would reject it as a replay.
     */
    private val generation = AtomicLong()

    /** Last issuedAt handed out; issuedAt only ever grows, even within one millisecond. */
    private val lastIssuedAt = AtomicLong()

    /** One signing per cache key at a time: an invalidation must not become a burst of HSM/KMS calls. */
    private val keyLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()

    /**
     * Thrown by [envelope] when the config was loaded under an older
     * [generation] than the current one: the caller must load it again. Signing
     * a config read before a change, AFTER the change was pre-signed, would hand
     * a device the old content with the newer issuedAt, and the device would
     * then reject the newer content's (older) cached envelope as a replay.
     */
    class StaleLoad : RuntimeException("config changed while it was being served")

    /** Capture before loading the config; pass it to [envelope] as loadedAt. */
    fun generation(): Long = generation.get()

    @Serializable
    data class Stats(
        val cacheEnabled: Boolean,
        val ttlSeconds: Long,
        val signaturesProduced: Long,
        val cacheHits: Long,
        val cachedEnvelopes: Int
    )

    fun stats() = Stats(
        cacheEnabled = cacheEnabled,
        ttlSeconds = ttlMs / 1000,
        signaturesProduced = signing.signaturesProduced.get(),
        cacheHits = cacheHits.get(),
        cachedEnvelopes = synchronized(cache) { cache.size }
    )

    /**
     * The envelope for [config] — already filtered to what the requesting
     * device may see, with `issuedAt`/`expiresAt` still 0. [scope] keeps
     * identical content of different Config APIs apart.
     *
     * [redeliveryOk]: the client said it accepts the same signed config twice
     * (`X-PinVault-Features: redelivery`). Only such clients get cached
     * envelopes; any other client gets a fresh signature, as before.
     */
    fun envelope(scope: String, view: PinConfig, redeliveryOk: Boolean = true, loadedAt: Long? = null): SignedConfig {
        val keySet = keySets?.latestWire()
        // Every signed payload names the Config API it was signed for: a block
        // with `serverScope` accepts only its own (one signing key often serves
        // several Config APIs). Inside the payload, so it cannot be swapped.
        val config = view.copy(configApiId = scope)
        // A fresh signature per request only with a local key: an external
        // signer signs once per content, whoever asks (see the class comment).
        if (!cacheEnabled || (!redeliveryOk && !signing.external)) return signFresh(config, clock()).copy(signingKeys = keySet)

        val gen = loadedAt ?: generation.get()
        if (gen != generation.get()) throw StaleLoad()
        val key = "$gen|$scope|" + sha256Hex(json.encodeToString(config.copy(issuedAt = 0, expiresAt = 0)))
        cachedFor(key, clock())?.let { return it.copy(signingKeys = keySet) }

        val lock = keyLocks.computeIfAbsent(key) { Any() }
        synchronized(lock) {
            // Another request may have signed this key while we waited.
            cachedFor(key, clock())?.let { return it.copy(signingKeys = keySet) }
            if (gen != generation.get()) throw StaleLoad()
            val fresh = signFresh(config, clock())
            val issuedAt = json.decodeFromString(PinConfig.serializer(), fresh.payload).issuedAt
            synchronized(cache) {
                // Keep the newer envelope if two signings raced.
                val existing = cache[key]
                if (existing == null || existing.issuedAt < issuedAt) cache[key] = Cached(issuedAt, fresh)
            }
            keyLocks.remove(key, lock)
            return fresh.copy(signingKeys = keySet)
        }
    }

    private fun cachedFor(key: String, now: Long): SignedConfig? = synchronized(cache) {
        val hit = cache[key]
        if (hit != null && now < hit.issuedAt + ttlMs / 2) {
            cacheHits.incrementAndGet()
            hit.envelope
        } else null
    }

    /**
     * Signs what [load] returns now if the cache is on, so the publish — not
     * the next device poll — pays for the signature. Call after [invalidate].
     * Failures are logged, never thrown: the pin change itself is already
     * stored, and a device request will simply sign again.
     */
    fun prewarm(scope: String, load: () -> PinConfig) {
        if (!cacheEnabled) return
        val gen = generation.get()
        try {
            envelope(scope, load(), redeliveryOk = true, loadedAt = gen)
        } catch (_: StaleLoad) {
            // Another change landed meanwhile; its own pre-signing covers it.
        } catch (e: Exception) {
            System.err.println("SignedConfigService: pre-signing '$scope' failed: ${e.message}")
        }
    }

    /**
     * Vault file signatures of [scope]'s file, one per signer, v1 and v2.
     * Cached per (scope, key, version, content) when the cache is on: the
     * canonical strings have no timestamp, so a signature stays valid for as
     * long as that version exists. The key names the scope and holds both
     * schemes, so no entry that was signed for v1 only (or for another Config
     * API) is ever served.
     */
    fun vaultSignatures(scope: String, key: String, version: Int, plaintext: ByteArray): VaultSignatures {
        fun sign() = VaultSignatures(
            v1 = signing.signVaultFileAll(key, version, plaintext),
            v2 = signing.signVaultFileV2All(scope, key, version, plaintext)
        )
        // Always cached, whatever CONFIG_SIGNATURE_CACHE says: a vault signature
        // carries no time, and a file's content is fixed per version (every
        // upload, encryption or policy change bumps it). Keyed without hashing
        // the content: a public file used to be hashed in full for every request.
        val cacheKey = "v2|$scope|$key|$version|${plaintext.size}"
        synchronized(vaultCache) { vaultCache[cacheKey]?.let { cacheHits.incrementAndGet(); return it } }
        // One signing per file version at a time: requests arriving together wait for it.
        val lock = keyLocks.computeIfAbsent("vault|$cacheKey") { Any() }
        synchronized(lock) {
            synchronized(vaultCache) { vaultCache[cacheKey]?.let { cacheHits.incrementAndGet(); return it } }
            val fresh = sign()
            synchronized(vaultCache) { vaultCache[cacheKey] = fresh }
            keyLocks.remove("vault|$cacheKey", lock)
            return fresh
        }
    }

    /**
     * Drops every cached signature. Called after every admin write — pins,
     * device ACLs, signing keys, key sets — so the next device request gets a
     * fresh signature with a newer issuedAt. A device that applied a set
     * revoking a key, for instance, must not keep receiving envelopes signed by it.
     */
    fun invalidate() {
        generation.incrementAndGet()
        synchronized(cache) { cache.clear() }
        synchronized(vaultCache) { vaultCache.clear() }
    }

    private fun signFresh(config: PinConfig, now: Long): SignedConfig {
        // Stamp issuedAt/expiresAt right before signing so the freshness
        // window is anchored to the server's wall clock. The client rejects
        // payloads where expiresAt <= now, so this TTL bounds how long a
        // captured signed config remains replayable.
        val issuedAt = lastIssuedAt.updateAndGet { last -> maxOf(now, last + 1) }
        val stamped = config.copy(issuedAt = issuedAt, expiresAt = issuedAt + ttlMs)
        val payload = json.encodeToString(stamped)
        val signatures = signing.signAll(payload)
        return SignedConfig(
            payload = payload,
            signature = signatures.first().signature,
            keyId = signatures.first().keyId,
            signatures = signatures.takeIf { it.size > 1 }
        )
    }

    private fun sha256Hex(text: String): String = sha256Hex(text.toByteArray(Charsets.UTF_8))

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    companion object {
        private const val MAX_ENTRIES = 512

        /**
         * Lifetime of a signed config in milliseconds (`CONFIG_TTL_SECONDS`,
         * default 24h). The PinVault client refreshes every 12h by default, so
         * 24h leaves a margin for devices that are offline for a while.
         */
        fun ttlFromEnv(): Long =
            System.getenv("CONFIG_TTL_SECONDS")?.toLongOrNull()?.times(1000L) ?: (24L * 60 * 60 * 1000)
    }
}
