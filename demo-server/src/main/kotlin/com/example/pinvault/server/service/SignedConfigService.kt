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
 * ## Narrowed views
 * A narrowed view (`?hosts=`, `X-Device-Id`, the attestation body's `hosts`)
 * names its request (`view`), so each distinct request is its own content —
 * and on a TLS listener those values are anyone's to make up. With the cache
 * on, a narrowed view that is not cached is signed only within its
 * requester's budget ([ViewSignLimits], else [ViewSignLimited] → 429), never
 * with the external signer's last permit nor after waiting in its queue
 * ([ConfigSigningService.signAllNarrowed]), and narrowed views are cached
 * apart from full ones, so they never evict a full view.
 *
 * Either way the latest signing-key set is attached to every envelope.
 */
class SignedConfigService(
    private val signing: ConfigSigningService,
    private val keySets: SigningKeySetService? = null,
    val ttlMs: Long = ttlFromEnv(),
    cacheEnabled: Boolean = com.example.pinvault.server.service.ServerEnv.get("CONFIG_SIGNATURE_CACHE") == "true",
    private val clock: () -> Long = System::currentTimeMillis,
    /**
     * Budget of NARROWED views each requester may have signed (cache misses
     * only; see [ViewSignLimits]); null = no limit. Never applied to the full
     * view, nor without the cache: then every request is signed anyway, the
     * full view's included.
     */
    private val viewLimits: ViewSignLimits? = null
) {
    /** Whether signatures are cached per content: asked for, or required by an external signer. */
    val cacheEnabled: Boolean = cacheEnabled || signing.external

    /** True when the cache was not asked for but an external signer made it necessary. */
    val cacheForced: Boolean = !cacheEnabled && signing.external

    private val json = Json { encodeDefaults = true }

    private data class Cached(val issuedAt: Long, val envelope: SignedConfig)

    /** Narrowed views (per device, per host set). */
    private val cache = object : LinkedHashMap<String, Cached>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Cached>?) = size > MAX_ENTRIES
    }

    /**
     * Full views (one content per Config API), apart from [cache]: however many
     * narrowed views anyone has signed, they never push a full view out and
     * make it be signed again.
     */
    private val fullCache = object : LinkedHashMap<String, Cached>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Cached>?) = size > MAX_FULL_ENTRIES
    }

    private fun cacheOf(narrowed: Boolean) = if (narrowed) cache else fullCache
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

    /**
     * Thrown by [envelope] when a narrowed view would have to be signed and its
     * requester's budget ([ViewSignLimits]) is spent. Answered with 429 and
     * `Retry-After: [retryAfterSeconds]`; a different view is never served in
     * its place (the client would refuse it).
     */
    class ViewSignLimited(val retryAfterSeconds: Long) : RuntimeException("too many narrowed config views signed for this requester")

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
        cachedEnvelopes = synchronized(cache) { cache.size } + synchronized(fullCache) { fullCache.size }
    )

    /**
     * The envelope for [config] — already filtered to what the requesting
     * device may see, with `issuedAt`/`expiresAt` still 0. [scope] keeps
     * identical content of different Config APIs apart.
     *
     * [redeliveryOk]: the client said it accepts the same signed config twice
     * (`X-PinVault-Features: redelivery`). Only such clients get cached
     * envelopes; any other client gets a fresh signature, as before.
     *
     * [requester]: who asked, for the narrowed-view budget ([ViewSignLimits]);
     * null (pre-signing, server-internal calls) = not counted. Throws
     * [ViewSignLimited] when a narrowed view is not cached and the budget is
     * spent; a cache hit is never refused.
     */
    fun envelope(
        scope: String,
        view: PinConfig,
        redeliveryOk: Boolean = true,
        loadedAt: Long? = null,
        requester: ViewSignLimits.Requester? = null
    ): SignedConfig {
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
        // The view a narrowed payload answers (`view`: requested hosts, device
        // id) is part of the hashed content and named again in the key, so a
        // narrowed envelope is never served for a full request, nor one
        // request's for another that happens to yield the same pins (M6).
        val narrowed = config.view != null
        val viewKey = config.view?.let { v -> "v:" + sha256Hex(json.encodeToString(com.example.pinvault.server.model.ConfigView.serializer(), v)) } ?: "full"
        val key = "$gen|$scope|$viewKey|" + sha256Hex(json.encodeToString(config.copy(issuedAt = 0, expiresAt = 0)))
        cachedFor(key, clock(), narrowed)?.let { return it.copy(signingKeys = keySet) }

        val lock = keyLocks.computeIfAbsent(key) { Any() }
        try {
            synchronized(lock) {
                // Another request may have signed this key while we waited.
                cachedFor(key, clock(), narrowed)?.let { return it.copy(signingKeys = keySet) }
                if (gen != generation.get()) throw StaleLoad()
                // A narrowed view nobody has signed yet: whoever asked pays from
                // their budget. Made-up device ids and host lists are a miss each.
                if (narrowed && requester != null && viewLimits != null && !viewLimits.allow(requester)) {
                    throw ViewSignLimited(viewLimits.retryAfterSeconds(requester))
                }
                val fresh = signFresh(config, clock())
                val issuedAt = json.decodeFromString(PinConfig.serializer(), fresh.payload).issuedAt
                val target = cacheOf(narrowed)
                synchronized(target) {
                    // Keep the newer envelope if two signings raced.
                    val existing = target[key]
                    if (existing == null || existing.issuedAt < issuedAt) target[key] = Cached(issuedAt, fresh)
                }
                return fresh.copy(signingKeys = keySet)
            }
        } finally {
            // Also when signing failed or was refused: a lock left behind per
            // made-up view would be memory anyone can fill.
            keyLocks.remove(key, lock)
        }
    }

    private fun cachedFor(key: String, now: Long, narrowed: Boolean): SignedConfig? = synchronized(cacheOf(narrowed)) {
        val cache = cacheOf(narrowed)
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
        synchronized(fullCache) { fullCache.clear() }
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
        // A narrowed view never takes the signer's last permit, nor waits in its queue.
        val signatures = if (config.view != null) signing.signAllNarrowed(payload) else signing.signAll(payload)
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
        private const val MAX_FULL_ENTRIES = 64

        /**
         * Lifetime of a signed config in milliseconds (`CONFIG_TTL_SECONDS`,
         * default 24h). The PinVault client refreshes every 12h by default, so
         * 24h leaves a margin for devices that are offline for a while.
         */
        fun ttlFromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): Long {
            val raw = env["CONFIG_TTL_SECONDS"]?.trim().orEmpty()
            if (raw.isEmpty()) return 24L * 60 * 60 * 1000
            // Unbounded it took 0 or a negative number (every config expired
            // as it was signed) and more than 30 days (devices refuse such a
            // window): either way the whole fleet stops taking configs.
            val seconds = raw.toLongOrNull()?.takeIf { it in MIN_TTL_SECONDS..MAX_TTL_SECONDS }
                ?: error("CONFIG_TTL_SECONDS must be a whole number from $MIN_TTL_SECONDS to $MAX_TTL_SECONDS (got '$raw')")
            return seconds * 1000L
        }

        /**
         * A minute at least (the dashboard's settings page starts at 300; the
         * environment may go lower for a test of expiry), and at most the 30
         * days the library accepts as a window.
         */
        const val MIN_TTL_SECONDS = 60L
        const val MAX_TTL_SECONDS = 2_592_000L
    }
}
