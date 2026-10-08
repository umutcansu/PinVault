package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.AttestationEventStatus
import io.github.umutcansu.pinvault.api.AttestationHttpException
import io.github.umutcansu.pinvault.api.AttestationTokenSource
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.AttestationResult
import io.github.umutcansu.pinvault.model.AttestationStatus
import io.github.umutcansu.pinvault.model.AttestationTokenResult
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.PinHostMatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber
import java.security.MessageDigest

/**
 * Attestation of one Config API block (`ATTESTATION.md`): the challenge /
 * report / verdict round trip, the token it yields, the refresh loop that
 * keeps the token fresh while the process lives, and the token source the
 * [io.github.umutcansu.pinvault.api.AttestationTokenInterceptor] reads.
 *
 * Everything here is in memory: the token, the status, the schedule.
 * Nothing new is written to disk.
 *
 * @param api the block's own HTTP client, or null for a custom
 *   `CertificateConfigApi` — attestation is then [AttestationResult.UNSUPPORTED].
 * @param identityKey the block's device key (the mTLS identity key); made
 *   with the identity attestation challenge if it does not exist yet.
 * @param deviceId the device id the request carries (`ANDROID_ID`); null = unknown.
 * @param currentConfigVersion / [currentIssuedAt] what the device holds, so
 *   the server can embed a fresh config when the device is behind.
 * @param liveConfig the block's active config, for the token hosts when the
 *   block names none.
 * @param buildReport the report JSON for a nonce, as a string — what is
 *   signed and sent, byte for byte.
 * @param applyConfig applies a signed config from the answer
 *   (`SSLCertificateUpdater.applySigned`).
 * @param onConfigApplied told the result of [applyConfig], the way the
 *   recovery interceptor reports its updates.
 * @param onEvent receives one [PinVaultConnectionEvent.Attestation] per attempt.
 */
internal class AttestationManager(
    private val block: ConfigApiBlock,
    private val api: DefaultCertificateConfigApi?,
    private val identityKey: () -> ClientIdentityKeyProvider,
    private val deviceId: () -> String?,
    private val currentConfigVersion: () -> Int,
    private val currentIssuedAt: () -> Long,
    private val liveConfig: () -> CertificateConfig?,
    /** `deviceId` is non-null when the server takes v2 verdicts, bound to the device. */
    private val buildReport: suspend (nonce: String, deviceId: String?, key: ClientIdentityKeyProvider) -> String,
    private val applyConfig: suspend (SignedConfigResponse) -> UpdateResult,
    private val onConfigApplied: (UpdateResult) -> Unit = { },
    private val onEvent: (PinVaultConnectionEvent.Attestation) -> Unit = { },
    private val clock: () -> Long = System::currentTimeMillis,
    /** A value in [0, 1) per call, for the jitter. Tests fix it. */
    private val jitter: () -> Double = { java.util.concurrent.ThreadLocalRandom.current().nextDouble() }
) : AttestationTokenSource {

    private val initialStatus = AttestationStatus(
        configApiId = block.id,
        result = if (api == null) AttestationResult.UNSUPPORTED else AttestationResult.NOT_ATTESTED,
        lastError = if (api == null) UNSUPPORTED_REASON else null
    )

    /** The last outcome; what `PinVault.attestationStatus` returns. */
    @Volatile
    var status: AttestationStatus = initialStatus
        private set

    @Volatile
    private var token: String? = null

    /** Device-clock expiry of [token]; 0 without one. */
    @Volatile
    private var tokenExpiresAt: Long = 0L

    /** When the last attempt ran, pass, reject or failure; null = never. */
    @Volatile
    private var lastAttemptAt: Long? = null

    /**
     * Whether the next request carries the key's attestation chain: on the
     * first attempt of the process, and again after the server said it does
     * not know the key or wants its attestation (`key_unknown`,
     * `attestation_required`, `attestation_invalid`). Once the server has
     * answered with a verdict the device is registered and the chain is of
     * no further use (a key cannot be re-attested).
     */
    @Volatile
    private var chainWanted = true

    @Volatile
    private var consecutiveFailures = 0

    /** One attestation at a time; callers that arrive meanwhile share its result. */
    private val lock = Mutex()
    private var inFlight: CompletableDeferred<AttestationStatus>? = null
    private val flightLock = Any()

    private var scope: CoroutineScope? = null

    /** True when this block attests (an `attestation()` block with the library's own client). */
    val supported: Boolean get() = api != null

    // ── Attesting ───────────────────────────────────────────────────────

    /**
     * Attests now and returns the outcome. Single flight: a caller that
     * arrives while an attestation is running waits for that one and gets
     * its result instead of starting another.
     */
    suspend fun attestNow(): AttestationStatus {
        val (flight, mine) = synchronized(flightLock) {
            inFlight?.let { it to false } ?: (CompletableDeferred<AttestationStatus>().also { inFlight = it } to true)
        }
        if (!mine) {
            Timber.d("Attestation [%s] already running — waiting for its result", block.id)
            return flight.await()
        }
        return try {
            lock.withLock { attestOnce() }.also { flight.complete(it) }
        } catch (e: Throwable) {
            // Only cancellation gets here (attestOnce reports failures as a status).
            flight.complete(status)
            throw e
        } finally {
            synchronized(flightLock) { inFlight = null }
        }
    }

    /**
     * The token for the header, attesting first when none with enough life
     * is held: [AttestationTokenResult.Token], or why there is none.
     */
    suspend fun fetchToken(): AttestationTokenResult {
        if (api == null) return AttestationTokenResult.Unsupported
        heldToken(clock())?.let { return it }
        val outcome = attestNow()
        heldToken(clock(), minRemainingMs = 0L)?.let { return it }
        return if (outcome.result == AttestationResult.REJECT) AttestationTokenResult.Rejected(outcome)
        else AttestationTokenResult.Failed(outcome.lastError ?: "The server passed the device but issued no token")
    }

    private fun heldToken(now: Long, minRemainingMs: Long = TOKEN_MIN_REMAINING_MS): AttestationTokenResult.Token? {
        val value = token ?: return null
        val expiresAt = tokenExpiresAt
        return if (expiresAt - now >= minRemainingMs && expiresAt > now) AttestationTokenResult.Token(value, expiresAt) else null
    }

    private suspend fun attestOnce(): AttestationStatus {
        val api = api ?: return status
        val startedAt = clock()
        lastAttemptAt = startedAt
        var skew: Long? = status.clockSkewMs
        return try {
            val key = identityKey()
            val did = resolvedDeviceId()
            // The same key, with the same challenge, as an mTLS enrollment
            // makes: a device that never enrolls still has it from here on.
            key.ensureKeyPair(ClientIdentityKeyProvider.attestationChallenge(did))

            val challenge = api.attestChallenge()
            val nonce = challenge.optString("nonce").ifBlank {
                throw IllegalStateException("The attestation challenge carries no nonce")
            }
            challenge.optLong("serverTime", 0L).takeIf { it > 0L }?.let { skew = it - clock() }
            // v2 verdicts (bound to the device) only for a server that takes them (ATTESTATION.md §2.1).
            val bindVerdict = challenge.optInt("verdictBinding", 1) >= 2

            val report = buildReport(nonce, did.takeIf { bindVerdict }, key)
            val canonical = canonicalString(nonce, did, report)
            val signature = base64(key.sign(canonical.toByteArray(Charsets.UTF_8)))
            val chain = if (chainWanted) attestationChainOf(key) else emptyList()

            val body = JSONObject()
                .put("v", PROTOCOL_VERSION)
                .put("nonce", nonce)
                .put("deviceId", did)
                .put("publicKey", base64(key.publicKey().encoded))
                .put("report", report)
                .put("signature", signature)
                .put("currentConfigVersion", currentConfigVersion())
                .put("currentIssuedAt", currentIssuedAt())
            if (chain.isNotEmpty()) body.put("attestationChain", JSONArray(chain))
            if (block.wantPinsFor.isNotEmpty()) body.put("hosts", JSONArray(block.wantPinsFor))

            val answer = api.attest(body)
            // Answered with a verdict: the key is registered; the chain has done its work.
            chainWanted = false
            handleVerdict(answer, skew)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: AttestationHttpException) {
            if (CHAIN_WANTED_AGAIN.contains(e.serverError.orEmpty())) chainWanted = true
            failed(e.message ?: "Attestation refused — HTTP ${e.httpStatus}", skew)
        } catch (e: Exception) {
            failed("${e.javaClass.simpleName}: ${e.message}", skew)
        } catch (e: LinkageError) {
            // An API this device lacks (a probe, the Keystore): attestation is not possible here.
            failed("This device lacks an API attestation needs: $e", skew)
        }
    }

    private suspend fun handleVerdict(answer: JSONObject, skew: Long?): AttestationStatus {
        val now = clock()
        val arc = answer.optString("arc").ifBlank { null }
        val warnings = strings(answer.optJSONArray("warnings"))
        val reasons = strings(answer.optJSONArray("rejectionReasons"))
        val policyVersion = if (answer.has("policyVersion") && !answer.isNull("policyVersion")) answer.optInt("policyVersion") else null
        val nextAttestInMs = answer.optLong("nextAttestIn", 0L).takeIf { it > 0L }?.times(1000)

        return when (val result = answer.optString("result")) {
            "pass" -> {
                val issued = answer.optString("token").ifBlank { null }
                val ttlMs = answer.optLong("tokenTtlSeconds", 0L).takeIf { it > 0L }?.times(1000)
                // Device-clock expiry: the server's `tokenExpiresAt` is in its
                // own time, so the TTL is preferred and the skew applied otherwise.
                val expiresAt = when {
                    issued == null -> null
                    ttlMs != null -> now + ttlMs
                    else -> answer.optLong("tokenExpiresAt", 0L).takeIf { it > 0L }?.let { it - (skew ?: 0L) } ?: now + DEFAULT_TOKEN_TTL_MS
                }
                if (issued == null) {
                    Timber.w("Attestation [%s] passed, but the server issued no token", block.id)
                    token = null
                    tokenExpiresAt = 0L
                } else {
                    token = issued
                    tokenExpiresAt = expiresAt!!
                }
                consecutiveFailures = 0
                val delay = refreshDelayMs(nextAttestInMs, block.attestationIntervalMs, expiresAt, now, jitter())
                val passed = AttestationStatus(
                    configApiId = block.id,
                    result = AttestationResult.PASS,
                    arc = arc,
                    rejectionReasons = emptyList(),
                    warnings = warnings,
                    tokenExpiresAt = expiresAt,
                    lastAttestedAt = now,
                    nextAttestAt = now + delay,
                    clockSkewMs = skew,
                    lastError = null,
                    policyVersion = policyVersion
                )
                Timber.i("Attestation [%s] passed (arc=%s, warnings=%s, token until %s)", block.id, arc, warnings, expiresAt)
                publish(passed, AttestationEventStatus.PASS, null)
                // The config rides along only on a pass, and goes through the
                // same checks as a fetched one.
                answer.optJSONObject("config")?.let { applyEmbeddedConfig(it) }
                passed
            }
            "reject" -> {
                token = null
                tokenExpiresAt = 0L
                consecutiveFailures = 0
                val delay = refreshDelayMs(nextAttestInMs, block.attestationIntervalMs, null, now, jitter())
                val rejected = AttestationStatus(
                    configApiId = block.id,
                    result = AttestationResult.REJECT,
                    arc = arc,
                    rejectionReasons = reasons,
                    warnings = warnings,
                    tokenExpiresAt = null,
                    lastAttestedAt = now,
                    nextAttestAt = now + delay,
                    clockSkewMs = skew,
                    lastError = null,
                    policyVersion = policyVersion
                )
                Timber.w("Attestation [%s] rejected (arc=%s, reasons=%s)", block.id, arc, reasons)
                publish(rejected, AttestationEventStatus.REJECT, null)
                rejected
            }
            else -> failed("The attestation answer has an unknown result '${result.take(32)}'", skew)
        }
    }

    private suspend fun applyEmbeddedConfig(json: JSONObject) {
        val signed = try {
            com.google.gson.Gson().fromJson(json.toString(), SignedConfigResponse::class.java)
        } catch (e: Exception) {
            Timber.w(e, "Attestation [%s]: the embedded config is not a signed envelope — ignored", block.id)
            return
        }
        if (signed == null) return
        val result = try {
            applyConfig(signed)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            UpdateResult.Failed(e.message ?: e.javaClass.simpleName, e)
        }
        Timber.d("Attestation [%s]: embedded config → %s", block.id, result)
        try {
            onConfigApplied(result)
        } catch (e: Exception) {
            Timber.w(e, "Attestation [%s]: update listener threw", block.id)
        }
    }

    private fun failed(reason: String, skew: Long?): AttestationStatus {
        val now = clock()
        consecutiveFailures += 1
        // The last token is kept until it expires (the loop keeps trying).
        if (tokenExpiresAt <= now) {
            token = null
            tokenExpiresAt = 0L
        }
        val previous = status
        val failedStatus = previous.copy(
            result = AttestationResult.FAILED,
            tokenExpiresAt = token?.let { tokenExpiresAt },
            nextAttestAt = now + backoffMs(consecutiveFailures),
            clockSkewMs = skew ?: previous.clockSkewMs,
            lastError = reason
        )
        Timber.w("Attestation [%s] failed: %s (attempt %d)", block.id, reason, consecutiveFailures)
        publish(failedStatus, AttestationEventStatus.FAILED, reason)
        return failedStatus
    }

    private fun publish(newStatus: AttestationStatus, eventStatus: AttestationEventStatus, failureReason: String?) {
        status = newStatus
        try {
            onEvent(
                PinVaultConnectionEvent.Attestation(
                    configApiId = block.id,
                    status = eventStatus,
                    arc = newStatus.arc,
                    rejectionReasons = newStatus.rejectionReasons,
                    warnings = newStatus.warnings,
                    tokenExpiresAt = newStatus.tokenExpiresAt,
                    failureReason = failureReason
                )
            )
        } catch (e: Exception) {
            Timber.w(e, "Attestation [%s]: event listener threw", block.id)
        }
    }

    private fun resolvedDeviceId(): String {
        val id = deviceId()?.trim().orEmpty()
        // The server's rule for the field; a device without an ANDROID_ID
        // still attests, under a fixed name, as it enrolls.
        return if (id.isNotEmpty() && DEVICE_ID.matches(id)) id else UNKNOWN_DEVICE_ID
    }

    private fun attestationChainOf(key: ClientIdentityKeyProvider): List<String> = try {
        key.attestationChain().map { base64(it) }
    } catch (e: Exception) {
        Timber.w(e, "Attestation [%s]: could not read the key's attestation chain — sending none", block.id)
        emptyList()
    } catch (e: LinkageError) {
        emptyList()
    }

    // ── The refresh loop ────────────────────────────────────────────────

    /**
     * Starts re-attesting in the background at `min(nextAttestIn, interval,
     * tokenExpiry − 60 s)` with jitter, backing off 30 s → 5 min on failure.
     * No-op for an unsupported block, and while already running.
     */
    fun start() {
        if (api == null) return
        synchronized(flightLock) {
            if (scope != null) return
            val s = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            scope = s
            s.launch { loop() }
        }
    }

    /** Stops the refresh loop. The token and the status stay. */
    fun stop() {
        synchronized(flightLock) {
            scope?.cancel()
            scope = null
        }
    }

    /** [stop], and forgets the token and the status — `PinVault.reset()`. */
    fun reset() {
        stop()
        token = null
        tokenExpiresAt = 0L
        consecutiveFailures = 0
        chainWanted = true
        lastAttemptAt = null
        status = initialStatus
    }

    private suspend fun loop() {
        while (true) {
            val wait = (status.nextAttestAt?.let { it - clock() } ?: block.attestationIntervalMs).coerceAtLeast(MIN_DELAY_MS)
            delay(wait)
            attestNow()
        }
    }

    // ── AttestationTokenSource ─────────────────────────────────────────

    override fun handlesHost(host: String, port: Int): Boolean =
        api != null && PinHostMatcher.match(tokenHostMap(), host, port) != null

    /**
     * The hosts whose requests carry the token: the block's `tokenHosts`,
     * or — when it names none — every host pinned by the live config and
     * the block's own Config API listener.
     */
    private fun tokenHostMap(): Map<String, Unit> {
        val hosts = if (block.tokenHosts.isNotEmpty()) {
            block.tokenHosts
        } else {
            liveConfig()?.pins?.map { it.hostname }.orEmpty() + listOfNotNull(configApiListener)
        }
        return hosts.associate { it.lowercase() to Unit }
    }

    private val configApiListener: String? =
        block.configUrl.toHttpUrlOrNull()?.let { "${it.host}:${it.port}" }

    override fun token(host: String, port: Int, forceRefresh: Boolean): String? {
        if (api == null) return null
        val now = clock()
        val held = token?.takeIf { tokenExpiresAt - now >= TOKEN_MIN_REMAINING_MS }
        if (!forceRefresh && held != null) return held
        if (!mayAttestOnDemand(now, forceRefresh)) return held
        return try {
            runBlocking { attestNow() }
            token?.takeIf { tokenExpiresAt > clock() }
        } catch (e: Exception) {
            Timber.w(e, "Attestation [%s] on demand for %s failed", block.id, host)
            held
        }
    }

    /**
     * Whether a request may trigger an attestation now. A passing device
     * whose token ran out always may (a forced one after a 401 only once per
     * [REATTEST_GAP_MS], so a backend that refuses every token does not make
     * every request attest); a rejected or failing device waits for its
     * scheduled next attempt, so requests do not turn a reject into a storm.
     */
    private fun mayAttestOnDemand(now: Long, force: Boolean): Boolean {
        val last = lastAttemptAt ?: return true
        return when (status.result) {
            AttestationResult.PASS, AttestationResult.NOT_ATTESTED -> !force || now - last >= REATTEST_GAP_MS
            else -> now >= (status.nextAttestAt ?: 0L)
        }
    }

    companion object {
        const val PROTOCOL_VERSION = 1

        /** `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>` (`ATTESTATION.md` §2.2). */
        fun canonicalString(nonce: String, deviceId: String, report: String): String =
            "pinvault-attest:v1:$nonce:$deviceId:${sha256Hex(report.toByteArray(Charsets.UTF_8))}"

        fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        private fun base64(bytes: ByteArray): String = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

        private fun strings(array: JSONArray?): List<String> =
            array?.let { a -> (0 until a.length()).mapNotNull { i -> a.optString(i).ifBlank { null } } }.orEmpty()

        /** The server's rule for `deviceId`. */
        private val DEVICE_ID = Regex("^[A-Za-z0-9._:-]{1,64}$")
        private const val UNKNOWN_DEVICE_ID = "unknown-device"

        /** Server errors after which the next request carries the key's attestation chain again. */
        private val CHAIN_WANTED_AGAIN = setOf("key_unknown", "attestation_required", "attestation_invalid")

        const val UNSUPPORTED_REASON =
            "This Config API block does not attest: attestation needs the library's own HTTP client, not a custom CertificateConfigApi"

        /** Shortest wait between two scheduled attestations. */
        const val MIN_DELAY_MS = 30_000L
        /** Re-attest this long before the token expires. */
        const val EXPIRY_MARGIN_MS = 60_000L
        /** Backoff after failures: 30 s, 60 s, 2 min, 4 min, then 5 min. */
        const val BACKOFF_MIN_MS = 30_000L
        const val BACKOFF_MAX_MS = 5L * 60 * 1000
        /** ±10 % on every scheduled delay. */
        const val JITTER = 0.10
        /** A held token with less life than this is replaced before it is used. */
        const val TOKEN_MIN_REMAINING_MS = 30_000L
        /** A 401 forces at most one re-attestation per this many ms. */
        const val REATTEST_GAP_MS = 5_000L
        /** When the server names neither a TTL nor an expiry. */
        const val DEFAULT_TOKEN_TTL_MS = 5L * 60 * 1000

        /**
         * How long to wait before the next scheduled attestation after a
         * verdict: the least of the server's `nextAttestIn`, the block's
         * interval and the token's expiry minus [EXPIRY_MARGIN_MS], at least
         * [MIN_DELAY_MS], spread by ±[JITTER] with [jitter] in [0, 1).
         */
        fun refreshDelayMs(nextAttestInMs: Long?, blockIntervalMs: Long, tokenExpiresAt: Long?, now: Long, jitter: Double): Long {
            var base = minOf(nextAttestInMs ?: blockIntervalMs, blockIntervalMs)
            if (tokenExpiresAt != null) base = minOf(base, tokenExpiresAt - now - EXPIRY_MARGIN_MS)
            base = base.coerceAtLeast(MIN_DELAY_MS)
            val spread = (base * JITTER * (2 * jitter.coerceIn(0.0, 1.0) - 1)).toLong()
            return (base + spread).coerceAtLeast(MIN_DELAY_MS)
        }

        /** The wait after the [consecutiveFailures]-th failure in a row: 30 s doubling up to 5 min. */
        fun backoffMs(consecutiveFailures: Int): Long {
            val exponent = (consecutiveFailures - 1).coerceIn(0, 10)
            return (BACKOFF_MIN_MS shl exponent).coerceAtMost(BACKOFF_MAX_MS)
        }
    }
}
