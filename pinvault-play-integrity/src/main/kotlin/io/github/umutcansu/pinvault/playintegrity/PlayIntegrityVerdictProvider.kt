package io.github.umutcansu.pinvault.playintegrity

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse
import com.google.android.play.core.integrity.model.IntegrityErrorCode
import io.github.umutcansu.pinvault.integrity.IntegrityVerdict
import io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Play Integrity as PinVault's second opinion (`ATTESTATION.md` §11): on an
 * attestation round this asks Google for a **classic** integrity token bound
 * to the round's nonce and hands it over as `verdictProvider`
 * `{ "name": "play-integrity", "token": … }` inside the signed report. The
 * PinVault server decrypts and verifies the token with the response keys
 * from the Play Console (`PLAY_INTEGRITY_DECRYPTION_KEY` /
 * `PLAY_INTEGRITY_VERIFICATION_KEY`), checks that Google saw the same
 * nonce, package and a device that meets the configured level, and raises
 * the `play_integrity` flag when it does not — `play_integrity_missing`
 * when a device sends no fresh verdict at all. What the policy makes of the
 * two flags (reject, warn, ignore) is the server's decision, so the feature
 * switches on and off at three places independently: this provider on the
 * app, the keys on the server, the flags in the policy.
 *
 * Optional, and separate from the core library on purpose: without this
 * module an app carries nothing of Play Services. Turn it on with
 *
 * ```kotlin
 * PinVaultConfig.Builder()
 *     .integrityVerdictProvider(PlayIntegrityVerdictProvider(context, cloudProjectNumber = 123456789012L))
 * ```
 *
 * **Quota.** Classic requests are limited (10 000 per app per day by
 * default; raise it in the Play Console) and the library attests every
 * five minutes, so the provider asks Google at most once per
 * [minInterval] (default 6 hours) and answers null in between — the report
 * then carries no `verdictProvider`, and the server keeps the last verified
 * verdict for `PLAY_INTEGRITY_MAX_AGE_SECONDS` (default 24 hours) before it
 * raises `play_integrity_missing`. Set [minInterval] to 0 to send a token
 * on every round.
 *
 * **Nonce.** Google is given
 * `base64url-nopad(SHA-256("pinvault-play-integrity:v2:" + nonce + ":" + deviceId))`
 * (v2): the token is bound to this device's round, not only to the round's
 * nonce, so a token minted for one device does not pass for another. The
 * reference server accepts it, and a server with `PLAY_INTEGRITY_REQUIRE_V2`
 * accepts nothing else. When the library has no device id for the round the
 * raw nonce (v1) is sent, as before.
 *
 * **Failures** never fail an attestation: the probe logs and attests
 * without the verdict. A failure that will not change (Play Store or Play
 * Services missing, the app not installed by Play while Google refuses,
 * an invalid project number) switches the provider off for the rest of
 * the process; a transient one (network, Google's server, too many
 * requests) is retried on the next eligible round.
 *
 * @param context any context; the application context is kept.
 * @param cloudProjectNumber the Google Cloud project number linked to the
 *   app in the Play Console (App integrity → Play Integrity API).
 * @param minInterval shortest time between two requests to Google, in
 *   [minIntervalUnit]; 0 = every attestation round.
 */
class PlayIntegrityVerdictProvider @JvmOverloads constructor(
    context: Context,
    private val cloudProjectNumber: Long,
    minInterval: Long = DEFAULT_MIN_INTERVAL_HOURS,
    minIntervalUnit: TimeUnit = TimeUnit.HOURS
) : IntegrityVerdictProvider {

    private val appContext: Context = context.applicationContext
    private val minIntervalMs: Long = minIntervalUnit.toMillis(minInterval).coerceAtLeast(0L)

    /** Replaceable for tests; the real one is made on first use. */
    internal var managerFactory: () -> IntegrityManager = { IntegrityManagerFactory.create(appContext) }
    internal var clock: () -> Long = System::currentTimeMillis

    private val manager: IntegrityManager by lazy { managerFactory() }

    /** When Google last answered with a token (device clock, ms); 0 = never. */
    @Volatile
    var lastTokenAt: Long = 0L
        private set

    /** The last failure, for diagnostics; null after a success. */
    @Volatile
    var lastError: String? = null
        private set

    /** True once a failure that will not change was seen; no further requests this process. */
    @Volatile
    var unavailable: Boolean = false
        private set

    init {
        require(cloudProjectNumber > 0) { "cloudProjectNumber must be the Play Console project number (a positive number)" }
    }

    override suspend fun verdict(nonce: String): IntegrityVerdict? = verdictFor(nonce)

    override suspend fun verdict(nonce: String, deviceId: String): IntegrityVerdict? = verdictFor(boundNonce(nonce, deviceId))

    private suspend fun verdictFor(nonce: String): IntegrityVerdict? {
        if (unavailable) return null
        val now = clock()
        if (minIntervalMs > 0 && lastTokenAt != 0L && now - lastTokenAt < minIntervalMs) {
            Timber.d("Play Integrity: last token %d s ago, next in %d s — attesting without one",
                (now - lastTokenAt) / 1000, (minIntervalMs - (now - lastTokenAt)) / 1000)
            return null
        }
        val token = try {
            request(nonce)
        } catch (e: IntegrityServiceException) {
            recordFailure(e)
            throw e
        } catch (e: Exception) {
            lastError = "${e.javaClass.simpleName}: ${e.message}"
            throw e
        }
        lastTokenAt = clock()
        lastError = null
        return IntegrityVerdict(NAME, token)
    }

    private suspend fun request(nonce: String): String {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudProjectNumber(cloudProjectNumber)
            .build()
        val response: IntegrityTokenResponse = manager.requestIntegrityToken(request).await()
        return response.token().ifBlank { throw IllegalStateException("Play Integrity returned an empty token") }
    }

    private fun recordFailure(e: IntegrityServiceException) {
        val code = e.errorCode
        lastError = "Play Integrity error $code: ${e.message}"
        when (code) {
            IntegrityErrorCode.TOO_MANY_REQUESTS -> {
                // The quota is spent: wait a full interval before asking again.
                lastTokenAt = clock()
                Timber.w("Play Integrity: quota exceeded — next request in %d s", minIntervalMs / 1000)
            }
            in PERMANENT_ERRORS -> {
                unavailable = true
                Timber.w("Play Integrity is not available on this device (error %d) — attesting without it from now on", code)
            }
            else -> Timber.w("Play Integrity request failed (error %d) — attesting without it this round", code)
        }
    }

    private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { cont ->
        addOnSuccessListener { if (cont.isActive) cont.resume(it) }
        addOnFailureListener { if (cont.isActive) cont.resumeWithException(it) }
        addOnCanceledListener { if (cont.isActive) cont.cancel() }
    }

    companion object {
        /** The `verdictProvider.name` the server recognises. */
        const val NAME = "play-integrity"

        /** The v2 nonce: the round's nonce bound to the device, 43 URL-safe characters. */
        @JvmStatic
        fun boundNonce(nonce: String, deviceId: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest("pinvault-play-integrity:v2:$nonce:$deviceId".toByteArray(Charsets.UTF_8))
            return base64UrlNoPad(digest)
        }

        /** URL-safe Base64 without padding (java.util.Base64 needs API 26; minSdk is 24). */
        internal fun base64UrlNoPad(bytes: ByteArray): String {
            val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            val out = StringBuilder((bytes.size * 4 + 2) / 3)
            var i = 0
            while (i < bytes.size) {
                val b0 = bytes[i].toInt() and 0xFF
                val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
                val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
                out.append(alphabet[b0 shr 2])
                out.append(alphabet[((b0 and 0x03) shl 4) or (b1 shr 4)])
                if (i + 1 < bytes.size) out.append(alphabet[((b1 and 0x0F) shl 2) or (b2 shr 6)])
                if (i + 2 < bytes.size) out.append(alphabet[b2 and 0x3F])
                i += 3
            }
            return out.toString()
        }

        /** Default [minInterval]: one request to Google per six hours per process. */
        const val DEFAULT_MIN_INTERVAL_HOURS = 6L

        /** Error codes after which asking again in this process is pointless. */
        private val PERMANENT_ERRORS = setOf(
            IntegrityErrorCode.API_NOT_AVAILABLE,
            IntegrityErrorCode.PLAY_STORE_NOT_FOUND,
            IntegrityErrorCode.PLAY_SERVICES_NOT_FOUND,
            IntegrityErrorCode.APP_NOT_INSTALLED,
            IntegrityErrorCode.APP_UID_MISMATCH,
            IntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID,
            IntegrityErrorCode.NONCE_TOO_SHORT,
            IntegrityErrorCode.NONCE_TOO_LONG,
            IntegrityErrorCode.NONCE_IS_NOT_BASE64,
            IntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED,
            IntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED
        )
    }
}
