package io.github.umutcansu.pinvault.ssl

import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import java.security.cert.CertificateException
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * OkHttp Application Interceptor that catches SSL pin mismatch errors
 * and automatically fetches updated pins, then retries the request.
 *
 * Flow:
 * 1. Request fails with SSL exception (pin mismatch)
 * 2. Triggers updater to fetch new pins from server
 * 3. If update succeeds → retries request with new client
 * 4. If update fails → throws original exception
 *
 * ## Recovery semantics
 *
 * Pin-mismatch detection relies on exception **type** only
 * ([SSLPeerUnverifiedException] or [SSLHandshakeException] whose cause is
 * a [CertificateException]). The pre-V2 implementation also matched on
 * the exception **message** containing the string "Certificate pinning",
 * which broke when OkHttp / Conscrypt changed message formatting. Removing
 * the string match makes recovery resilient to upstream wording shifts.
 *
 * ## Circuit breaker
 *
 * Recovery is gated per-host so a backend that's actually serving bad pins
 * cannot thrash a client into a tight retry loop:
 *   - After [MAX_ATTEMPTS_PER_WINDOW] failed recoveries within
 *     [ATTEMPT_WINDOW_MS], the host enters cooldown for [COOLDOWN_MS].
 *   - During cooldown, the interceptor short-circuits and rethrows the
 *     original exception without consulting the updater.
 */
internal class PinRecoveryInterceptor(
    private val updater: () -> Boolean,
    private val newClientProvider: () -> okhttp3.OkHttpClient
) : Interceptor {

    private val lock = Any()

    /**
     * Per-host recovery state. Tracked separately so a misbehaving host
     * cannot starve recovery for unrelated hosts.
     */
    private data class RecoveryState(
        var firstAttemptMs: Long = 0L,
        var attemptCount: Int = 0,
        var cooldownUntilMs: Long = 0L
    )

    private val recoveryState = ConcurrentHashMap<String, RecoveryState>()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        return try {
            chain.proceed(request)
        } catch (e: IOException) {
            if (!isPinMismatch(e)) throw e

            val host = request.url.host
            if (isInCooldown(host)) {
                Timber.w("Pin recovery in cooldown for %s — rethrowing", host)
                throw e
            }

            Timber.w("Pin mismatch detected for %s — attempting auto-recovery", host)

            val updated = synchronized(lock) { updater() }

            if (!updated) {
                recordFailure(host)
                Timber.e("Auto-recovery failed for %s — update unsuccessful", host)
                throw e
            }

            Timber.d("Pins updated — retrying request to %s with new client", host)
            try {
                retryWithNewClient(request).also { recordSuccess(host) }
            } catch (retryErr: IOException) {
                recordFailure(host)
                throw retryErr
            }
        }
    }

    private fun retryWithNewClient(request: Request): Response {
        val newClient = newClientProvider()
        return newClient.newCall(request).execute()
    }

    private fun isPinMismatch(e: IOException): Boolean {
        return e is SSLPeerUnverifiedException ||
            (e is SSLHandshakeException && e.cause is CertificateException)
    }

    private fun isInCooldown(host: String): Boolean {
        val state = recoveryState[host] ?: return false
        return System.currentTimeMillis() < state.cooldownUntilMs
    }

    private fun recordFailure(host: String) {
        val now = System.currentTimeMillis()
        recoveryState.compute(host) { _, existing ->
            val state = existing ?: RecoveryState()
            // Reset window if the previous window has elapsed.
            if (now - state.firstAttemptMs > ATTEMPT_WINDOW_MS) {
                state.firstAttemptMs = now
                state.attemptCount = 1
            } else {
                state.attemptCount += 1
            }
            if (state.attemptCount >= MAX_ATTEMPTS_PER_WINDOW) {
                state.cooldownUntilMs = now + COOLDOWN_MS
                Timber.w("Pin recovery circuit-broken for %s until +%dms", host, COOLDOWN_MS)
            }
            state
        }
    }

    private fun recordSuccess(host: String) {
        // Clear state on success — host is healthy, next failure starts fresh.
        recoveryState.remove(host)
    }

    companion object {
        /** How many failed recoveries within [ATTEMPT_WINDOW_MS] trip the breaker. */
        private const val MAX_ATTEMPTS_PER_WINDOW = 3
        /** Sliding window for counting recovery failures (5 minutes). */
        private const val ATTEMPT_WINDOW_MS = 5L * 60 * 1000
        /** How long the breaker stays open after tripping (10 minutes). */
        private const val COOLDOWN_MS = 10L * 60 * 1000
    }
}
