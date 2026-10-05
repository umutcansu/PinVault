package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateValidityException
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import java.security.cert.CertificateException
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
 * One certificate failure is deliberately excluded:
 * [io.github.umutcansu.pinvault.model.CertificateValidityException] (server
 * certificate expired or not yet valid). A config refresh cannot repair it,
 * so it is rethrown untouched instead of triggering recovery.
 *
 * ## Budget
 *
 * A refetch costs the backend a request, and a failing handshake is something
 * anyone on the network can cause. Recovery is therefore bounded three ways:
 *   - **Per host** (circuit breaker): after [MAX_ATTEMPTS_PER_WINDOW] failed
 *     recoveries within [ATTEMPT_WINDOW_MS], the host enters cooldown for
 *     [COOLDOWN_MS]; the interceptor then rethrows the original exception
 *     without consulting the updater. At most [MAX_TRACKED_HOSTS] hosts are
 *     tracked (least recently used first out).
 *   - **Across hosts**: at most [GLOBAL_MAX_REFETCHES] refetches per
 *     [ATTEMPT_WINDOW_MS], whatever the hosts. Without it every new host
 *     name came with a fresh per-host budget.
 *   - **Unknown hosts**: a host the config has no pin entry for
 *     ([UnpinnedHostException]) is worth one refetch — the config may have
 *     gained the host since — but only one per [ATTEMPT_WINDOW_MS] for all
 *     such hosts together.
 *
 * Refetches are serialised, and requests that fail together share one: the
 * cooldown and the budget are checked inside the lock, and a request that
 * finds a refetch finished since it started takes that refetch's outcome
 * instead of running its own.
 */
internal class PinRecoveryInterceptor(
    private val updater: () -> Boolean,
    /**
     * Optional fallback client for the retry, used only when retrying on the
     * caller's own chain still hits a pin mismatch. See [retry].
     */
    private val newClientProvider: (() -> okhttp3.OkHttpClient)? = null,
    /** Wall clock for the windows and the cooldown. Tests set it. */
    private val clock: () -> Long = System::currentTimeMillis
) : Interceptor {

    /** Guards every field below and serialises refetches. */
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

    /** Access-ordered and bounded: host names come from requests, so the map must not grow with them. */
    private val recoveryState = object : LinkedHashMap<String, RecoveryState>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, RecoveryState>?): Boolean =
            size > MAX_TRACKED_HOSTS
    }

    /** When the refetches of the current window started, oldest first — the budget across hosts. */
    private val refetchTimes = ArrayDeque<Long>()

    /** When a refetch was last spent on a host without a pin entry; null = never. */
    private var lastUnknownHostRefetchMs: Long? = null

    /** The last refetch: when it finished ([System.nanoTime]) and whether it brought a usable config. */
    private class Refetch(val finishedAtNanos: Long, val updated: Boolean)

    private var lastRefetch: Refetch? = null

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        // The fallback retry below runs on a client that has this interceptor
        // too; one recovery per request, never a nested one.
        if (request.tag(RecoveryAttempt::class.java) != null) return chain.proceed(request)
        val startedAtNanos = System.nanoTime()
        return try {
            chain.proceed(request)
        } catch (e: IOException) {
            if (!isPinMismatch(e)) throw e

            val host = request.url.host
            val updated = synchronized(lock) {
                // Inside the lock on purpose: of several requests failing
                // together, the first refetches; by the time the others get
                // here the host may be in cooldown or the answer may be in.
                if (isInCooldown(host)) {
                    Timber.w("Pin recovery in cooldown for %s — rethrowing", host)
                    throw e
                }
                val finishedSinceStart = lastRefetch?.takeIf { it.finishedAtNanos - startedAtNanos > 0 }
                if (finishedSinceStart != null) {
                    Timber.d("Pin failure for %s — a config refetch finished since this request started, using its result", host)
                    finishedSinceStart.updated
                } else {
                    if (!takeBudget(host, unknownHost = e.cause is io.github.umutcansu.pinvault.model.UnpinnedHostException)) throw e
                    Timber.w("Pin mismatch detected for %s — attempting auto-recovery", host)
                    val result = try {
                        updater()
                    } catch (updateErr: Exception) {
                        Timber.e(updateErr, "Auto-recovery for %s threw", host)
                        false
                    }
                    lastRefetch = Refetch(System.nanoTime(), result)
                    result
                }
            }

            if (!updated) {
                recordFailure(host)
                Timber.e("Auto-recovery failed for %s — update unsuccessful", host)
                throw e
            }

            Timber.d("Pins updated — retrying request to %s", host)
            try {
                retry(chain, request).also { recordSuccess(host) }
            } catch (retryErr: IOException) {
                recordFailure(host)
                throw retryErr
            }
        }
    }

    /**
     * True when one more refetch may be spent now, and then it is counted.
     * Call with [lock] held.
     */
    private fun takeBudget(host: String, unknownHost: Boolean): Boolean {
        val now = clock()
        while (refetchTimes.isNotEmpty() && now - refetchTimes.first() > ATTEMPT_WINDOW_MS) refetchTimes.removeFirst()
        if (unknownHost) {
            val last = lastUnknownHostRefetchMs
            if (last != null && now - last in 0..ATTEMPT_WINDOW_MS) {
                Timber.w("No pin entry for %s — a refetch for an unknown host was already spent in this window, rethrowing", host)
                return false
            }
        }
        if (refetchTimes.size >= GLOBAL_MAX_REFETCHES) {
            Timber.w("Pin recovery budget used up (%d refetches in %d min) — rethrowing for %s",
                GLOBAL_MAX_REFETCHES, ATTEMPT_WINDOW_MS / 60_000, host)
            return false
        }
        if (unknownHost) lastUnknownHostRefetchMs = now
        refetchTimes.addLast(now)
        return true
    }

    /**
     * Retries on the CALLER's chain first. When this interceptor is installed
     * through [io.github.umutcansu.pinvault.PinVault.applyTo], that client owns
     * the consumer's `Dns`, interceptors and timeouts, and its trust manager
     * re-reads the live config on every handshake — so the retry must not be
     * moved onto a different client (doing so used to drop a custom `Dns` and
     * fail the retry with `UnknownHostException`).
     *
     * The internally managed client is built against a config snapshot, so its
     * chain would still see the old pins; for that path a second attempt runs
     * on the freshly swapped client from [newClientProvider].
     *
     * If that fallback fails too, the caller gets the exception from **its own
     * chain**, with the fallback's failure attached as suppressed — see the
     * comment inside.
     */
    private fun retry(chain: Interceptor.Chain, request: Request): Response {
        return try {
            chain.proceed(request)
        } catch (e: IOException) {
            val newClient = newClientProvider?.invoke()
            if (newClient == null || !isPinMismatch(e)) throw e
            Timber.d("Retry on the caller's client still mismatched — retrying on the refreshed client")
            try {
                newClient.newCall(request.newBuilder().tag(RecoveryAttempt::class.java, RecoveryAttempt).build()).execute()
            } catch (fallbackErr: IOException) {
                // The fallback is the library's own client. It does NOT carry
                // the caller's Dns, interceptors or timeouts, so when it fails
                // it usually fails for a reason that has nothing to do with the
                // request the caller made — most often `UnknownHostException`
                // from a custom `Dns` the internal client never had. Throwing
                // that would hand the app a DNS error in place of the real pin
                // mismatch it hit on its own chain.
                //
                // Report the caller-chain failure and attach the fallback's as
                // suppressed, so the fallback attempt is still visible in a
                // stack trace / bug report without masking the diagnosis.
                if (fallbackErr !== e) e.addSuppressed(fallbackErr)
                Timber.w(
                    fallbackErr,
                    "Fallback retry on the refreshed client also failed — rethrowing the original pin error"
                )
                throw e
            }
        }
    }

    private fun isPinMismatch(e: IOException): Boolean {
        // A certificate outside its validity window is NOT a pin mismatch:
        // fetching a fresh config cannot make an expired cert valid, so
        // recovering would only burn a backend round-trip, replace the real
        // reason with the retry's failure, and trip the circuit breaker on
        // something pinning can't fix. See
        // [io.github.umutcansu.pinvault.model.CertificateValidityException].
        if (e.cause is CertificateValidityException) return false
        // Same for a chain the platform CAs refuse (requireCaTrust): pins
        // cannot make it trusted. An EXPIRED config, on the other hand, is
        // exactly what a refetch repairs, so it stays a recoverable failure.
        if (e.cause is io.github.umutcansu.pinvault.model.CaTrustException) return false

        return e is SSLPeerUnverifiedException ||
            (e is SSLHandshakeException && e.cause is CertificateException)
    }

    private fun isInCooldown(host: String): Boolean = synchronized(lock) {
        val state = recoveryState[host] ?: return false
        clock() < state.cooldownUntilMs
    }

    private fun recordFailure(host: String) {
        val now = clock()
        synchronized(lock) {
            val state = recoveryState.getOrPut(host) { RecoveryState() }
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
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun recordSuccess(host: String) {
        // Intentionally no-op. Previously the entire per-host state was cleared
        // on a successful recovery, but that let a partial MITM keep the
        // breaker open indefinitely by interleaving forged handshakes with
        // legitimate ones: every success zeroed the failure counter, so the
        // 3-in-5-minutes threshold was never reached and the backend kept
        // getting hit with refetch requests at attacker-controlled cadence.
        //
        // Now the failure counter only ages out via ATTEMPT_WINDOW_MS in
        // recordFailure, so sustained pin-mismatch noise still trips the
        // breaker even when interleaved with valid handshakes.
    }

    companion object {
        /** How many failed recoveries within [ATTEMPT_WINDOW_MS] trip the breaker. */
        private const val MAX_ATTEMPTS_PER_WINDOW = 3
        /** Sliding window for counting recovery failures (5 minutes). */
        private const val ATTEMPT_WINDOW_MS = 5L * 60 * 1000
        /** How long the breaker stays open after tripping (10 minutes). */
        private const val COOLDOWN_MS = 10L * 60 * 1000
        /** Refetches allowed per [ATTEMPT_WINDOW_MS] across all hosts. */
        internal const val GLOBAL_MAX_REFETCHES = 6
        /** Hosts whose recovery state is kept; the least recently used one goes first. */
        internal const val MAX_TRACKED_HOSTS = 64
    }
}

/** Marks the fallback retry of a recovery, so it does not start a recovery of its own. */
internal object RecoveryAttempt
