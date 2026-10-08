package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import io.github.umutcansu.pinvault.model.GuardedOperation
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * `environmentGuard` answered by a JS callback. The library asks on a
 * background thread; this sends `{requestId, operation}` to JS and waits for
 * [answer] up to [timeoutMs]. Fail closed: no answer in time, an unknown
 * request id, an interrupt — every one of them is a refusal.
 *
 * The answer comes on the native-modules thread, the question is asked on the
 * library's worker thread, so waiting here never blocks the thread that
 * delivers the answer.
 */
internal class JsEnvironmentGuard(
    private val timeoutMs: Long,
    private val ask: (requestId: String, operation: String) -> Unit,
) : EnvironmentGuard {

    private val pending = ConcurrentHashMap<String, CompletableFuture<Boolean>>()

    override fun allows(operation: GuardedOperation): Boolean {
        val id = UUID.randomUUID().toString()
        val answer = CompletableFuture<Boolean>()
        pending[id] = answer
        return try {
            ask(id, operation.name)
            answer.get(timeoutMs, TimeUnit.MILLISECONDS) == true
        } catch (_: Exception) {
            false
        } finally {
            pending.remove(id)
        }
    }

    /** JS's verdict; ignored when the request is unknown or already timed out. */
    fun answer(requestId: String, allowed: Boolean) {
        pending[requestId]?.complete(allowed)
    }

    fun pendingCount(): Int = pending.size

    companion object {
        const val DEFAULT_TIMEOUT_MS = 5000L
        const val MIN_TIMEOUT_MS = 100L
        const val MAX_TIMEOUT_MS = 30_000L
    }
}
