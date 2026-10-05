package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.UnpinnedHostException
import io.mockk.every
import io.mockk.mockk
import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.security.cert.CertificateException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLHandshakeException

/**
 * What a failing handshake may cost the backend: the refetch budget across
 * hosts, the single refetch for hosts the config does not know, the bounded
 * state, and one refetch for requests that fail together.
 */
class PinRecoveryBudgetTest {

    private var now = 1_000_000L
    private val minute = 60_000L
    private val refetches = AtomicInteger()

    private fun interceptor(updated: Boolean = false, onRefetch: () -> Unit = { }) = PinRecoveryInterceptor(
        updater = { refetches.incrementAndGet(); onRefetch(); updated },
        clock = { now }
    )

    private fun mismatch() = SSLHandshakeException("pin mismatch").apply { initCause(CertificateException("Certificate pinning failure")) }

    private fun noPinEntry(host: String) =
        SSLHandshakeException("no entry").apply { initCause(UnpinnedHostException("No pin entry for hostname '$host'")) }

    /** A chain for [host] whose every attempt fails with [failure]. */
    private fun failing(host: String, failure: (String) -> IOException = { mismatch() }): Interceptor.Chain {
        val chain = mockk<Interceptor.Chain>()
        every { chain.request() } returns Request.Builder().url("https://$host/").build()
        every { chain.proceed(any()) } answers { throw failure(host) }
        return chain
    }

    private fun attempt(interceptor: PinRecoveryInterceptor, chain: Interceptor.Chain) {
        try {
            interceptor.intercept(chain)
            fail("the request should have failed")
        } catch (e: IOException) {
            // expected
        }
    }

    @Test
    fun `the refetch budget is shared by all hosts`() {
        val interceptor = interceptor()
        // Every new host name used to bring a fresh budget of its own.
        repeat(40) { attempt(interceptor, failing("host$it.example.com")) }
        assertEquals(PinRecoveryInterceptor.GLOBAL_MAX_REFETCHES, refetches.get())

        // The window passes: there is budget again.
        now += 6 * minute
        attempt(interceptor, failing("later.example.com"))
        assertEquals(PinRecoveryInterceptor.GLOBAL_MAX_REFETCHES + 1, refetches.get())
    }

    @Test
    fun `hosts without a pin entry get one refetch per window between them`() {
        val interceptor = interceptor()
        attempt(interceptor, failing("unknown-1.example.com", ::noPinEntry))
        attempt(interceptor, failing("unknown-2.example.com", ::noPinEntry))
        attempt(interceptor, failing("unknown-3.example.com", ::noPinEntry))
        assertEquals("one refetch: the config may have gained the host", 1, refetches.get())

        // A real mismatch on a pinned host is not held back by that.
        attempt(interceptor, failing("pinned.example.com"))
        assertEquals(2, refetches.get())

        now += 6 * minute
        attempt(interceptor, failing("unknown-4.example.com", ::noPinEntry))
        assertEquals(3, refetches.get())
    }

    @Test
    fun `a host the refetch brought in is retried`() {
        val interceptor = interceptor(updated = true)
        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://new.example.com/").build()
        every { chain.request() } returns request
        var calls = 0
        every { chain.proceed(any()) } answers {
            if (calls++ == 0) throw noPinEntry("new.example.com")
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("OK").build()
        }

        assertEquals(200, interceptor.intercept(chain).code)
        assertEquals(1, refetches.get())
    }

    @Test
    fun `the per-host state is bounded`() {
        val interceptor = interceptor()
        // Failed recoveries for far more hosts than are tracked (the budget
        // is refilled between rounds so each host gets its failure recorded).
        repeat(PinRecoveryInterceptor.MAX_TRACKED_HOSTS * 3) {
            now += 6 * minute
            attempt(interceptor, failing("host$it.example.com"))
        }

        val field = PinRecoveryInterceptor::class.java.getDeclaredField("recoveryState").apply { isAccessible = true }
        val tracked = field.get(interceptor) as Map<*, *>
        assertEquals(PinRecoveryInterceptor.MAX_TRACKED_HOSTS, tracked.size)
    }

    @Test
    fun `the breaker still trips per host`() {
        val interceptor = interceptor()
        val chain = failing("api.example.com")
        repeat(10) { attempt(interceptor, chain) }
        assertEquals("three failed recoveries, then cooldown", 3, refetches.get())
    }

    @Test
    fun `requests that fail together share one refetch`() {
        val threads = 8
        val allFailed = CyclicBarrier(threads)
        val inRefetch = CountDownLatch(1)
        val interceptor = interceptor(updated = false) {
            inRefetch.countDown()
            Thread.sleep(300) // the others pile up on the lock meanwhile
        }
        val chain = object : Interceptor.Chain {
            private val request = Request.Builder().url("https://api.example.com/").build()
            override fun request() = request
            override fun proceed(request: Request): Response {
                // All requests are in flight before any of them fails.
                allFailed.await(5, TimeUnit.SECONDS)
                throw mismatch()
            }
            override fun connection() = null
            override fun call() = throw UnsupportedOperationException()
            override fun connectTimeoutMillis() = 0
            override fun withConnectTimeout(timeout: Int, unit: TimeUnit) = this
            override fun readTimeoutMillis() = 0
            override fun withReadTimeout(timeout: Int, unit: TimeUnit) = this
            override fun writeTimeoutMillis() = 0
            override fun withWriteTimeout(timeout: Int, unit: TimeUnit) = this
        }

        val workers = (1..threads).map {
            Thread {
                try {
                    interceptor.intercept(chain)
                } catch (e: IOException) {
                    // expected
                }
            }.also { it.start() }
        }
        assertTrue(inRefetch.await(5, TimeUnit.SECONDS))
        workers.forEach { it.join(10_000) }

        assertEquals("one Config API request for $threads failures", 1, refetches.get())
    }
}
