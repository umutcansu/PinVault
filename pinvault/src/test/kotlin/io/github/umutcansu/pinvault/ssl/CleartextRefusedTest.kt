package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.UnknownServiceException
import java.security.MessageDigest
import java.util.Base64

/**
 * Review 2026-11-14: the guide says pinned clients refuse plain HTTP, and
 * only the bootstrap client did. A pin is checked in a TLS handshake; an
 * `http://` request through `getClient()` or an `applyTo` builder went out
 * checked by nothing, and an `applyTo` client followed a redirect from a
 * pinned https host to http. Clients leave `applyTo` without a cleartext
 * connection spec now.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CleartextRefusedTest {

    private val plain = MockWebServer()
    private val secure = MockWebServer()
    private val held = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val manager = DynamicSSLManager()

    @After
    fun tearDown() {
        runCatching { plain.shutdown() }
        runCatching { secure.shutdown() }
    }

    private fun pinsFor(host: String) = CertificateConfig(
        version = 1,
        pins = listOf(
            HostPin(
                host,
                listOf(
                    Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(held.certificate.publicKey.encoded)),
                    "BACKUP_PIN_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                )
            )
        )
    )

    private fun startSecure() {
        secure.useHttps(HandshakeCertificates.Builder().heldCertificate(held).build().sslSocketFactory(), false)
        secure.start()
    }

    private fun assertCleartextRefused(client: OkHttpClient, request: Request) {
        val failure = runCatching { client.newCall(request).execute().close() }.exceptionOrNull()
        assertTrue("expected OkHttp's cleartext refusal, got $failure", failure is UnknownServiceException)
        assertTrue(failure!!.message, failure.message!!.contains("CLEARTEXT communication not enabled"))
    }

    @Test
    fun `an http URL is refused by a client the library builds`() {
        // What PinVault.getClient() and getClient(settings) hand out.
        plain.start()
        plain.enqueue(MockResponse().setBody("served in the clear"))
        val config = pinsFor(plain.hostName)
        val client = manager.buildDynamicClient({ config })

        assertCleartextRefused(client, Request.Builder().url(plain.url("/api")).header("X-API-Key", "key-123").build())
        assertEquals("nothing was sent", 0, plain.requestCount)
    }

    @Test
    fun `an http URL is refused on a builder that went through applyTo`() {
        plain.start()
        plain.enqueue(MockResponse().setBody("served in the clear"))
        val config = pinsFor(plain.hostName)
        val builder = OkHttpClient.Builder()
        manager.applyTo(builder) { config }

        assertCleartextRefused(builder.build(), Request.Builder().url(plain.url("/api")).build())
        assertEquals(0, plain.requestCount)
    }

    @Test
    fun `a redirect from a pinned https host to http is not followed on an applyTo builder`() {
        startSecure()
        plain.start()
        secure.enqueue(MockResponse().setResponseCode(302).setHeader("Location", plain.url("/landed")))
        plain.enqueue(MockResponse().setBody("served in the clear"))
        val config = pinsFor(secure.hostName)
        // The app's builder keeps OkHttp's defaults: followSslRedirects is on.
        val builder = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }
        manager.applyTo(builder) { config }
        val client = builder.build()
        assertTrue(client.followSslRedirects)

        assertCleartextRefused(client, Request.Builder().url(secure.url("/start")).header("X-API-Key", "key-123").build())
        assertEquals("the pinned host was asked", 1, secure.requestCount)
        assertEquals("nothing went out in the clear", 0, plain.requestCount)
    }

    @Test
    fun `a pinned https request still works`() {
        startSecure()
        secure.enqueue(MockResponse().setBody("ok"))
        val config = pinsFor(secure.hostName)
        val builder = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }
        manager.applyTo(builder) { config }

        builder.build().newCall(Request.Builder().url(secure.url("/api")).build()).execute().use { assertEquals(200, it.code) }
    }

    @Test
    fun `an app that puts the cleartext spec back after applyTo gets plain http for its own hosts`() {
        plain.start()
        plain.enqueue(MockResponse().setBody("ok"))
        val config = pinsFor("pinned.example")
        val builder = OkHttpClient.Builder()
        manager.applyTo(builder) { config }
        builder.connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.CLEARTEXT))

        builder.build().newCall(Request.Builder().url(plain.url("/health")).build()).execute().use { assertEquals(200, it.code) }
        assertEquals(1, plain.requestCount)
    }

    @Test
    fun `the TLS specs an app chose are kept, the cleartext one goes`() {
        val builder = OkHttpClient.Builder().connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS, ConnectionSpec.CLEARTEXT))
        manager.applyTo(builder) { null }
        assertEquals(listOf(ConnectionSpec.RESTRICTED_TLS), builder.build().connectionSpecs)

        // OkHttp's default list: MODERN_TLS stays.
        val defaults = OkHttpClient.Builder()
        manager.applyTo(defaults) { null }
        assertEquals(listOf(ConnectionSpec.MODERN_TLS), defaults.build().connectionSpecs)

        // A builder that had cleartext only gets a TLS spec, never an empty list.
        val cleartextOnly = OkHttpClient.Builder().connectionSpecs(listOf(ConnectionSpec.CLEARTEXT))
        manager.applyTo(cleartextOnly) { null }
        assertEquals(listOf(ConnectionSpec.MODERN_TLS), cleartextOnly.build().connectionSpecs)
    }

    @Test
    fun `the bootstrap client speaks http only when the block asked for an unpinned Config API`() {
        plain.start()
        plain.enqueue(MockResponse().setBody("ok"))
        val pins = pinsFor(plain.hostName).pins

        val pinned = manager.buildBootstrapClient(pins)
        assertFalse(ConnectionSpec.CLEARTEXT in pinned.connectionSpecs)
        val refused = runCatching { pinned.newCall(Request.Builder().url(plain.url("/c")).build()).execute().close() }.exceptionOrNull()
        assertTrue("$refused", refused?.message?.contains("plain-HTTP request to the Config API") == true)
        assertEquals(0, plain.requestCount)

        // allowUnpinnedConfigApi(): tests and development servers, as before.
        val unpinned = manager.buildBootstrapClient(pins, allowUnpinned = true)
        unpinned.newCall(Request.Builder().url(plain.url("/c")).build()).execute().use { assertEquals(200, it.code) }
    }
}
