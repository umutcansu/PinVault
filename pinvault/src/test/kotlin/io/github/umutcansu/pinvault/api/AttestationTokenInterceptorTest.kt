package io.github.umutcansu.pinvault.api

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.BufferedSink
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The `PinVault-Token` header, and the one retry after a 401 that names the token. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class AttestationTokenInterceptorTest {

    private lateinit var server: MockWebServer

    /** A source whose token is `t1` until a forced refresh makes it `t2`. */
    private class FakeSource(var handles: Boolean = true, var nextOnForce: String? = "t2") : AttestationTokenSource {
        var token: String? = "t1"
        var forced = 0
        var asked = 0
        override fun handlesHost(host: String, port: Int) = handles
        var proofs: Boolean = false
        val proofFor = mutableListOf<String>()
        override fun proof(method: String, url: okhttp3.HttpUrl, token: String): String? {
            if (!proofs) return null
            proofFor += "$method ${url.encodedPath} $token"
            return "proof-${proofFor.size}-$token"
        }
        override fun token(host: String, port: Int, forceRefresh: Boolean): String? {
            asked++
            if (forceRefresh) {
                forced++
                token = nextOnForce
            }
            return token
        }
    }

    private lateinit var source: FakeSource
    private lateinit var client: OkHttpClient
    private lateinit var trust: HandshakeCertificates

    private fun clientWith(interceptor: AttestationTokenInterceptor) = OkHttpClient.Builder()
        .sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
        .addInterceptor(interceptor)
        .build()

    @Before
    fun setUp() {
        // The token is a bearer credential: it only goes out over TLS, so the test server speaks it.
        val localhost = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        server = MockWebServer().also {
            it.useHttps(HandshakeCertificates.Builder().heldCertificate(localhost).build().sslSocketFactory(), false)
            it.start()
        }
        trust = HandshakeCertificates.Builder().addTrustedCertificate(localhost.certificate).build()
        source = FakeSource()
        client = clientWith(AttestationTokenInterceptor { listOf(source) })
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun get() = Request.Builder().url(server.url("/api/data")).build()

    @Test
    fun `requests to a token host carry the header`() {
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(get()).execute().use { assertEquals(200, it.code) }
        assertEquals("t1", server.takeRequest().getHeader("PinVault-Token"))
        assertEquals(0, source.forced)
    }

    @Test
    fun `requests to other hosts carry nothing and ask for no token`() {
        source.handles = false
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(get()).execute().close()
        assertNull(server.takeRequest().getHeader("PinVault-Token"))
        assertEquals(0, source.asked)
    }

    @Test
    fun `without a token the request goes out bare`() {
        source.token = null
        source.nextOnForce = null
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(get()).execute().close()
        assertNull(server.takeRequest().getHeader("PinVault-Token"))
    }

    @Test
    fun `a 401 whose WWW-Authenticate names the token forces one re-attestation and one retry`() {
        server.enqueue(MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", """Bearer realm="api", error="invalid_token", header="PinVault-Token""""))
        server.enqueue(MockResponse().setBody("ok"))

        client.newCall(get()).execute().use { assertEquals(200, it.code) }

        assertEquals("t1", server.takeRequest().getHeader("PinVault-Token"))
        assertEquals("t2", server.takeRequest().getHeader("PinVault-Token"))
        assertEquals(1, source.forced)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a 401 whose body says invalid_token is retried once too — and the retry is never retried`() {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token","message":"expired"}"""))
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}"""))

        client.newCall(get()).execute().use { assertEquals(401, it.code) }

        assertEquals(2, server.requestCount)
        assertEquals(1, source.forced)
    }

    @Test
    fun `a 401 that is not about the token is returned as it is`() {
        server.enqueue(MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "Basic realm=\"x\"").setBody("""{"error":"login_required"}"""))
        client.newCall(get()).execute().use { assertEquals(401, it.code) }
        assertEquals(1, server.requestCount)
        assertEquals(0, source.forced)
    }

    @Test
    fun `no retry when the re-attestation brings no new token`() {
        source.nextOnForce = null
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}"""))
        client.newCall(get()).execute().use { response ->
            assertEquals(401, response.code)
            assertEquals("the original answer, body intact", """{"error":"invalid_token"}""", response.body!!.string())
        }
        assertEquals(1, server.requestCount)
        assertEquals(1, source.forced)

        // The same token again is no reason to retry either.
        source.token = "t1"
        source.nextOnForce = "t1"
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}"""))
        client.newCall(get()).execute().use { assertEquals(401, it.code) }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a request whose body can be sent once only is not retried`() {
        val oneShot = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun isOneShot() = true
            override fun writeTo(sink: BufferedSink) { sink.writeUtf8("stream") }
        }
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}"""))
        val request = Request.Builder().url(server.url("/upload")).post(oneShot).build()

        client.newCall(request).execute().use { assertEquals(401, it.code) }

        assertEquals(1, server.requestCount)
        assertEquals(0, source.forced)
    }

    @Test
    fun `a replayable POST body is retried with the new token`() {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid_token"}"""))
        server.enqueue(MockResponse().setBody("ok"))
        val request = Request.Builder().url(server.url("/upload")).post("{}".toRequestBody("application/json".toMediaType())).build()

        client.newCall(request).execute().use { assertEquals(200, it.code) }

        server.takeRequest()
        val retry = server.takeRequest()
        assertEquals("t2", retry.getHeader("PinVault-Token"))
        assertEquals("{}", retry.body.readUtf8())
    }

    @Test
    fun `the first source that handles the host wins`() {
        val other = FakeSource().also { it.token = "other" }
        val two = clientWith(AttestationTokenInterceptor { listOf(FakeSource(handles = false), other) })
        server.enqueue(MockResponse().setBody("ok"))
        two.newCall(get()).execute().close()
        assertEquals("other", server.takeRequest().getHeader("PinVault-Token"))
    }

    @Test
    fun `with proofs each request carries one for its token, and the retry a new one for the new token`() {
        source.proofs = true
        server.enqueue(MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "PinVault-Token error=\"invalid_token\""))
        server.enqueue(MockResponse().setBody("ok"))

        client.newCall(Request.Builder().url(server.url("/api/data?q=1")).build()).execute().use { assertEquals(200, it.code) }

        val first = server.takeRequest()
        assertEquals("t1", first.getHeader("PinVault-Token"))
        assertEquals("proof-1-t1", first.getHeader("PinVault-Proof"))
        val retry = server.takeRequest()
        assertEquals("t2", retry.getHeader("PinVault-Token"))
        assertEquals("proof-2-t2", retry.getHeader("PinVault-Proof"))
        assertEquals(listOf("GET /api/data t1", "GET /api/data t2"), source.proofFor)
    }

    @Test
    fun `without proofs no proof header is sent`() {
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(get()).execute().close()
        assertNull(server.takeRequest().getHeader("PinVault-Proof"))
    }

    @Test
    fun `the token never goes out over cleartext`() {
        val plain = MockWebServer().also { it.start() }
        try {
            plain.enqueue(MockResponse().setBody("ok"))
            client.newCall(Request.Builder().url(plain.url("/api/data")).build()).execute().close()
            assertNull(plain.takeRequest().getHeader("PinVault-Token"))
            assertEquals("no token was asked for", 0, source.asked)
        } finally {
            plain.shutdown()
        }
    }
}
