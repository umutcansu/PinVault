package io.github.umutcansu.pinvault.flutter

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class PinnedFetchTest {

    private val server = MockWebServer()
    private lateinit var client: OkHttpClient

    @Before fun setUp() {
        // A TLS test server and a client that trusts it: stands in for the pinned client here.
        val cert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverCerts = HandshakeCertificates.Builder().heldCertificate(cert).build()
        server.useHttps(serverCerts.sslSocketFactory(), false)
        server.start()
        val clientCerts = HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        client = OkHttpClient.Builder().sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager).build()
    }

    @After fun tearDown() = server.shutdown()

    private fun url(path: String = "/") = server.url(path).toString()

    @Test fun `only https`() {
        try {
            PinnedFetch.parse("""{"url":"http://example.com/"}""")
            fail()
        } catch (e: BridgeInputException) {
            assertTrue(e.message!!.contains("only https"))
        }
    }

    @Test fun `request fields are strict`() {
        listOf(
            """{"url":"https://a/","metod":"GET"}""" to "'metod'",
            """{"url":"https://a/","method":"TRACE"}""" to "not supported",
            """{"url":"https://a/","headers":{"X-A":1}}""" to "must be a string",
            """{"url":"https://a/","headers":{"Bad Name":"x"}}""" to "not a header name",
            """{"url":"https://a/","headers":{"X-A":"a\r\nInjected: 1"}}""" to "line breaks",
            """{"url":"https://a/","method":"GET","body":"x"}""" to "has no body",
            """{"url":"https://a/","method":"POST","body":"%%%","bodyEncoding":"base64"}""" to "Base64",
            """{"url":"https://a/","maxResponseBytes":999999999999}""" to "maxResponseBytes",
            """{"url":"https://a/","settings":{"readTimeout":5,"x":1}}""" to "'x'",
        ).forEach { (json, fragment) ->
            try {
                PinnedFetch.parse(json)
                fail("accepted $json")
            } catch (e: BridgeInputException) {
                assertTrue("'${e.message}' lacks '$fragment'", e.message!!.contains(fragment))
            }
        }
    }

    @Test fun `a request round-trips with headers, body and encoding`() {
        server.enqueue(MockResponse().setResponseCode(201).addHeader("X-Reply", "1").addHeader("X-Reply", "2").setBody("ok"))
        val request = PinnedFetch.parse("""{"url":"${url("/p")}","method":"POST","headers":{"Content-Type":"application/json"},"body":"{\"a\":1}"}""")
        val r = PinnedFetch.execute(client, request)
        assertEquals(201, r["status"])
        assertEquals("ok", r["body"])
        @Suppress("UNCHECKED_CAST")
        assertEquals("1, 2", (r["headers"] as Map<String, String>)["x-reply"])
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("{\"a\":1}", recorded.body.readUtf8())
        assertEquals("application/json", recorded.getHeader("Content-Type"))

        server.enqueue(MockResponse().setBody(okio.Buffer().write(byteArrayOf(0, -1))))
        val bin = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}","responseEncoding":"base64"}"""))
        assertEquals("AP8=", bin["body"])
    }

    @Test fun `responses over the limit are refused`() {
        server.enqueue(MockResponse().setBody("x".repeat(2048)))
        try {
            PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}","maxResponseBytes":1024}"""))
            fail()
        } catch (e: ResponseTooLargeException) {
            assertTrue(e.message!!.contains("1024"))
        }
        // Chunked: no Content-Length, the stream itself is cut.
        server.enqueue(MockResponse().setChunkedBody("y".repeat(4096), 512))
        try {
            PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}","maxResponseBytes":1024}"""))
            fail()
        } catch (_: ResponseTooLargeException) {
        }
    }

    @Test fun `an https to http redirect is not followed`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "http://example.com/"))
        val r = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}"}"""))
        assertEquals(302, r["status"])
        assertEquals(1, server.requestCount)
    }
}
