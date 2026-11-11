package io.github.umutcansu.pinvault.flutter

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class PinnedFetchTest {

    private val server = MockWebServer()
    /** A second origin: the same host on another port. */
    private val other = MockWebServer()
    private lateinit var client: OkHttpClient

    @Before fun setUp() {
        // A TLS test server and a client that trusts it: stands in for the pinned client here.
        val cert = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverCerts = HandshakeCertificates.Builder().heldCertificate(cert).build()
        server.useHttps(serverCerts.sslSocketFactory(), false)
        server.start()
        other.useHttps(serverCerts.sslSocketFactory(), false)
        other.start()
        val clientCerts = HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        client = OkHttpClient.Builder().sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager).build()
    }

    @After fun tearDown() {
        server.shutdown()
        other.shutdown()
    }

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
            """{"url":"https://a/","headers":{"PinVault-Token":"t"}}""" to "set by PinVault itself",
            """{"url":"https://a/","headers":{"pinvault-proof":"p"}}""" to "set by PinVault itself",
            """{"url":"https://a/","headers":{"Host":"other.example"}}""" to "set by the HTTP client",
            """{"url":"https://a/","headers":{"content-length":"0"}}""" to "set by the HTTP client",
            """{"url":"https://a/","headers":{"Transfer-Encoding":"chunked"}}""" to "set by the HTTP client",
            """{"url":"https://a/","headers":{"Connection":"Upgrade","Upgrade":"websocket"}}""" to "set by the HTTP client",
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

    // OkHttp carries every header but Authorization (and a 307/308 body) across a
    // redirect to another host; the bridge follows redirects itself.
    @Test fun `a redirect to another origin takes only neutral headers along`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing").toString()))
        other.enqueue(MockResponse().setBody("there"))
        val r = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url("/start")}","method":"POST","body":"secret",
            "headers":{"Content-Type":"text/plain","Authorization":"Bearer t","Cookie":"sid=1","X-App-Session":"s-1","X-Api-Key":"k",
                       "Accept":"text/plain","Accept-Language":"tr","User-Agent":"app/1"}}"""))
        assertEquals(200, r["status"])
        assertEquals("there", r["body"])
        assertEquals(other.url("/landing").toString(), r["url"])
        assertEquals("s-1", server.takeRequest().getHeader("X-App-Session"))
        val landed = other.takeRequest()
        assertEquals("GET", landed.method)
        assertEquals(0L, landed.bodySize)
        for (name in listOf("Authorization", "Cookie", "X-App-Session", "X-Api-Key", "Content-Type")) {
            assertNull("another origin gets no $name", landed.getHeader(name))
        }
        assertEquals("text/plain", landed.getHeader("Accept"))
        assertEquals("tr", landed.getHeader("Accept-Language"))
        assertEquals("app/1", landed.getHeader("User-Agent"))
    }

    @Test fun `a body is not sent again to another origin`() {
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", other.url("/landing").toString()))
        val r = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url("/start")}","method":"POST","body":"secret"}"""))
        assertEquals("the 307 is the answer", 307, r["status"])
        assertEquals(0, other.requestCount)
    }

    @Test fun `a redirect within the origin keeps headers, and a 307 its body`() {
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", "/moved"))
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/done"))
        server.enqueue(MockResponse().setBody("ok"))
        val r = PinnedFetch.execute(client, PinnedFetch.parse(
            """{"url":"${url("/start")}","method":"POST","body":"payload","headers":{"X-App-Session":"s-1","Content-Type":"text/plain"}}"""))
        assertEquals(200, r["status"])
        server.takeRequest()
        val moved = server.takeRequest()
        assertEquals("POST", moved.method)
        assertEquals("payload", moved.body.readUtf8())
        assertEquals("s-1", moved.getHeader("X-App-Session"))
        val done = server.takeRequest()
        assertEquals("GET", done.method)
        assertEquals("s-1", done.getHeader("X-App-Session"))
        assertNull(done.getHeader("Content-Type"))
    }

    @Test fun `redirects end somewhere`() {
        repeat(PinnedFetch.MAX_FOLLOW_UPS + 1) { server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/again")) }
        try {
            PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}"}"""))
            fail()
        } catch (e: java.net.ProtocolException) {
            assertTrue(e.message!!.contains("Too many follow-up requests"))
        }
    }

    // A WebSocket's upgrade is an HTTP request on the pinned connection: the same
    // headers are the client's, plus the handshake's own.
    @Test fun `a socket's upgrade request refuses what fetch refuses and the handshake headers`() {
        for (name in PinnedFetch.CLIENT_HEADERS + PinnedFetch.CLIENT_HEADERS.map { it.lowercase() }) {
            assertTrue(name, PinnedFetch.refusedSocketHeader(name)!!.contains("set by the HTTP client"))
            assertEquals(PinnedFetch.refusedHeader(name), PinnedFetch.refusedSocketHeader(name))
        }
        for (name in PinnedFetch.LIBRARY_HEADERS) assertTrue(PinnedFetch.refusedSocketHeader(name)!!.contains("set by PinVault itself"))
        for (name in listOf("Sec-WebSocket-Key", "sec-websocket-protocol", "SEC-WEBSOCKET-EXTENSIONS", "Sec-WebSocket-Version")) {
            assertTrue(name, PinnedFetch.refusedSocketHeader(name)!!.contains("WebSocket handshake"))
            assertNull("fetch has no handshake", PinnedFetch.refusedHeader(name))
        }
        for (name in listOf("Authorization", "X-App-Session", "Origin", "Cookie", "Sec-Fetch-Mode")) assertNull(name, PinnedFetch.refusedSocketHeader(name))
    }

    @Test fun `a socket's subprotocols are tokens, bounded and listed once`() {
        assertEquals(emptyList<String>(), PinnedFetch.socketProtocols(null))
        assertEquals(listOf("graphql-transport-ws", "v2.chat"), PinnedFetch.socketProtocols(listOf("graphql-transport-ws", "v2.chat")))
        listOf(
            listOf("a, b"), listOf("a b"), listOf(""), listOf("a\r\nX-Injected: 1"), listOf("a\u0000"), listOf("ä"), listOf("a;q=1"),
            listOf(1), listOf(null), listOf("a", "a"), listOf("x".repeat(PinnedFetch.MAX_SOCKET_PROTOCOL_LENGTH + 1)),
            List(PinnedFetch.MAX_SOCKET_PROTOCOLS + 1) { "p$it" },
        ).forEach { bad ->
            try {
                PinnedFetch.socketProtocols(bad)
                fail("accepted $bad")
            } catch (e: BridgeInputException) {
                assertTrue(e.message!!.startsWith("protocols:"))
            }
        }
    }

    // An empty body carries nothing: a 307 to another origin is followed with the method kept.
    @Test fun `a body-less POST follows a 307 to another origin`() {
        server.enqueue(MockResponse().setResponseCode(307).addHeader("Location", other.url("/landing").toString()))
        other.enqueue(MockResponse().setBody("there"))
        val r = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url("/start")}","method":"POST","headers":{"X-App-Session":"s-1"}}"""))
        assertEquals(200, r["status"])
        val landed = other.takeRequest()
        assertEquals("POST", landed.method)
        assertEquals(0L, landed.bodySize)
        assertNull(landed.getHeader("X-App-Session"))
    }

    @Test fun `the time limit covers the redirects too`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/slow").setHeadersDelay(300, java.util.concurrent.TimeUnit.MILLISECONDS))
        server.enqueue(MockResponse().setBody("late").setHeadersDelay(300, java.util.concurrent.TimeUnit.MILLISECONDS))
        try {
            // Each hop alone is inside the limit; the two together are not.
            PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}","timeoutMs":450}"""))
            fail()
        } catch (_: java.io.InterruptedIOException) {
        }
    }

    @Test fun `an https to http redirect is not followed`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "http://example.com/"))
        val r = PinnedFetch.execute(client, PinnedFetch.parse("""{"url":"${url()}"}"""))
        assertEquals(302, r["status"])
        assertEquals(1, server.requestCount)
    }
}
