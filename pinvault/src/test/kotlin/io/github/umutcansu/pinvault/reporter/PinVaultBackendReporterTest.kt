package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * Wire-format guarantees for [PinVaultBackendReporter]: the canned JSON
 * shape it emits is the exact contract demo-server's
 * `/api/v1/connection-history/client-report` route accepts. If a future
 * refactor reorders the fields or drops one, this test must catch it.
 */
class PinVaultBackendReporterTest {

    private lateinit var server: MockWebServer
    private lateinit var reporter: PinVaultBackendReporter

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        // Use a quick-fail client so the test never hangs on a slow mock.
        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS)
            .readTimeout(2, TimeUnit.SECONDS)
            .build()
        reporter = PinVaultBackendReporter(server.url("/").toString(), client)
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `success event posts healthy status with all fields`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"saved":true}"""))

        reporter.onEvent(PinVaultConnectionEvent.Connection(
            hostname = "api.example.com",
            success = true,
            pinVersion = 13,
            deviceManufacturer = "Samsung",
            deviceModel = "SM-G975F",
            actualPin = "AAAAprimary=",
            expectedPins = listOf("AAAAprimary=", "BBBBbackup=")
        ))

        val recorded = server.takeRequest(2, TimeUnit.SECONDS)!!
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/connection-history/client-report", recorded.path)
        assertEquals("application/json; charset=utf-8", recorded.getHeader("Content-Type"))

        val body = recorded.body.readUtf8()
        // Field-level assertions rather than exact match — we don't want
        // the test to break if a future patch adds a field at the end.
        assertTrue("hostname missing: $body", body.contains("\"hostname\":\"api.example.com\""))
        assertTrue("status not healthy: $body", body.contains("\"status\":\"healthy\""))
        assertTrue("pinMatched=true missing: $body", body.contains("\"pinMatched\":true"))
        assertTrue("pinVersion missing: $body", body.contains("\"pinVersion\":13"))
        assertTrue("manufacturer missing: $body", body.contains("\"deviceManufacturer\":\"Samsung\""))
        assertTrue("model missing: $body", body.contains("\"deviceModel\":\"SM-G975F\""))
        assertTrue("serverCertPin missing: $body", body.contains("\"serverCertPin\":\"AAAAprimary=\""))
        assertTrue("storedPin missing: $body", body.contains("\"storedPin\":\"AAAAprimary=\""))
    }

    @Test
    fun `mismatch event posts pin_mismatch status`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"saved":true}"""))

        reporter.onEvent(PinVaultConnectionEvent.Connection(
            hostname = "evil.example.com",
            success = false,
            pinVersion = 13,
            deviceManufacturer = "Pixel",
            deviceModel = "8 Pro",
            actualPin = "ATTACKER=",
            expectedPins = listOf("AAAA=", "BBBB=")
        ))

        val body = server.takeRequest(2, TimeUnit.SECONDS)!!.body.readUtf8()
        assertTrue("status should be pin_mismatch: $body", body.contains("\"status\":\"pin_mismatch\""))
        assertTrue("pinMatched=false missing: $body", body.contains("\"pinMatched\":false"))
        assertTrue("actualPin missing: $body", body.contains("\"serverCertPin\":\"ATTACKER=\""))
    }

    @Test
    fun `network failure is swallowed silently`() {
        // Don't enqueue any response — server will close immediately when called.
        // The reporter must not propagate the exception out to the listener pipeline.
        server.shutdown()

        reporter.onEvent(PinVaultConnectionEvent.Connection(
            hostname = "api.example.com",
            success = true,
            pinVersion = 1,
            deviceManufacturer = "Vendor",
            deviceModel = "Model",
            actualPin = "PIN=",
            expectedPins = listOf("PIN=")
        ))

        // If we reach this line, the reporter did not throw. That is the assertion.
    }

    @Test
    fun `quotes in device fields are JSON-escaped`() {
        server.enqueue(MockResponse().setResponseCode(200))

        reporter.onEvent(PinVaultConnectionEvent.Connection(
            hostname = "api.example.com",
            success = true,
            pinVersion = 1,
            deviceManufacturer = """Acme "Pro"""",  // contains literal quotes
            deviceModel = """back\\slash""",
            actualPin = "P=",
            expectedPins = listOf("P=")
        ))

        val body = server.takeRequest(2, TimeUnit.SECONDS)!!.body.readUtf8()
        // Quotes in input must be escaped in JSON output, otherwise the
        // server's JSON parser would barf on the malformed payload.
        assertTrue(
            "manufacturer quotes not escaped: $body",
            body.contains("""\"deviceManufacturer\":\"Acme \\\"Pro\\\"\"""".replace("\\\\", "\\"))
                || body.contains("\"deviceManufacturer\":\"Acme \\\"Pro\\\"\"")
        )
    }
}
