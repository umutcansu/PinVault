package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.api.ConfigUpdateStatus
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
    fun `dedupWindowMs suppresses duplicate success events within window`() {
        // First success goes through; the immediately-following duplicate
        // (same host/version/cert tuple) must be dropped.
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        val dedupReporter = PinVaultBackendReporter(
            server.url("/").toString(),
            httpClient = client,
            dedupWindowMs = 60_000L
        )

        val event = PinVaultConnectionEvent.Connection(
            hostname = "api.example.com",
            success = true,
            pinVersion = 13,
            deviceManufacturer = "Samsung",
            deviceModel = "SM-G975F",
            actualPin = "AAAAprimary=",
            expectedPins = listOf("AAAAprimary=")
        )

        dedupReporter.onEvent(event)
        dedupReporter.onEvent(event)  // duplicate — must be dropped

        val first = server.takeRequest(2, TimeUnit.SECONDS)
        assertNotNull("first POST should reach server", first)
        val second = server.takeRequest(500, TimeUnit.MILLISECONDS)
        assertNull("duplicate POST must be suppressed within dedup window", second)
    }

    @Test
    fun `dedupWindowMs does NOT suppress pin mismatch events`() {
        // Mismatch events bypass dedup — they are the signal we cannot drop.
        server.enqueue(MockResponse().setResponseCode(200))
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        val dedupReporter = PinVaultBackendReporter(
            server.url("/").toString(),
            httpClient = client,
            dedupWindowMs = 60_000L
        )

        val mismatch = PinVaultConnectionEvent.Connection(
            hostname = "evil.example.com",
            success = false,
            pinVersion = 13,
            deviceManufacturer = "Pixel",
            deviceModel = "8 Pro",
            actualPin = "ATTACKER=",
            expectedPins = listOf("AAAA=")
        )

        dedupReporter.onEvent(mismatch)
        dedupReporter.onEvent(mismatch)  // both must reach the server

        val first = server.takeRequest(2, TimeUnit.SECONDS)
        val second = server.takeRequest(2, TimeUnit.SECONDS)
        assertNotNull("first mismatch POST should reach server", first)
        assertNotNull("second mismatch POST must NOT be deduped — anomaly signal", second)
    }

    @Test
    fun `reportSuccessEvents=false drops healthy events but keeps mismatches`() {
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        val anomalyReporter = PinVaultBackendReporter(
            server.url("/").toString(),
            httpClient = client,
            reportSuccessEvents = false
        )

        val healthy = PinVaultConnectionEvent.Connection(
            hostname = "api.example.com", success = true, pinVersion = 1,
            deviceManufacturer = "V", deviceModel = "M",
            actualPin = "P=", expectedPins = listOf("P=")
        )
        val mismatch = healthy.copy(success = false, actualPin = "ATT=")

        anomalyReporter.onEvent(healthy)   // dropped
        anomalyReporter.onEvent(mismatch)  // delivered

        val recorded = server.takeRequest(2, TimeUnit.SECONDS)
        assertNotNull(recorded)
        assertTrue(
            "only the mismatch POST should reach the server",
            recorded!!.body.readUtf8().contains("\"status\":\"pin_mismatch\"")
        )

        val none = server.takeRequest(500, TimeUnit.MILLISECONDS)
        assertNull("healthy event must be dropped when reportSuccessEvents=false", none)
    }

    @Test
    fun `ConfigUpdate event posts to dedicated endpoint with correct status`() {
        server.enqueue(MockResponse().setResponseCode(200))

        reporter.onEvent(PinVaultConnectionEvent.ConfigUpdate(
            status = ConfigUpdateStatus.UPDATED,
            newVersion = 22,
            deviceManufacturer = "Xiaomi",
            deviceModel = "Mi9T"
        ))

        val recorded = server.takeRequest(2, TimeUnit.SECONDS)!!
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/connection-history/config-update-report", recorded.path)
        val body = recorded.body.readUtf8()
        assertTrue("status should be config_updated: $body", body.contains("\"status\":\"config_updated\""))
        assertTrue("pinVersion missing: $body", body.contains("\"pinVersion\":22"))
        assertTrue("manufacturer missing: $body", body.contains("\"deviceManufacturer\":\"Xiaomi\""))
    }

    @Test
    fun `ConfigUpdate FAILED event includes failureReason and bypasses reportSuccessEvents`() {
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        val anomalyReporter = PinVaultBackendReporter(
            server.url("/").toString(),
            httpClient = client,
            reportSuccessEvents = false  // would normally drop config_updated/unchanged
        )

        // FAILED is anomaly — must go through regardless.
        anomalyReporter.onEvent(PinVaultConnectionEvent.ConfigUpdate(
            status = ConfigUpdateStatus.FAILED,
            newVersion = 21,
            deviceManufacturer = "Xiaomi",
            deviceModel = "Mi9T",
            failureReason = "Backend unreachable"
        ))

        val recorded = server.takeRequest(2, TimeUnit.SECONDS)!!
        val body = recorded.body.readUtf8()
        assertTrue("status should be config_update_failed: $body", body.contains("\"status\":\"config_update_failed\""))
        assertTrue("failureReason missing: $body", body.contains("\"failureReason\":\"Backend unreachable\""))
    }

    @Test
    fun `ConfigUpdate UPDATED event is suppressed when reportSuccessEvents=false`() {
        val client = OkHttpClient.Builder()
            .connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        val anomalyReporter = PinVaultBackendReporter(
            server.url("/").toString(),
            httpClient = client,
            reportSuccessEvents = false
        )

        anomalyReporter.onEvent(PinVaultConnectionEvent.ConfigUpdate(
            status = ConfigUpdateStatus.UPDATED,
            newVersion = 22,
            deviceManufacturer = "Xiaomi", deviceModel = "Mi9T"
        ))
        anomalyReporter.onEvent(PinVaultConnectionEvent.ConfigUpdate(
            status = ConfigUpdateStatus.UNCHANGED,
            newVersion = 22,
            deviceManufacturer = "Xiaomi", deviceModel = "Mi9T"
        ))

        val none = server.takeRequest(500, TimeUnit.MILLISECONDS)
        assertNull("UPDATED/UNCHANGED must be dropped under reportSuccessEvents=false", none)
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
