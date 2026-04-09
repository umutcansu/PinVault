package io.github.umutcansu.pinvault.model

import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test

/** A.1 — HostPin mtls + clientCertVersion parse/serialize */
class HostPinTest {

    private val gson = Gson()

    @Test
    fun `HostPin defaults — mtls false, clientCertVersion null`() {
        val pin = HostPin("api.example.com", listOf("AAAA", "BBBB"))
        assertFalse(pin.mtls)
        assertNull(pin.clientCertVersion)
        assertEquals(0, pin.version)
        assertFalse(pin.forceUpdate)
    }

    @Test
    fun `HostPin with mtls true and clientCertVersion`() {
        val pin = HostPin("mtls.example.com", listOf("CCCC", "DDDD"), mtls = true, clientCertVersion = 3)
        assertTrue(pin.mtls)
        assertEquals(3, pin.clientCertVersion)
    }

    @Test
    fun `HostPin JSON round-trip with mtls fields`() {
        val original = HostPin(
            hostname = "api.firmab.com",
            sha256 = listOf("AAAA1234567890123456789012345678901234567890", "BBBB1234567890123456789012345678901234567890"),
            version = 2,
            mtls = true,
            clientCertVersion = 1
        )
        val json = gson.toJson(original)
        val parsed = gson.fromJson(json, HostPin::class.java)

        assertEquals(original.hostname, parsed.hostname)
        assertEquals(original.sha256, parsed.sha256)
        assertEquals(original.version, parsed.version)
        assertEquals(original.mtls, parsed.mtls)
        assertEquals(original.clientCertVersion, parsed.clientCertVersion)
    }

    @Test
    fun `HostPin JSON parse — mtls fields missing defaults correctly`() {
        val json = """{"hostname":"api.example.com","sha256":["AA","BB"]}"""
        val parsed = gson.fromJson(json, HostPin::class.java)

        assertEquals("api.example.com", parsed.hostname)
        assertFalse(parsed.mtls)
        assertNull(parsed.clientCertVersion)
    }

    @Test
    fun `HostPin JSON parse — mtls true with clientCertVersion`() {
        val json = """{"hostname":"mtls.host","sha256":["XX","YY"],"version":5,"mtls":true,"clientCertVersion":2}"""
        val parsed = gson.fromJson(json, HostPin::class.java)

        assertTrue(parsed.mtls)
        assertEquals(2, parsed.clientCertVersion)
        assertEquals(5, parsed.version)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `HostPin requires at least 2 pins`() {
        HostPin("test.com", listOf("onlyOne"))
    }

    @Test
    fun `CertificateConfig computedVersion from pins`() {
        val config = CertificateConfig(
            version = 0,
            pins = listOf(
                HostPin("a.com", listOf("AA", "BB"), version = 3),
                HostPin("b.com", listOf("CC", "DD"), version = 7),
                HostPin("c.com", listOf("EE", "FF"), version = 5, mtls = true, clientCertVersion = 1)
            )
        )
        assertEquals(7, config.computedVersion())
    }

    @Test
    fun `CertificateConfig with mixed mtls and non-mtls pins`() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("tls.host", listOf("AA", "BB"), mtls = false),
                HostPin("mtls.host", listOf("CC", "DD"), mtls = true, clientCertVersion = 2)
            )
        )
        val mtlsHosts = config.pins.filter { it.mtls }
        assertEquals(1, mtlsHosts.size)
        assertEquals("mtls.host", mtlsHosts[0].hostname)
        assertEquals(2, mtlsHosts[0].clientCertVersion)
    }
}
