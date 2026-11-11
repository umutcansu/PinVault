package io.github.umutcansu.pinvault.crypto

import io.github.umutcansu.pinvault.model.ConfigViewMismatchException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The client decision for the signed `view` field (M6; SERVER_IMPLEMENTATION_GUIDE.md
 * §3) over five fixed payload vectors, which the iOS twin runs too.
 */
class ConfigViewBindingTest {

    private val base = """{"version":3,"pins":[{"hostname":"api.example.com","sha256":["n4Gm1u/KyX6Yh1Yd6m6Ob0HPU+uKiDQqgw7hQvmRvr0=","r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="],"version":3,"forceUpdate":false,"mtls":false}],"forceUpdate":false,"issuedAt":1800000000000,"expiresAt":1800086400000,"configApiId":"default-tls""""

    private val v1Full = "$base}"
    private val v2Scoped = """$base,"view":{"hosts":["api.example.com","cdn.example.com"],"deviceId":"a1b2c3d4e5f60718"}}"""
    private val v3NoDevice = """$base,"view":{"hosts":["api.example.com"]}}"""
    private val v4DeviceOnly = """$base,"view":{"deviceId":"a1b2c3d4e5f60718"}}"""
    private val v5Unknown = """$base,"view":{"hosts":["api.example.com"],"deviceId":"a1b2c3d4e5f60718","aclVersion":7}}"""

    private val full: ConfigViewBinding.Expected? = null
    private fun scoped(vararg hosts: String, deviceId: String? = "a1b2c3d4e5f60718") =
        ConfigViewBinding.expected(hosts.toList(), deviceId)

    private fun accepts(payload: String, expected: ConfigViewBinding.Expected?) = ConfigViewBinding.check(payload, expected)
    private fun refuses(payload: String, expected: ConfigViewBinding.Expected?) {
        assertThrows(ConfigViewMismatchException::class.java) { ConfigViewBinding.check(payload, expected) }
    }

    @Test
    fun `canonical host set`() {
        assertEquals(listOf("api.example.com", "cdn.example.com"),
            ConfigViewBinding.canonicalHosts(listOf("CDN.Example.com", " api.example.com", "cdn.example.com,,")))
        assertEquals(listOf("a.com", "a.com:8443", "b-1.a.com"), ConfigViewBinding.canonicalHosts(listOf("b-1.a.com", "A.com:8443", "a.com")))
        assertEquals(emptyList<String>(), ConfigViewBinding.canonicalHosts(listOf(" ", ",")))
        // Only A-Z folds: no locale rules (Turkish dotted I stays as it is).
        assertEquals(listOf("i.com", "İ.com"), ConfigViewBinding.canonicalHosts(listOf("İ.com", "I.com")))
    }

    @Test
    fun `vector 1 - full payload`() {
        accepts(v1Full, full)
        accepts(v1Full, scoped("api.example.com")) // no view: a full view or an older server
    }

    @Test
    fun `vector 2 - narrowed for two hosts and a device`() {
        accepts(v2Scoped, scoped("cdn.example.com", "API.example.com"))
        refuses(v2Scoped, full)
        refuses(v2Scoped, scoped("api.example.com"))
        refuses(v2Scoped, scoped("api.example.com", "cdn.example.com", deviceId = "another-device"))
        refuses(v2Scoped, scoped("api.example.com", "cdn.example.com", deviceId = null))
    }

    @Test
    fun `vector 3 - narrowed without a device id`() {
        accepts(v3NoDevice, scoped("api.example.com", deviceId = null))
        refuses(v3NoDevice, scoped("api.example.com"))
        refuses(v3NoDevice, full)
    }

    @Test
    fun `vector 4 - narrowed by the device ACL alone`() {
        refuses(v4DeviceOnly, full)
        refuses(v4DeviceOnly, scoped("api.example.com"))
    }

    @Test
    fun `vector 5 - an unknown narrowing is never accepted`() {
        refuses(v5Unknown, full)
        refuses(v5Unknown, scoped("api.example.com"))
    }

    @Test
    fun `a stored view may name the fetch form or the attestation form of the device id`() {
        val either = ConfigViewBinding.expected(listOf("api.example.com"), null, "unknown-device")
        accepts(v3NoDevice, either)
        accepts("""$base,"view":{"hosts":["api.example.com"],"deviceId":"unknown-device"}}""", either)
        refuses(v2Scoped, either)
    }
}
