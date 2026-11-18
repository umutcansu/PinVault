package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.service.TlsHardening
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What OWASP ZAP (authenticated active scan of the management API) and
 * testssl (Config API, recovery door) found on 2026-11-18. No injection: the
 * "SQL injection" alerts were 500 answers to malformed input, with no SQL
 * error behind any of them. Those 500s are the caller's mistakes and are 400s
 * now, and a host name is checked before a key pair is generated for it.
 */
class ScannerFindings20261118Test {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() { dir = kotlin.io.path.createTempDirectory("pinvault-scanner-").toFile() }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    @Test
    fun `a host name that is not one is refused before a certificate is made for it`() {
        GovernanceHarness(dir, required = 1).use { h ->
            for (name in listOf("a\"b.example.com", "x.example.com, O=Evil", "ZAP%n%s%n%s", "a".repeat(70) + ".example.com", "*.com")) {
                val body = kotlinx.serialization.json.buildJsonObject { put("hostname", kotlinx.serialization.json.JsonPrimitive(name)) }.toString()
                val answer = h.call("POST", "/api/v1/hosts/generate-cert", ALICE, body)
                assertEquals(400, answer.status, "$name: ${answer.body}")
                assertNull(h.pinsOf(name))
            }
            assertEquals(200, h.call("POST", "/api/v1/hosts/generate-cert", ALICE, """{"hostname":"fine.example.com"}""").status)
        }
    }

    @Test
    fun `a mock host start with a port or flag of the wrong kind is a 400`() {
        GovernanceHarness(dir, required = 1).use { h ->
            for (body in listOf("""{"port":"8443' AND 1=1"}""", """{"port":70000}""", """{"port":1.5}""", """{"mtls":"yes"}""")) {
                val answer = h.call("POST", "/api/v1/hosts/api.example.com/start-mock", ALICE, body)
                assertEquals(400, answer.status, "$body: ${answer.body}")
            }
        }
    }

    @Test
    fun `an unknown vault access policy or encryption is a 400`() {
        GovernanceHarness(dir, required = 1).use { h ->
            val path = "/api/v1/config-apis/default-tls/vault/ml-model/policy"
            val policy = h.call("PUT", path, ALICE, """{"access_policy":"S4feV4lu3","encryption":"plain"}""")
            assertEquals(400, policy.status, policy.body)
            assertTrue(policy.body.contains("invalid_access_policy"))
            val encryption = h.call("PUT", path, ALICE, """{"access_policy":"token","encryption":"S4feV4lu3"}""")
            assertEquals(400, encryption.status, encryption.body)
            assertTrue(encryption.body.contains("invalid_encryption"))
        }
    }

    @Test
    fun `TLS refuses client renegotiation and offers no SHA-1 or SHA-224 signatures, unless the operator set otherwise`() {
        val props = java.util.Properties()
        TlsHardening.apply(props)
        assertEquals("true", props.getProperty("jdk.tls.rejectClientInitiatedRenegotiation"))
        val schemes = props.getProperty("jdk.tls.server.SignatureSchemes").split(',')
        assertTrue(schemes.none { it.endsWith("sha1") || it.endsWith("sha224") }, schemes.toString())
        assertTrue("ecdsa_secp256r1_sha256" in schemes && "rsa_pss_rsae_sha256" in schemes && "rsa_pkcs1_sha256" in schemes)
        // Every scheme named is one this JDK knows: a misspelt one would silently drop out.
        val known = javax.net.ssl.SSLContext.getDefault().createSSLEngine().sslParameters.let { p ->
            runCatching { p.javaClass.getMethod("getSignatureSchemes").invoke(p) as? Array<*> }.getOrNull()
        }
        if (known != null) assertTrue(schemes.all { it in known.map(Any?::toString) }, "unknown: ${schemes - known.map(Any?::toString).toSet()}")

        val operator = java.util.Properties().apply { setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "false") }
        TlsHardening.apply(operator)
        assertEquals("false", operator.getProperty("jdk.tls.rejectClientInitiatedRenegotiation"))
    }
}
