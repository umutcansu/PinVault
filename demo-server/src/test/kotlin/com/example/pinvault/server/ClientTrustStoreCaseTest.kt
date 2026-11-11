package com.example.pinvault.server

import com.example.pinvault.server.service.CertificateService
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Review 2026-11-11, C-11: PKCS12 aliases ignore letter case and client ids do
 * not, so an id differing from another only in case found, replaced or removed
 * (and retired) the other's anchor. And the truststore was rewritten in place.
 */
class ClientTrustStoreCaseTest {

    private lateinit var certsDir: File
    private lateinit var certService: CertificateService

    @BeforeTest
    fun setUp() {
        certsDir = Files.createTempDirectory("truststore-case").toFile()
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
    }

    @AfterTest
    fun tearDown() { certsDir.deleteRecursively() }

    private fun uploaded(cn: String): X509Certificate {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return TestPki.build("CN=$cn", key.public, "CN=$cn", key.private, eku = listOf("1.3.6.1.5.5.7.3.2"))
    }

    private fun anchor(alias: String): X509Certificate? = certService.getTrustStore()?.getCertificate(alias) as? X509Certificate

    @Test
    fun `an id differing only in letter case cannot take another id's certificate slot`() {
        val alice = uploaded("alice")
        certService.importClientCertificate("alice", TestPki.pem(alice))

        val e = assertFailsWith<IllegalArgumentException> { certService.importClientCertificate("Alice", TestPki.pem(uploaded("Alice"))) }
        assertTrue(e.message!!.contains("letter case"), e.message)
        assertEquals(alice, anchor("alice"), "alice's certificate is still the one on record")
    }

    @Test
    fun `enrolling revoking or forgetting an id never removes its case twin's anchor`() {
        val alice = uploaded("alice")
        certService.importClientCertificate("alice", TestPki.pem(alice))

        assertNull(certService.removeLegacyAnchor("Alice"), "not Alice's anchor: nothing to retire")
        certService.removeFromTrustStore("Alice")
        assertEquals(alice, anchor("alice"))

        assertNotNull(certService.removeLegacyAnchor("alice"), "its own id still removes it")
        assertNull(anchor("alice"))
    }

    @Test
    fun `an anchor recorded under an unrelated id is still removed with that id`() {
        // An upload from before the CN rule: recorded under "partner", CN names "gateway".
        certService.importClientCertificate("partner", TestPki.pem(uploaded("gateway")))
        certService.removeFromTrustStore("partner")
        assertNull(anchor("partner"))
    }

    @Test
    fun `the truststore is replaced whole and readable by its owner only`() {
        certService.importClientCertificate("alice", TestPki.pem(uploaded("alice")))
        val file = certService.getTrustStoreFile()
        val perms = runCatching { Files.getPosixFilePermissions(file.toPath()) }.getOrNull()
        if (perms != null) {
            assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"), perms)
        }
        assertTrue(certsDir.listFiles()!!.none { it.name.endsWith(".tmp") }, "no temp file left behind")
        assertNotNull(anchor(CertificateService.CLIENT_CA_ALIAS), "the client CA is still trusted")
    }
}
