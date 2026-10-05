package com.example.pinvault.server.service

import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * S-5: the server's keystores are PKCS12. Files written by earlier versions
 * are JKS; they still open, and the startup pass rewrites them.
 */
class ServerKeyStoresTest {

    private lateinit var dir: File
    private lateinit var certService: CertificateService
    private val password = CertificateService.KEYSTORE_PASSWORD.toCharArray()

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pinvault-keystores").toFile()
        certService = CertificateService(File(dir, "certs").also { it.mkdirs() })
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    @Test
    fun `every keystore the server writes is PKCS12 even though the file is named jks`() {
        val generated = certService.generateCertificate("host_test", "host.test")
        certService.ensureClientCa()
        certService.ensureServerCa()
        certService.ensureRecoveryCertificate()
        certService.generateClientCertificate("dev-1", "pw") // puts an entry in the client truststore

        val files = listOf(
            File(generated.keystorePath), File(File(generated.keystorePath).parentFile, "host_test.backup.jks"),
            certService.clientCaFile(), certService.serverCaFile(), certService.recoveryKeystoreFile(), certService.getTrustStoreFile()
        )
        for (file in files) {
            assertTrue(file.isFile, file.name)
            assertTrue(file.name.endsWith(".jks"), "the historical name stays: ${file.name}")
            assertFalse(ServerKeyStores.isLegacyJks(file.readBytes()), "${file.name} is still JKS")
            // Opens as plain PKCS12 with the JDK, no helper needed.
            KeyStore.getInstance("PKCS12").apply { file.inputStream().use { load(it, password) } }
        }
        assertEquals("server", ServerKeyStores.load(File(generated.keystorePath), password).aliases().toList().single())
    }

    @Test
    fun `a legacy JKS file opens, comes back as PKCS12 in memory, and is rewritten by the startup pass`() {
        val generated = certService.generateCertificate("legacy_test", "legacy.test")
        val file = File(generated.keystorePath)
        // What an earlier version left on disk: the same entries, JKS form.
        val current = ServerKeyStores.load(file, password)
        val jks = KeyStore.getInstance("JKS").apply { load(null, null) }
        jks.setKeyEntry("server", current.getKey("server", password), password, current.getCertificateChain("server"))
        file.outputStream().use { jks.store(it, password) }
        assertTrue(ServerKeyStores.isLegacyJks(file.readBytes()))

        val loaded = ServerKeyStores.load(file, password)
        assertEquals("PKCS12", loaded.type, "converted in memory, so a store() never writes JKS again")
        assertNotNull(loaded.getKey("server", password))
        assertEquals(current.getCertificate("server"), loaded.getCertificate("server"))
        assertTrue(ServerKeyStores.isLegacyJks(file.readBytes()), "a plain load does not touch the file")
        assertEquals(generated.sha256Pins[0], certService.extractHashFromKeystore(file.absolutePath), "the service reads it as before")

        val report = KeystoreRekey(certService, password = CertificateService.KEYSTORE_PASSWORD, previous = null).run(listOf(file), null)
        assertEquals(listOf(file.name), report.converted)
        assertTrue(report.rekeyed.isEmpty() && report.unreadable.isEmpty())
        assertFalse(ServerKeyStores.isLegacyJks(file.readBytes()), "rewritten as PKCS12")
        assertNotNull(ServerKeyStores.load(file, password).getKey("server", password))
        assertTrue(ServerKeyStores.convertLegacy(file, password).not(), "nothing left to convert")
        assertTrue(KeystoreRekey(certService, password = CertificateService.KEYSTORE_PASSWORD, previous = null).run(listOf(file), null).converted.isEmpty())
    }

    @Test
    fun `a legacy JKS under the old default password is rekeyed and converted in one step`() {
        val generated = certService.generateCertificate("old_pw_test", "old.test")
        val file = File(generated.keystorePath)
        val old = CertificateService.LEGACY_KEYSTORE_PASSWORD.toCharArray()
        val current = ServerKeyStores.load(file, password)
        val jks = KeyStore.getInstance("JKS").apply { load(null, null) }
        jks.setKeyEntry("server", current.getKey("server", password), old, current.getCertificateChain("server"))
        file.outputStream().use { jks.store(it, old) }

        val report = KeystoreRekey(certService, password = "a-new-secret", previous = null).run(listOf(file), null)
        assertEquals(listOf(file.name), report.rekeyed)
        assertFalse(ServerKeyStores.isLegacyJks(file.readBytes()))
        assertNotNull(ServerKeyStores.load(file, "a-new-secret".toCharArray()).getKey("server", "a-new-secret".toCharArray()))
    }
}
