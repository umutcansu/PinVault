package com.example.pinvault.server.service

import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `EXTRA_CERT_SANS` lets a containerised server put the Docker host's LAN IP
 * into the certificates it generates. Without it the interface scan only sees
 * the container's private address and Android clients fail TLS hostname
 * verification when they connect by the host's IP.
 */
class CertificateServiceSanTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pinvault-san-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun sansOf(result: CertGenResult): List<Pair<Int, String>> {
        val ks = KeyStore.getInstance("JKS")
        File(result.keystorePath).inputStream().use {
            ks.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray())
        }
        val cert = ks.getCertificate("server") as X509Certificate
        return cert.subjectAlternativeNames.map { (it[0] as Int) to (it[1] as String) }
    }

    // RFC 5737 documentation address: never assigned to a real interface, so the
    // interface scan in buildSanNames cannot add it on its own on any machine.
    private val DOC_IP = "203.0.113.7"

    private val dns = 2
    private val ip = 7

    @Test
    fun `extra SANs are added to generated certificates`() {
        val service = CertificateService(dir, extraSans = listOf(DOC_IP, "pinvault.lan"))
        val sans = sansOf(service.generateCertificate("demo-server", "localhost"))

        assertTrue(ip to DOC_IP in sans, "LAN IP must be an iPAddress SAN: $sans")
        assertTrue(dns to "pinvault.lan" in sans, "hostname must be a dNSName SAN: $sans")
        // Built-in entries are kept.
        assertTrue(dns to "localhost" in sans)
        assertTrue(ip to "10.0.2.2" in sans)
        assertTrue(ip to "127.0.0.1" in sans)
    }

    @Test
    fun `entries already present are not duplicated`() {
        val service = CertificateService(dir, extraSans = listOf("127.0.0.1", "localhost"))
        val sans = sansOf(service.generateCertificate("demo-server", "localhost"))

        assertEquals(1, sans.count { it == ip to "127.0.0.1" })
        assertEquals(1, sans.count { it == dns to "localhost" })
    }

    @Test
    fun `without extra SANs the certificate is unchanged`() {
        val service = CertificateService(dir, extraSans = emptyList())
        val sans = sansOf(service.generateCertificate("demo-server", "localhost"))

        assertTrue(dns to "localhost" in sans)
        assertTrue(sans.none { it.second == DOC_IP })
    }

    @Test
    fun `parseExtraSans keeps valid IPs and names and drops the rest`() {
        assertEquals(
            listOf("192.168.1.80", "pinvault.lan", "*.example.com"),
            CertificateService.parseExtraSans(" 192.168.1.80, pinvault.lan ,, *.example.com ,192.168.1.80")
        )
        assertEquals(emptyList(), CertificateService.parseExtraSans(null))
        assertEquals(emptyList(), CertificateService.parseExtraSans(""))
        assertEquals(
            emptyList(),
            CertificateService.parseExtraSans("999.1.1.1, bad host!, a/b, -leading.dash, trailing-.lan")
        )
    }
}
