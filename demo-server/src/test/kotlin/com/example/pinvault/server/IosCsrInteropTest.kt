package com.example.pinvault.server

import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.IntegrityRequestHash
import com.example.pinvault.server.service.VerificationCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.io.File
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A certificate signing request the iOS library made (its `Pkcs10Csr`, over a
 * Secure Enclave P-256 key, on the simulator) goes through the server's own
 * CSR code: `pinvault-ios/Tests/PinVaultTests/Fixtures/enrollment/ios-device.csr`,
 * with what the iOS side computed in `ios-device.json`.
 */
class IosCsrInteropTest {

    private val fixtures = File("../pinvault-ios/Tests/PinVaultTests/Fixtures/enrollment")
    private val der: ByteArray = File(fixtures, "ios-device.csr").readBytes()
    private val expected = Json.parseToJsonElement(File(fixtures, "ios-device.json").readText()).jsonObject
        .mapValues { it.value.jsonPrimitive.content }

    private lateinit var certsDir: File
    private lateinit var certService: CertificateService

    @BeforeTest
    fun setUp() {
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-ios-csr-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
    }

    @AfterTest
    fun tearDown() {
        certsDir.deleteRecursively()
    }

    @Test
    fun `the server parses the iOS request and verifies its proof of possession`() {
        val parsed = certService.parseCsr(der)
        assertEquals(expected.getValue("spkiSha256"), parsed.spkiSha256)
        assertTrue(parsed.publicKey.algorithm in setOf("EC", "ECDSA"), parsed.publicKey.algorithm)
        // The same request as the body carries it (Base64).
        assertEquals(parsed.spkiSha256, certService.parseCsr(Base64.getEncoder().encodeToString(der)).spkiSha256)
        assertEquals(expected.getValue("keySecurityLevel"), "secure_enclave")
    }

    @Test
    fun `BouncyCastle reads the subject, the key, the algorithm and the empty attributes`() {
        val csr = PKCS10CertificationRequest(der)
        assertEquals("CN=${expected.getValue("commonName")}", csr.subject.toString())
        assertEquals("1.2.840.10045.4.3.2", csr.signatureAlgorithm.algorithm.id)
        assertEquals(0, csr.attributes.size)
        val spkiHash = MessageDigest.getInstance("SHA-256").digest(csr.subjectPublicKeyInfo.encoded)
        assertEquals(expected.getValue("spkiSha256"), Base64.getEncoder().encodeToString(spkiHash))
        assertEquals("1.2.840.10045.3.1.7", csr.subjectPublicKeyInfo.algorithm.parameters.toString(), "P-256")
        assertTrue(
            csr.isSignatureValid(
                JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(csr.subjectPublicKeyInfo)
            )
        )
    }

    @Test
    fun `the device and the dashboard show the same verification code and bind the same request hash`() {
        assertEquals(expected.getValue("verificationCode"), VerificationCode.ofSpkiSha256(expected.getValue("spkiSha256")))
        val requestHash = IntegrityRequestHash.of(expected.getValue("commonName"), der)
        assertEquals(expected.getValue("integrityRequestHash"), requestHash)
        // What an App Attest attestation of this request binds (PORTING.md §6).
        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(requestHash.toByteArray(Charsets.UTF_8))
        assertEquals(expected.getValue("appAttestClientDataHash"), Base64.getEncoder().encodeToString(clientDataHash))
    }

    @Test
    fun `a certificate the server issues over the iOS request is over the Secure Enclave key`() {
        val parsed = certService.parseCsr(der)
        val issued = certService.issueClientCertificate("ios-field-1", parsed, Duration.ofDays(90))
        assertContentEquals(parsed.publicKey.encoded, issued.leaf.publicKey.encoded)
        assertEquals(expected.getValue("spkiSha256"), issued.spkiSha256)
        assertEquals("PinVault Client: ios-field-1", issued.commonName)
        assertEquals(2, issued.chainPem.size, "the leaf and the client CA the iOS library requires")
        issued.leaf.verify(issued.issuer.publicKey)
    }

    @Test
    fun `a tampered iOS request is refused`() {
        val tampered = der.copyOf()
        // A byte inside the CN: the signature no longer covers what is sent.
        val cn = expected.getValue("commonName").toByteArray(Charsets.UTF_8)
        val at = (0..tampered.size - cn.size).first { start -> cn.indices.all { tampered[start + it] == cn[it] } }
        tampered[at] = (tampered[at] + 1).toByte()
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(tampered) }
    }
}
