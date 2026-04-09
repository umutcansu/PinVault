package io.github.umutcansu.pinvault.util

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.util.*

/**
 * Utility for generating self-signed certificates and PKCS12 keystores in tests.
 */
object TestCertUtil {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    data class CertResult(
        val keyPair: KeyPair,
        val certificate: X509Certificate,
        val p12Bytes: ByteArray,
        val sha256Pin: String
    )

    fun generateSelfSigned(
        cn: String = "localhost",
        password: String = "changeit",
        validDays: Int = 365,
        alias: String = "server"
    ): CertResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val notBefore = Date()
        val notAfter = Date(notBefore.time + validDays.toLong() * 86400_000)

        val issuer = X500Name("CN=$cn")
        val serial = BigInteger.valueOf(System.nanoTime())

        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.private)

        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry(alias, keyPair.private, password.toCharArray(), arrayOf(cert))

        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, password.toCharArray())

        val pin = sha256Base64(keyPair.public.encoded)

        return CertResult(keyPair, cert, baos.toByteArray(), pin)
    }

    fun generateExpired(cn: String = "expired.test", password: String = "changeit"): CertResult {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()

        val notBefore = Date(System.currentTimeMillis() - 86400_000 * 30)
        val notAfter = Date(System.currentTimeMillis() - 86400_000)

        val issuer = X500Name("CN=$cn")
        val serial = BigInteger.valueOf(System.nanoTime())

        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.private)

        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("server", keyPair.private, password.toCharArray(), arrayOf(cert))

        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, password.toCharArray())

        return CertResult(keyPair, cert, baos.toByteArray(), sha256Base64(keyPair.public.encoded))
    }

    fun sha256Base64(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.getEncoder().encodeToString(digest)
    }

    /** Generate an ECDSA key pair for config signing tests */
    fun generateEcKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        gen.initialize(256)
        return gen.generateKeyPair()
    }

    /** Sign payload with ECDSA-SHA256 */
    fun signPayload(payload: String, privateKey: java.security.PrivateKey): String {
        val sig = java.security.Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }
}
