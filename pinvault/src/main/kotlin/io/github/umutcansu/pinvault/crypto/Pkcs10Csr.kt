package io.github.umutcansu.pinvault.crypto

import android.util.Base64
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Minimal PKCS#10 (RFC 2986) encoder for the device's certificate signing
 * request, plus the PEM helpers the CSR flow needs.
 *
 * Hand-rolled DER on purpose: the library has no BouncyCastle at runtime
 * (only the test source set does), and pulling `bcpkix` into every host app
 * for one fixed-shape message is not worth the size or the provider clashes
 * with Android's built-in BC. The request is always the same shape —
 *
 * ```
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo  SEQUENCE {
 *     version        INTEGER 0,
 *     subject        Name (a single CN),
 *     subjectPKInfo  SubjectPublicKeyInfo (the key's own X.509 encoding),
 *     attributes     [0] IMPLICIT SET (empty) },
 *   signatureAlgorithm  ecdsa-with-SHA256 (no parameters),
 *   signature           BIT STRING }
 * ```
 *
 * — and the server ignores the subject anyway (it names the certificate
 * after the enrolled client id), so nothing beyond this ever needs encoding.
 * `Pkcs10CsrTest` parses the output with BouncyCastle to prove it is valid.
 */
internal object Pkcs10Csr {

    /** id-at-commonName, 2.5.4.3 */
    private val OID_COMMON_NAME = byteArrayOf(0x55, 0x04, 0x03)

    /** ecdsa-with-SHA256, 1.2.840.10045.4.3.2 */
    private val OID_ECDSA_WITH_SHA256 =
        byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02)

    private const val TAG_INTEGER = 0x02
    private const val TAG_BIT_STRING = 0x03
    private const val TAG_OID = 0x06
    private const val TAG_UTF8_STRING = 0x0C
    private const val TAG_SEQUENCE = 0x30
    private const val TAG_SET = 0x31
    private const val TAG_CONTEXT_0 = 0xA0

    /**
     * Encodes a CSR for [publicKey] with subject `CN=[commonName]`.
     *
     * @param signer signs the DER-encoded CertificationRequestInfo with the
     *        key's private half using SHA256withECDSA and returns the DER
     *        `ECDSA-Sig-Value` — exactly what `java.security.Signature`
     *        produces. Kept as a lambda so the key never has to leave an
     *        Android Keystore provider.
     */
    fun encode(commonName: String, publicKey: PublicKey, signer: (tbs: ByteArray) -> ByteArray): ByteArray {
        require(commonName.isNotBlank()) { "commonName must not be blank" }
        require(publicKey.format == "X.509") {
            "Public key must encode as X.509 SubjectPublicKeyInfo, got ${publicKey.format}"
        }
        val subject = der(
            TAG_SEQUENCE,
            der(
                TAG_SET,
                der(
                    TAG_SEQUENCE,
                    der(TAG_OID, OID_COMMON_NAME) + der(TAG_UTF8_STRING, commonName.toByteArray(Charsets.UTF_8))
                )
            )
        )
        val info = der(
            TAG_SEQUENCE,
            der(TAG_INTEGER, byteArrayOf(0)) +
                subject +
                publicKey.encoded +
                der(TAG_CONTEXT_0, ByteArray(0))
        )
        val signature = signer(info)
        val algorithm = der(TAG_SEQUENCE, der(TAG_OID, OID_ECDSA_WITH_SHA256))
        // BIT STRING: one leading byte for the count of unused bits (0).
        val bitString = der(TAG_BIT_STRING, byteArrayOf(0) + signature)
        return der(TAG_SEQUENCE, info + algorithm + bitString)
    }

    /** SHA-256 of the key's SubjectPublicKeyInfo, Base64 — the same form pins are written in. */
    fun spkiSha256Base64(publicKey: PublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    fun toPem(certificate: X509Certificate): String {
        val body = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP).chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----"
    }

    /** Parses PEM certificates, one per entry, in order. Throws on anything unreadable. */
    fun parsePemChain(pems: List<String>): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        return pems.map { pem ->
            val body = pem.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("-----") }
                .joinToString("")
            require(body.isNotEmpty()) { "Empty PEM certificate" }
            val der = Base64.decode(body, Base64.DEFAULT)
            factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }
    }

    // ── DER helpers ──────────────────────────────────────────────────────

    private fun der(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + derLength(content.size) + content

    private fun derLength(length: Int): ByteArray {
        if (length < 0x80) return byteArrayOf(length.toByte())
        var n = length
        val bytes = ArrayList<Byte>(4)
        while (n > 0) {
            bytes.add(0, (n and 0xFF).toByte())
            n = n ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }
}
