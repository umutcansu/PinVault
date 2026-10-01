package io.github.umutcansu.pinvault.model

/**
 * Result of a client certificate enrollment request.
 * Returned by [io.github.umutcansu.pinvault.api.CertificateConfigApi.enroll]
 * and [io.github.umutcansu.pinvault.api.CertificateConfigApi.enrollWithCsr].
 *
 * One of two shapes: a PKCS12 bundle the server generated ([p12Bytes]), or —
 * when the device enrolled with a CSR over its own Keystore key — the PEM
 * certificate chain issued over that key ([certificateChainPem]), in which
 * case [p12Bytes] is empty.
 */
data class EnrollmentResult @JvmOverloads constructor(
    /** PKCS12 certificate bytes. Empty for a CSR enrollment. */
    val p12Bytes: ByteArray,
    /** Optional SHA-256 hash of the P12 for integrity verification. */
    val p12Hash: String? = null,
    /**
     * The password [p12Bytes] is wrapped with, when the server sent one for
     * this response (`X-P12-Password`). Null: the block's `clientKeyPassword`
     * opens it, as with servers that do not negotiate a password.
     */
    val p12Password: String? = null,
    /**
     * CSR enrollment: the issued certificate chain as PEM, leaf first, then
     * its issuer(s). Null for a P12 response.
     */
    val certificateChainPem: List<String>? = null
) {
    /** True when the server answered a CSR enrollment with a certificate chain. */
    val isCertificateChain: Boolean get() = certificateChainPem != null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EnrollmentResult) return false
        return p12Bytes.contentEquals(other.p12Bytes) && p12Hash == other.p12Hash &&
            p12Password == other.p12Password && certificateChainPem == other.certificateChainPem
    }

    override fun hashCode(): Int =
        ((p12Bytes.contentHashCode() * 31 + (p12Hash?.hashCode() ?: 0)) * 31 + (p12Password?.hashCode() ?: 0)) * 31 +
            (certificateChainPem?.hashCode() ?: 0)

    /** The password is a secret: never in logs. */
    override fun toString(): String =
        "EnrollmentResult(p12Bytes=${p12Bytes.size} bytes, p12Hash=$p12Hash, " +
            "p12Password=${if (p12Password == null) "null" else "***"}, chain=${certificateChainPem?.size ?: "null"})"
}
