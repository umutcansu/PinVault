package io.github.umutcansu.pinvault.model

/**
 * Result of a client certificate enrollment request.
 * Returned by [io.github.umutcansu.pinvault.api.CertificateConfigApi.enroll].
 */
data class EnrollmentResult(
    /** PKCS12 certificate bytes. */
    val p12Bytes: ByteArray,
    /** Optional SHA-256 hash of the P12 for integrity verification. */
    val p12Hash: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EnrollmentResult) return false
        return p12Bytes.contentEquals(other.p12Bytes) && p12Hash == other.p12Hash
    }

    override fun hashCode(): Int = p12Bytes.contentHashCode() * 31 + (p12Hash?.hashCode() ?: 0)
}
