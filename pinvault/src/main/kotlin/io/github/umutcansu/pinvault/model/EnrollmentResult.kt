package io.github.umutcansu.pinvault.model

/**
 * Result of a client certificate enrollment request.
 * Returned by [io.github.umutcansu.pinvault.api.CertificateConfigApi.enroll].
 */
data class EnrollmentResult @JvmOverloads constructor(
    /** PKCS12 certificate bytes. */
    val p12Bytes: ByteArray,
    /** Optional SHA-256 hash of the P12 for integrity verification. */
    val p12Hash: String? = null,
    /**
     * The password [p12Bytes] is wrapped with, when the server sent one for
     * this response (`X-P12-Password`). Null: the block's `clientKeyPassword`
     * opens it, as with servers that do not negotiate a password.
     */
    val p12Password: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EnrollmentResult) return false
        return p12Bytes.contentEquals(other.p12Bytes) && p12Hash == other.p12Hash && p12Password == other.p12Password
    }

    override fun hashCode(): Int =
        (p12Bytes.contentHashCode() * 31 + (p12Hash?.hashCode() ?: 0)) * 31 + (p12Password?.hashCode() ?: 0)

    /** The password is a secret: never in logs. */
    override fun toString(): String =
        "EnrollmentResult(p12Bytes=${p12Bytes.size} bytes, p12Hash=$p12Hash, p12Password=${if (p12Password == null) "null" else "***"})"
}
