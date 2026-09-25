package com.example.pinvault.server.service.signing

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Produces ECDSA P-256 / SHA-256 signatures for config payloads, vault files
 * and anything else a device verifies.
 *
 * The server never needs more than this from a key: devices only ever hold
 * the public half, so where the private half lives is the operator's choice.
 * Three implementations ship with the reference server, selected with
 * `CONFIG_SIGNERS`:
 *
 *  - [LocalFileSigner] (`local`, the default): a key file in the data
 *    directory, optionally encrypted at rest with `SIGNING_KEY_PASSWORD`.
 *  - [Pkcs11Signer] (`pkcs11`): a key inside an HSM (or SoftHSM for testing)
 *    that is generated there and can never be read out.
 *  - [CommandSigner] (`command`): any external signer — a cloud KMS CLI, a
 *    Vault transit call, a signing service on another host — reached through
 *    a command that reads the bytes to sign on stdin.
 *
 * Several signers at once give every document several signatures, which is
 * what a device configured with `requiredSignatures(n)` needs.
 */
interface ConfigSigner {
    /** The `CONFIG_SIGNERS` entry this signer came from, e.g. `local` or `command:kms`. */
    val name: String

    /** `local`, `pkcs11` or `command`. */
    val type: String

    /** One line for the dashboard and logs. Never contains secrets. */
    val description: String

    /** Base64 X.509 SubjectPublicKeyInfo — the value devices embed. */
    val publicKeyBase64: String

    /** Base64 SHA-256 over the SubjectPublicKeyInfo (same shape as a TLS SPKI pin). */
    val keyId: String get() = SigningKeys.keyIdOf(publicKeyBase64)

    /** A DER-encoded ECDSA signature over [data] (SHA-256). */
    fun sign(data: ByteArray): ByteArray
}

/** Helpers shared by the signers and the routes that talk about keys. */
object SigningKeys {

    fun keyIdOf(publicKeyBase64: String): String =
        Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(Base64.getDecoder().decode(publicKeyBase64))
        )

    /** Parses a Base64 X.509 key, or a PEM `PUBLIC KEY` block. */
    fun decodePublicKey(text: String): PublicKey {
        val b64 = text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(b64)))
    }

    fun base64Of(publicKey: PublicKey): String = Base64.getEncoder().encodeToString(publicKey.encoded)

    /** One text form per key (PEM or Base64 in, single-line Base64 X.509 out), so keys can be compared. */
    fun canonical(text: String): String = base64Of(decodePublicKey(text))

    fun verify(publicKey: PublicKey, data: ByteArray, derSignature: ByteArray): Boolean = try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(derSignature)
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Accepts what external signers typically print: Base64 or raw bytes, in
     * DER or in the fixed-width r||s form (IEEE P1363) some KMS and PKCS#11
     * tools emit, and returns DER — the only form devices verify.
     */
    fun normalizeSignature(output: ByteArray): ByteArray {
        val text = String(output, Charsets.US_ASCII).trim()
        val decoded = try {
            if (text.isNotEmpty() && text.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }) {
                Base64.getDecoder().decode(text)
            } else null
        } catch (_: IllegalArgumentException) {
            null
        }
        val bytes = decoded ?: output
        return when {
            bytes.isNotEmpty() && bytes[0] == 0x30.toByte() -> bytes
            bytes.size == 64 -> p1363ToDer(bytes)
            else -> throw IllegalArgumentException("signer output is neither a DER nor a 64-byte r||s ECDSA signature")
        }
    }

    /** IEEE P1363 (r||s, 32 bytes each for P-256) → ASN.1 DER SEQUENCE { r, s }. */
    fun p1363ToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64) { "expected 64 bytes, got ${raw.size}" }
        fun integer(part: ByteArray): ByteArray {
            var start = 0
            while (start < part.size - 1 && part[start] == 0.toByte()) start++
            var value = part.copyOfRange(start, part.size)
            if (value[0].toInt() and 0x80 != 0) value = byteArrayOf(0) + value
            return byteArrayOf(0x02, value.size.toByte()) + value
        }
        val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
