package com.example.pinvault.server.service

import com.example.pinvault.server.store.VaultFileTokenStore
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

/**
 * Generates and validates per-device, per-file access tokens.
 *
 * Plaintext is 32 random bytes (256-bit), URL-safe base64 (no padding). This
 * yields ~43-char strings suitable for copy-paste / QR-code transport.
 *
 * The service does NOT store plaintext. [VaultFileTokenStore] retains only
 * SHA-256(plaintext). [generate] is the only moment the plaintext exists —
 * it is returned to the caller (admin UI), which is responsible for delivering
 * it to the device via a secure out-of-band channel.
 */
class VaultAccessTokenService(
    private val tokenStore: VaultFileTokenStore,
    private val clock: () -> Instant = Instant::now,
    private val random: SecureRandom = SecureRandom()
) {

    /**
     * Issue a new token for (configApiId, vaultKey, deviceId). If an active
     * token already exists for this triple the store replaces it (old token
     * becomes invalid).
     *
     * @return [GeneratedToken] containing the plaintext (shown once to admin)
     *         and the stored row id (usable for later revocation).
     */
    fun generate(configApiId: String, vaultKey: String, deviceId: String): GeneratedToken {
        val plaintext = randomUrlSafeBase64(TOKEN_BYTES)
        val timestamp = clock().toString()
        val tokenId = tokenStore.put(configApiId, vaultKey, deviceId, plaintext, timestamp)
        return GeneratedToken(
            id = tokenId,
            plaintext = plaintext,
            configApiId = configApiId,
            vaultKey = vaultKey,
            deviceId = deviceId,
            createdAt = timestamp
        )
    }

    /**
     * Constant-time validation. Returns false on any mismatch (wrong device,
     * wrong file, wrong token, revoked, or no active token at all).
     *
     * Never log the plaintext — pass only the result of this method to logs.
     */
    fun validate(
        configApiId: String,
        vaultKey: String,
        deviceId: String,
        tokenPlaintext: String
    ): Boolean = tokenStore.validate(configApiId, vaultKey, deviceId, tokenPlaintext)

    fun revoke(tokenId: Long): Boolean = tokenStore.revoke(tokenId)

    fun revokeByTriple(configApiId: String, vaultKey: String, deviceId: String): Boolean =
        tokenStore.revokeByTriple(configApiId, vaultKey, deviceId)

    private fun randomUrlSafeBase64(byteCount: Int): String {
        val buf = ByteArray(byteCount)
        random.nextBytes(buf)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf)
    }

    companion object {
        /** 32 bytes = 256 bit entropy. Plenty against brute-force. */
        private const val TOKEN_BYTES = 32
    }
}

data class GeneratedToken(
    val id: Long,
    val plaintext: String,
    val configApiId: String,
    val vaultKey: String,
    val deviceId: String,
    val createdAt: String
)
