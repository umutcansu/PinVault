package io.github.umutcansu.pinvault.keystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import timber.log.Timber
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * Manages the device's RSA key pair used for end-to-end vault file
 * encryption. The server wraps per-file AES session keys with this key's
 * public half; only the device can unwrap them using the private half.
 *
 * Production: Android Keystore-backed RSA 2048 with OAEP SHA-256 padding.
 * The private key never leaves the TEE/StrongBox when hardware is available.
 *
 * Test/Robolectric: software [KeyPairGenerator] fallback, used when the
 * Android Keystore isn't available (unit tests). The key is still stored
 * in an in-memory JKS-like container so repeated [ensureKeyPair] calls
 * return the same key.
 *
 * Usage:
 * ```kotlin
 * val provider = DeviceKeyProvider.androidKeystore(context)
 * provider.ensureKeyPair()
 * val pem = provider.getPublicKeyPem()
 * api.registerDevicePublicKey(deviceId, pem)
 * // later, when downloading an end_to_end file:
 * val plain = VaultFileDecryptor.decrypt(envelope, provider.getPrivateKey())
 * ```
 */
interface DeviceKeyProvider {

    /** Generate the key pair if missing. Idempotent. */
    fun ensureKeyPair()

    /** PEM-encoded public key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----". */
    fun getPublicKeyPem(): String

    /** Private key handle. On Android Keystore backends, the raw material is NOT accessible — only used via Cipher. */
    fun getPrivateKey(): PrivateKey

    /** Remove the key pair. Next [ensureKeyPair] call regenerates. */
    fun clear()

    companion object {
        const val DEFAULT_ALIAS = "pinvault_vault_e2e_rsa"

        /** Android Keystore implementation. Preferred on device. */
        fun androidKeystore(
            context: Context,
            alias: String = DEFAULT_ALIAS
        ): DeviceKeyProvider = AndroidKeystoreDeviceKeyProvider(context, alias)

        /**
         * Software fallback for tests / non-Android environments. The key is
         * held in a transient JKS-like map; it persists for the process
         * lifetime but not across restarts.
         */
        fun software(alias: String = DEFAULT_ALIAS): DeviceKeyProvider =
            SoftwareDeviceKeyProvider(alias)
    }
}

// ── Android Keystore impl ───────────────────────────────────────────────

internal class AndroidKeystoreDeviceKeyProvider(
    @Suppress("unused") private val context: Context,
    private val alias: String
) : DeviceKeyProvider {

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    override fun ensureKeyPair() {
        if (keystore.containsAlias(alias)) {
            Timber.d("Device RSA key exists: %s", alias)
            return
        }
        Timber.i("Generating device RSA key in AndroidKeyStore: %s", alias)
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_DECRYPT
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .apply {
                // StrongBox on API 28+ when available. Fall back silently.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try { setIsStrongBoxBacked(true) } catch (_: Exception) { /* optional */ }
                }
            }
            .build()
        try {
            gen.initialize(spec)
            gen.generateKeyPair()
        } catch (e: Exception) {
            // StrongBox might fail on devices that advertise support but don't
            // have room for another key. Retry without StrongBox.
            Timber.w(e, "StrongBox key generation failed, retrying without")
            val fallback = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_DECRYPT
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(2048)
                .build()
            gen.initialize(fallback)
            gen.generateKeyPair()
        }
    }

    override fun getPublicKeyPem(): String {
        val cert = keystore.getCertificate(alias)
            ?: error("Device RSA key not found — call ensureKeyPair() first")
        return publicKeyToPem(cert.publicKey)
    }

    override fun getPrivateKey(): PrivateKey {
        val entry = keystore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Device RSA key not found — call ensureKeyPair() first")
        return entry.privateKey
    }

    override fun clear() {
        if (keystore.containsAlias(alias)) keystore.deleteEntry(alias)
    }
}

// ── Software fallback (tests) ───────────────────────────────────────────

internal class SoftwareDeviceKeyProvider(private val alias: String) : DeviceKeyProvider {

    @Volatile private var keyPair: KeyPair? = null

    override fun ensureKeyPair() {
        if (keyPair != null) return
        synchronized(this) {
            if (keyPair != null) return
            val gen = KeyPairGenerator.getInstance("RSA")
            gen.initialize(2048)
            keyPair = gen.generateKeyPair()
            Timber.d("Generated software RSA key: %s", alias)
        }
    }

    override fun getPublicKeyPem(): String =
        publicKeyToPem((keyPair ?: error("ensureKeyPair() first")).public)

    override fun getPrivateKey(): PrivateKey =
        (keyPair ?: error("ensureKeyPair() first")).private

    override fun clear() { keyPair = null }
}

// ── Shared helpers ──────────────────────────────────────────────────────

private fun publicKeyToPem(publicKey: PublicKey): String {
    val encoded = Base64.getEncoder().encodeToString(publicKey.encoded)
    val chunked = encoded.chunked(64).joinToString("\n")
    return "-----BEGIN PUBLIC KEY-----\n$chunked\n-----END PUBLIC KEY-----"
}
