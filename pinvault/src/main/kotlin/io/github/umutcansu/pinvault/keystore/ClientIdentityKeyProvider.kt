package io.github.umutcansu.pinvault.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import timber.log.Timber
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.ConcurrentHashMap

/**
 * The device's mTLS identity: a permanent EC P-256 signing key that lives in
 * the Android Keystore. The client certificate is only a short-lived
 * credential issued over this key — it is renewed by signing a CSR with it,
 * and the key itself never leaves the device (TEE/StrongBox when available).
 *
 * Separate from [DeviceKeyProvider] on purpose: that key is RSA and was
 * generated for decryption only, and Keystore purposes cannot be widened
 * after the fact. One identity key per client-cert label, so a host app with
 * several mTLS Config API blocks gets one identity per block.
 *
 * Robolectric has no AndroidKeyStore; unit tests use [software].
 */
interface ClientIdentityKeyProvider {

    /** Generate the key pair if missing. Idempotent. */
    fun ensureKeyPair()

    /** True when the key exists (without generating it). */
    fun exists(): Boolean

    fun publicKey(): PublicKey

    /** Opaque on Keystore backends — usable only through [sign] and TLS key managers. */
    fun privateKey(): PrivateKey

    /** SHA256withECDSA over [data], DER-encoded ECDSA-Sig-Value. */
    fun sign(data: ByteArray): ByteArray

    /** SHA-256 of the SubjectPublicKeyInfo, Base64 — what the server keeps in its registry. */
    fun spkiSha256(): String

    /** Delete the key. The next [ensureKeyPair] generates a new identity. */
    fun clear()

    companion object {
        private const val ALIAS_PREFIX = "pinvault_client_identity_ec_"

        /** Keystore alias for the identity that backs the client cert stored under [label]. */
        fun aliasFor(label: String): String = ALIAS_PREFIX + label

        /** Android Keystore implementation. Preferred on device. */
        fun androidKeystore(label: String): ClientIdentityKeyProvider =
            AndroidKeystoreClientIdentityKeyProvider(aliasFor(label))

        /**
         * Software fallback for tests / non-Android environments. Keys are
         * held per alias for the process lifetime, so separate instances for
         * the same label see the same key — like the Keystore does.
         */
        fun software(label: String): ClientIdentityKeyProvider =
            SoftwareClientIdentityKeyProvider(aliasFor(label))
    }
}

// ── Android Keystore impl ───────────────────────────────────────────────

internal class AndroidKeystoreClientIdentityKeyProvider(
    private val alias: String
) : ClientIdentityKeyProvider {

    private val keystore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    override fun ensureKeyPair() {
        if (keystore.containsAlias(alias)) {
            Timber.d("Client identity key exists: %s", alias)
            return
        }
        Timber.i("Generating client identity key in AndroidKeyStore: %s", alias)
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try {
            gen.initialize(spec(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P))
            gen.generateKeyPair()
        } catch (e: Exception) {
            // StrongBox may be advertised but full, or the ROM may reject the
            // flag outright. Same key parameters, just not hardware-isolated.
            Timber.w(e, "StrongBox key generation failed, retrying without")
            gen.initialize(spec(strongBox = false))
            gen.generateKeyPair()
        }
    }

    private fun spec(strongBox: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // SHA-256 signs the CSR. NONE is what the TLS stack needs: Conscrypt
            // hashes the handshake transcript itself and asks the Keystore for a
            // raw `NONEwithECDSA` signature — without it the key is refused at
            // handshake time and the device silently presents no certificate.
            .setDigests(
                KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512
            )
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try { setIsStrongBoxBacked(true) } catch (_: Exception) { /* optional */ }
                }
            }
            .build()

    override fun exists(): Boolean = keystore.containsAlias(alias)

    override fun publicKey(): PublicKey =
        (keystore.getCertificate(alias) ?: error("Client identity key not found — call ensureKeyPair() first"))
            .publicKey

    override fun privateKey(): PrivateKey =
        (keystore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Client identity key not found — call ensureKeyPair() first"))
            .privateKey

    override fun sign(data: ByteArray): ByteArray = signWith(privateKey(), data)

    override fun spkiSha256(): String = Pkcs10Csr.spkiSha256Base64(publicKey())

    override fun clear() {
        if (keystore.containsAlias(alias)) keystore.deleteEntry(alias)
    }
}

// ── Software fallback (tests) ───────────────────────────────────────────

internal class SoftwareClientIdentityKeyProvider(private val alias: String) : ClientIdentityKeyProvider {

    private fun keyPair(): KeyPair = keys[alias] ?: error("ensureKeyPair() first")

    override fun ensureKeyPair() {
        keys.computeIfAbsent(alias) {
            val gen = KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec("secp256r1"))
            gen.generateKeyPair().also { Timber.d("Generated software client identity key: %s", alias) }
        }
    }

    override fun exists(): Boolean = keys.containsKey(alias)
    override fun publicKey(): PublicKey = keyPair().public
    override fun privateKey(): PrivateKey = keyPair().private
    override fun sign(data: ByteArray): ByteArray = signWith(privateKey(), data)
    override fun spkiSha256(): String = Pkcs10Csr.spkiSha256Base64(publicKey())
    override fun clear() { keys.remove(alias) }

    private companion object {
        val keys = ConcurrentHashMap<String, KeyPair>()
    }
}

private fun signWith(key: PrivateKey, data: ByteArray): ByteArray =
    Signature.getInstance("SHA256withECDSA").run {
        initSign(key)
        update(data)
        sign()
    }
