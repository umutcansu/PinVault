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

    /**
     * [ensureKeyPair] asking the Keystore to attest a key it generates now:
     * the certificate chain of the new key then carries [attestationChallenge]
     * and the key's properties, signed by the device's attestation key (see
     * [attestationChain]). An existing key is left as it is — a challenge
     * cannot be added to it. Null, or a Keystore that cannot attest: a key
     * without attestation.
     */
    fun ensureKeyPair(attestationChallenge: ByteArray?) = ensureKeyPair()

    /**
     * The key's Android key attestation chain, DER, leaf first — exactly
     * what `KeyStore.getCertificateChain` returns — or empty when the key was
     * generated without an attestation challenge (the leaf has no attestation
     * extension then, and there is nothing to send).
     */
    fun attestationChain(): List<ByteArray> = emptyList()

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

        /** OID of the Android key attestation extension in the leaf certificate. */
        const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /**
         * The attestation challenge of an identity key: SHA-256 of
         * `pinvault-identity-key:v1:<deviceUid>` (UTF-8), where [deviceUid] is
         * the device id the enrollment request carries (its `deviceUid`, or
         * its `deviceId` when it sends no `deviceUid`). The server computes
         * the same from the request and refuses a chain whose leaf carries
         * anything else.
         */
        fun attestationChallenge(deviceUid: String): ByteArray =
            java.security.MessageDigest.getInstance("SHA-256")
                .digest("pinvault-identity-key:v1:$deviceUid".toByteArray(Charsets.UTF_8))

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

    override fun ensureKeyPair() = ensureKeyPair(null)

    /**
     * Tries, in order: StrongBox with attestation (Android 9+), the TEE with
     * attestation, the TEE without. A device whose Keystore cannot attest
     * still gets a key; it enrolls without a chain, and a server that
     * enforces attestation refuses it. StrongBox may be advertised but full,
     * or the ROM may reject the flag outright.
     */
    override fun ensureKeyPair(attestationChallenge: ByteArray?) {
        if (keystore.containsAlias(alias)) {
            Timber.d("Client identity key exists")
            return
        }
        val attempts = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) add(true to attestationChallenge)
            if (attestationChallenge != null) add(false to attestationChallenge)
            add(false to null)
        }.distinct()
        KeystoreOptions.generating("Client identity key", cleanUp = ::clear) { unlockedDeviceRequired ->
            var last: Exception? = null
            for ((strongBox, challenge) in attempts) {
                try {
                    val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    gen.initialize(spec(strongBox, challenge, unlockedDeviceRequired))
                    gen.generateKeyPair()
                    Timber.i("Client identity key generated (strongBox=%s, attestation=%s)", strongBox, challenge != null)
                    return@generating
                } catch (e: Exception) {
                    last = e
                    Timber.w(e, "Client identity key generation failed (strongBox=%s, attestation=%s), trying the next way",
                        strongBox, challenge != null)
                    runCatching { clear() }
                }
            }
            throw last ?: IllegalStateException("client identity key generation failed")
        }
    }

    override fun attestationChain(): List<ByteArray> {
        val chain = keystore.getCertificateChain(alias) ?: return emptyList()
        val leaf = chain.firstOrNull() as? java.security.cert.X509Certificate ?: return emptyList()
        // Without a challenge the Keystore still returns a one-certificate
        // chain (a self-signed placeholder): nothing a server can check.
        if (leaf.getExtensionValue(ClientIdentityKeyProvider.ATTESTATION_EXTENSION_OID) == null) return emptyList()
        return chain.map { it.encoded }
    }

    private fun spec(strongBox: Boolean, attestationChallenge: ByteArray?, unlockedDeviceRequired: Boolean): KeyGenParameterSpec =
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
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                if (unlockedDeviceRequired && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(true)
                // The leaf certificate then carries this challenge and the
                // key's properties, signed by the device's attestation key.
                attestationChallenge?.let { setAttestationChallenge(it) }
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

    override fun ensureKeyPair() = ensureKeyPair(null)

    override fun ensureKeyPair(attestationChallenge: ByteArray?) {
        keys.computeIfAbsent(alias) {
            val gen = KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec("secp256r1"))
            if (attestationChallenge != null) challenges[alias] = attestationChallenge.copyOf() else challenges.remove(alias)
            gen.generateKeyPair().also { Timber.d("Generated software client identity key") }
        }
    }

    /** What [attestation] makes of the challenge this key was generated with; empty without either. */
    override fun attestationChain(): List<ByteArray> {
        if (!keys.containsKey(alias)) return emptyList()
        val challenge = challenges[alias] ?: return emptyList()
        return attestation?.invoke(challenge).orEmpty()
    }

    override fun exists(): Boolean = keys.containsKey(alias)
    override fun publicKey(): PublicKey = keyPair().public
    override fun privateKey(): PrivateKey = keyPair().private
    override fun sign(data: ByteArray): ByteArray = signWith(privateKey(), data)
    override fun spkiSha256(): String = Pkcs10Csr.spkiSha256Base64(publicKey())
    override fun clear() {
        keys.remove(alias)
        challenges.remove(alias)
    }

    internal companion object {
        private val keys = ConcurrentHashMap<String, KeyPair>()
        private val challenges = ConcurrentHashMap<String, ByteArray>()

        /**
         * Tests: stands in for the device's attestation key. Given the
         * challenge a key was generated with, returns its "chain" (any
         * bytes); null = this "device" cannot attest.
         */
        @Volatile
        var attestation: ((challenge: ByteArray) -> List<ByteArray>)? = null
    }
}

private fun signWith(key: PrivateKey, data: ByteArray): ByteArray =
    Signature.getInstance("SHA256withECDSA").run {
        initSign(key)
        update(data)
        sign()
    }
