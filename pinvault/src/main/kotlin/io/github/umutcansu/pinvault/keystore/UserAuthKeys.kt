package io.github.umutcansu.pinvault.keystore

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import timber.log.Timber
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * How the user-auth key is opened. Fixed when the key is made and read back
 * from the key itself, so a key made on Android 10 keeps its kind after an
 * upgrade to 11.
 */
internal enum class UserAuthKeyKind {
    /**
     * Android 11+: every use asks; a strong biometric or the screen lock.
     * Authorised by `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`, the key is bound
     * to the device credential (the Keystore ties it to the screen lock's
     * secure id, not to the enrolled biometrics): only removing the screen
     * lock retires it. Enrolling a new fingerprint or face does NOT — that
     * invalidates biometric-only keys, which this is not.
     */
    PER_USE,

    /**
     * Android 7–10 with a strong fingerprint at key generation: every use
     * asks, fingerprint only. This is the one biometric-only kind, bound to
     * the enrolled fingerprints: a new fingerprint, removing all fingerprints
     * or removing the screen lock retires the key.
     */
    PER_USE_BIOMETRIC,

    /**
     * Android 7–10 without one: opens for [KeystoreUserAuthKeys.LEGACY_WINDOW_SECONDS]
     * seconds after the screen lock is passed, in the prompt or by unlocking
     * the phone. Only removing the screen lock retires it; a new fingerprint
     * does not.
     */
    TIME_BOUND
}

/**
 * The key behind [io.github.umutcansu.pinvault.model.UserAuth] vault files:
 * ONE RSA key pair for the device whose private half the hardware uses only
 * after the user has passed the screen lock or a strong biometric. Files
 * sealed on the device and files the server seals for it
 * ([io.github.umutcansu.pinvault.model.VaultFileEncryption.USER_AUTH]) both
 * use it. Wrapping uses the public half and needs no prompt.
 *
 * Errors: [KeyPermanentlyInvalidatedException] means Android retired the key.
 * Any other exception is a Keystore hiccup (busy, locked, a vendor bug):
 * callers keep the key and every copy sealed with it and try again later.
 */
internal interface UserAuthKeys {
    fun isScreenLockSet(): Boolean

    /** Whether the key exists and works. Throws on an error that says neither. */
    fun state(): State

    /**
     * Makes a key when there is none or Android retired it; true when it did.
     * Never replaces a key that may still work. Needs a screen lock.
     */
    fun ensureKey(): Boolean

    /** The public half of the existing key. */
    fun publicKey(): PublicKey

    fun kind(): UserAuthKeyKind

    /**
     * The cipher the prompt must authorise for a per-use key, or null for a
     * time-bound key, which [unwrap] opens inside its window.
     * Throws [KeyPermanentlyInvalidatedException] for a retired or missing key.
     */
    fun cipherForPrompt(): Cipher?

    /** Unwraps [wrapped] after a successful prompt; [authorised] is the prompt's cipher, if any. */
    fun unwrap(authorised: Cipher?, wrapped: ByteArray): ByteArray

    /**
     * The key's Android key attestation chain, DER, leaf first — exactly
     * what `KeyStore.getCertificateChain` returns — or empty when the key was
     * made without attestation (the device cannot attest, or no device id was
     * known). The leaf carries the challenge [attestationChallenge] for this
     * device, so a server can tell a hardware key of this app from a key made
     * in software by someone holding the app's credentials.
     */
    fun attestationChain(): List<ByteArray>

    fun delete()

    enum class State { USABLE, MISSING, INVALIDATED }

    companion object {
        /** One key for the whole device; see the class comment. */
        const val ALIAS = "pinvault_userauth_device"

        /**
         * RSA-OAEP SHA-256 with MGF1-SHA1: the one the Android Keystore
         * accepts on every version, and the one the server wraps with (see
         * VaultFileDecryptor).
         */
        val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        /** First 8 bytes of SHA-256 over the public key: names the key a copy was sealed with. */
        fun keyId(publicKey: PublicKey): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(publicKey.encoded).copyOf(KEY_ID_BYTES)

        const val KEY_ID_BYTES = 8

        /** OID of the Android key attestation extension in the leaf certificate. */
        const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /**
         * The attestation challenge for [deviceId]: SHA-256 of
         * `pinvault-user-auth-key:v1:<deviceId>` (UTF-8). The server computes
         * the same from the device id of the registration and refuses a chain
         * whose leaf carries anything else.
         */
        fun attestationChallenge(deviceId: String): ByteArray =
            MessageDigest.getInstance("SHA-256").digest("pinvault-user-auth-key:v1:$deviceId".toByteArray(Charsets.UTF_8))

        /**
         * True when [e] says Android retired the key. Newer Keystores wrap the
         * [KeyPermanentlyInvalidatedException] (an UnrecoverableKeyException
         * when loading, for one), so the whole cause chain is searched.
         */
        fun isRetired(e: Throwable): Boolean =
            generateSequence(e) { it.cause?.takeIf { cause -> cause !== it } }
                .take(8)
                .any { it is KeyPermanentlyInvalidatedException }
    }
}

/**
 * The Android Keystore user-auth key. [attestationDeviceId] is the device id
 * the library sends (`X-Device-Id`); when it is known the key is generated with
 * an attestation challenge bound to it (see [UserAuthKeys.attestationChallenge]).
 */
internal class KeystoreUserAuthKeys(
    context: Context,
    private val attestationDeviceId: () -> String? = { null }
) : UserAuthKeys {

    private val appContext = context.applicationContext
    private val keyguard = appContext.getSystemService(KeyguardManager::class.java)

    override fun isScreenLockSet(): Boolean = keyguard?.isDeviceSecure == true

    override fun state(): UserAuthKeys.State {
        val keyStore = keyStore()
        if (!keyStore.containsAlias(ALIAS)) return UserAuthKeys.State.MISSING
        return try {
            val key = keyStore.getKey(ALIAS, null) as? PrivateKey ?: return UserAuthKeys.State.MISSING
            Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).init(Cipher.DECRYPT_MODE, key, UserAuthKeys.OAEP)
            UserAuthKeys.State.USABLE
        } catch (_: UserNotAuthenticatedException) {
            // Time-bound key outside its window: alive, just locked.
            UserAuthKeys.State.USABLE
        } catch (e: Exception) {
            // Anything but a retired key propagates: not a reason to replace it.
            if (UserAuthKeys.isRetired(e)) UserAuthKeys.State.INVALIDATED else throw e
        }
    }

    // Synchronized: a local seal and a registration may both find no key;
    // only one of them may make it, or the other deletes the new key.
    @Synchronized
    override fun ensureKey(): Boolean {
        if (state() == UserAuthKeys.State.USABLE) return false
        delete()
        generate()
        Timber.i("User-auth key created (%s)", kind())
        return true
    }

    override fun publicKey(): PublicKey {
        // Encrypt in software with a plain copy of the public key: the
        // Keystore's own public key object would route through the Keystore
        // provider and its purpose checks for no gain.
        val certificate = keyStore().getCertificate(ALIAS)
            ?: throw KeyPermanentlyInvalidatedException("no user-auth key")
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(certificate.publicKey.encoded))
    }

    override fun kind(): UserAuthKeyKind {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey
            ?: throw KeyPermanentlyInvalidatedException("no user-auth key")
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        @Suppress("DEPRECATION")
        val window = info.userAuthenticationValidityDurationSeconds
        return when {
            window > 0 -> UserAuthKeyKind.TIME_BOUND
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                info.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0 -> UserAuthKeyKind.PER_USE
            else -> UserAuthKeyKind.PER_USE_BIOMETRIC
        }
    }

    override fun cipherForPrompt(): Cipher? {
        if (kind() == UserAuthKeyKind.TIME_BOUND) return null
        return decryptCipher()
    }

    override fun unwrap(authorised: Cipher?, wrapped: ByteArray): ByteArray =
        (authorised ?: decryptCipher()).doFinal(wrapped)

    override fun attestationChain(): List<ByteArray> {
        val chain = keyStore().getCertificateChain(ALIAS) ?: return emptyList()
        val leaf = chain.firstOrNull() as? X509Certificate ?: return emptyList()
        // Without attestation the Keystore still returns a one-certificate
        // chain (a self-signed placeholder): not worth sending.
        if (leaf.getExtensionValue(UserAuthKeys.ATTESTATION_EXTENSION_OID) == null) return emptyList()
        return chain.map { it.encoded }
    }

    override fun delete() {
        try {
            keyStore().takeIf { it.containsAlias(ALIAS) }?.deleteEntry(ALIAS)
        } catch (e: Exception) {
            Timber.w(e, "Could not delete the user-auth key")
        }
    }

    private fun decryptCipher(): Cipher {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey
            ?: throw KeyPermanentlyInvalidatedException("no user-auth key")
        return Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, UserAuthKeys.OAEP)
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /**
     * Before Android 11 the screen lock can only open a key for a time window.
     * A per-use key is possible there, but fingerprint-only: made when the
     * phone has a strong fingerprint now, so a phone unlock does not open it.
     */
    private fun strongFingerprintEnrolled(): Boolean =
        BiometricManager.from(appContext).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private fun generate() {
        val perUseBiometric = Build.VERSION.SDK_INT < Build.VERSION_CODES.R && strongFingerprintEnrolled()
        try {
            generate(perUseBiometric)
        } catch (e: Exception) {
            if (!perUseBiometric) throw e
            // A fingerprint the Keystore does not count (or none after all):
            // fall back to the screen-lock key rather than to nothing.
            Timber.w(e, "Per-use fingerprint key refused — falling back to a time-bound screen-lock key")
            generate(perUseBiometric = false)
        }
    }

    /**
     * Tries, in order: StrongBox with attestation (Android 9+), the TEE with
     * attestation, the TEE without. Attestation is what lets a server that
     * enforces it (`USER_AUTH_ATTESTATION=enforce`) accept the key; a device
     * whose Keystore cannot attest still gets a key, registered without a
     * chain. StrongBox may be advertised but full, or reject the parameters.
     */
    private fun generate(perUseBiometric: Boolean) {
        val challenge = attestationDeviceId()?.takeIf { it.isNotBlank() }?.let(UserAuthKeys::attestationChallenge)
        val attempts = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) add(true to challenge)
            if (challenge != null) add(false to challenge)
            add(false to null)
        }.distinct()
        var last: Exception? = null
        for ((strongBox, attest) in attempts) {
            try {
                generate(perUseBiometric, strongBox, attest)
                // requireHardwareBackedKeys(): a software key is deleted and refused, not tried another way.
                KeystoreOptions.checkLevel("User-auth key", generatedLevel(), cleanUp = ::delete)
                return
            } catch (e: io.github.umutcansu.pinvault.model.HardwareBackedKeyRequiredException) {
                throw e
            } catch (e: Exception) {
                last = e
                Timber.w(e, "User-auth key generation failed (strongBox=%s, attestation=%s), trying the next way",
                    strongBox, attest != null)
                delete()
            }
        }
        throw last ?: IllegalStateException("user-auth key generation failed")
    }

    /** Where the key just generated under [ALIAS] lives, as the Keystore reports it. */
    private fun generatedLevel(): io.github.umutcansu.pinvault.model.KeySecurityLevel {
        val key = keyStore().getKey(ALIAS, null) as? PrivateKey
            ?: return io.github.umutcansu.pinvault.model.KeySecurityLevel.UNKNOWN
        return KeyInspector.securityLevel(key)
    }

    private fun generate(perUseBiometric: Boolean, strongBox: Boolean, attestationChallenge: ByteArray?) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .setUserAuthenticationRequired(true)
            .apply {
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                        // Every unlock asks, and the screen lock counts as well
                        // as a strong biometric, so phones without one still work.
                        // With both allowed the Keystore binds the key to the
                        // screen lock's secure id: a new biometric enrollment
                        // does not invalidate it, removing the screen lock does.
                        setUserAuthenticationParameters(
                            0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    perUseBiometric -> {
                        // Every use asks, fingerprint only (a CryptoObject). A
                        // biometric-only key: a new fingerprint retires it.
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                        setInvalidatedByBiometricEnrollment(true)
                    }
                    else ->
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(LEGACY_WINDOW_SECONDS)
                }
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                // The leaf certificate then carries this challenge and the
                // key's properties, signed by the device's attestation key.
                attestationChallenge?.let { setAttestationChallenge(it) }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = UserAuthKeys.ALIAS
        /** Long enough to unwrap right after the prompt, short enough to matter. */
        const val LEGACY_WINDOW_SECONDS = 10
    }
}
