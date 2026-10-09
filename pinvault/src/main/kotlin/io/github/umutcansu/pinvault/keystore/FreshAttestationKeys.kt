package io.github.umutcansu.pinvault.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import timber.log.Timber
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

/**
 * A key made for one attestation round only (`ATTESTATION.md` §3.1). A key's
 * attestation chain is fixed when the key is generated, so the identity
 * key's chain says what the device was at registration; the chain of a key
 * generated now, with this round's challenge, says what it is now — the
 * bootloader, the boot state, the patch level — in the secure hardware's
 * word. The key is deleted as soon as its chain has been read.
 */
internal interface FreshAttestationKeys {
    /**
     * The attestation chain (DER, leaf first) of a new key generated with
     * [challenge], in StrongBox when [strongBox] and the device has one, else
     * in the TEE; empty when the device cannot attest. The key is gone when
     * this returns.
     */
    fun chain(challenge: ByteArray, strongBox: Boolean): List<ByteArray>

    companion object {
        /** SHA-256 of UTF-8 `pinvault-fresh-attest:v1:<nonce>:<deviceId>:<hex SHA-256 of the identity key's SPKI>`. */
        fun challenge(nonce: String, deviceId: String, identitySpkiDer: ByteArray): ByteArray {
            val spki = MessageDigest.getInstance("SHA-256").digest(identitySpkiDer).joinToString("") { "%02x".format(it) }
            return MessageDigest.getInstance("SHA-256").digest("pinvault-fresh-attest:v1:$nonce:$deviceId:$spki".toByteArray(Charsets.UTF_8))
        }

        val androidKeystore: FreshAttestationKeys = AndroidKeystoreFreshAttestationKeys()
    }
}

internal class AndroidKeystoreFreshAttestationKeys(private val alias: String = "pinvault_fresh_attestation") : FreshAttestationKeys {

    private val keystore: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    @Synchronized
    override fun chain(challenge: ByteArray, strongBox: Boolean): List<ByteArray> {
        val attempts = listOfNotNull(true.takeIf { strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P }, false)
        try {
            for (inStrongBox in attempts) {
                try {
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                        initialize(spec(inStrongBox, challenge))
                        generateKeyPair()
                    }
                    val chain = keystore.getCertificateChain(alias) ?: return emptyList()
                    val leaf = chain.firstOrNull() as? java.security.cert.X509Certificate ?: return emptyList()
                    if (leaf.getExtensionValue(ClientIdentityKeyProvider.ATTESTATION_EXTENSION_OID) == null) return emptyList()
                    Timber.d("Fresh attestation key made (strongBox=%s), chain of %d", inStrongBox, chain.size)
                    return chain.map { it.encoded }
                } catch (e: Exception) {
                    Timber.w(e, "Fresh attestation key generation failed (strongBox=%s)", inStrongBox)
                    runCatching { keystore.deleteEntry(alias) }
                }
            }
            return emptyList()
        } finally {
            runCatching { keystore.deleteEntry(alias) }
        }
    }

    private fun spec(strongBox: Boolean, challenge: ByteArray): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true) }
            .build()
}
