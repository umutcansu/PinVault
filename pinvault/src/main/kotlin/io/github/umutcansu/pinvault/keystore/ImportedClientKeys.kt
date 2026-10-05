package io.github.umutcansu.pinvault.keystore

import android.os.Build
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import timber.log.Timber
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * Private keys that reached the device inside a PKCS12 bundle — a host's
 * client certificate, a server-made enrollment (`allowServerGeneratedKey()`),
 * a keystore bundled with the app — kept as NON-EXPORTABLE Android Keystore
 * keys instead of as P12 bytes in app storage.
 *
 * A P12 in storage is the key itself: whoever reads the app's data and can
 * use the app's storage key walks away with it, and its password is a
 * constant compiled into the app. An imported key can still be USED by code
 * running as the app, but it cannot be copied off the device.
 *
 * The import cannot undo where the key has already been (the server, the
 * wire, the APK): it only stops the device from being one more place to
 * steal it from.
 *
 * Robolectric has no AndroidKeyStore; unit tests use [software].
 */
internal interface ImportedClientKeys {

    /**
     * Stores [key] under [alias], replacing what was there. Throws when the
     * platform refuses the key (the caller then keeps the P12 form for it).
     */
    fun import(alias: String, key: PrivateKey, chain: Array<X509Certificate>)

    /**
     * The key under [alias] — opaque, usable only through signatures and TLS
     * key managers — or null when there is none. Throws when the Keystore
     * cannot say right now: "unreadable" must not read as "gone", or a
     * Keystore hiccup would make the caller drop a good certificate.
     */
    fun privateKey(alias: String): PrivateKey?

    fun delete(alias: String)

    companion object {
        private const val ALIAS_PREFIX = "pinvault_client_imported_"

        /** Keystore alias of the key imported for the credential stored under [label]. */
        fun aliasFor(label: String): String = ALIAS_PREFIX + label

        fun androidKeystore(): ImportedClientKeys = AndroidKeystoreImportedClientKeys

        /** Software stand-in for tests: keys are held per alias for the process lifetime. */
        fun software(): ImportedClientKeys = SoftwareImportedClientKeys
    }
}

internal object AndroidKeystoreImportedClientKeys : ImportedClientKeys {

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun import(alias: String, key: PrivateKey, chain: Array<X509Certificate>) {
        require(chain.isNotEmpty()) { "certificate chain must not be empty" }
        val keyStore = keyStore()
        KeystoreOptions.generating("Imported client key", cleanUp = { runCatching { delete(alias) } }) { unlockedDeviceRequired ->
            keyStore.setEntry(alias, KeyStore.PrivateKeyEntry(key, chain), protection(key, unlockedDeviceRequired))
        }
        // An entry that cannot be read back is of no use: say so now, while
        // the caller still holds the P12.
        check(keyStore.getKey(alias, null) is PrivateKey) { "imported key cannot be read back" }
    }

    /**
     * What a TLS client key needs, and nothing else: signing only.
     *
     * Conscrypt hashes the handshake transcript itself and asks for a raw
     * signature, so `DIGEST_NONE` must be allowed or the key is refused at
     * handshake time and no certificate is presented. For RSA it applies the
     * padding itself as well (PKCS#1 v1.5 in TLS 1.2, PSS in TLS 1.3) and
     * hands the Keystore a block to sign with "no padding", which the
     * Keystore authorises through the padding list a key carries — hence
     * `ENCRYPTION_PADDING_NONE` on a key that never encrypts.
     */
    private fun protection(key: PrivateKey, unlockedDeviceRequired: Boolean): KeyProtection {
        val builder = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            .setDigests(
                KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512
            )
        if (key.algorithm.equals("RSA", ignoreCase = true)) {
            builder
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setRandomizedEncryptionRequired(false)
        }
        if (unlockedDeviceRequired && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setUnlockedDeviceRequired(true)
        return builder.build()
    }

    override fun privateKey(alias: String): PrivateKey? {
        val keyStore = keyStore()
        if (!keyStore.containsAlias(alias)) return null
        return keyStore.getKey(alias, null) as? PrivateKey
    }

    override fun delete(alias: String) {
        try {
            keyStore().takeIf { it.containsAlias(alias) }?.deleteEntry(alias)
        } catch (e: Exception) {
            Timber.w(e, "Could not delete an imported client key")
        }
    }
}

internal object SoftwareImportedClientKeys : ImportedClientKeys {
    private val keys = ConcurrentHashMap<String, PrivateKey>()

    /** Tests: aliases whose import fails, like a platform that refuses the key. */
    val refused: MutableSet<String> = ConcurrentHashMap.newKeySet()

    override fun import(alias: String, key: PrivateKey, chain: Array<X509Certificate>) {
        require(chain.isNotEmpty()) { "certificate chain must not be empty" }
        if (alias in refused) throw java.security.KeyStoreException("import refused (test)")
        keys[alias] = key
    }

    /** Tests: while true every read fails, like a Keystore that is busy or locked. */
    @Volatile
    var unreadable: Boolean = false

    override fun privateKey(alias: String): PrivateKey? {
        if (unreadable) throw java.security.ProviderException("Keystore operation failed (test)")
        return keys[alias]
    }

    override fun delete(alias: String) {
        keys.remove(alias)
    }

    fun reset() {
        keys.clear()
        refused.clear()
        unreadable = false
    }
}
