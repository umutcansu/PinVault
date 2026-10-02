package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.annotation.VisibleForTesting
import timber.log.Timber

/**
 * Encrypted storage for the device's mTLS client credentials, one entry per
 * label (`default` for the Config API, `host_<hostname>` for host certs).
 *
 * Two forms live side by side under different key prefixes:
 * - `client_p12_<label>` — a PKCS12 keystore the server generated (key and
 *   cert together, Base64). The pre-CSR flow, still what `clientKeystore(...)`
 *   bundles and what older servers hand out.
 * - `client_chain_<label>` — a PEM certificate chain issued over the device's
 *   own identity key, which lives in the Android Keystore
 *   ([io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider]) and is
 *   never stored here.
 *
 * A label has one form or the other; [mode] says which. Everything is kept
 * in [SecurePreferences] (keys in the Android Keystore),
 * `pinvault_secure_client_cert.xml`.
 */
internal class ClientCertSecureStore private constructor(private val prefs: SharedPreferences) {

    constructor(context: Context) : this(
        SecurePreferences.open(context, FILE_NAME, namespace = PREFS_NAME, legacyName = PREFS_NAME)
    )

    enum class Mode { NONE, P12, CHAIN }

    // ── PKCS12 form ──────────────────────────────────────────────────────

    fun save(p12Bytes: ByteArray) = save(DEFAULT_LABEL, p12Bytes)

    fun save(label: String, p12Bytes: ByteArray) {
        prefs.edit()
            .putString(p12Key(label), Base64.encodeToString(p12Bytes, Base64.NO_WRAP))
            .remove(chainKey(label))
            .remove(pendingKey(label))
            .apply()
        Timber.d("Client P12 saved [%s]", label)
    }

    fun load(): ByteArray? = load(DEFAULT_LABEL)

    fun load(label: String): ByteArray? {
        val encoded = prefs.getString(p12Key(label), null) ?: return null
        return try {
            Base64.decode(encoded, Base64.NO_WRAP).also {
                Timber.d("Client P12 loaded [%s] (%d bytes)", label, it.size)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to decode stored P12 [%s]", label)
            null
        }
    }

    fun hasP12(label: String): Boolean = prefs.contains(p12Key(label))

    // ── Certificate-chain form (CSR flow) ────────────────────────────────

    /**
     * Stores the PEM chain (leaf first) for [label], replacing any P12.
     * Written with `commit()`: a renewed chain must be on disk before the
     * KeyManager that presents it is swapped in — a crash in between would
     * otherwise leave the device presenting a certificate it no longer holds.
     */
    fun saveChain(label: String, pemChain: List<String>) {
        require(pemChain.isNotEmpty()) { "Certificate chain must not be empty" }
        prefs.edit()
            .putString(chainKey(label), pemChain.joinToString(CHAIN_SEPARATOR))
            .remove(p12Key(label))
            .remove(pendingKey(label))
            .commit()
        Timber.d("Client certificate chain saved [%s] (%d certs)", label, pemChain.size)
    }

    fun loadChain(label: String): List<String>? {
        val joined = prefs.getString(chainKey(label), null) ?: return null
        return joined.split(CHAIN_SEPARATOR).filter { it.isNotBlank() }.ifEmpty { null }
    }

    fun hasChain(label: String): Boolean = prefs.contains(chainKey(label))

    // ── Enrollment waiting for approval ───────────────────────────────────

    /** An enrollment request an administrator has not decided on yet; see [savePendingRequest]. */
    data class PendingRequest(val requestId: String, val clientId: String?)

    /**
     * Remembers the request an enrollment code was answered with (HTTP 202)
     * while an administrator decides. The device asks again by this id with a
     * CSR from the same key; storing a credential for [label] forgets it.
     */
    fun savePendingRequest(label: String, requestId: String, clientId: String?) {
        prefs.edit()
            .putString(pendingKey(label), requestId + PENDING_SEPARATOR + clientId.orEmpty())
            .commit()
        Timber.d("Enrollment waits for approval [%s] — request %s", label, requestId)
    }

    fun loadPendingRequest(label: String): PendingRequest? {
        val stored = prefs.getString(pendingKey(label), null) ?: return null
        val requestId = stored.substringBefore(PENDING_SEPARATOR).ifBlank { return null }
        return PendingRequest(requestId, stored.substringAfter(PENDING_SEPARATOR, "").ifBlank { null })
    }

    fun clearPendingRequest(label: String) {
        prefs.edit().remove(pendingKey(label)).apply()
    }

    // ── Either form ──────────────────────────────────────────────────────

    fun mode(label: String): Mode = when {
        hasChain(label) -> Mode.CHAIN
        hasP12(label) -> Mode.P12
        else -> Mode.NONE
    }

    fun exists(): Boolean = exists(DEFAULT_LABEL)

    fun exists(label: String): Boolean = hasP12(label) || hasChain(label)

    fun clear() = clear(DEFAULT_LABEL)

    fun clear(label: String) {
        prefs.edit().remove(p12Key(label)).remove(chainKey(label)).remove(pendingKey(label)).apply()
        Timber.d("Client credentials cleared [%s]", label)
    }

    fun clearAll() {
        prefs.edit().clear().apply()
        Timber.d("All client credentials cleared")
    }

    private fun p12Key(label: String): String = "$P12_PREFIX$label"
    private fun chainKey(label: String): String = "$CHAIN_PREFIX$label"
    private fun pendingKey(label: String): String = "$PENDING_PREFIX$label"

    companion object {
        /** Keep in sync with res/xml/pinvault_backup_rules.xml and pinvault_data_extraction_rules.xml. */
        internal const val FILE_NAME = "pinvault_secure_client_cert"
        /** Namespace, and the file PinVault 2.0.x used (migrated on first open). */
        private const val PREFS_NAME = "pinvault_client_cert"
        private const val P12_PREFIX = "client_p12_"
        private const val CHAIN_PREFIX = "client_chain_"
        private const val PENDING_PREFIX = "client_pending_"
        private const val PENDING_SEPARATOR = "\n"
        /** PEM never contains this, so joining the chain with it is unambiguous. */
        private const val CHAIN_SEPARATOR = "\n\n"
        internal const val DEFAULT_LABEL = "default"

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = ClientCertSecureStore(prefs)
    }
}
