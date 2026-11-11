package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ImportedClientKeys
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import timber.log.Timber
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Client credentials that arrived as a PKCS12 bundle, kept the safe way: the
 * private key as a non-exportable Android Keystore key ([ImportedClientKeys]),
 * the certificate chain in [ClientCertSecureStore], and no P12 bytes.
 *
 * Used for every P12 the library accepts: a host's client certificate, an
 * enrollment the server made the key for (`allowServerGeneratedKey()`), the
 * keystore bundled with the app, and P12s an earlier version stored — those
 * are moved over the first time they are loaded.
 */
internal class ImportedIdentities(
    private val certStore: ClientCertSecureStore,
    private val keys: ImportedClientKeys
) {

    /** A key the TLS stack can sign with, and the chain to present with it. */
    class Identity(val privateKey: PrivateKey, val chain: Array<X509Certificate>)

    /**
     * Imports the key of [p12] for [label] and stores its chain in place of
     * whatever [label] held (a stored P12 included). Returns null when the
     * platform refuses the key: nothing was changed then, and the caller
     * keeps using the P12 form for this credential.
     *
     * @throws Exception when [p12] itself is unusable (wrong password, no key entry)
     */
    fun import(label: String, p12: ByteArray, password: String): Identity? {
        val (key, chain) = readP12(p12, password)
        val alias = ImportedClientKeys.aliasFor(label)
        val imported = try {
            keys.import(alias, key, chain)
            keys.privateKey(alias) ?: throw IllegalStateException("imported key cannot be read back")
        } catch (e: Exception) {
            Timber.w(e, "The Android Keystore refused to import a client key (%s) — it stays in its PKCS12 form", key.algorithm)
            runCatching { keys.delete(alias) }
            return null
        }
        certStore.saveImported(label, chain.map(Pkcs10Csr::toPem))
        Timber.i("Client key imported into the Android Keystore (%s, non-exportable); PKCS12 bytes dropped", key.algorithm)
        return Identity(imported, chain)
    }

    /** What [read] found under a label. */
    sealed class Stored {
        /** An imported credential, ready to present. */
        class Present(val identity: Identity) : Stored()
        /** No imported credential (never stored, or dropped just now because it can never be presented). */
        object Absent : Stored()
        /**
         * One is stored, but the Keystore cannot read its chain or its key
         * right now. Everything is kept. Not [Absent]: the caller must not go
         * on to another identity as if this one did not exist.
         */
        object Unreadable : Stored()
    }

    /**
     * The imported credential stored under [label]; null when there is none
     * or the Keystore cannot be read right now (nothing is dropped then) —
     * [read] tells the two apart.
     */
    fun load(label: String): Identity? = (read(label) as? Stored.Present)?.identity

    /**
     * The imported credential stored under [label]. A chain whose Keystore
     * key is gone (a restored backup, a wiped Keystore) cannot be presented:
     * it is dropped, and the answer is [Stored.Absent].
     */
    fun read(label: String): Stored {
        val pems = certStore.loadImported(label)
            // An entry that is there but did not read is a Keystore failure
            // of the non-strict store, not a missing credential.
            ?: return if (certStore.hasImported(label)) Stored.Unreadable else Stored.Absent
        val key = try {
            keys.privateKey(ImportedClientKeys.aliasFor(label))
        } catch (e: Exception) {
            // The Keystore failed; the key may be fine. Keep the chain and
            // present nothing for now.
            Timber.w(e, "An imported client key cannot be read right now — certificate kept, not presented")
            return Stored.Unreadable
        }
        if (key == null) {
            Timber.w("An imported client certificate has no Keystore key — dropping it")
            certStore.clear(label)
            return Stored.Absent
        }
        return try {
            Stored.Present(Identity(key, Pkcs10Csr.parsePemChain(pems).toTypedArray()))
        } catch (e: Exception) {
            Timber.e(e, "An imported client certificate chain is unreadable — dropping it")
            forget(label)
            Stored.Absent
        }
    }

    /**
     * The credential stored under [label] in the imported form, moving a P12
     * an earlier version stored there into the Keystore first. Null when
     * [label] holds no imported credential and its P12 (if any) could not be
     * moved; the caller then loads the P12 as before. Also null while an
     * imported credential cannot be read — [readOrMigrate] says which.
     */
    fun loadOrMigrate(label: String, password: String): Identity? =
        (readOrMigrate(label, password) as? Stored.Present)?.identity

    /** [loadOrMigrate], telling "nothing imported" from "cannot be read right now". */
    fun readOrMigrate(label: String, password: String): Stored {
        val stored = read(label)
        if (stored !is Stored.Absent) return stored
        val p12 = certStore.load(label) ?: return Stored.Absent
        return try {
            import(label, p12, password)?.let { Stored.Present(it) } ?: Stored.Absent
        } catch (e: Exception) {
            Timber.w(e, "A stored PKCS12 could not be read for import — left as it is")
            Stored.Absent
        }
    }

    /** Deletes the credential under [label] in every form, and its imported key. */
    fun forget(label: String) {
        certStore.clear(label)
        keys.delete(ImportedClientKeys.aliasFor(label))
    }

    companion object {
        /** The first key entry of [p12] and its certificate chain. */
        fun readP12(p12: ByteArray, password: String): Pair<PrivateKey, Array<X509Certificate>> {
            val chars = password.toCharArray()
            val store = KeyStore.getInstance("PKCS12").apply { load(p12.inputStream(), chars) }
            val alias = store.aliases().toList().firstOrNull { store.isKeyEntry(it) }
                ?: throw SecurityException("The PKCS12 holds no private key")
            val key = store.getKey(alias, chars) as? PrivateKey
                ?: throw SecurityException("The PKCS12 entry is not a private key")
            val chain = store.getCertificateChain(alias)?.filterIsInstance<X509Certificate>()?.toTypedArray()
            if (chain.isNullOrEmpty()) throw SecurityException("The PKCS12 holds no certificate for its key")
            return key to chain
        }
    }
}
