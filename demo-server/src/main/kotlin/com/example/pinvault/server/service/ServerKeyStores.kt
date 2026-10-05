package com.example.pinvault.server.service

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore

/**
 * The server's own keystores — its TLS key and backup key, each host's
 * keystore and backup key, the client truststore, the client and server CAs,
 * the recovery listener's key — are PKCS12 files.
 *
 * They used to be JKS (S-5 of the security report): JKS protects private
 * keys with a proprietary SHA-1 based cipher that the JDK itself abandoned
 * (its default store type has been PKCS12 since JDK 9), and the client CA
 * key that signs every device certificate sat in such a file. PKCS12 keys
 * are wrapped with PBES2/AES by the JDK.
 *
 * The `.jks` file names are kept: host keystore paths are stored in the
 * database (`hosts.keystore_path`), named in compose files, backups and
 * docs. The extension is historical; the content is PKCS12. A legacy JKS
 * file is still opened — converted in memory, so anything written back is
 * PKCS12 — and [KeystoreRekey] rewrites every legacy file at startup.
 */
object ServerKeyStores {

    /** The type every server keystore is written as. */
    const val TYPE = "PKCS12"

    private const val LEGACY_TYPE = "JKS"

    /** An empty PKCS12 keystore to fill and store. */
    fun empty(): KeyStore = KeyStore.getInstance(TYPE).apply { load(null, null) }

    /** Whether [bytes] are a JKS file (magic `0xFEEDFEED`); anything else is read as PKCS12. */
    fun isLegacyJks(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            bytes[0] == 0xFE.toByte() && bytes[1] == 0xED.toByte() && bytes[2] == 0xFE.toByte() && bytes[3] == 0xED.toByte()

    /**
     * Opens a keystore from [bytes] with [password]. A legacy JKS is loaded as
     * such and copied into a PKCS12 store (key entries under the same
     * password), so the caller always holds a PKCS12 store and a later
     * `store()` never writes JKS again. Throws like `KeyStore.load` when the
     * password is wrong or the bytes are neither format.
     */
    fun load(bytes: ByteArray, password: CharArray): KeyStore {
        if (!isLegacyJks(bytes)) {
            return KeyStore.getInstance(TYPE).apply { bytes.inputStream().use { load(it, password) } }
        }
        val legacy = KeyStore.getInstance(LEGACY_TYPE).apply { bytes.inputStream().use { load(it, password) } }
        return copy(legacy, password, password)
    }

    /** [load] from [file]. The file is not rewritten here; see [convertLegacy]. */
    fun load(file: File, password: CharArray): KeyStore = load(file.readBytes(), password)

    /**
     * Rewrites [file] as PKCS12 when it is a legacy JKS that opens with
     * [password]. Returns true when it was converted, false when it already
     * is PKCS12 (or does not exist). Throws when the password is wrong.
     */
    fun convertLegacy(file: File, password: CharArray): Boolean {
        if (!file.isFile) return false
        val bytes = file.readBytes()
        if (!isLegacyJks(bytes)) return false
        writeAtomically(file, load(bytes, password), password)
        return true
    }

    /**
     * Every entry of [source] in a new PKCS12 store: key entries re-protected
     * with [targetPassword] (read with [sourcePassword]), certificate entries
     * as they are.
     */
    fun copy(source: KeyStore, sourcePassword: CharArray, targetPassword: CharArray): KeyStore {
        val target = empty()
        for (alias in source.aliases().toList()) {
            if (source.isKeyEntry(alias)) {
                target.setKeyEntry(alias, source.getKey(alias, sourcePassword), targetPassword, source.getCertificateChain(alias))
            } else {
                target.setCertificateEntry(alias, source.getCertificate(alias))
            }
        }
        return target
    }

    /** [keyStore] serialised under [password]. */
    fun toBytes(keyStore: KeyStore, password: CharArray): ByteArray =
        ByteArrayOutputStream().also { keyStore.store(it, password) }.toByteArray()

    /** Writes next to [file], then swaps it in: a crash never leaves a half-written keystore. */
    fun writeAtomically(file: File, keyStore: KeyStore, password: CharArray) {
        val temp = File(file.absoluteFile.parentFile, ".${file.name}.tmp")
        temp.outputStream().use { keyStore.store(it, password) }
        Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }
}
