package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.VaultFileStatus
import java.util.concurrent.ConcurrentHashMap

/**
 * The signatures a vault file was accepted with: [scheme] 1 signs
 * `pinvault-vault-file:v1:<key>:<version>:<sha256>`, 2 the v2 string that
 * also names the Config API. Kept so the stored copy can be checked again
 * every time it is read, not only when it was downloaded.
 */
internal data class StoredSignatures(val version: Int, val scheme: Int, val entries: List<SignatureEntry>)

/**
 * What the library remembers about each stored vault file besides its
 * content: the signatures it came with, when the server last confirmed it,
 * and why it was last refused.
 *
 * Every read may throw
 * [io.github.umutcansu.pinvault.model.StoreUnreadableException]: "the Keystore
 * cannot open this right now" must not read as "never confirmed" (a stale
 * file, possibly wiped) or "no signature" (an unverified file).
 */
internal interface VaultFileMeta {
    fun signatures(key: String): StoredSignatures?
    fun saveSignatures(key: String, signatures: StoredSignatures?)

    /** When the server last confirmed the stored copy (trusted-clock ms); 0 = never on record. */
    fun confirmedAt(key: String): Long
    fun setConfirmedAt(key: String, time: Long)

    /** Why the copy was last refused and removed, until a fetch stores a new one. */
    fun problem(key: String): VaultFileStatus?
    fun setProblem(key: String, problem: VaultFileStatus?)

    /** Forgets everything about [key] except a recorded problem. */
    fun clear(key: String)

    /** This process only (tests). */
    class InMemory : VaultFileMeta {
        private val signatures = ConcurrentHashMap<String, StoredSignatures>()
        private val confirmed = ConcurrentHashMap<String, Long>()
        private val problems = ConcurrentHashMap<String, VaultFileStatus>()

        override fun signatures(key: String) = signatures[key]
        override fun saveSignatures(key: String, signatures: StoredSignatures?) {
            if (signatures == null) this.signatures.remove(key) else this.signatures[key] = signatures
        }
        override fun confirmedAt(key: String) = confirmed[key] ?: 0L
        override fun setConfirmedAt(key: String, time: Long) { confirmed[key] = time }
        override fun problem(key: String) = problems[key]
        override fun setProblem(key: String, problem: VaultFileStatus?) {
            if (problem == null) problems.remove(key) else problems[key] = problem
        }
        override fun clear(key: String) {
            signatures.remove(key)
            confirmed.remove(key)
        }
    }

    /** In a strict [SecurePreferences] namespace of the vault-file store's encrypted file. */
    class Persistent(private val prefs: SharedPreferences) : VaultFileMeta {

        override fun signatures(key: String): StoredSignatures? {
            val lines = prefs.getString(SIGNATURES + key, null)?.split('\n') ?: return null
            if (lines.size < 2) return null
            val scheme = lines[0].toIntOrNull() ?: return null
            val version = lines[1].toIntOrNull() ?: return null
            val entries = lines.drop(2).filter { it.isNotBlank() }.map { line ->
                val keyId = line.substringBefore(':', "")
                SignatureEntry(keyId = keyId.ifEmpty { null }, signature = line.substringAfter(':'))
            }
            return StoredSignatures(version, scheme, entries)
        }

        // `keyId:signature` per line, as in the X-Vault-Signatures header:
        // Base64 has no `:` and no newline.
        override fun saveSignatures(key: String, signatures: StoredSignatures?) {
            val editor = prefs.edit()
            if (signatures == null) editor.remove(SIGNATURES + key)
            else editor.putString(
                SIGNATURES + key,
                (listOf(signatures.scheme.toString(), signatures.version.toString()) +
                    signatures.entries.map { "${it.keyId.orEmpty()}:${it.signature}" }).joinToString("\n")
            )
            editor.apply()
        }

        override fun confirmedAt(key: String): Long = prefs.getLong(CONFIRMED + key, 0L)

        override fun setConfirmedAt(key: String, time: Long) {
            prefs.edit().putLong(CONFIRMED + key, time).apply()
        }

        override fun problem(key: String): VaultFileStatus? =
            prefs.getString(PROBLEM + key, null)?.let { name -> VaultFileStatus.entries.find { it.name == name } }

        override fun setProblem(key: String, problem: VaultFileStatus?) {
            val editor = prefs.edit()
            if (problem == null) editor.remove(PROBLEM + key) else editor.putString(PROBLEM + key, problem.name)
            editor.apply()
        }

        override fun clear(key: String) {
            prefs.edit().remove(SIGNATURES + key).remove(CONFIRMED + key).apply()
        }
    }

    companion object {
        private const val NAMESPACE = "pinvault_vault_file_meta"
        private const val SIGNATURES = "sig_"
        private const val CONFIRMED = "seen_"
        private const val PROBLEM = "problem_"

        /**
         * Inside `pinvault_secure_vault_files.xml`, which the backup rules
         * already exclude. Strict: a Keystore failure is reported, never read
         * as "nothing on record".
         */
        fun persistent(context: Context): VaultFileMeta =
            Persistent(SecurePreferences.openStrict(context, VaultFileStore.FILE_NAME, namespace = NAMESPACE))
    }
}
