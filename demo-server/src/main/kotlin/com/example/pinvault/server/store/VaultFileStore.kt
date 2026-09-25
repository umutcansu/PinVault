package com.example.pinvault.server.store

import com.example.pinvault.server.service.VaultAtRestCipher
import com.example.pinvault.server.service.VaultKeyMismatchException

/**
 * Persistent store for vault file content. Every entry is scoped to a Config
 * API — two Config APIs may hold files with the same key without collision.
 *
 * Added in V2: access_policy and encryption are persisted per-file. Default
 * policy is "token" (least-privilege); admin must explicitly issue a per-device
 * token before the device can fetch the file.
 */
class VaultFileStore(
    private val db: DatabaseManager,
    private val cipher: VaultAtRestCipher = VaultAtRestCipher.fromEnv()
) {

    fun get(configApiId: String, key: String): VaultEntry? {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT config_api_id, key, version, content, access_policy, encryption, updated_at
                FROM vault_files
                WHERE config_api_id = ? AND key = ?
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.toEntry() else null
            }
        }
    }

    /**
     * Upsert file content. Version is auto-incremented on every call (no
     * content-dedup; identical uploads still bump the version — see
     * VaultRoutesTest.`v1 to v2 to v3 bump`).
     *
     * If the row exists, [accessPolicy] / [encryption] defaults keep the
     * existing values; pass non-null to override.
     */
    fun put(
        configApiId: String,
        key: String,
        content: ByteArray,
        accessPolicy: String? = null,
        encryption: String? = null
    ) {
        db.connection().use { conn ->
            // Metadata only: a file that no longer decrypts can still be replaced.
            val existing = meta(configApiId, key)
            val newVersion = (existing?.version ?: 0) + 1
            val finalPolicy = accessPolicy ?: existing?.accessPolicy ?: "token"
            val finalEncryption = encryption ?: existing?.encryption ?: "plain"
            // at_rest and end_to_end: store the content AES-256-GCM encrypted;
            // reads decrypt it transparently (see toEntry). The wire format is
            // unchanged: plain for at_rest, per-device envelope for end_to_end.
            val storedContent = storedForm(finalEncryption, content)

            conn.prepareStatement("""
                INSERT OR REPLACE INTO vault_files
                    (config_api_id, key, content, version, access_policy, encryption, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                stmt.setBytes(3, storedContent)
                stmt.setInt(4, newVersion)
                stmt.setString(5, finalPolicy)
                stmt.setString(6, finalEncryption)
                stmt.executeUpdate()
            }
        }
    }

    /**
     * Update policy/encryption for an existing row (version unchanged). When the
     * encryption mode flips to/from `at_rest`, the stored content is rewritten in
     * the target format — get() returns plaintext, so we just re-encrypt it (or
     * keep it plain). Without this, an at_rest read would fail or a plain file
     * would be served as ciphertext after a mode switch.
     */
    fun updatePolicy(configApiId: String, key: String, accessPolicy: String, encryption: String): Boolean {
        val current = get(configApiId, key) ?: return false   // content already decrypted
        val storedContent = storedForm(encryption, current.content)
        db.connection().use { conn ->
            conn.prepareStatement("""
                UPDATE vault_files
                SET access_policy = ?, encryption = ?, content = ?, updated_at = datetime('now')
                WHERE config_api_id = ? AND key = ?
            """).use { stmt ->
                stmt.setString(1, accessPolicy)
                stmt.setString(2, encryption)
                stmt.setBytes(3, storedContent)
                stmt.setString(4, configApiId)
                stmt.setString(5, key)
                return stmt.executeUpdate() > 0
            }
        }
    }

    /**
     * Startup pass over every at_rest / end_to_end file so each one opens with
     * the current `VAULT_AT_REST_PASSWORD`:
     * - stored before it was kept encrypted (end_to_end files once were): encrypted;
     * - opens only with a previous password (`VAULT_AT_REST_PASSWORD_PREVIOUS`,
     *   or the demo password when the variable was unset): re-encrypted;
     * - opens with none: listed in [AtRestReport.unreadable] and left as it is.
     *   Reads of it fail until the old password is supplied or it is uploaded again.
     * One key derivation per file, so a few hundred files take seconds.
     */
    fun secureStoredFiles(): AtRestReport = db.connection().use { conn ->
        val rows = conn.prepareStatement(
            "SELECT config_api_id, key, content FROM vault_files WHERE encryption IN ('at_rest', 'end_to_end') ORDER BY config_api_id, key"
        ).use { stmt ->
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(Triple(rs.getString(1), rs.getString(2), rs.getBytes(3))) }
        }
        val encrypted = mutableListOf<String>()
        val rekeyed = mutableListOf<String>()
        val unreadable = mutableListOf<String>()
        for ((scope, key, stored) in rows) {
            val name = "$scope/$key"
            val plaintext = if (!VaultAtRestCipher.isEncrypted(stored)) {
                encrypted += name
                stored
            } else when (val opened = cipher.open(stored)) {
                VaultAtRestCipher.Opened.Current -> continue
                is VaultAtRestCipher.Opened.Previous -> { rekeyed += name; opened.plaintext }
                VaultAtRestCipher.Opened.Unreadable -> { unreadable += name; continue }
            }
            conn.prepareStatement("UPDATE vault_files SET content = ? WHERE config_api_id = ? AND key = ?").use { stmt ->
                stmt.setBytes(1, cipher.encrypt(plaintext))
                stmt.setString(2, scope)
                stmt.setString(3, key)
                stmt.executeUpdate()
            }
        }
        AtRestReport(encrypted, rekeyed, unreadable)
    }

    data class AtRestReport(val encrypted: List<String>, val rekeyed: List<String>, val unreadable: List<String>)

    private fun meta(configApiId: String, key: String): VaultFileSummary? {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT version, access_policy, encryption FROM vault_files WHERE config_api_id = ? AND key = ?
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                val rs = stmt.executeQuery()
                return if (rs.next()) VaultFileSummary(key, rs.getInt(1), 0, rs.getString(2), rs.getString(3)) else null
            }
        }
    }

    private fun storedForm(encryption: String, content: ByteArray): ByteArray =
        if (encryption in ENCRYPTED_MODES) cipher.encrypt(content) else content

    fun delete(configApiId: String, key: String) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "DELETE FROM vault_files WHERE config_api_id = ? AND key = ?"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                stmt.executeUpdate()
            }
        }
    }

    /**
     * The admin listing: sizes come from the stored blob, nothing is
     * decrypted (one key derivation per file per listing would add up, and a
     * file that no longer opens must still be listed).
     */
    fun summaries(configApiId: String): List<VaultFileSummary> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT key, version, content, access_policy, encryption
                FROM vault_files
                WHERE config_api_id = ?
                ORDER BY key
            """).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList {
                    while (rs.next()) {
                        val encryption = rs.getString("encryption")
                        val stored = rs.getBytes("content")
                        add(VaultFileSummary(
                            key = rs.getString("key"),
                            version = rs.getInt("version"),
                            size = if (encryption in ENCRYPTED_MODES) VaultAtRestCipher.plaintextSize(stored) else stored.size,
                            accessPolicy = rs.getString("access_policy"),
                            encryption = encryption
                        ))
                    }
                }
            }
        }
    }

    /** All files for a specific Config API, content decrypted. */
    fun listForConfigApi(configApiId: String): List<VaultEntry> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT config_api_id, key, version, content, access_policy, encryption, updated_at
                FROM vault_files
                WHERE config_api_id = ?
                ORDER BY key
            """).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toEntry()) }
            }
        }
    }

    /** All files across all Config APIs (admin-wide listing, rarely used). */
    fun listAll(): List<VaultEntry> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("""
                    SELECT config_api_id, key, version, content, access_policy, encryption, updated_at
                    FROM vault_files
                    ORDER BY config_api_id, key
                """)
                return buildList { while (rs.next()) add(rs.toEntry()) }
            }
        }
    }

    private fun java.sql.ResultSet.toEntry() = VaultEntry(
        configApiId  = getString("config_api_id"),
        key          = getString("key"),
        version      = getInt("version"),
        content      = readContent(getString("key"), getString("encryption"), getBytes("content")),
        accessPolicy = getString("access_policy"),
        encryption   = getString("encryption"),
        updatedAt    = getString("updated_at")
    )

    /**
     * A plain file is served as stored. An encrypted one must open with the
     * current password: serving the ciphertext instead would hand devices a
     * garbage file with a valid signature (the signature covers what is served).
     */
    private fun readContent(key: String, encryption: String, stored: ByteArray): ByteArray {
        if (encryption !in ENCRYPTED_MODES || !VaultAtRestCipher.isEncrypted(stored)) return stored
        return try {
            cipher.decrypt(stored)
        } catch (e: VaultKeyMismatchException) {
            throw VaultKeyMismatchException(
                "vault file '$key' does not open with VAULT_AT_REST_PASSWORD: set VAULT_AT_REST_PASSWORD_PREVIOUS " +
                "to the password it was stored with and restart, or upload the file again"
            )
        }
    }

    private companion object {
        val ENCRYPTED_MODES = setOf("at_rest", "end_to_end")
    }
}

/** A vault file without its content (listings). */
data class VaultFileSummary(
    val key: String,
    val version: Int,
    val size: Int,
    val accessPolicy: String,
    val encryption: String
)

data class VaultEntry(
    val configApiId: String,
    val key: String,
    val version: Int,
    val content: ByteArray,
    val accessPolicy: String = "token",
    val encryption: String = "plain",
    val updatedAt: String = ""
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultEntry) return false
        return configApiId == other.configApiId &&
                key == other.key &&
                version == other.version &&
                content.contentEquals(other.content) &&
                accessPolicy == other.accessPolicy &&
                encryption == other.encryption
    }

    override fun hashCode(): Int {
        var result = configApiId.hashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + version
        result = 31 * result + content.contentHashCode()
        result = 31 * result + accessPolicy.hashCode()
        result = 31 * result + encryption.hashCode()
        return result
    }
}
