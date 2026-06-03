package com.example.pinvault.server.store

import com.example.pinvault.server.service.VaultAtRestCipher

/**
 * Persistent store for vault file content. Every entry is scoped to a Config
 * API — two Config APIs may hold files with the same key without collision.
 *
 * Added in V2: access_policy and encryption are persisted per-file. Default
 * policy is "token" (least-privilege); admin must explicitly issue a per-device
 * token before the device can fetch the file.
 */
class VaultFileStore(private val db: DatabaseManager) {

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
            val existing = get(configApiId, key)
            val newVersion = (existing?.version ?: 0) + 1
            val finalPolicy = accessPolicy ?: existing?.accessPolicy ?: "token"
            val finalEncryption = encryption ?: existing?.encryption ?: "plain"
            // at_rest: store the content AES-256-GCM encrypted; reads decrypt it
            // transparently (see toEntry). Wire format stays identical to plain.
            val storedContent =
                if (finalEncryption == "at_rest") VaultAtRestCipher.encrypt(content) else content

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
        val storedContent =
            if (encryption == "at_rest") VaultAtRestCipher.encrypt(current.content) else current.content
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

    /** All files for a specific Config API (used by admin list endpoint). */
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
        content      = VaultAtRestCipher.decryptIfPresent(getBytes("content")),
        accessPolicy = getString("access_policy"),
        encryption   = getString("encryption"),
        updatedAt    = getString("updated_at")
    )
}

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
