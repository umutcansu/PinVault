package com.example.pinvault.server.store

class VaultFileStore(private val db: DatabaseManager) {

    init {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS vault_files (
                        key TEXT PRIMARY KEY,
                        version INTEGER NOT NULL DEFAULT 1,
                        content BLOB NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                """)
            }
        }
    }

    fun get(key: String): VaultEntry? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT key, version, content FROM vault_files WHERE key = ?").use { stmt ->
                stmt.setString(1, key)
                val rs = stmt.executeQuery()
                return if (rs.next()) {
                    VaultEntry(
                        key = rs.getString("key"),
                        version = rs.getInt("version"),
                        content = rs.getBytes("content")
                    )
                } else null
            }
        }
    }

    fun put(key: String, content: ByteArray) {
        db.connection().use { conn ->
            // Check if exists to increment version
            val existing = get(key)
            val newVersion = (existing?.version ?: 0) + 1

            conn.prepareStatement("""
                INSERT OR REPLACE INTO vault_files (key, version, content, updated_at)
                VALUES (?, ?, ?, datetime('now'))
            """).use { stmt ->
                stmt.setString(1, key)
                stmt.setInt(2, newVersion)
                stmt.setBytes(3, content)
                stmt.executeUpdate()
            }
        }
    }

    fun delete(key: String) {
        db.connection().use { conn ->
            conn.prepareStatement("DELETE FROM vault_files WHERE key = ?").use { stmt ->
                stmt.setString(1, key)
                stmt.executeUpdate()
            }
        }
    }

    fun listAll(): List<VaultEntry> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT key, version, content FROM vault_files ORDER BY key")
                val entries = mutableListOf<VaultEntry>()
                while (rs.next()) {
                    entries.add(VaultEntry(
                        key = rs.getString("key"),
                        version = rs.getInt("version"),
                        content = rs.getBytes("content")
                    ))
                }
                return entries
            }
        }
    }
}

data class VaultEntry(val key: String, val version: Int, val content: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultEntry) return false
        return key == other.key && version == other.version && content.contentEquals(other.content)
    }
    override fun hashCode(): Int = 31 * (31 * key.hashCode() + version) + content.contentHashCode()
}
