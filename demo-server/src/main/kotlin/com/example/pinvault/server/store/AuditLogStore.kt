package com.example.pinvault.server.store

import kotlinx.serialization.Serializable
import java.security.MessageDigest

@Serializable
data class AuditEntry(
    val id: Long,
    val at: String,
    val actor: String,
    val action: String,
    val configApiId: String = "",
    val target: String = "",
    val summary: String = "",
    /** JSON text; empty when there is nothing beyond the summary. */
    val detail: String = "",
    val sourceIp: String = "",
    val prevHash: String,
    val hash: String
)

@Serializable
data class AuditChainCheck(val ok: Boolean, val entries: Int, val firstBrokenId: Long? = null)

/**
 * Append-only, hash-chained audit log (see V10__audit_log.sql).
 */
class AuditLogStore(private val db: DatabaseManager) {

    /** Appends one entry, chained to the current last one. Serialized so the chain never forks. */
    @Synchronized
    fun append(
        at: String,
        actor: String,
        action: String,
        configApiId: String = "",
        target: String = "",
        summary: String = "",
        detail: String = "",
        sourceIp: String = ""
    ): AuditEntry = db.connection().use { conn ->
        val prev = conn.prepareStatement("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").use { stmt ->
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getString(1) else GENESIS
        }
        val hash = chainHash(prev, at, actor, action, configApiId, target, summary, detail, sourceIp)
        val id = conn.prepareStatement(
            "INSERT INTO audit_log (at, actor, action, config_api_id, target, summary, detail, source_ip, prev_hash, hash) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).use { stmt ->
            listOf(at, actor, action, configApiId, target, summary, detail, sourceIp, prev, hash)
                .forEachIndexed { i, v -> stmt.setString(i + 1, v) }
            stmt.executeUpdate()
            conn.prepareStatement("SELECT last_insert_rowid()").use { it.executeQuery().getLong(1) }
        }
        AuditEntry(id, at, actor, action, configApiId, target, summary, detail, sourceIp, prev, hash)
    }

    /** Newest first. */
    fun page(limit: Int, offset: Int, action: String? = null, configApiId: String? = null): List<AuditEntry> {
        val (where, args) = filter(action, configApiId)
        return db.connection().use { conn ->
            conn.prepareStatement("SELECT * FROM audit_log $where ORDER BY id DESC LIMIT ? OFFSET ?").use { stmt ->
                args.forEachIndexed { i, v -> stmt.setString(i + 1, v) }
                stmt.setInt(args.size + 1, limit)
                stmt.setInt(args.size + 2, offset)
                val rs = stmt.executeQuery()
                buildList { while (rs.next()) add(rs.toEntry()) }
            }
        }
    }

    fun count(action: String? = null, configApiId: String? = null): Int {
        val (where, args) = filter(action, configApiId)
        return db.connection().use { conn ->
            conn.prepareStatement("SELECT COUNT(*) FROM audit_log $where").use { stmt ->
                args.forEachIndexed { i, v -> stmt.setString(i + 1, v) }
                stmt.executeQuery().getInt(1)
            }
        }
    }

    /** Recomputes the whole chain; reports the first entry whose link or hash does not hold. */
    fun verify(): AuditChainCheck = db.connection().use { conn ->
        conn.prepareStatement("SELECT * FROM audit_log ORDER BY id ASC").use { stmt ->
            val rs = stmt.executeQuery()
            var expectedPrev = GENESIS
            var count = 0
            while (rs.next()) {
                val e = rs.toEntry()
                count++
                val recomputed = chainHash(e.prevHash, e.at, e.actor, e.action, e.configApiId, e.target, e.summary, e.detail, e.sourceIp)
                if (e.prevHash != expectedPrev || e.hash != recomputed) {
                    return@use AuditChainCheck(ok = false, entries = count, firstBrokenId = e.id)
                }
                expectedPrev = e.hash
            }
            AuditChainCheck(ok = true, entries = count)
        }
    }

    private fun filter(action: String?, configApiId: String?): Pair<String, List<String>> {
        val clauses = mutableListOf<String>()
        val args = mutableListOf<String>()
        action?.takeIf { it.isNotBlank() }?.let { clauses += "action = ?"; args += it }
        configApiId?.takeIf { it.isNotBlank() }?.let { clauses += "config_api_id = ?"; args += it }
        return (if (clauses.isEmpty()) "" else "WHERE " + clauses.joinToString(" AND ")) to args
    }

    private fun java.sql.ResultSet.toEntry() = AuditEntry(
        id = getLong("id"),
        at = getString("at"),
        actor = getString("actor"),
        action = getString("action"),
        configApiId = getString("config_api_id"),
        target = getString("target"),
        summary = getString("summary"),
        detail = getString("detail"),
        sourceIp = getString("source_ip"),
        prevHash = getString("prev_hash"),
        hash = getString("hash")
    )

    companion object {
        const val GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"

        /**
         * SHA-256 (hex) over the previous hash and every field, each followed
         * by a unit separator (0x1F) so field boundaries cannot be shifted.
         */
        fun chainHash(prev: String, vararg fields: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(prev.toByteArray(Charsets.UTF_8))
            for (field in fields) {
                digest.update(0x1F.toByte())
                digest.update(field.toByteArray(Charsets.UTF_8))
            }
            return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
    }
}
