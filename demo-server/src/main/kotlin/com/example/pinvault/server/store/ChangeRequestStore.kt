package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/** A pin-affecting request waiting for approval (see V11__change_requests.sql). */
@Serializable
data class ChangeRequest(
    val id: Long,
    val createdAt: String,
    val expiresAt: String,
    val requestedBy: String,
    val method: String,
    val path: String,
    val query: String = "",
    val contentType: String = "",
    val configApiId: String = "",
    val summary: String,
    /** JSON text: the diff and, when the live gate is on, its dry run. */
    val detail: String = "",
    /** pending | applied | failed | rejected | expired */
    val status: String,
    val approvedBy: List<String> = emptyList(),
    val decidedBy: String? = null,
    val decidedAt: String? = null,
    val reason: String? = null,
    val resultStatus: Int? = null,
    val resultBody: String? = null
)

class ChangeRequestStore(private val db: DatabaseManager) {

    fun create(
        createdAt: String,
        expiresAt: String,
        requestedBy: String,
        method: String,
        path: String,
        query: String,
        contentType: String,
        body: ByteArray,
        configApiId: String,
        summary: String,
        detail: String
    ): Long = db.connection().use { conn ->
        conn.prepareStatement(
            "INSERT INTO change_requests (created_at, expires_at, requested_by, method, path, query, content_type, body, " +
                "config_api_id, summary, detail, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')"
        ).use { stmt ->
            stmt.setString(1, createdAt)
            stmt.setString(2, expiresAt)
            stmt.setString(3, requestedBy)
            stmt.setString(4, method)
            stmt.setString(5, path)
            stmt.setString(6, query)
            stmt.setString(7, contentType)
            stmt.setBytes(8, body)
            stmt.setString(9, configApiId)
            stmt.setString(10, summary)
            stmt.setString(11, detail)
            stmt.executeUpdate()
        }
        conn.prepareStatement("SELECT last_insert_rowid()").use { it.executeQuery().getLong(1) }
    }

    fun get(id: Long): ChangeRequest? = query("SELECT * FROM change_requests WHERE id = ?", id).firstOrNull()

    fun body(id: Long): ByteArray? = db.connection().use { conn ->
        conn.prepareStatement("SELECT body FROM change_requests WHERE id = ?").use { stmt ->
            stmt.setLong(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getBytes(1) ?: ByteArray(0) else null
        }
    }

    /** Newest first; [status] null = all. */
    fun list(status: String?, limit: Int = 100): List<ChangeRequest> =
        if (status == null) query("SELECT * FROM change_requests ORDER BY id DESC LIMIT $limit")
        else query("SELECT * FROM change_requests WHERE status = ? ORDER BY id DESC LIMIT $limit", status)

    fun addApproval(id: Long, approver: String) = db.connection().use { conn ->
        conn.prepareStatement(
            "UPDATE change_requests SET approved_by = CASE WHEN approved_by = '' THEN ? ELSE approved_by || ',' || ? END WHERE id = ?"
        ).use { stmt ->
            stmt.setString(1, approver)
            stmt.setString(2, approver)
            stmt.setLong(3, id)
            stmt.executeUpdate()
        }
    }

    /**
     * Records the outcome of a request that is still pending — and only then,
     * so a slow sweep can never turn an applied request into "expired". The
     * stored body is dropped with the decision: uploads can carry private keys
     * and passwords, and nothing needs them once the request is decided.
     * Returns false when the request was no longer pending.
     */
    fun decideIfPending(id: Long, status: String, decidedBy: String?, decidedAt: String, reason: String?, resultStatus: Int?, resultBody: String?): Boolean =
        db.connection().use { conn ->
            conn.prepareStatement(
                "UPDATE change_requests SET status = ?, decided_by = ?, decided_at = ?, reason = ?, result_status = ?, result_body = ?, body = NULL " +
                    "WHERE id = ? AND status = 'pending'"
            ).use { stmt ->
                stmt.setString(1, status)
                stmt.setString(2, decidedBy)
                stmt.setString(3, decidedAt)
                stmt.setString(4, reason)
                if (resultStatus == null) stmt.setNull(5, java.sql.Types.INTEGER) else stmt.setInt(5, resultStatus)
                stmt.setString(6, resultBody)
                stmt.setLong(7, id)
                stmt.executeUpdate() == 1
            }
        }

    /** Pending requests whose expiry is before [now] (ISO-8601), all of them. */
    fun pendingExpiredBefore(now: String): List<ChangeRequest> =
        query("SELECT * FROM change_requests WHERE status = 'pending' AND expires_at < ? ORDER BY id", now)

    private fun query(sql: String, vararg args: Any): List<ChangeRequest> = db.connection().use { conn ->
        conn.prepareStatement(sql).use { stmt ->
            args.forEachIndexed { i, a ->
                when (a) {
                    is Long -> stmt.setLong(i + 1, a)
                    else -> stmt.setString(i + 1, a.toString())
                }
            }
            val rs = stmt.executeQuery()
            buildList {
                while (rs.next()) add(
                    ChangeRequest(
                        id = rs.getLong("id"),
                        createdAt = rs.getString("created_at"),
                        expiresAt = rs.getString("expires_at"),
                        requestedBy = rs.getString("requested_by"),
                        method = rs.getString("method"),
                        path = rs.getString("path"),
                        query = rs.getString("query"),
                        contentType = rs.getString("content_type"),
                        configApiId = rs.getString("config_api_id"),
                        summary = rs.getString("summary"),
                        detail = rs.getString("detail"),
                        status = rs.getString("status"),
                        approvedBy = rs.getString("approved_by").split(',').filter { it.isNotBlank() },
                        decidedBy = rs.getString("decided_by"),
                        decidedAt = rs.getString("decided_at"),
                        reason = rs.getString("reason"),
                        resultStatus = rs.getObject("result_status") as? Int,
                        resultBody = rs.getString("result_body")
                    )
                )
            }
        }
    }
}
