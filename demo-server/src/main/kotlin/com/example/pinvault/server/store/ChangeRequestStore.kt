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
    /**
     * pending | approved | applied | failed | rejected | expired | stale.
     * `approved`: enough admins agreed and the requester may now run it once
     * (operations whose answer carries a secret — see V18).
     */
    val status: String,
    val approvedBy: List<String> = emptyList(),
    val decidedBy: String? = null,
    val decidedAt: String? = null,
    val reason: String? = null,
    val resultStatus: Int? = null,
    val resultBody: String? = null
)

/**
 * [cipher]: the body and the plan of a request wait here until it is decided —
 * an uploaded P12 with its password, a generated keystore with its private
 * key — so they are stored under the at-rest key (`VAULT_AT_REST_PASSWORD`,
 * AES-GCM) when one is given; Main always gives it. Rows written before are
 * read as they are.
 */
class ChangeRequestStore(
    private val db: DatabaseManager,
    private val cipher: com.example.pinvault.server.service.VaultAtRestCipher? = null
) {
    private fun seal(bytes: ByteArray?): ByteArray? = if (bytes == null || cipher == null) bytes else cipher.encrypt(bytes)

    private fun unseal(bytes: ByteArray?): ByteArray? {
        if (bytes == null || cipher == null || !com.example.pinvault.server.service.VaultAtRestCipher.isEncrypted(bytes)) return bytes
        // A previous password (VAULT_AT_REST_PASSWORD_PREVIOUS) still opens what
        // waited across a rotation. A body that merely starts with the marker
        // (sent so, or stored before encryption) does not open: it is the request as sent.
        return when (val opened = cipher.open(bytes)) {
            com.example.pinvault.server.service.VaultAtRestCipher.Opened.Current -> cipher.decrypt(bytes)
            is com.example.pinvault.server.service.VaultAtRestCipher.Opened.Previous -> opened.plaintext
            com.example.pinvault.server.service.VaultAtRestCipher.Opened.Unreadable -> bytes
        }
    }

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
        detail: String,
        /** What the change will install, fixed at request time (see V18); null when the request itself says it all. */
        prepared: ByteArray? = null
    ): Long = db.connection().use { conn ->
        conn.prepareStatement(
            "INSERT INTO change_requests (created_at, expires_at, requested_by, method, path, query, content_type, body, " +
                "config_api_id, summary, detail, prepared, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')"
        ).use { stmt ->
            stmt.setString(1, createdAt)
            stmt.setString(2, expiresAt)
            stmt.setString(3, requestedBy)
            stmt.setString(4, method)
            stmt.setString(5, path)
            stmt.setString(6, query)
            stmt.setString(7, contentType)
            stmt.setBytes(8, seal(body))
            stmt.setString(9, configApiId)
            stmt.setString(10, summary)
            stmt.setString(11, detail)
            stmt.setBytes(12, seal(prepared))
            stmt.executeUpdate()
        }
        conn.prepareStatement("SELECT last_insert_rowid()").use { it.executeQuery().getLong(1) }
    }

    fun get(id: Long): ChangeRequest? = query("SELECT * FROM change_requests WHERE id = ?", id).firstOrNull()

    fun body(id: Long): ByteArray? = db.connection().use { conn ->
        conn.prepareStatement("SELECT body FROM change_requests WHERE id = ?").use { stmt ->
            stmt.setLong(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) unseal(rs.getBytes(1)) ?: ByteArray(0) else null
        }
    }

    /** The plan stored with request [id] (see V18); null when it has none or was decided. */
    fun prepared(id: Long): ByteArray? = db.connection().use { conn ->
        conn.prepareStatement("SELECT prepared FROM change_requests WHERE id = ?").use { stmt ->
            stmt.setLong(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) unseal(rs.getBytes(1)) else null
        }
    }

    /** Newest first; [status] null = all, `open` = still to be decided or run (pending and approved). */
    fun list(status: String?, limit: Int = 100): List<ChangeRequest> = when (status) {
        null -> query("SELECT * FROM change_requests ORDER BY id DESC LIMIT $limit")
        "open" -> query("SELECT * FROM change_requests WHERE status IN ('pending', 'approved') ORDER BY id DESC LIMIT $limit")
        else -> query("SELECT * FROM change_requests WHERE status = ? ORDER BY id DESC LIMIT $limit", status)
    }

    /**
     * A pending request becomes `approved`: the requester may now run it once
     * ([claimApproved]). Body and plan are kept — the run is compared with them.
     */
    fun markApproved(id: Long): Boolean = db.connection().use { conn ->
        conn.prepareStatement("UPDATE change_requests SET status = 'approved' WHERE id = ? AND status = 'pending'").use { stmt ->
            stmt.setLong(1, id)
            stmt.executeUpdate() == 1
        }
    }

    /** Approved requests of [requestedBy] that were not run yet, oldest first. */
    fun approvedOf(requestedBy: String): List<ChangeRequest> =
        query("SELECT * FROM change_requests WHERE status = 'approved' AND requested_by = ? ORDER BY id", requestedBy)

    /**
     * Spends an approved request in one statement: of two identical requests
     * racing for it, exactly one gets `true` and runs. The body is dropped.
     */
    fun claimApproved(id: Long, decidedBy: String?, decidedAt: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement(
            "UPDATE change_requests SET status = 'applied', decided_by = ?, decided_at = ?, body = NULL, prepared = NULL " +
                "WHERE id = ? AND status = 'approved'"
        ).use { stmt ->
            stmt.setString(1, decidedBy)
            stmt.setString(2, decidedAt)
            stmt.setLong(3, id)
            stmt.executeUpdate() == 1
        }
    }

    /** The HTTP status a claimed request ended with; anything but 2xx turns it into `failed`. Its answer is never stored. */
    fun recordRun(id: Long, resultStatus: Int) = db.connection().use { conn ->
        conn.prepareStatement("UPDATE change_requests SET result_status = ?, status = ? WHERE id = ? AND status = 'applied'").use { stmt ->
            stmt.setInt(1, resultStatus)
            stmt.setString(2, if (resultStatus in 200..299) "applied" else "failed")
            stmt.setLong(3, id)
            stmt.executeUpdate()
        }
    }

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
     * Records the outcome of a request that is still open (pending, or
     * approved and not run yet) — and only then, so a slow sweep can never
     * turn an applied request into "expired". The stored body and plan are
     * dropped with the decision: uploads can carry private keys and
     * passwords, and nothing needs them once the request is decided.
     * Returns false when the request was no longer open.
     */
    fun decideIfPending(id: Long, status: String, decidedBy: String?, decidedAt: String, reason: String?, resultStatus: Int?, resultBody: String?): Boolean =
        db.connection().use { conn ->
            conn.prepareStatement(
                "UPDATE change_requests SET status = ?, decided_by = ?, decided_at = ?, reason = ?, result_status = ?, result_body = ?, body = NULL, prepared = NULL " +
                    "WHERE id = ? AND status IN ('pending', 'approved')"
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

    /** Open requests (pending, or approved and not run) whose expiry is before [now] (ISO-8601), all of them. */
    fun pendingExpiredBefore(now: String): List<ChangeRequest> =
        query("SELECT * FROM change_requests WHERE status IN ('pending', 'approved') AND expires_at < ? ORDER BY id", now)

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
