package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * A CSR-enrolled device: its permanent key (as an SPKI hash) and the
 * certificate currently issued over it.
 */
@Serializable
data class ClientIdentity(
    val clientId: String,
    val configApiId: String,
    /** SHA-256 of the device key's SubjectPublicKeyInfo, Base64 — the same form as a pin. */
    val spkiSha256: String,
    /** Serial of the current certificate, hex. */
    val serial: String,
    val notBefore: String,
    val notAfter: String,
    val keyRegisteredAt: String,
    val lastRenewedAt: String? = null,
    val renewCount: Int = 0,
    val revoked: Boolean = false,
    val deviceAlias: String? = null,
    val deviceUid: String? = null
)

/**
 * The registry a client-certificate renewal is checked against.
 *
 * Unlike `client_certs`, a row here is never silently replaced: enrolling a
 * client id that was revoked is refused ([register] returns false), and
 * [recordRenewal] touches only the certificate columns — the key and the
 * revoked flag stay what they are.
 *
 * Every key a client id enrolled with is also kept in `client_keys`, so that
 * [forget] can retire them all: a certificate over a retired key is refused
 * on every request ([isRetired]) and the key never enrolls again.
 */
class ClientIdentityStore(private val db: DatabaseManager) {

    /** What [forget] did. */
    enum class Forget { FORGOTTEN, NOT_FOUND, NOT_REVOKED }

    fun get(clientId: String): ClientIdentity? = db.connection().use { conn ->
        conn.prepareStatement("SELECT $COLUMNS FROM client_identities WHERE client_id = ?").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toIdentity() else null
        }
    }

    /**
     * Enrollment: registers the key and the first certificate. An existing
     * row is replaced only while it is not revoked — a fresh enrollment of a
     * revoked client id is refused and the row is left as it is. A retired
     * key is refused too, under any client id.
     *
     * @return false when the client id is revoked or the key retired.
     */
    fun register(
        clientId: String,
        configApiId: String,
        spkiSha256: String,
        serial: String,
        notBefore: String,
        notAfter: String,
        deviceAlias: String?,
        deviceUid: String?,
        now: String
    ): Boolean = db.connection().use { conn ->
        inTransaction(conn) {
            // The write comes first, so the transaction holds the write lock
            // from its first statement; the key check is part of it.
            val registered = conn.prepareStatement(
                """
                INSERT INTO client_identities
                    (client_id, config_api_id, spki_sha256, serial, not_before, not_after, key_registered_at,
                     last_renewed_at, renew_count, revoked, device_alias, device_uid)
                SELECT ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM client_keys WHERE spki_sha256 = ? AND retired_at IS NOT NULL)
                ON CONFLICT(client_id) DO UPDATE SET
                    config_api_id = excluded.config_api_id,
                    spki_sha256 = excluded.spki_sha256,
                    serial = excluded.serial,
                    not_before = excluded.not_before,
                    not_after = excluded.not_after,
                    key_registered_at = excluded.key_registered_at,
                    last_renewed_at = NULL,
                    renew_count = 0,
                    device_alias = excluded.device_alias,
                    device_uid = excluded.device_uid
                WHERE client_identities.revoked = 0
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, clientId)
                stmt.setString(2, configApiId)
                stmt.setString(3, spkiSha256)
                stmt.setString(4, serial)
                stmt.setString(5, notBefore)
                stmt.setString(6, notAfter)
                stmt.setString(7, now)
                stmt.setString(8, deviceAlias)
                stmt.setString(9, deviceUid)
                stmt.setString(10, spkiSha256)
                stmt.executeUpdate() > 0
            }
            if (registered) {
                conn.prepareStatement("INSERT OR IGNORE INTO client_keys (client_id, spki_sha256, registered_at) VALUES (?, ?, ?)").use { stmt ->
                    stmt.setString(1, clientId)
                    stmt.setString(2, spkiSha256)
                    stmt.setString(3, now)
                    stmt.executeUpdate()
                }
            }
            registered
        }
    }

    /** Whether [spkiSha256] belonged to an identity that was forgotten: never trusted again. */
    fun isRetired(spkiSha256: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("SELECT 1 FROM client_keys WHERE spki_sha256 = ? AND retired_at IS NOT NULL LIMIT 1").use { stmt ->
            stmt.setString(1, spkiSha256)
            stmt.executeQuery().next()
        }
    }

    /**
     * Forgets a revoked identity so that its client id can enroll again — in
     * open enrollment the client id is the device's own id, so without this a
     * revoked device could never enroll again. Every key the client id
     * enrolled with is retired first; then its `client_identities` and
     * `client_certs` rows are deleted, in one transaction.
     *
     * An identity that is not revoked is left alone ([Forget.NOT_REVOKED]):
     * revoke first, so that nothing still in use is forgotten.
     */
    fun forget(clientId: String, now: String): Forget = db.connection().use { conn ->
        inTransaction(conn) {
            // Write first (see register); rolled back unless the identity qualifies.
            conn.prepareStatement("UPDATE client_keys SET retired_at = ? WHERE client_id = ? AND retired_at IS NULL").use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.executeUpdate()
            }
            val identity = conn.prepareStatement("SELECT spki_sha256, revoked FROM client_identities WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getString("spki_sha256") to (rs.getInt("revoked") == 1) else null
            }
            val certRevoked = conn.prepareStatement("SELECT revoked FROM client_certs WHERE id = ?").use { stmt ->
                stmt.setString(1, clientId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getInt("revoked") == 1 else null
            }
            when {
                identity == null && certRevoked == null -> { conn.rollback(); Forget.NOT_FOUND }
                identity?.second == false || certRevoked == false -> { conn.rollback(); Forget.NOT_REVOKED }
                else -> {
                    // The current key, should it predate client_keys.
                    if (identity != null) {
                        conn.prepareStatement(
                            """
                            INSERT INTO client_keys (client_id, spki_sha256, registered_at, retired_at) VALUES (?, ?, ?, ?)
                            ON CONFLICT(client_id, spki_sha256) DO UPDATE SET retired_at = COALESCE(client_keys.retired_at, excluded.retired_at)
                            """.trimIndent()
                        ).use { stmt ->
                            stmt.setString(1, clientId)
                            stmt.setString(2, identity.first)
                            stmt.setString(3, now)
                            stmt.setString(4, now)
                            stmt.executeUpdate()
                        }
                    }
                    for (sql in listOf("DELETE FROM client_identities WHERE client_id = ?", "DELETE FROM client_certs WHERE id = ?")) {
                        conn.prepareStatement(sql).use { stmt ->
                            stmt.setString(1, clientId)
                            stmt.executeUpdate()
                        }
                    }
                    Forget.FORGOTTEN
                }
            }
        }
    }

    /** Keys [clientId] enrolled with that are retired. */
    fun retiredKeys(clientId: String): Int = db.connection().use { conn ->
        conn.prepareStatement("SELECT COUNT(*) FROM client_keys WHERE client_id = ? AND retired_at IS NOT NULL").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) else 0
        }
    }

    private fun <T> inTransaction(conn: java.sql.Connection, block: () -> T): T {
        conn.autoCommit = false
        try {
            val result = block()
            if (!conn.autoCommit) conn.commit()
            return result
        } catch (e: Exception) {
            runCatching { conn.rollback() }
            throw e
        } finally {
            runCatching { conn.autoCommit = true }
        }
    }

    /**
     * Renewal: a new certificate over the same key. Never changes the key or
     * the revoked flag.
     *
     * @return false when there is no such (unrevoked) identity.
     */
    fun recordRenewal(clientId: String, serial: String, notBefore: String, notAfter: String, now: String): Boolean =
        db.connection().use { conn ->
            conn.prepareStatement(
                """
                UPDATE client_identities
                SET serial = ?, not_before = ?, not_after = ?, last_renewed_at = ?, renew_count = renew_count + 1
                WHERE client_id = ? AND revoked = 0
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, serial)
                stmt.setString(2, notBefore)
                stmt.setString(3, notAfter)
                stmt.setString(4, now)
                stmt.setString(5, clientId)
                stmt.executeUpdate() > 0
            }
        }

    fun revoke(clientId: String) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE client_identities SET revoked = 1 WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                stmt.executeUpdate()
            }
        }
    }

    fun getAll(): List<ClientIdentity> = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            val rs = stmt.executeQuery("SELECT $COLUMNS FROM client_identities ORDER BY key_registered_at DESC")
            buildList { while (rs.next()) add(rs.toIdentity()) }
        }
    }

    private fun java.sql.ResultSet.toIdentity() = ClientIdentity(
        clientId = getString("client_id"),
        configApiId = getString("config_api_id"),
        spkiSha256 = getString("spki_sha256"),
        serial = getString("serial"),
        notBefore = getString("not_before"),
        notAfter = getString("not_after"),
        keyRegisteredAt = getString("key_registered_at"),
        lastRenewedAt = getString("last_renewed_at"),
        renewCount = getInt("renew_count"),
        revoked = getInt("revoked") == 1,
        deviceAlias = getString("device_alias"),
        deviceUid = getString("device_uid")
    )

    private companion object {
        const val COLUMNS = "client_id, config_api_id, spki_sha256, serial, not_before, not_after, key_registered_at, " +
            "last_renewed_at, renew_count, revoked, device_alias, device_uid"
    }
}
