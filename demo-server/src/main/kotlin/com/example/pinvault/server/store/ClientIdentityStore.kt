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
 */
class ClientIdentityStore(private val db: DatabaseManager) {

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
     * revoked client id is refused and the row is left as it is.
     *
     * @return false when the client id is revoked.
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
        conn.prepareStatement(
            """
            INSERT INTO client_identities
                (client_id, config_api_id, spki_sha256, serial, not_before, not_after, key_registered_at,
                 last_renewed_at, renew_count, revoked, device_alias, device_uid)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, ?, ?)
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
            stmt.executeUpdate() > 0
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
