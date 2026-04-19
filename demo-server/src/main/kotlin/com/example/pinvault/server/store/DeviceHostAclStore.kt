package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * Per-device pin scoping. When a device calls
 * GET /api/v1/certificate-config?hosts=host1,host2 the server must only return
 * pins for hostnames the device is authorized to see.
 *
 * Policy resolution for a given (configApiId, deviceId):
 *
 *     allowed = device_host_acl(configApiId, deviceId)
 *               ∪ default_host_acl(configApiId)
 *     returned_pins = requested ∩ allowed
 *
 * If `requested - allowed ≠ ∅`, the server logs an "unauthorized host request"
 * event and responds with the intersection (or empty, if nothing matches).
 *
 * Grants are additive-only; there is no "deny" rule. To revoke access, remove
 * the row via [revoke] (or clear the default ACL entry).
 */
class DeviceHostAclStore(private val db: DatabaseManager) {

    // ── Per-device ACL ────────────────────────────────────────────────

    fun grant(configApiId: String, deviceId: String, hostname: String, timestamp: String) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT OR IGNORE INTO device_host_acl
                    (config_api_id, device_id, hostname, granted_at)
                VALUES (?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, deviceId)
                stmt.setString(3, hostname)
                stmt.setString(4, timestamp)
                stmt.executeUpdate()
            }
        }
    }

    fun revoke(configApiId: String, deviceId: String, hostname: String): Boolean {
        db.connection().use { conn ->
            conn.prepareStatement("""
                DELETE FROM device_host_acl
                WHERE config_api_id = ? AND device_id = ? AND hostname = ?
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, deviceId)
                stmt.setString(3, hostname)
                return stmt.executeUpdate() > 0
            }
        }
    }

    fun listForDevice(configApiId: String, deviceId: String): List<String> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT hostname FROM device_host_acl
                WHERE config_api_id = ? AND device_id = ?
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, deviceId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.getString("hostname")) }
            }
        }
    }

    // ── Default ACL ──────────────────────────────────────────────────

    fun addDefault(configApiId: String, hostname: String) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT OR IGNORE INTO default_host_acl (config_api_id, hostname) VALUES (?, ?)"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, hostname)
                stmt.executeUpdate()
            }
        }
    }

    fun removeDefault(configApiId: String, hostname: String): Boolean {
        db.connection().use { conn ->
            conn.prepareStatement(
                "DELETE FROM default_host_acl WHERE config_api_id = ? AND hostname = ?"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, hostname)
                return stmt.executeUpdate() > 0
            }
        }
    }

    fun listDefault(configApiId: String): List<String> {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT hostname FROM default_host_acl WHERE config_api_id = ?"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.getString("hostname")) }
            }
        }
    }

    // ── Policy resolution ────────────────────────────────────────────

    /**
     * Compute the full allowed-hostname set for a device: union of its
     * per-device ACL and the Config API's default ACL.
     */
    fun getAllowed(configApiId: String, deviceId: String): Set<String> {
        val perDevice = listForDevice(configApiId, deviceId)
        val default = listDefault(configApiId)
        return (perDevice + default).toSet()
    }

    /**
     * Given a list of hosts the client asked for, return the intersection with
     * allowed hosts. Hosts the client requested but is not authorized for are
     * returned separately in [AclDecision.denied] for audit logging.
     *
     * If [requested] is null (client sent no `?hosts=` filter — legacy / trust),
     * [allowed] itself is returned and denied is empty.
     */
    fun resolve(configApiId: String, deviceId: String, requested: List<String>?): AclDecision {
        val allowed = getAllowed(configApiId, deviceId)
        if (requested == null) return AclDecision(granted = allowed, denied = emptySet())
        val requestedSet = requested.toSet()
        return AclDecision(
            granted = requestedSet intersect allowed,
            denied = requestedSet - allowed
        )
    }
}

/** Output of [DeviceHostAclStore.resolve]. */
data class AclDecision(
    val granted: Set<String>,
    val denied: Set<String>
) {
    val hasUnauthorized: Boolean get() = denied.isNotEmpty()
}

@Serializable
data class DeviceHostAclEntry(
    val configApiId: String,
    val deviceId: String,
    val hostname: String,
    val grantedAt: String
)
