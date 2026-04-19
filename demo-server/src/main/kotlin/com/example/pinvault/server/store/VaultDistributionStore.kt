package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * Distribution history: per-fetch record of which device downloaded which
 * vault file at which version, and the outcome (downloaded / cached / failed).
 *
 * V2: all rows are scoped to a Config API. Queries may optionally filter by
 * configApiId; stats are computed per Config API to avoid cross-tenant
 * leakage in the web UI.
 */
class VaultDistributionStore(private val db: DatabaseManager) {

    fun add(
        configApiId: String,
        key: String,
        version: Int,
        deviceId: String,
        manufacturer: String?,
        model: String?,
        enrollmentLabel: String?,
        status: String,
        timestamp: String,
        deviceAlias: String? = null,
        failureReason: String? = null,
        authMethod: String? = null
    ) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT INTO vault_distributions
                    (config_api_id, vault_key, version, device_id, device_manufacturer,
                     device_model, enrollment_label, status, timestamp, device_alias, failure_reason, auth_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                stmt.setInt(3, version)
                stmt.setString(4, deviceId)
                stmt.setString(5, manufacturer)
                stmt.setString(6, model)
                stmt.setString(7, enrollmentLabel)
                stmt.setString(8, status)
                stmt.setString(9, timestamp)
                stmt.setString(10, deviceAlias)
                stmt.setString(11, failureReason)
                stmt.setString(12, authMethod)
                stmt.executeUpdate()
            }
            trimEntries(conn)
        }
    }

    fun getAll(configApiId: String? = null): List<VaultDistribution> {
        db.connection().use { conn ->
            val sql = if (configApiId != null) {
                "SELECT * FROM vault_distributions WHERE config_api_id = ? ORDER BY id DESC LIMIT 200"
            } else {
                "SELECT * FROM vault_distributions ORDER BY id DESC LIMIT 200"
            }
            conn.prepareStatement(sql).use { stmt ->
                if (configApiId != null) stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getByKey(configApiId: String, key: String): List<VaultDistribution> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT * FROM vault_distributions
                WHERE config_api_id = ? AND vault_key = ?
                ORDER BY id DESC LIMIT 100
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, key)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getByDevice(configApiId: String, deviceId: String): List<VaultDistribution> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT * FROM vault_distributions
                WHERE config_api_id = ? AND device_id = ?
                ORDER BY id DESC LIMIT 100
            """).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, deviceId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getStats(configApiId: String? = null): VaultDistStats {
        db.connection().use { conn ->
            val where = if (configApiId != null) "WHERE config_api_id = ?" else ""

            fun count(sql: String): Int {
                conn.prepareStatement(sql).use { stmt ->
                    if (configApiId != null) stmt.setString(1, configApiId)
                    val rs = stmt.executeQuery()
                    rs.next(); return rs.getInt(1)
                }
            }

            val total         = count("SELECT COUNT(*) FROM vault_distributions $where")
            val uniqueDevices = count("SELECT COUNT(DISTINCT device_id) FROM vault_distributions $where")
            val uniqueKeys    = count("SELECT COUNT(DISTINCT vault_key) FROM vault_distributions $where")
            val downloaded    = count("SELECT COUNT(*) FROM vault_distributions $where${if (where.isEmpty()) "WHERE" else " AND"} status = 'downloaded'")
            val failed        = count("SELECT COUNT(*) FROM vault_distributions $where${if (where.isEmpty()) "WHERE" else " AND"} status = 'failed'")

            return VaultDistStats(total, uniqueDevices, uniqueKeys, downloaded, failed)
        }
    }

    private fun trimEntries(conn: java.sql.Connection) {
        conn.createStatement().use { stmt ->
            stmt.executeUpdate("""
                DELETE FROM vault_distributions WHERE id NOT IN (
                    SELECT id FROM vault_distributions ORDER BY id DESC LIMIT 500
                )
            """)
        }
    }

    private fun java.sql.ResultSet.toDistribution() = VaultDistribution(
        configApiId = try { getString("config_api_id") } catch (_: Exception) { "" },
        vaultKey = getString("vault_key"),
        version = getInt("version"),
        deviceId = getString("device_id"),
        deviceManufacturer = getString("device_manufacturer"),
        deviceModel = getString("device_model"),
        enrollmentLabel = getString("enrollment_label"),
        status = getString("status"),
        timestamp = getString("timestamp"),
        deviceAlias = try { getString("device_alias") } catch (_: Exception) { null },
        failureReason = try { getString("failure_reason") } catch (_: Exception) { null },
        authMethod = try { getString("auth_method") } catch (_: Exception) { null }
    )
}

@Serializable
data class VaultDistribution(
    val configApiId: String = "",
    val vaultKey: String,
    val version: Int,
    val deviceId: String,
    val deviceManufacturer: String? = null,
    val deviceModel: String? = null,
    val enrollmentLabel: String? = null,
    val status: String,
    val timestamp: String,
    val deviceAlias: String? = null,
    val failureReason: String? = null,
    val authMethod: String? = null
)

@Serializable
data class VaultDistStats(
    val totalDistributions: Int,
    val uniqueDevices: Int,
    val uniqueKeys: Int,
    val downloaded: Int,
    val failed: Int
)
