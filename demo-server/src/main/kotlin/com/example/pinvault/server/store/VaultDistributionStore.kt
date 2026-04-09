package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

class VaultDistributionStore(private val db: DatabaseManager) {

    fun add(
        key: String,
        version: Int,
        deviceId: String,
        manufacturer: String?,
        model: String?,
        enrollmentLabel: String?,
        status: String,
        timestamp: String
    ) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT INTO vault_distributions (vault_key, version, device_id, device_manufacturer, device_model, enrollment_label, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, key)
                stmt.setInt(2, version)
                stmt.setString(3, deviceId)
                stmt.setString(4, manufacturer)
                stmt.setString(5, model)
                stmt.setString(6, enrollmentLabel)
                stmt.setString(7, status)
                stmt.setString(8, timestamp)
                stmt.executeUpdate()
            }
            trimEntries(conn)
        }
    }

    fun getAll(): List<VaultDistribution> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT * FROM vault_distributions ORDER BY id DESC LIMIT 200")
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getByKey(key: String): List<VaultDistribution> {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT * FROM vault_distributions WHERE vault_key = ? ORDER BY id DESC LIMIT 100").use { stmt ->
                stmt.setString(1, key)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getByDevice(deviceId: String): List<VaultDistribution> {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT * FROM vault_distributions WHERE device_id = ? ORDER BY id DESC LIMIT 100").use { stmt ->
                stmt.setString(1, deviceId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toDistribution()) }
            }
        }
    }

    fun getStats(): VaultDistStats {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val total = stmt.executeQuery("SELECT COUNT(*) FROM vault_distributions").let { it.next(); it.getInt(1) }
                val uniqueDevices = stmt.executeQuery("SELECT COUNT(DISTINCT device_id) FROM vault_distributions").let { it.next(); it.getInt(1) }
                val uniqueKeys = stmt.executeQuery("SELECT COUNT(DISTINCT vault_key) FROM vault_distributions").let { it.next(); it.getInt(1) }
                val downloaded = stmt.executeQuery("SELECT COUNT(*) FROM vault_distributions WHERE status = 'downloaded'").let { it.next(); it.getInt(1) }
                val failed = stmt.executeQuery("SELECT COUNT(*) FROM vault_distributions WHERE status = 'failed'").let { it.next(); it.getInt(1) }
                return VaultDistStats(total, uniqueDevices, uniqueKeys, downloaded, failed)
            }
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
        vaultKey = getString("vault_key"),
        version = getInt("version"),
        deviceId = getString("device_id"),
        deviceManufacturer = getString("device_manufacturer"),
        deviceModel = getString("device_model"),
        enrollmentLabel = getString("enrollment_label"),
        status = getString("status"),
        timestamp = getString("timestamp")
    )
}

@Serializable
data class VaultDistribution(
    val vaultKey: String,
    val version: Int,
    val deviceId: String,
    val deviceManufacturer: String? = null,
    val deviceModel: String? = null,
    val enrollmentLabel: String? = null,
    val status: String,
    val timestamp: String
)

@Serializable
data class VaultDistStats(
    val totalDistributions: Int,
    val uniqueDevices: Int,
    val uniqueKeys: Int,
    val downloaded: Int,
    val failed: Int
)
