package com.example.pinvault.server.store

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.PinConfigHistoryEntry

class PinConfigStore(private val db: DatabaseManager) {

    fun ensureConfigExists(configApiId: String) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT OR IGNORE INTO pin_config (config_api_id, force_update) VALUES (?, 0)"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.executeUpdate()
            }
        }
    }

    fun load(configApiId: String): PinConfig {
        db.connection().use { conn ->
            val forceUpdate = conn.prepareStatement(
                "SELECT force_update FROM pin_config WHERE config_api_id = ?"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getInt("force_update") == 1 else false
            }

            data class HostData(val version: Int, val forceUpdate: Boolean, val mtls: Boolean, val clientCertVersion: Int?, val hashes: MutableList<String> = mutableListOf())
            val hosts = mutableMapOf<String, HostData>()
            conn.prepareStatement(
                "SELECT hostname, sha256, version, force_update, mtls, client_cert_version FROM pin_hashes WHERE config_api_id = ? ORDER BY id"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                while (rs.next()) {
                    val hostname = rs.getString("hostname")
                    val version = rs.getInt("version")
                    val fu = rs.getInt("force_update") == 1
                    val mtls = rs.getInt("mtls") == 1
                    val ccv = rs.getObject("client_cert_version") as? Int
                    val data = hosts.getOrPut(hostname) { HostData(version, fu, mtls, ccv) }
                    data.hashes.add(rs.getString("sha256"))
                }
            }

            val pins = hosts.map { (hostname, data) -> HostPin(hostname, data.hashes, data.version, data.forceUpdate, data.mtls, data.clientCertVersion) }
            return PinConfig(
                version = pins.maxOfOrNull { it.version } ?: 1,
                pins = pins,
                forceUpdate = forceUpdate
            )
        }
    }

    fun save(configApiId: String, config: PinConfig) {
        db.connection().use { conn ->
            conn.autoCommit = false
            try {
                ensureConfigExists(configApiId)

                conn.prepareStatement(
                    "UPDATE pin_config SET force_update = ? WHERE config_api_id = ?"
                ).use { stmt ->
                    stmt.setInt(1, if (config.forceUpdate) 1 else 0)
                    stmt.setString(2, configApiId)
                    stmt.executeUpdate()
                }

                conn.prepareStatement("DELETE FROM pin_hashes WHERE config_api_id = ?").use { stmt ->
                    stmt.setString(1, configApiId)
                    stmt.executeUpdate()
                }

                conn.prepareStatement(
                    "INSERT INTO pin_hashes (config_api_id, hostname, sha256, version, force_update, mtls, client_cert_version) VALUES (?, ?, ?, ?, ?, ?, ?)"
                ).use { stmt ->
                    config.pins.forEach { pin ->
                        pin.sha256.forEach { hash ->
                            stmt.setString(1, configApiId)
                            stmt.setString(2, pin.hostname)
                            stmt.setString(3, hash)
                            stmt.setInt(4, pin.version)
                            stmt.setInt(5, if (pin.forceUpdate) 1 else 0)
                            stmt.setInt(6, if (pin.mtls) 1 else 0)
                            stmt.setObject(7, pin.clientCertVersion)
                            stmt.addBatch()
                        }
                    }
                    stmt.executeBatch()
                }

                conn.commit()
            } catch (e: Exception) {
                conn.rollback()
                throw e
            }
        }
    }

    /** Tüm config API'lerdeki tüm host'ları döner (Web UI yönetim için) */
    fun loadAll(): Map<String, PinConfig> {
        db.connection().use { conn ->
            val apiIds = mutableSetOf<String>()
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT DISTINCT config_api_id FROM pin_hashes")
                while (rs.next()) apiIds.add(rs.getString("config_api_id"))
            }
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT config_api_id FROM pin_config")
                while (rs.next()) apiIds.add(rs.getString("config_api_id"))
            }
            return apiIds.associateWith { load(it) }
        }
    }
}

class PinConfigHistoryStore(private val db: DatabaseManager) {

    fun add(configApiId: String, entry: PinConfigHistoryEntry) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO pin_history (config_api_id, hostname, version, timestamp, event, pin_prefix) VALUES (?, ?, ?, ?, ?, ?)"
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setString(2, entry.hostname)
                stmt.setInt(3, entry.version)
                stmt.setString(4, entry.timestamp)
                stmt.setString(5, entry.event)
                stmt.setString(6, entry.pinPrefix)
                stmt.executeUpdate()
            }

            conn.createStatement().use { stmt ->
                stmt.executeUpdate("""
                    DELETE FROM pin_history WHERE id NOT IN (
                        SELECT id FROM pin_history ORDER BY id DESC LIMIT 100
                    )
                """)
            }
        }
    }

    fun getByHostname(hostname: String): List<PinConfigHistoryEntry> {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT hostname, version, timestamp, event, pin_prefix FROM pin_history WHERE hostname = ? ORDER BY id DESC"
            ).use { stmt ->
                stmt.setString(1, hostname)
                val rs = stmt.executeQuery()
                val entries = mutableListOf<PinConfigHistoryEntry>()
                while (rs.next()) {
                    entries.add(PinConfigHistoryEntry(
                        hostname = rs.getString("hostname"),
                        version = rs.getInt("version"),
                        timestamp = rs.getString("timestamp"),
                        event = rs.getString("event"),
                        pinPrefix = rs.getString("pin_prefix")
                    ))
                }
                return entries
            }
        }
    }
}

@kotlinx.serialization.Serializable
data class ConnectionEntry(
    val source: String,
    val hostname: String = "",
    val timestamp: String,
    val status: String,
    val responseTimeMs: Long = 0,
    val errorMessage: String? = null,
    val serverCertPin: String? = null,
    val storedPin: String? = null,
    val pinMatched: Boolean? = null,
    val pinVersion: Int? = null,
    val deviceManufacturer: String? = null,
    val deviceModel: String? = null
)

class ConnectionHistoryStore(private val db: DatabaseManager) {

    fun addWebCheck(hostname: String = "", timestamp: String, status: String, responseTimeMs: Long, errorMessage: String? = null) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO connection_history (source, hostname, timestamp, status, response_time_ms, error_message) VALUES ('web', ?, ?, ?, ?, ?)"
            ).use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, timestamp)
                stmt.setString(3, status)
                stmt.setLong(4, responseTimeMs)
                stmt.setString(5, errorMessage)
                stmt.executeUpdate()
            }
            trimEntries(conn)
        }
    }

    fun addClientReport(
        hostname: String = "",
        timestamp: String,
        status: String,
        responseTimeMs: Long,
        serverCertPin: String?,
        storedPin: String?,
        pinMatched: Boolean?,
        pinVersion: Int?,
        deviceManufacturer: String?,
        deviceModel: String?,
        errorMessage: String? = null
    ) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT INTO connection_history
                (source, hostname, timestamp, status, response_time_ms, server_cert_pin, stored_pin, pin_matched, pin_version, device_manufacturer, device_model, error_message)
                VALUES ('android', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, timestamp)
                stmt.setString(3, status)
                stmt.setLong(4, responseTimeMs)
                stmt.setString(5, serverCertPin)
                stmt.setString(6, storedPin)
                stmt.setObject(7, pinMatched?.let { if (it) 1 else 0 })
                stmt.setObject(8, pinVersion)
                stmt.setString(9, deviceManufacturer)
                stmt.setString(10, deviceModel)
                stmt.setString(11, errorMessage)
                stmt.executeUpdate()
            }
            trimEntries(conn)
        }
    }

    private fun readEntries(rs: java.sql.ResultSet): List<ConnectionEntry> {
        val entries = mutableListOf<ConnectionEntry>()
        while (rs.next()) {
            entries.add(ConnectionEntry(
                source = rs.getString("source"),
                hostname = rs.getString("hostname") ?: "",
                timestamp = rs.getString("timestamp"),
                status = rs.getString("status"),
                responseTimeMs = rs.getLong("response_time_ms"),
                errorMessage = rs.getString("error_message"),
                serverCertPin = rs.getString("server_cert_pin"),
                storedPin = rs.getString("stored_pin"),
                pinMatched = rs.getObject("pin_matched")?.let { (it as Int) == 1 },
                pinVersion = rs.getObject("pin_version") as? Int,
                deviceManufacturer = rs.getString("device_manufacturer"),
                deviceModel = rs.getString("device_model")
            ))
        }
        return entries
    }

    fun getAll(): List<ConnectionEntry> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("""
                    SELECT source, hostname, timestamp, status, http_code, response_time_ms, error_message,
                           server_cert_pin, stored_pin, pin_matched, pin_version,
                           device_manufacturer, device_model
                    FROM connection_history ORDER BY id DESC
                """)
                return readEntries(rs)
            }
        }
    }

    fun getByHostname(hostname: String): List<ConnectionEntry> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT source, hostname, timestamp, status, http_code, response_time_ms, error_message,
                       server_cert_pin, stored_pin, pin_matched, pin_version,
                       device_manufacturer, device_model
                FROM connection_history WHERE hostname = ? ORDER BY id DESC
            """).use { stmt ->
                stmt.setString(1, hostname)
                return readEntries(stmt.executeQuery())
            }
        }
    }

    private fun trimEntries(conn: java.sql.Connection) {
        conn.createStatement().use { stmt ->
            stmt.executeUpdate("""
                DELETE FROM connection_history WHERE id NOT IN (
                    SELECT id FROM connection_history ORDER BY id DESC LIMIT 200
                )
            """)
        }
    }
}

data class HostRecord(
    val hostname: String,
    val configApiId: String = "default-tls",
    val keystorePath: String?,
    val certValidUntil: String?,
    val mockServerPort: Int?,
    val createdAt: String
)

class HostStore(private val db: DatabaseManager) {

    fun save(record: HostRecord) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT OR REPLACE INTO hosts (hostname, config_api_id, keystore_path, cert_valid_until, mock_server_port, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, record.hostname)
                stmt.setString(2, record.configApiId)
                stmt.setString(3, record.keystorePath)
                stmt.setString(4, record.certValidUntil)
                stmt.setObject(5, record.mockServerPort)
                stmt.setString(6, record.createdAt)
                stmt.executeUpdate()
            }
        }
    }

    fun get(hostname: String, configApiId: String): HostRecord? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT * FROM hosts WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                val rs = stmt.executeQuery()
                if (!rs.next()) return null
                return HostRecord(
                    hostname = rs.getString("hostname"),
                    configApiId = rs.getString("config_api_id"),
                    keystorePath = rs.getString("keystore_path"),
                    certValidUntil = rs.getString("cert_valid_until"),
                    mockServerPort = rs.getObject("mock_server_port") as? Int,
                    createdAt = rs.getString("created_at")
                )
            }
        }
    }

    fun delete(hostname: String, configApiId: String) {
        db.connection().use { conn ->
            conn.prepareStatement("DELETE FROM hosts WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                stmt.executeUpdate()
            }
        }
    }

    fun getAll(): List<HostRecord> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT * FROM hosts ORDER BY hostname")
                return buildList {
                    while (rs.next()) add(HostRecord(
                        hostname = rs.getString("hostname"),
                        configApiId = rs.getString("config_api_id"),
                        keystorePath = rs.getString("keystore_path"),
                        certValidUntil = rs.getString("cert_valid_until"),
                        mockServerPort = rs.getObject("mock_server_port") as? Int,
                        createdAt = rs.getString("created_at")
                    ))
                }
            }
        }
    }

    fun updateMockPort(hostname: String, configApiId: String, port: Int?) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE hosts SET mock_server_port = ? WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setObject(1, port)
                stmt.setString(2, hostname)
                stmt.setString(3, configApiId)
                stmt.executeUpdate()
            }
        }
    }
}

@kotlinx.serialization.Serializable
data class ClientDevice(
    val deviceId: String,
    val deviceManufacturer: String?,
    val deviceModel: String?,
    val pinVersion: Int,
    val lastStatus: String,
    val lastSeen: String
)

class ClientDeviceStore(private val db: DatabaseManager) {

    fun upsert(hostname: String, deviceId: String, manufacturer: String?, model: String?, pinVersion: Int, status: String, timestamp: String) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT INTO client_devices (hostname, device_id, device_manufacturer, device_model, pin_version, last_status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname, device_id) DO UPDATE SET
                    device_manufacturer = excluded.device_manufacturer,
                    device_model = excluded.device_model,
                    pin_version = excluded.pin_version,
                    last_status = excluded.last_status,
                    last_seen = excluded.last_seen
            """).use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, deviceId)
                stmt.setString(3, manufacturer)
                stmt.setString(4, model)
                stmt.setInt(5, pinVersion)
                stmt.setString(6, status)
                stmt.setString(7, timestamp)
                stmt.executeUpdate()
            }
        }
    }

    fun getByHostname(hostname: String): List<ClientDevice> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT device_id, device_manufacturer, device_model, pin_version, last_status, last_seen
                FROM client_devices WHERE hostname = ? ORDER BY last_seen DESC
            """).use { stmt ->
                stmt.setString(1, hostname)
                val rs = stmt.executeQuery()
                val entries = mutableListOf<ClientDevice>()
                while (rs.next()) {
                    entries.add(ClientDevice(
                        deviceId = rs.getString("device_id"),
                        deviceManufacturer = rs.getString("device_manufacturer"),
                        deviceModel = rs.getString("device_model"),
                        pinVersion = rs.getInt("pin_version"),
                        lastStatus = rs.getString("last_status"),
                        lastSeen = rs.getString("last_seen")
                    ))
                }
                return entries
            }
        }
    }
}

@kotlinx.serialization.Serializable
data class ClientCertRecord(
    val id: String,
    val commonName: String,
    val fingerprint: String,
    val createdAt: String,
    val revoked: Boolean = false,
    val deviceAlias: String? = null,
    val deviceUid: String? = null
)

class ClientCertStore(private val db: DatabaseManager) {

    fun add(id: String, commonName: String, fingerprint: String, createdAt: String,
            deviceAlias: String? = null, deviceUid: String? = null) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT OR REPLACE INTO client_certs (id, common_name, fingerprint, created_at, revoked, device_alias, device_uid) VALUES (?, ?, ?, ?, 0, ?, ?)"
            ).use { stmt ->
                stmt.setString(1, id)
                stmt.setString(2, commonName)
                stmt.setString(3, fingerprint)
                stmt.setString(4, createdAt)
                stmt.setString(5, deviceAlias)
                stmt.setString(6, deviceUid)
                stmt.executeUpdate()
            }
        }
    }

    fun revoke(id: String) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE client_certs SET revoked = 1 WHERE id = ?").use { stmt ->
                stmt.setString(1, id)
                stmt.executeUpdate()
            }
        }
    }

    fun getAll(): List<ClientCertRecord> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT id, common_name, fingerprint, created_at, revoked, device_alias, device_uid FROM client_certs ORDER BY created_at DESC")
                val entries = mutableListOf<ClientCertRecord>()
                while (rs.next()) {
                    entries.add(ClientCertRecord(
                        id = rs.getString("id"),
                        commonName = rs.getString("common_name"),
                        fingerprint = rs.getString("fingerprint"),
                        createdAt = rs.getString("created_at"),
                        revoked = rs.getInt("revoked") == 1,
                        deviceAlias = rs.getString("device_alias"),
                        deviceUid = rs.getString("device_uid")
                    ))
                }
                return entries
            }
        }
    }
}

@kotlinx.serialization.Serializable
data class EnrollmentToken(
    val token: String,
    val clientId: String,
    val createdAt: String,
    val used: Boolean = false
)

@kotlinx.serialization.Serializable
data class HostClientCertRecord(
    val hostname: String,
    val version: Int,
    val commonName: String?,
    val fingerprint: String?,
    val createdAt: String
)

class HostClientCertStore(private val db: DatabaseManager) {

    fun save(hostname: String, configApiId: String, p12Bytes: ByteArray, version: Int, commonName: String?, fingerprint: String?) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT OR REPLACE INTO host_client_certs (hostname, config_api_id, p12_bytes, version, common_name, fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                stmt.setBytes(3, p12Bytes)
                stmt.setInt(4, version)
                stmt.setString(5, commonName)
                stmt.setString(6, fingerprint)
                stmt.setString(7, java.time.Instant.now().toString())
                stmt.executeUpdate()
            }
        }
    }

    fun getP12(hostname: String, configApiId: String): ByteArray? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT p12_bytes FROM host_client_certs WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.getBytes("p12_bytes") else null
            }
        }
    }

    fun get(hostname: String, configApiId: String): HostClientCertRecord? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT hostname, version, common_name, fingerprint, created_at FROM host_client_certs WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                val rs = stmt.executeQuery()
                return if (rs.next()) HostClientCertRecord(
                    hostname = rs.getString("hostname"),
                    version = rs.getInt("version"),
                    commonName = rs.getString("common_name"),
                    fingerprint = rs.getString("fingerprint"),
                    createdAt = rs.getString("created_at")
                ) else null
            }
        }
    }

    fun delete(hostname: String, configApiId: String) {
        db.connection().use { conn ->
            conn.prepareStatement("DELETE FROM host_client_certs WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, configApiId)
                stmt.executeUpdate()
            }
        }
    }
}

class EnrollmentTokenStore(private val db: DatabaseManager) {

    fun create(clientId: String): String {
        val token = java.util.UUID.randomUUID().toString().replace("-", "").take(12)
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO enrollment_tokens (token, client_id, created_at) VALUES (?, ?, ?)"
            ).use { stmt ->
                stmt.setString(1, token)
                stmt.setString(2, clientId)
                stmt.setString(3, java.time.Instant.now().toString())
                stmt.executeUpdate()
            }
        }
        return token
    }

    fun validate(token: String): String? {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT client_id FROM enrollment_tokens WHERE token = ? AND used = 0"
            ).use { stmt ->
                stmt.setString(1, token)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.getString("client_id") else null
            }
        }
    }

    fun markUsed(token: String) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE enrollment_tokens SET used = 1 WHERE token = ?").use { stmt ->
                stmt.setString(1, token)
                stmt.executeUpdate()
            }
        }
    }

    fun getAll(): List<EnrollmentToken> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT token, client_id, created_at, used FROM enrollment_tokens ORDER BY created_at DESC")
                val entries = mutableListOf<EnrollmentToken>()
                while (rs.next()) {
                    entries.add(EnrollmentToken(
                        token = rs.getString("token"),
                        clientId = rs.getString("client_id"),
                        createdAt = rs.getString("created_at"),
                        used = rs.getInt("used") == 1
                    ))
                }
                return entries
            }
        }
    }
}
