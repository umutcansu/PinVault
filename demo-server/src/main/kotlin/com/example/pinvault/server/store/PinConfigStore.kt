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

    /**
     * Persists [config] for [configApiId] and returns what was actually stored.
     *
     * Per-host versions never move backwards, even across delete + re-add: a
     * host that is new to this scope is stored above its high-water mark
     * (`host_version_watermark`). Clients reject per-host version downgrades,
     * so a re-added host restarting at v1 would be ignored by every client
     * that had seen the old versions. Callers that report the version of a
     * newly added host must read it from the returned config.
     */
    fun save(configApiId: String, config: PinConfig): PinConfig {
        val listener = onSaved
        val before = if (listener != null) load(configApiId) else null
        val saved = saveInTransaction(configApiId, config)
        // After the commit, outside the transaction: listeners read the store
        // back (e.g. to pre-sign the new config) and must see the new state.
        if (listener != null) {
            try {
                listener(configApiId, before, saved)
            } catch (e: Exception) {
                // The change is committed; a failing listener means a missing
                // audit entry or pre-signature — say so loudly.
                System.err.println("PinConfigStore: onSaved listener FAILED for $configApiId (audit entry may be missing): ${e.message}")
            }
        }
        return saved
    }

    /**
     * Called after every successful [save] with the scope, what it held before
     * and what was stored. Every pin-writing route funnels through [save], so
     * this sees them all (the audit log records its diff from here).
     */
    @Volatile
    var onSaved: ((configApiId: String, before: PinConfig?, after: PinConfig) -> Unit)? = null

    private fun saveInTransaction(configApiId: String, config: PinConfig): PinConfig {
        db.connection().use { conn ->
            conn.autoCommit = false
            try {
                ensureConfigExists(configApiId)

                val existingHosts = conn.prepareStatement(
                    "SELECT DISTINCT hostname FROM pin_hashes WHERE config_api_id = ?"
                ).use { stmt ->
                    stmt.setString(1, configApiId)
                    val rs = stmt.executeQuery()
                    buildSet { while (rs.next()) add(rs.getString(1)) }
                }
                val pins = config.pins.map { pin ->
                    if (pin.hostname in existingHosts) return@map pin
                    val floor = versionWatermark(conn, configApiId, pin.hostname)
                    if (pin.version > floor) pin else pin.copy(version = floor + 1)
                }
                val effective = config.copy(pins = pins, version = pins.maxOfOrNull { it.version } ?: config.version)

                conn.prepareStatement(
                    "UPDATE pin_config SET force_update = ? WHERE config_api_id = ?"
                ).use { stmt ->
                    stmt.setInt(1, if (effective.forceUpdate) 1 else 0)
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
                    effective.pins.forEach { pin ->
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

                conn.prepareStatement(
                    """INSERT INTO host_version_watermark (config_api_id, hostname, max_version) VALUES (?, ?, ?)
                       ON CONFLICT(config_api_id, hostname) DO UPDATE SET max_version = MAX(max_version, excluded.max_version)"""
                ).use { stmt ->
                    effective.pins.forEach { pin ->
                        stmt.setString(1, configApiId)
                        stmt.setString(2, pin.hostname)
                        stmt.setInt(3, pin.version)
                        stmt.addBatch()
                    }
                    stmt.executeBatch()
                }

                conn.commit()
                return effective
            } catch (e: Exception) {
                conn.rollback()
                throw e
            }
        }
    }

    /** Highest version this host has ever had in [configApiId]; 0 if never seen. */
    fun versionWatermark(configApiId: String, hostname: String): Int =
        db.connection().use { versionWatermark(it, configApiId, hostname) }

    private fun versionWatermark(conn: java.sql.Connection, configApiId: String, hostname: String): Int =
        conn.prepareStatement(
            "SELECT max_version FROM host_version_watermark WHERE config_api_id = ? AND hostname = ?"
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, hostname)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) else 0
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

    /**
     * Config-rotation report from a PinVault client (UPDATED / UNCHANGED /
     * FAILED outcome). Reuses [connection_history] with `source='config_update'`
     * and an empty hostname — the event is per-device, not per-host.
     */
    fun addConfigUpdateReport(
        timestamp: String,
        status: String,
        pinVersion: Int?,
        deviceManufacturer: String?,
        deviceModel: String?,
        failureReason: String? = null
    ) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT INTO connection_history
                (source, hostname, timestamp, status, response_time_ms, pin_version, device_manufacturer, device_model, error_message)
                VALUES ('config_update', '', ?, ?, 0, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, timestamp)
                stmt.setString(2, status)
                stmt.setObject(3, pinVersion)
                stmt.setString(4, deviceManufacturer)
                stmt.setString(5, deviceModel)
                stmt.setString(6, failureReason)
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

    // Mock server + keystore hostname başına global (fiziksel kaynak), scope'lara
    // göre bölünmemiş. Status/test-connection gibi okumalar için scope eşleşmediğinde
    // başka bir scope'taki kayıt da yeterlidir — böylece bir scope'ta pin'lenmiş ama
    // o scope'ta hostStore kaydı olmayan host da UI'da görünür.
    fun getAnyByHostname(hostname: String): HostRecord? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT * FROM hosts WHERE hostname = ? LIMIT 1").use { stmt ->
                stmt.setString(1, hostname)
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

    // Mock host cert'i (fiziksel) global — aynı hostname birden fazla config
    // API scope'unda kayıtlı olabilir, ya da bir scope onu host kaydı olmadan
    // pinleyebilir (pin'ler doğrudan o scope'a yazıldıysa). Cert rotation
    // sonrasi bu scope'ların HEPSİNDE pin_hashes güncellenmeli; aksi halde
    // güncellenmeyen scope'un client'ları pin mismatch alır. Bu metod o scope
    // listesini döner.
    fun listConfigApisFor(hostname: String): List<String> {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT config_api_id FROM hosts WHERE hostname = ? UNION SELECT config_api_id FROM pin_hashes WHERE hostname = ?"
            ).use { stmt ->
                stmt.setString(1, hostname)
                stmt.setString(2, hostname)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.getString(1)) }
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

    /**
     * Every device known to a Config API, keyed by the identifier the
     * per-device host ACL uses (`X-Device-Id`, i.e. ANDROID_ID).
     *
     * Two sources are merged because a device can be known through either:
     *  - `client_certs.device_uid` — recorded at enrollment, the authoritative
     *    list of devices that hold a certificate from this server;
     *  - `client_devices` — populated by connection reports, scoped to this
     *    Config API through the hosts registered under it.
     *
     * Enrollment data wins on conflict (it carries the admin-visible alias).
     */
    fun getByConfigApi(configApiId: String): List<ScopedClientDevice> {
        val merged = LinkedHashMap<String, ScopedClientDevice>()

        db.connection().use { conn ->
            // 1) Enrolled devices — certificate issued by this server.
            conn.prepareStatement("""
                SELECT device_uid, device_alias, common_name, created_at, revoked
                FROM client_certs
                WHERE device_uid IS NOT NULL AND device_uid != '' AND revoked = 0
                ORDER BY created_at DESC
            """).use { stmt ->
                val rs = stmt.executeQuery()
                while (rs.next()) {
                    val id = rs.getString("device_uid")
                    merged.putIfAbsent(id, ScopedClientDevice(
                        deviceId = id,
                        deviceAlias = rs.getString("device_alias"),
                        deviceModel = rs.getString("device_alias"),
                        lastSeen = rs.getString("created_at"),
                        source = "enrollment"
                    ))
                }
            }

            // 2) Devices seen by hosts that belong to this Config API.
            conn.prepareStatement("""
                SELECT cd.device_id, cd.device_manufacturer, cd.device_model,
                       MAX(cd.pin_version) AS pin_version, cd.last_status, MAX(cd.last_seen) AS last_seen
                FROM client_devices cd
                WHERE cd.hostname IN (SELECT hostname FROM hosts WHERE config_api_id = ?)
                GROUP BY cd.device_id
                ORDER BY last_seen DESC
            """).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                while (rs.next()) {
                    val id = rs.getString("device_id")
                    val reported = ScopedClientDevice(
                        deviceId = id,
                        deviceManufacturer = rs.getString("device_manufacturer"),
                        deviceModel = rs.getString("device_model"),
                        pinVersion = rs.getInt("pin_version"),
                        lastStatus = rs.getString("last_status"),
                        lastSeen = rs.getString("last_seen"),
                        source = "connection"
                    )
                    val existing = merged[id]
                    merged[id] = if (existing == null) reported else existing.copy(
                        deviceManufacturer = reported.deviceManufacturer ?: existing.deviceManufacturer,
                        deviceModel = reported.deviceModel ?: existing.deviceModel,
                        pinVersion = reported.pinVersion,
                        lastStatus = reported.lastStatus,
                        lastSeen = reported.lastSeen ?: existing.lastSeen,
                        source = "enrollment+connection"
                    )
                }
            }
        }

        return merged.values.toList()
    }
}

/**
 * A device as the Device-ACL manager sees it: identified by the value the
 * device sends as `X-Device-Id`, not by hostname.
 */
@kotlinx.serialization.Serializable
data class ScopedClientDevice(
    val deviceId: String,
    val deviceAlias: String? = null,
    val deviceManufacturer: String? = null,
    val deviceModel: String? = null,
    val pinVersion: Int = 0,
    val lastStatus: String = "unknown",
    val lastSeen: String? = null,
    /** "enrollment", "connection", or both — shown for diagnostics. */
    val source: String = "unknown"
)

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

    /**
     * Single certificate record by client id. Used by the `token_mtls` vault
     * policy to bind a presented certificate to the device that enrolled it.
     */
    fun get(id: String): ClientCertRecord? {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT id, common_name, fingerprint, created_at, revoked, device_alias, device_uid FROM client_certs WHERE id = ?"
            ).use { stmt ->
                stmt.setString(1, id)
                val rs = stmt.executeQuery()
                if (!rs.next()) return null
                return ClientCertRecord(
                    id = rs.getString("id"),
                    commonName = rs.getString("common_name"),
                    fingerprint = rs.getString("fingerprint"),
                    createdAt = rs.getString("created_at"),
                    revoked = rs.getInt("revoked") == 1,
                    deviceAlias = rs.getString("device_alias"),
                    deviceUid = rs.getString("device_uid")
                )
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
    /**
     * Masked prefix, never the plaintext — see [EnrollmentTokenStore]. The
     * field keeps its name so existing dashboard/API consumers do not break,
     * but [masked] tells them the value is not usable for enrollment.
     */
    val token: String,
    val clientId: String,
    val createdAt: String,
    val used: Boolean = false,
    val masked: Boolean = true,
    /** ISO-8601 instant the token stops being accepted; null for rows predating expiry. */
    val expiresAt: String? = null,
    /**
     * True when [expiresAt] is already in the past. Computed server-side so
     * the dashboard does not have to reimplement the rule
     * [EnrollmentTokenStore.validate] applies — a token that is neither used
     * nor usable was otherwise listed as "waiting".
     */
    val expired: Boolean = false
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

    /** Every stored certificate as (hostname, scope, P12 bytes). */
    fun allP12(): List<Triple<String, String, ByteArray>> = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            val rs = stmt.executeQuery("SELECT hostname, config_api_id, p12_bytes FROM host_client_certs")
            buildList { while (rs.next()) add(Triple(rs.getString(1), rs.getString(2), rs.getBytes(3))) }
        }
    }

    /** Replaces one certificate's P12 bytes (re-encrypted), keeping its version and metadata. */
    fun replaceP12(hostname: String, configApiId: String, p12Bytes: ByteArray) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE host_client_certs SET p12_bytes = ? WHERE hostname = ? AND config_api_id = ?").use { stmt ->
                stmt.setBytes(1, p12Bytes)
                stmt.setString(2, hostname)
                stmt.setString(3, configApiId)
                stmt.executeUpdate()
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

/**
 * Single-use enrollment tokens.
 *
 * ## At-rest model (audit N-8)
 * The plaintext token exists exactly once: it is returned by [create] and never
 * stored. The `token` column holds SHA-256(plaintext) as lowercase hex, so a
 * dump of `pinvault.db` — or the admin token list — yields nothing an attacker
 * can enroll with. This mirrors [com.example.pinvault.server.service.VaultAccessTokenService].
 *
 * [maskedPrefix] is kept for display so an admin can still tell rows apart
 * ("did the device use the token I minted at 14:02?") without the list being a
 * credential store. 8 chars of a 256-bit secret is not enough to brute-force
 * the remainder.
 *
 * Tokens minted before the hashing migration were plaintext; V8 invalidates
 * them rather than grandfathering a plaintext-comparison path.
 */
class EnrollmentTokenStore(private val db: DatabaseManager) {

    private val rng = java.security.SecureRandom()

    /**
     * Create a single-use enrollment token and return its plaintext — the only
     * time it is available. Only the SHA-256 hash is persisted.
     *
     * audit M-1: 256 bits from a CSPRNG (was a 48-bit truncated UUID) with an
     * expiry (was valid forever). TTL is ENROLLMENT_TOKEN_TTL_SECONDS (24h default).
     */
    fun create(clientId: String): String {
        val token = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(32).also(rng::nextBytes))
        val now = java.time.Instant.now()
        val ttlSeconds = System.getenv("ENROLLMENT_TOKEN_TTL_SECONDS")?.toLongOrNull() ?: 86_400L
        val expiresAt = now.plusSeconds(ttlSeconds)
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO enrollment_tokens (token, client_id, created_at, expires_at, token_prefix) VALUES (?, ?, ?, ?, ?)"
            ).use { stmt ->
                stmt.setString(1, hash(token))
                stmt.setString(2, clientId)
                stmt.setString(3, now.toString())
                stmt.setString(4, expiresAt.toString())
                stmt.setString(5, maskedPrefix(token))
                stmt.executeUpdate()
            }
        }
        return token
    }

    /**
     * Looks the token up by hash. Returns the client id when the token is
     * active (unused and unexpired), null otherwise.
     */
    fun validate(token: String): String? {
        db.connection().use { conn ->
            conn.prepareStatement(
                "SELECT client_id, expires_at FROM enrollment_tokens WHERE token = ? AND used = 0"
            ).use { stmt ->
                stmt.setString(1, hash(token))
                val rs = stmt.executeQuery()
                if (!rs.next()) return null
                val expiresAt = rs.getString("expires_at")
                if (expiresAt != null &&
                    java.time.Instant.parse(expiresAt).isBefore(java.time.Instant.now())) {
                    return null
                }
                return rs.getString("client_id")
            }
        }
    }

    fun markUsed(token: String) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE enrollment_tokens SET used = 1 WHERE token = ?").use { stmt ->
                stmt.setString(1, hash(token))
                stmt.executeUpdate()
            }
        }
    }

    /**
     * Admin listing. [EnrollmentToken.token] carries the masked prefix, NOT a
     * usable credential — the plaintext is unrecoverable by design.
     */
    fun getAll(): List<EnrollmentToken> {
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery(
                    "SELECT token, client_id, created_at, used, token_prefix, expires_at FROM enrollment_tokens ORDER BY created_at DESC"
                )
                val now = java.time.Instant.now()
                val entries = mutableListOf<EnrollmentToken>()
                while (rs.next()) {
                    val prefix = rs.getString("token_prefix")
                    val expiresAt = rs.getString("expires_at")
                    entries.add(EnrollmentToken(
                        // Legacy rows (pre-V8) have no prefix and were invalidated
                        // by the migration; show the hash head so the row is still
                        // identifiable without being usable.
                        token = prefix ?: ("sha256:" + rs.getString("token").take(8) + "…"),
                        clientId = rs.getString("client_id"),
                        createdAt = rs.getString("created_at"),
                        used = rs.getInt("used") == 1,
                        masked = true,
                        expiresAt = expiresAt,
                        // Same rule as validate(): an unparseable or absent
                        // expires_at is treated as "no expiry", never as expired.
                        expired = expiresAt != null &&
                            runCatching { java.time.Instant.parse(expiresAt).isBefore(now) }.getOrDefault(false)
                    ))
                }
                return entries
            }
        }
    }

    companion object {
        /** Lowercase hex SHA-256 — the value stored in the `token` column. */
        internal fun hash(token: String): String =
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(token.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        /** Display-only fingerprint of a plaintext token, e.g. `AbC12dEf…`. */
        internal fun maskedPrefix(token: String): String = token.take(8) + "…"
    }
}
