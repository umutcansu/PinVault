package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * Stores device RSA public keys per Config API. Used by VaultEncryptionService
 * to wrap AES-256-GCM session keys for files with encryption = "end_to_end".
 *
 * Keys are idempotent per (deviceId, configApiId): calling register() again
 * for the same pair overwrites the PEM. This supports re-enrollment and key
 * rotation on the device side — the device generates a new Android-Keystore
 * RSA key and re-registers it.
 */
class DevicePublicKeyStore(private val db: DatabaseManager) {

    /**
     * @param publicKeyPem PEM-encoded public key ("-----BEGIN PUBLIC KEY-----" …).
     *                     RSA 2048+ expected; shorter keys are accepted but should
     *                     be rejected at service layer.
     * @param algorithm e.g. "RSA-OAEP-SHA256" (default).
     */
    fun register(
        deviceId: String,
        configApiId: String,
        publicKeyPem: String,
        algorithm: String = "RSA-OAEP-SHA256",
        timestamp: String
    ) {
        db.connection().use { conn ->
            conn.prepareStatement("""
                INSERT OR REPLACE INTO device_public_keys
                    (device_id, config_api_id, public_key_pem, algorithm, registered_at)
                VALUES (?, ?, ?, ?, ?)
            """).use { stmt ->
                stmt.setString(1, deviceId)
                stmt.setString(2, configApiId)
                stmt.setString(3, publicKeyPem)
                stmt.setString(4, algorithm)
                stmt.setString(5, timestamp)
                stmt.executeUpdate()
            }
        }
    }

    fun get(deviceId: String, configApiId: String): DevicePublicKey? {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT device_id, config_api_id, public_key_pem, algorithm, registered_at
                FROM device_public_keys
                WHERE device_id = ? AND config_api_id = ?
            """).use { stmt ->
                stmt.setString(1, deviceId)
                stmt.setString(2, configApiId)
                val rs = stmt.executeQuery()
                return if (rs.next()) DevicePublicKey(
                    deviceId = rs.getString("device_id"),
                    configApiId = rs.getString("config_api_id"),
                    publicKeyPem = rs.getString("public_key_pem"),
                    algorithm = rs.getString("algorithm"),
                    registeredAt = rs.getString("registered_at")
                ) else null
            }
        }
    }

    fun listForConfigApi(configApiId: String): List<DevicePublicKey> {
        db.connection().use { conn ->
            conn.prepareStatement("""
                SELECT device_id, config_api_id, public_key_pem, algorithm, registered_at
                FROM device_public_keys
                WHERE config_api_id = ?
                ORDER BY device_id
            """).use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList {
                    while (rs.next()) add(DevicePublicKey(
                        deviceId = rs.getString("device_id"),
                        configApiId = rs.getString("config_api_id"),
                        publicKeyPem = rs.getString("public_key_pem"),
                        algorithm = rs.getString("algorithm"),
                        registeredAt = rs.getString("registered_at")
                    ))
                }
            }
        }
    }
}

@Serializable
data class DevicePublicKey(
    val deviceId: String,
    val configApiId: String,
    val publicKeyPem: String,
    val algorithm: String,
    val registeredAt: String
)
