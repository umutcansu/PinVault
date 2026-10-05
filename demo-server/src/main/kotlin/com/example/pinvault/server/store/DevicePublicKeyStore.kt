package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * Stores device RSA public keys per Config API. Used by VaultEncryptionService
 * to wrap AES-256-GCM session keys for files with encryption = "end_to_end".
 *
 * Keys are idempotent per (deviceId, configApiId): calling register() again
 * for the same pair overwrites the PEM. Who may do that is decided by the
 * registration route (VaultRoutes), not here.
 *
 * The same store over `device_user_auth_keys` ([userAuthKeys]) holds each
 * device's USER-AUTH key — the one its hardware uses only after the user
 * unlocked — for files with encryption = "user_auth". The two kinds live in
 * separate tables so neither registration can overwrite the other. A
 * user-auth key also carries what Android Key Attestation said about it
 * ([KeyAttestation]); the E2E table has no such columns.
 */
class DevicePublicKeyStore private constructor(
    private val db: DatabaseManager,
    /** Fixed table name, never caller input. */
    private val table: String
) {

    constructor(db: DatabaseManager) : this(db, E2E_TABLE)

    /** The device USER-AUTH keys of the same database (`device_user_auth_keys`). */
    fun userAuthKeys(): DevicePublicKeyStore = DevicePublicKeyStore(db, USER_AUTH_TABLE)

    private val withAttestation = table == USER_AUTH_TABLE

    private val columns = "device_id, config_api_id, public_key_pem, algorithm, registered_at" +
        if (withAttestation) ", attested, attestation_security_level, attestation_reason, key_kind, auth_timeout_seconds, biometric_only" else ""

    companion object {
        const val E2E_TABLE = "device_public_keys"
        const val USER_AUTH_TABLE = "device_user_auth_keys"

        /** Every table holding device keys: what a revocation or a Config API purge clears. */
        val TABLES = listOf(E2E_TABLE, USER_AUTH_TABLE)
    }

    /**
     * @param publicKeyPem PEM-encoded public key ("-----BEGIN PUBLIC KEY-----" …).
     *                     RSA 2048+ expected; shorter keys are accepted but should
     *                     be rejected at service layer.
     * @param algorithm e.g. "RSA-OAEP-SHA256" (default).
     * @param attestation what attestation said about a user-auth key (ignored
     *                    for E2E keys); null = not checked.
     */
    fun register(
        deviceId: String,
        configApiId: String,
        publicKeyPem: String,
        algorithm: String = "RSA-OAEP-SHA256",
        timestamp: String,
        attestation: KeyAttestation? = null
    ) {
        db.connection().use { conn ->
            val placeholders = if (withAttestation) "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?" else "?, ?, ?, ?, ?"
            conn.prepareStatement("INSERT OR REPLACE INTO $table ($columns) VALUES ($placeholders)").use { stmt ->
                stmt.setString(1, deviceId)
                stmt.setString(2, configApiId)
                stmt.setString(3, publicKeyPem)
                stmt.setString(4, algorithm)
                stmt.setString(5, timestamp)
                if (withAttestation) {
                    if (attestation == null) stmt.setNull(6, java.sql.Types.INTEGER) else stmt.setInt(6, if (attestation.attested) 1 else 0)
                    stmt.setString(7, attestation?.securityLevel)
                    stmt.setString(8, attestation?.reason)
                    stmt.setString(9, attestation?.keyKind)
                    attestation?.authTimeoutSeconds?.let { stmt.setLong(10, it) } ?: stmt.setNull(10, java.sql.Types.INTEGER)
                    attestation?.biometricOnly?.let { stmt.setInt(11, if (it) 1 else 0) } ?: stmt.setNull(11, java.sql.Types.INTEGER)
                }
                stmt.executeUpdate()
            }
        }
    }

    /** Removes the key of [deviceId] in [configApiId]; true when there was one. */
    fun delete(deviceId: String, configApiId: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("DELETE FROM $table WHERE device_id = ? AND config_api_id = ?").use { stmt ->
            stmt.setString(1, deviceId)
            stmt.setString(2, configApiId)
            stmt.executeUpdate() > 0
        }
    }

    /** How many device keys [configApiId] holds; the registration route caps it. */
    fun count(configApiId: String): Int = db.connection().use { conn ->
        conn.prepareStatement("SELECT COUNT(*) FROM $table WHERE config_api_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.executeQuery().use { rs -> if (rs.next()) rs.getInt(1) else 0 }
        }
    }

    fun get(deviceId: String, configApiId: String): DevicePublicKey? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT $columns FROM $table WHERE device_id = ? AND config_api_id = ?").use { stmt ->
                stmt.setString(1, deviceId)
                stmt.setString(2, configApiId)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.toKey() else null
            }
        }
    }

    fun listForConfigApi(configApiId: String): List<DevicePublicKey> {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT $columns FROM $table WHERE config_api_id = ? ORDER BY device_id").use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                return buildList { while (rs.next()) add(rs.toKey()) }
            }
        }
    }

    private fun java.sql.ResultSet.toKey() = DevicePublicKey(
        deviceId = getString("device_id"),
        configApiId = getString("config_api_id"),
        publicKeyPem = getString("public_key_pem"),
        algorithm = getString("algorithm"),
        registeredAt = getString("registered_at"),
        attestation = if (!withAttestation) null else {
            val attested = getInt("attested").takeUnless { wasNull() }
            attested?.let {
                KeyAttestation(
                    it == 1, getString("attestation_security_level"), getString("attestation_reason"),
                    keyKind = getString("key_kind"),
                    authTimeoutSeconds = getLong("auth_timeout_seconds").takeUnless { wasNull() },
                    biometricOnly = getInt("biometric_only").takeUnless { wasNull() }?.let { b -> b == 1 }
                )
            }
        }
    )
}

/**
 * What Android Key Attestation said about a key when it was registered: a
 * user-auth key, or (with no kind) the identity key a device enrolled with.
 */
@Serializable
data class KeyAttestation(
    /** The chain verified and the key is what the profile asks for, in TEE or StrongBox. */
    val attested: Boolean,
    /** tee | strongbox | software; null when unknown. */
    val securityLevel: String? = null,
    /** `ok`, or why it failed (`chain_missing`, `device_unlocked`, …). */
    val reason: String? = null,
    /** User-auth keys: `per_use` or `time_bound`; null when not known (no passing attestation, or an older row). */
    val keyKind: String? = null,
    /** User-auth keys, `time_bound`: seconds the key stays usable after an unlock. */
    val authTimeoutSeconds: Long? = null,
    /** User-auth keys: only a biometric unlocks it (not the screen-lock PIN/pattern/password). */
    val biometricOnly: Boolean? = null
)

@Serializable
data class DevicePublicKey(
    val deviceId: String,
    val configApiId: String,
    val publicKeyPem: String,
    val algorithm: String,
    val registeredAt: String,
    /** User-auth keys only; null = attestation not checked. */
    val attestation: KeyAttestation? = null
)
