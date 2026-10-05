package com.example.pinvault.server.store

import com.example.pinvault.server.service.attestation.AttestationPolicy
import java.time.Instant

/** Per-Config-API attestation policies (V21 `attestation_policies`); none stored = the defaults. */
class AttestationPolicyStore(private val db: DatabaseManager) {

    /** The stored policy of [configApiId] with its version, or null when none was ever PUT. */
    fun get(configApiId: String, defaults: AttestationPolicy): AttestationPolicy? = db.connection().use { conn ->
        conn.prepareStatement("SELECT version, policy_json FROM attestation_policies WHERE config_api_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            val rs = stmt.executeQuery()
            if (rs.next()) AttestationPolicy.fromStored(rs.getString("policy_json"), rs.getInt("version"), defaults) else null
        }
    }

    /** [get], or [defaults] (version 0). */
    fun effective(configApiId: String, defaults: AttestationPolicy): AttestationPolicy = get(configApiId, defaults) ?: defaults

    /** Replaces the policy of [configApiId]; the version becomes the stored one + 1 (1 for the first). */
    fun put(configApiId: String, policy: AttestationPolicy, updatedBy: String, now: Instant = Instant.now()): AttestationPolicy = db.connection().use { conn ->
        conn.autoCommit = false
        try {
            val current = conn.prepareStatement("SELECT version FROM attestation_policies WHERE config_api_id = ?").use { stmt ->
                stmt.setString(1, configApiId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getInt(1) else 0
            }
            val next = policy.copy(version = current + 1)
            conn.prepareStatement(
                """INSERT INTO attestation_policies (config_api_id, version, policy_json, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(config_api_id) DO UPDATE SET version = excluded.version, policy_json = excluded.policy_json,
                   updated_by = excluded.updated_by, updated_at = excluded.updated_at"""
            ).use { stmt ->
                stmt.setString(1, configApiId)
                stmt.setInt(2, next.version)
                stmt.setString(3, next.toJson())
                stmt.setString(4, updatedBy)
                stmt.setString(5, now.toString())
                stmt.executeUpdate()
            }
            conn.commit()
            next
        } catch (e: Exception) {
            runCatching { conn.rollback() }
            throw e
        } finally {
            runCatching { conn.autoCommit = true }
        }
    }

    /** Removes the stored policy (a purged Config API); true when there was one. */
    fun delete(configApiId: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("DELETE FROM attestation_policies WHERE config_api_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.executeUpdate() > 0
        }
    }
}
