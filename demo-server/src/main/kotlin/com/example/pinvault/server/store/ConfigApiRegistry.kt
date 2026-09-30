package com.example.pinvault.server.store

/**
 * Row-level access to the `config_apis` table — the registry every Config API
 * scope is keyed on, and the home of the per-scope `vault_enabled` switch.
 *
 * Two things this fixes, both found by E2E scenario C09:
 *
 *  1. The default Config API (`default-tls`) is started directly by Main.kt
 *     and never went through `POST /api/v1/config-apis/start`, so it had no
 *     row here. `PUT /api/v1/config-apis/default-tls/vault-enabled` then hit
 *     `UPDATE … WHERE id = ?` with zero affected rows and answered 404: the
 *     switch was dead on exactly the scope the sample app uses.
 *     [ensureRegistered] is called at boot so every served scope has a row.
 *  2. Nothing read the flag back. [isVaultEnabled] is now consulted by the
 *     vault download route.
 *
 * [isVaultEnabled] answers `true` for a scope with no row. A missing row means
 * "not registered", not "disabled" — failing closed there would silently break
 * embedded/test listeners that mount [com.example.pinvault.server.route.vaultRoutes]
 * without a registry entry. The flag is an operator switch, not an
 * authentication boundary; per-file `access_policy` is what guards content.
 */
class ConfigApiRegistry(private val db: DatabaseManager) {

    /**
     * Makes sure [id] has a row, without disturbing an existing one's
     * `vault_enabled` value.
     *
     * `INSERT OR IGNORE` + a separate `UPDATE` of the mutable columns, rather
     * than the `INSERT OR REPLACE` used by the start route: REPLACE deletes
     * and re-inserts, which would reset `vault_enabled` to its column default
     * (1) on every boot and quietly re-enable a vault the operator had turned
     * off.
     */
    fun ensureRegistered(id: String, port: Int, mode: String) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT OR IGNORE INTO config_apis (id, port, mode, auto_start, created_at) " +
                    "VALUES (?, ?, ?, 1, datetime('now'))"
            ).use { stmt ->
                stmt.setString(1, id)
                stmt.setInt(2, port)
                stmt.setString(3, mode)
                stmt.executeUpdate()
            }
            conn.prepareStatement("UPDATE config_apis SET port = ?, mode = ? WHERE id = ?").use { stmt ->
                stmt.setInt(1, port)
                stmt.setString(2, mode)
                stmt.setString(3, id)
                stmt.executeUpdate()
            }
        }
    }

    /** True when the scope may serve vault downloads. Unknown scope → true. */
    fun isVaultEnabled(id: String): Boolean {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT vault_enabled FROM config_apis WHERE id = ?").use { stmt ->
                stmt.setString(1, id)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.getInt("vault_enabled") == 1 else true
            }
        }
    }

    /** Writes the flag. Returns false when [id] has no row (caller → 404). */
    fun setVaultEnabled(id: String, enabled: Boolean): Boolean {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE config_apis SET vault_enabled = ? WHERE id = ?").use { stmt ->
                stmt.setInt(1, if (enabled) 1 else 0)
                stmt.setString(2, id)
                return stmt.executeUpdate() > 0
            }
        }
    }

    /** What [purge] removed, for the caller's follow-up (mock servers, audit). */
    data class Purged(val hostnames: List<String>, val cancelledChangeRequests: List<Long>)

    /**
     * Removes everything scoped to Config API [id], in one transaction.
     *
     * Deleting used to clear only the pin tables. The `config_apis` row stayed
     * (auto_start = 1, so the API came back on the next boot), and vault files,
     * vault tokens, device keys, host ACLs and host client certs stayed too —
     * a new API created under the same id inherited all of them.
     *
     * Kept on purpose:
     *  - `host_version_watermark`: a recreated API continues each host's version
     *    from the old maximum. Starting again at 1 would look like a downgrade
     *    to every device that still holds the old config, and they would
     *    refuse it.
     *  - `audit_log`: hash-chained, never rewritten.
     *  - `change_requests` history. Pending requests for [id] are closed as
     *    rejected so they cannot later apply to a new API with the same id —
     *    except [keepChangeRequest], the approved request performing this
     *    delete, which its replay closes as applied.
     */
    fun purge(id: String, keepChangeRequest: Long? = null): Purged {
        db.connection().use { conn ->
            conn.autoCommit = false
            try {
                val hostnames = conn.prepareStatement(
                    "SELECT hostname FROM hosts WHERE config_api_id = ? " +
                        "UNION SELECT hostname FROM pin_hashes WHERE config_api_id = ?"
                ).use { stmt ->
                    stmt.setString(1, id)
                    stmt.setString(2, id)
                    val rs = stmt.executeQuery()
                    buildList { while (rs.next()) add(rs.getString(1)) }
                }
                val cancelled = conn.prepareStatement(
                    "SELECT id FROM change_requests WHERE config_api_id = ? AND status = 'pending' AND id <> ?"
                ).use { stmt ->
                    stmt.setString(1, id)
                    stmt.setLong(2, keepChangeRequest ?: -1)
                    val rs = stmt.executeQuery()
                    buildList { while (rs.next()) add(rs.getLong(1)) }
                }
                for (cr in cancelled) {
                    conn.prepareStatement(
                        "UPDATE change_requests SET status = 'rejected', decided_by = 'system', decided_at = ?, " +
                            "reason = 'Config API deleted', body = NULL WHERE id = ? AND status = 'pending'"
                    ).use { stmt ->
                        stmt.setString(1, java.time.Instant.now().toString())
                        stmt.setLong(2, cr)
                        stmt.executeUpdate()
                    }
                }
                conn.prepareStatement("DELETE FROM config_apis WHERE id = ?").use { stmt ->
                    stmt.setString(1, id)
                    stmt.executeUpdate()
                }
                for (table in SCOPED_TABLES) {
                    conn.prepareStatement("DELETE FROM $table WHERE config_api_id = ?").use { stmt ->
                        stmt.setString(1, id)
                        stmt.executeUpdate()
                    }
                }
                conn.commit()
                return Purged(hostnames, cancelled)
            } catch (e: Exception) {
                conn.rollback()
                throw e
            }
        }
    }

    /** Reads the flag. Null when [id] has no row (caller → 404). */
    fun vaultEnabledOrNull(id: String): Boolean? {
        db.connection().use { conn ->
            conn.prepareStatement("SELECT vault_enabled FROM config_apis WHERE id = ?").use { stmt ->
                stmt.setString(1, id)
                val rs = stmt.executeQuery()
                return if (rs.next()) rs.getInt("vault_enabled") == 1 else null
            }
        }
    }

    companion object {
        /** Tables whose rows belong to one Config API (column `config_api_id`). */
        val SCOPED_TABLES = listOf(
            "pin_config", "pin_hashes", "pin_history", "hosts", "host_client_certs",
            "vault_files", "vault_file_tokens", "vault_distributions", "device_public_keys",
            "device_host_acl", "default_host_acl", "connection_history"
        )
    }
}
