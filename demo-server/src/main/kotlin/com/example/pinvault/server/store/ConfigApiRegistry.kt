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
}
