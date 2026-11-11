package com.example.pinvault.server.service

import com.example.pinvault.server.store.DatabaseManager
import java.io.File

/**
 * Refuses to start when key material this server made before is missing.
 *
 * The config signing key, the client CA, the server's TLS keystore and the
 * server CA are made on the first start and then trusted by every device: the
 * app carries the signing key's public half and the server's TLS pins, the
 * devices' certificates chain to the client CA. A start that found one of
 * them missing (a database restored without `data/certs`, a volume that was
 * not mounted) used to make a new one and come up cleanly — and every device
 * then refused everything it said (review 2026-11-11, C-10).
 *
 * What was made is recorded in `key_material` (V31). A recorded file that is
 * gone stops the start. A database from before V31 has no records: there a
 * file that every start makes counts as recorded when the database already
 * holds data (pins, identities or audit entries) — an existing install, not a
 * first start. `ALLOW_KEY_REGENERATION=<name>,…` (or `all`) lets the named
 * ones be made again on purpose.
 */
class KeyMaterialGuard(private val db: DatabaseManager) {

    /**
     * One piece of key material. [alwaysMade]: every start makes it when it is
     * missing, so a pre-V31 database with data had it.
     */
    data class Item(val name: String, val file: File, val alwaysMade: Boolean = true)

    /** Null: go ahead. Otherwise why the start is refused. */
    fun startProblem(items: List<Item>, allowed: Set<String> = allowedFromEnv()): String? {
        val recorded = recorded()
        val existingInstall = recorded.isEmpty() && hasData()
        val missing = items
            .filter { !it.file.exists() }
            .filter { it.name in recorded || (existingInstall && it.alwaysMade) }
            .filterNot { ALL in allowed || it.name in allowed }
        if (missing.isEmpty()) return null
        return "Refusing to start: key material this server made before is missing — " +
            missing.joinToString { "${it.name} (${it.file.path})" } + ". Every device that trusts it would refuse this " +
            "server (a database restored without its key files? a volume not mounted?). Restore the files, or set " +
            "ALLOW_KEY_REGENERATION=${missing.joinToString(",") { it.name }} (or all) to make new ones on purpose — " +
            "devices then need what trusts the new keys (an app build or signing-key set, new pins, re-enrollment)."
    }

    /** Records every item whose file exists now (after the start made what it makes). */
    fun record(items: List<Item>) {
        db.connection().use { conn ->
            conn.prepareStatement("INSERT OR IGNORE INTO key_material (name, recorded_at) VALUES (?, ?)").use { stmt ->
                for (item in items.filter { it.file.exists() }) {
                    stmt.setString(1, item.name)
                    stmt.setLong(2, System.currentTimeMillis())
                    stmt.executeUpdate()
                }
            }
        }
    }

    fun recorded(): Set<String> = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            stmt.executeQuery("SELECT name FROM key_material").use { rs ->
                buildSet { while (rs.next()) add(rs.getString(1)) }
            }
        }
    }

    private fun hasData(): Boolean = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            stmt.executeQuery(
                "SELECT EXISTS(SELECT 1 FROM pin_hashes) OR EXISTS(SELECT 1 FROM client_identities) OR EXISTS(SELECT 1 FROM audit_log)"
            ).use { rs -> rs.next() && rs.getInt(1) == 1 }
        }
    }

    companion object {
        const val ALL = "all"
        const val SIGNING_KEY = "signing-key"
        const val CLIENT_CA = "client-ca"
        const val SERVER_TLS = "server-tls"
        const val SERVER_TLS_BACKUP = "server-tls-backup"
        const val SERVER_CA = "server-ca"
        const val SERVER_CA_BACKUP = "server-ca-backup"

        /** `ALLOW_KEY_REGENERATION`: names (lower case), or `all`. */
        fun allowedFromEnv(value: String? = ServerEnv.get("ALLOW_KEY_REGENERATION")): Set<String> =
            value?.split(',')?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }?.toSet() ?: emptySet()
    }
}
