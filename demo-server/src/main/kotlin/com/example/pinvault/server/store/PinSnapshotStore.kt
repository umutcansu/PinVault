package com.example.pinvault.server.store

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.sql.Connection

/** One stored pin set of a Config API: what devices were served after that save. */
data class PinSnapshot(
    val id: Long,
    val configApiId: String,
    val takenAt: String,
    val actor: String,
    val config: PinConfig
)

/** A snapshot row without its content, for listings. */
data class PinSnapshotSummary(
    val id: Long,
    val configApiId: String,
    val takenAt: String,
    val actor: String,
    val hostCount: Int,
    val version: Int,
    /** `hostname vN` for the hosts that differ from the snapshot before it; empty for the first. */
    val changedHosts: List<String>
)

/** One pin set a host had, with the snapshot it was first seen in. */
data class HostPinVersion(
    val snapshotId: Long,
    val hostname: String,
    val version: Int,
    val sha256: List<String>,
    val mtls: Boolean,
    val clientCertVersion: Int?,
    val forceUpdate: Boolean,
    val takenAt: String,
    val actor: String
)

/**
 * The pin sets a Config API has served, one row per save that changed
 * something ([PinConfigStore.save] writes them inside its transaction). The
 * newest [KEEP] rows per scope are kept. Read by the dashboard's history and
 * by the restore route; see `PinRestore`.
 */
class PinSnapshotStore(private val db: DatabaseManager) {

    /** Writes [config] as the state of [configApiId] now, unless the newest row already holds it. */
    fun record(conn: Connection, configApiId: String, config: PinConfig, actor: String, takenAt: String) {
        val json = JSON.encodeToString(PinConfig.serializer(), normalized(config))
        val hash = sha256Hex(json)
        val latest = conn.prepareStatement(
            "SELECT content_hash FROM pin_snapshots WHERE config_api_id = ? ORDER BY id DESC LIMIT 1"
        ).use { stmt ->
            stmt.setString(1, configApiId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getString(1) else null
        }
        if (latest == hash) return
        conn.prepareStatement(
            "INSERT INTO pin_snapshots (config_api_id, taken_at, actor, content_hash, config_json) VALUES (?, ?, ?, ?, ?)"
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, takenAt)
            stmt.setString(3, actor.take(200))
            stmt.setString(4, hash)
            stmt.setString(5, json)
            stmt.executeUpdate()
        }
        conn.prepareStatement(
            """DELETE FROM pin_snapshots WHERE config_api_id = ? AND id NOT IN (
                   SELECT id FROM pin_snapshots WHERE config_api_id = ? ORDER BY id DESC LIMIT ?)"""
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, configApiId)
            stmt.setInt(3, KEEP)
            stmt.executeUpdate()
        }
    }

    /** True when [configApiId] has a snapshot (the first save of an upgraded server records the state before it too). */
    fun hasAny(conn: Connection, configApiId: String): Boolean = conn.prepareStatement(
        "SELECT 1 FROM pin_snapshots WHERE config_api_id = ? LIMIT 1"
    ).use { stmt ->
        stmt.setString(1, configApiId)
        stmt.executeQuery().next()
    }

    fun get(id: Long): PinSnapshot? = db.connection().use { conn ->
        conn.prepareStatement(
            "SELECT id, config_api_id, taken_at, actor, config_json FROM pin_snapshots WHERE id = ?"
        ).use { stmt ->
            stmt.setLong(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toSnapshot() else null
        }
    }

    /** Newest first. */
    fun list(configApiId: String, limit: Int = KEEP): List<PinSnapshotSummary> {
        val rows = all(configApiId)   // oldest first, to diff each against the one before
        val out = mutableListOf<PinSnapshotSummary>()
        var previous: Map<String, HostPin> = emptyMap()
        var previousRoots: Set<String>? = null
        rows.forEach { snap ->
            val now = snap.config.pins.associateBy { it.hostname }
            val roots = snap.config.trustRoots.toSet()
            val changed = buildList {
                now.values.forEach { pin ->
                    val old = previous[pin.hostname]
                    if (old == null || old.copy(version = 0) != pin.copy(version = 0) || old.version != pin.version) add("${pin.hostname} v${pin.version}")
                }
                previous.keys.filter { it !in now }.forEach { add("$it removed") }
                if (previousRoots != null && previousRoots != roots) add("trust roots (${roots.size})")
            }
            previousRoots = roots
            out += PinSnapshotSummary(snap.id, snap.configApiId, snap.takenAt, snap.actor, now.size, snap.config.computedVersion(), changed)
            previous = now
        }
        return out.asReversed().take(limit)
    }

    /**
     * Every pin set [hostname] had in [configApiId], newest first: the
     * snapshots in which the host's entry differs from the one before.
     */
    fun versionsOf(configApiId: String, hostname: String): List<HostPinVersion> {
        val out = mutableListOf<HostPinVersion>()
        var previous: HostPin? = null
        all(configApiId).forEach { snap ->
            val pin = snap.config.pins.firstOrNull { it.hostname.equals(hostname, ignoreCase = true) }
            if (pin == null) { previous = null; return@forEach }
            if (previous == null || previous != pin) {
                out += HostPinVersion(snap.id, pin.hostname, pin.version, pin.sha256, pin.mtls, pin.clientCertVersion, pin.forceUpdate, snap.takenAt, snap.actor)
            }
            previous = pin
        }
        return out.asReversed()
    }

    private fun all(configApiId: String): List<PinSnapshot> = db.connection().use { conn ->
        conn.prepareStatement(
            "SELECT id, config_api_id, taken_at, actor, config_json FROM pin_snapshots WHERE config_api_id = ? ORDER BY id"
        ).use { stmt ->
            stmt.setString(1, configApiId)
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(rs.toSnapshot()) }
        }
    }

    private fun java.sql.ResultSet.toSnapshot() = PinSnapshot(
        id = getLong("id"),
        configApiId = getString("config_api_id"),
        takenAt = getString("taken_at"),
        actor = getString("actor"),
        config = JSON.decodeFromString(PinConfig.serializer(), getString("config_json"))
    )

    companion object {
        const val KEEP = 200
        private val JSON = Json { encodeDefaults = true; ignoreUnknownKeys = true }

        /** The stored shape: pins in name order, no envelope fields (issuedAt, expiresAt, configApiId are per fetch). */
        fun normalized(config: PinConfig): PinConfig = PinConfig(
            version = config.computedVersion(),
            pins = config.pins.sortedBy { it.hostname.lowercase() },
            forceUpdate = config.forceUpdate,
            trustRoots = config.trustRoots
        )

        private fun sha256Hex(text: String): String =
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
