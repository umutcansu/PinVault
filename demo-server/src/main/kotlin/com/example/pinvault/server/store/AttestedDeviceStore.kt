package com.example.pinvault.server.store

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.sql.Connection
import java.sql.ResultSet
import java.time.Instant

/** A device that attested in a Config API (V21 `attested_devices`), as listed and shown. */
@Serializable
data class AttestedDevice(
    val configApiId: String,
    val deviceId: String,
    /** False until a first attestation registered the device key (an annotated-only row). */
    val registered: Boolean,
    /** SHA-256 hex of the registered key's SPKI; null when unregistered. */
    val spkiSha256: String? = null,
    /** The registered key, Base64 DER; null when unregistered. */
    val publicKey: String? = null,
    /** What Android Key Attestation said about the key at registration (null = not checked). */
    val keyAttestation: KeyAttestation? = null,
    val firstSeen: String,
    val lastSeen: String,
    /** pass | reject; null before the first verdict. */
    val lastResult: String? = null,
    val lastArc: String? = null,
    val lastReasons: List<String> = emptyList(),
    val lastWarnings: List<String> = emptyList(),
    val lastPolicyVersion: Int? = null,
    val lastSdkVersion: String? = null,
    val attestCount: Int = 0,
    val forcePass: Boolean = false,
    val forceFail: Boolean = false,
    val annotations: List<String> = emptyList(),
    val keyMismatches: Int = 0,
    val lastKeyMismatchAt: String? = null,
    val verdictProvider: String? = null,
    /** pass | fail: the last Play Integrity verdict this server verified (ATTESTATION.md §11); null = none yet. */
    val playIntegrityResult: String? = null,
    /** When that verdict was verified (ISO instant). */
    val playIntegrityAt: String? = null,
    /** What Google said, as `PlayIntegrityVerifier` summarised it (JSON text: reason, deviceVerdicts, appVerdict, licensing, …). */
    val playIntegrity: String? = null,
    /** What the last report ran on: `ios`, or `android` for a report that names no platform; null before the first verdict. */
    val platform: String? = null,
    /** Base64 key id of the App Attest key an attestation registered (ATTESTATION.md §12); null = none. */
    val appAttestKeyId: String? = null,
    /** The authenticator counter of that key's last verified assertion (0 right after the attestation). */
    val appAttestCounter: Long? = null,
    /** pass | fail: the last App Attest verdict this server verified; null = none yet. */
    val appAttestResult: String? = null,
    /** When that verdict was verified (ISO instant). */
    val appAttestAt: String? = null,
    /** The verdict's summary (JSON text: reason, kind, appId, environment). */
    val appAttest: String? = null,
    /** The last report trimmed to its app, device and signals blocks (JSON text); only in the single-device answer. */
    val lastReport: String? = null
)

/** Verdict counters of a window (`GET …/attestation/stats`). */
@Serializable
data class AttestationWindowStats(
    val passes: Int,
    val rejects: Int,
    val byReason: Map<String, Int>,
    val byWarning: Map<String, Int>
)

/** How many devices a Config API has in each state. */
@Serializable
data class AttestedDeviceCounts(
    val total: Int,
    val registered: Int,
    val lastPassed: Int,
    val lastRejected: Int,
    val forcePass: Int,
    val forceFail: Int,
    val keyMismatches: Int
)

@Serializable
data class AttestedDevicePage(val items: List<AttestedDevice>, val total: Int, val page: Int, val pageSize: Int)

/**
 * Attested devices with their key, overrides and last verdict, plus the
 * hourly verdict counters behind the stats endpoint (V21 `attestation_verdict_counts`).
 */
class AttestedDeviceStore(private val db: DatabaseManager) {

    private val json = Json { ignoreUnknownKeys = true }
    private val strings = ListSerializer(String.serializer())

    fun get(configApiId: String, deviceId: String, withReport: Boolean = false): AttestedDevice? = db.connection().use { conn ->
        conn.prepareStatement("SELECT * FROM attested_devices WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            val rs = stmt.executeQuery()
            if (rs.next()) read(rs, withReport) else null
        }
    }

    /**
     * Registers [deviceId]'s key, inserting the row or filling an unregistered
     * one. False when the device already has a key (the caller compared it).
     */
    fun register(
        configApiId: String, deviceId: String, spkiSha256: String, publicKey: String,
        attestation: KeyAttestation?, now: Instant = Instant.now()
    ): Boolean = db.connection().use { conn ->
        val at = now.toString()
        val inserted = conn.prepareStatement(
            """INSERT INTO attested_devices (config_api_id, device_id, spki_sha256, public_key, key_attested, key_security_level, key_attestation_reason, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(config_api_id, device_id) DO UPDATE SET
                 spki_sha256 = excluded.spki_sha256, public_key = excluded.public_key, key_attested = excluded.key_attested,
                 key_security_level = excluded.key_security_level, key_attestation_reason = excluded.key_attestation_reason,
                 last_seen = excluded.last_seen
               WHERE attested_devices.spki_sha256 IS NULL"""
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            stmt.setString(3, spkiSha256)
            stmt.setString(4, publicKey)
            stmt.setInt(5, if (attestation?.attested == true) 1 else 0)
            stmt.setString(6, attestation?.securityLevel)
            stmt.setString(7, attestation?.reason)
            stmt.setString(8, at)
            stmt.setString(9, at)
            stmt.executeUpdate() > 0
        }
        inserted
    }

    /** Records a verdict on a registered device and counts it for the stats. */
    fun recordVerdict(
        configApiId: String, deviceId: String, result: String, arc: String,
        reasons: List<String>, warnings: List<String>, policyVersion: Int,
        trimmedReport: String?, sdkVersion: String?, verdictProvider: String?, verdictToken: String?,
        now: Instant = Instant.now(),
        /** What the report ran on (`ios`, `android`); null keeps the stored one. */
        platform: String? = null
    ) = db.connection().use { conn ->
        inTransaction(conn) {
            conn.prepareStatement(
                """UPDATE attested_devices SET last_seen = ?, last_result = ?, last_arc = ?, last_reasons = ?, last_warnings = ?,
                   last_report = ?, last_policy_version = ?, last_sdk_version = ?, attest_count = attest_count + 1,
                   verdict_provider = COALESCE(?, verdict_provider), verdict_token = COALESCE(?, verdict_token),
                   platform = COALESCE(?, platform)
                   WHERE config_api_id = ? AND device_id = ?"""
            ).use { stmt ->
                stmt.setString(1, now.toString())
                stmt.setString(2, result)
                stmt.setString(3, arc)
                stmt.setString(4, json.encodeToString(strings, reasons))
                stmt.setString(5, json.encodeToString(strings, warnings))
                stmt.setString(6, trimmedReport)
                stmt.setInt(7, policyVersion)
                stmt.setString(8, sdkVersion)
                stmt.setString(9, verdictProvider)
                stmt.setString(10, verdictToken)
                stmt.setString(11, platform)
                stmt.setString(12, configApiId)
                stmt.setString(13, deviceId)
                stmt.executeUpdate()
            }
            val hour = now.toEpochMilli() / HOUR_MS
            conn.prepareStatement(
                """INSERT INTO attestation_verdict_counts (config_api_id, hour, kind, name, count) VALUES (?, ?, ?, ?, 1)
                   ON CONFLICT(config_api_id, hour, kind, name) DO UPDATE SET count = count + 1"""
            ).use { stmt ->
                fun bump(kind: String, name: String) {
                    stmt.setString(1, configApiId); stmt.setLong(2, hour); stmt.setString(3, kind); stmt.setString(4, name)
                    stmt.addBatch()
                }
                bump("result", result)
                reasons.forEach { bump("reason", it) }
                warnings.forEach { bump("warning", it) }
                stmt.executeBatch()
            }
            // Counters older than the retention go; cheap on the primary key's hour.
            conn.prepareStatement("DELETE FROM attestation_verdict_counts WHERE hour < ?").use { stmt ->
                stmt.setLong(1, hour - RETENTION_HOURS)
                stmt.executeUpdate()
            }
        }
    }

    /** Records a Play Integrity verdict this server verified ([result] = pass | fail, [summary] JSON). */
    fun recordPlayIntegrity(configApiId: String, deviceId: String, result: String, summary: String, now: Instant = Instant.now()) = db.connection().use { conn ->
        conn.prepareStatement("UPDATE attested_devices SET play_integrity_result = ?, play_integrity_at = ?, play_integrity = ? WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, result)
            stmt.setString(2, now.toString())
            stmt.setString(3, summary)
            stmt.setString(4, configApiId)
            stmt.setString(5, deviceId)
            stmt.executeUpdate()
        }
    }

    /** The App Attest key on record for a device: [keyId] Base64, [publicKey] Base64 DER SPKI, its last [counter]. */
    data class AppAttestKey(val keyId: String, val publicKey: String, val counter: Long)

    fun appAttestKey(configApiId: String, deviceId: String): AppAttestKey? = db.connection().use { conn ->
        conn.prepareStatement("SELECT app_attest_key_id, app_attest_public_key, app_attest_counter FROM attested_devices WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            val rs = stmt.executeQuery()
            if (!rs.next()) return@use null
            val keyId = rs.getString(1) ?: return@use null
            val publicKey = rs.getString(2) ?: return@use null
            AppAttestKey(keyId, publicKey, rs.getLong(3))
        }
    }

    /** Stores the key a verified App Attest attestation registered (counter 0) with its verdict. */
    fun registerAppAttestKey(configApiId: String, deviceId: String, keyId: String, publicKey: String, summary: String, now: Instant = Instant.now()) =
        db.connection().use { conn ->
            conn.prepareStatement(
                """UPDATE attested_devices SET app_attest_key_id = ?, app_attest_public_key = ?, app_attest_counter = 0,
                   app_attest_result = 'pass', app_attest_at = ?, app_attest = ? WHERE config_api_id = ? AND device_id = ?"""
            ).use { stmt ->
                stmt.setString(1, keyId)
                stmt.setString(2, publicKey)
                stmt.setString(3, now.toString())
                stmt.setString(4, summary)
                stmt.setString(5, configApiId)
                stmt.setString(6, deviceId)
                stmt.executeUpdate()
            }
        }

    /**
     * Moves [keyId]'s counter to [counter] and records a passing verdict —
     * only while the stored counter is lower, so two rounds racing with the
     * same counter cannot both pass. False when it was not (a replay).
     */
    fun advanceAppAttestCounter(configApiId: String, deviceId: String, keyId: String, counter: Long, summary: String, now: Instant = Instant.now()): Boolean =
        db.connection().use { conn ->
            conn.prepareStatement(
                """UPDATE attested_devices SET app_attest_counter = ?, app_attest_result = 'pass', app_attest_at = ?, app_attest = ?
                   WHERE config_api_id = ? AND device_id = ? AND app_attest_key_id = ? AND app_attest_counter < ?"""
            ).use { stmt ->
                stmt.setLong(1, counter)
                stmt.setString(2, now.toString())
                stmt.setString(3, summary)
                stmt.setString(4, configApiId)
                stmt.setString(5, deviceId)
                stmt.setString(6, keyId)
                stmt.setLong(7, counter)
                stmt.executeUpdate() > 0
            }
        }

    /** Records an App Attest verdict that failed; the key on record (if any) stays. */
    fun recordAppAttestFailure(configApiId: String, deviceId: String, summary: String, now: Instant = Instant.now()) = db.connection().use { conn ->
        conn.prepareStatement("UPDATE attested_devices SET app_attest_result = 'fail', app_attest_at = ?, app_attest = ? WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, now.toString())
            stmt.setString(2, summary)
            stmt.setString(3, configApiId)
            stmt.setString(4, deviceId)
            stmt.executeUpdate()
        }
    }

    /** Counts an attestation signed with a key other than the registered one. */
    fun recordKeyMismatch(configApiId: String, deviceId: String, now: Instant = Instant.now()): Int = db.connection().use { conn ->
        conn.prepareStatement("UPDATE attested_devices SET key_mismatches = key_mismatches + 1, last_key_mismatch_at = ? WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, now.toString())
            stmt.setString(2, configApiId)
            stmt.setString(3, deviceId)
            stmt.executeUpdate()
        }
        conn.prepareStatement("SELECT key_mismatches FROM attested_devices WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) else 0
        }
    }

    /** Sets the overrides and annotations; a device that never attested gets an unregistered row. */
    fun annotate(
        configApiId: String, deviceId: String, forcePass: Boolean, forceFail: Boolean, annotations: List<String>,
        now: Instant = Instant.now()
    ): AttestedDevice = db.connection().use { conn ->
        val at = now.toString()
        conn.prepareStatement(
            """INSERT INTO attested_devices (config_api_id, device_id, first_seen, last_seen, force_pass, force_fail, annotations)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(config_api_id, device_id) DO UPDATE SET
                 force_pass = excluded.force_pass, force_fail = excluded.force_fail, annotations = excluded.annotations"""
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            stmt.setString(3, at)
            stmt.setString(4, at)
            stmt.setInt(5, if (forcePass) 1 else 0)
            stmt.setInt(6, if (forceFail) 1 else 0)
            stmt.setString(7, json.encodeToString(strings, annotations))
            stmt.executeUpdate()
        }
        get(configApiId, deviceId)!!
    }

    /** Forgets the device entirely (its key, verdicts and annotations); true when there was a row. */
    fun forget(configApiId: String, deviceId: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("DELETE FROM attested_devices WHERE config_api_id = ? AND device_id = ?").use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setString(2, deviceId)
            stmt.executeUpdate() > 0
        }
    }

    /** Removes everything of a purged Config API. */
    fun purge(configApiId: String) = db.connection().use { conn ->
        for (table in listOf("attested_devices", "attestation_verdict_counts")) {
            conn.prepareStatement("DELETE FROM $table WHERE config_api_id = ?").use { stmt ->
                stmt.setString(1, configApiId)
                stmt.executeUpdate()
            }
        }
    }

    /**
     * Devices of [configApiId], most recently seen first. [result] = `pass`
     * / `reject` keeps only devices whose last verdict was that; [q] matches
     * the device id, an annotation, a reason or a warning (substring).
     */
    fun list(configApiId: String, result: String? = null, q: String? = null, page: Int = 1, pageSize: Int = 50): AttestedDevicePage = db.connection().use { conn ->
        val where = StringBuilder("WHERE config_api_id = ?")
        val args = mutableListOf<String>(configApiId)
        if (!result.isNullOrBlank()) { where.append(" AND last_result = ?"); args += result }
        if (!q.isNullOrBlank()) {
            where.append(" AND (device_id LIKE ? ESCAPE '\\' OR annotations LIKE ? ESCAPE '\\' OR last_reasons LIKE ? ESCAPE '\\' OR last_warnings LIKE ? ESCAPE '\\' OR last_arc = ?)")
            val like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += listOf(like, like, like, like, q)
        }
        val total = conn.prepareStatement("SELECT COUNT(*) FROM attested_devices $where").use { stmt ->
            args.forEachIndexed { i, a -> stmt.setString(i + 1, a) }
            stmt.executeQuery().let { rs -> if (rs.next()) rs.getInt(1) else 0 }
        }
        val size = pageSize.coerceIn(1, 500)
        val pageNo = page.coerceAtLeast(1)
        val items = conn.prepareStatement("SELECT * FROM attested_devices $where ORDER BY last_seen DESC, device_id LIMIT ? OFFSET ?").use { stmt ->
            args.forEachIndexed { i, a -> stmt.setString(i + 1, a) }
            stmt.setInt(args.size + 1, size)
            stmt.setInt(args.size + 2, (pageNo - 1) * size)
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(read(rs, withReport = false)) }
        }
        AttestedDevicePage(items, total, pageNo, size)
    }

    fun counts(configApiId: String): AttestedDeviceCounts = db.connection().use { conn ->
        conn.prepareStatement(
            """SELECT COUNT(*), SUM(spki_sha256 IS NOT NULL), SUM(last_result = 'pass'), SUM(last_result = 'reject'),
                      SUM(force_pass), SUM(force_fail), SUM(key_mismatches > 0)
               FROM attested_devices WHERE config_api_id = ?"""
        ).use { stmt ->
            stmt.setString(1, configApiId)
            val rs = stmt.executeQuery()
            rs.next()
            AttestedDeviceCounts(rs.getInt(1), rs.getInt(2), rs.getInt(3), rs.getInt(4), rs.getInt(5), rs.getInt(6), rs.getInt(7))
        }
    }

    /** Verdicts of the last [hours] hours (the current hour included). */
    fun windowStats(configApiId: String, hours: Int, now: Instant = Instant.now()): AttestationWindowStats = db.connection().use { conn ->
        conn.prepareStatement(
            "SELECT kind, name, SUM(count) FROM attestation_verdict_counts WHERE config_api_id = ? AND hour > ? GROUP BY kind, name"
        ).use { stmt ->
            stmt.setString(1, configApiId)
            stmt.setLong(2, now.toEpochMilli() / HOUR_MS - hours)
            val rs = stmt.executeQuery()
            var passes = 0
            var rejects = 0
            val reasons = linkedMapOf<String, Int>()
            val warnings = linkedMapOf<String, Int>()
            while (rs.next()) {
                val name = rs.getString(2)
                val count = rs.getInt(3)
                when (rs.getString(1)) {
                    "result" -> if (name == "pass") passes = count else if (name == "reject") rejects = count
                    "reason" -> reasons[name] = count
                    "warning" -> warnings[name] = count
                }
            }
            AttestationWindowStats(passes, rejects, reasons.toSortedMap(), warnings.toSortedMap())
        }
    }

    private fun read(rs: ResultSet, withReport: Boolean): AttestedDevice {
        val spki = rs.getString("spki_sha256")
        val level = rs.getString("key_security_level")
        val reason = rs.getString("key_attestation_reason")
        return AttestedDevice(
            configApiId = rs.getString("config_api_id"),
            deviceId = rs.getString("device_id"),
            registered = spki != null,
            spkiSha256 = spki,
            publicKey = rs.getString("public_key"),
            keyAttestation = if (spki == null || (reason == null && level == null && rs.getInt("key_attested") == 0)) null
                else KeyAttestation(rs.getInt("key_attested") == 1, level, reason),
            firstSeen = rs.getString("first_seen"),
            lastSeen = rs.getString("last_seen"),
            lastResult = rs.getString("last_result"),
            lastArc = rs.getString("last_arc"),
            lastReasons = decode(rs.getString("last_reasons")),
            lastWarnings = decode(rs.getString("last_warnings")),
            lastPolicyVersion = rs.getObject("last_policy_version")?.let { rs.getInt("last_policy_version") },
            lastSdkVersion = rs.getString("last_sdk_version"),
            attestCount = rs.getInt("attest_count"),
            forcePass = rs.getInt("force_pass") == 1,
            forceFail = rs.getInt("force_fail") == 1,
            annotations = decode(rs.getString("annotations")),
            keyMismatches = rs.getInt("key_mismatches"),
            lastKeyMismatchAt = rs.getString("last_key_mismatch_at"),
            verdictProvider = rs.getString("verdict_provider"),
            playIntegrityResult = rs.getString("play_integrity_result"),
            playIntegrityAt = rs.getString("play_integrity_at"),
            playIntegrity = rs.getString("play_integrity"),
            platform = rs.getString("platform"),
            appAttestKeyId = rs.getString("app_attest_key_id"),
            appAttestCounter = rs.getObject("app_attest_counter")?.let { rs.getLong("app_attest_counter") },
            appAttestResult = rs.getString("app_attest_result"),
            appAttestAt = rs.getString("app_attest_at"),
            appAttest = rs.getString("app_attest"),
            lastReport = if (withReport) rs.getString("last_report") else null
        )
    }

    private fun decode(text: String?): List<String> = try {
        if (text.isNullOrBlank()) emptyList() else json.decodeFromString(strings, text)
    } catch (_: Exception) {
        emptyList()
    }

    private fun <T> inTransaction(conn: Connection, block: () -> T): T {
        conn.autoCommit = false
        try {
            val result = block()
            if (!conn.autoCommit) conn.commit()
            return result
        } catch (e: Exception) {
            runCatching { conn.rollback() }
            throw e
        } finally {
            runCatching { conn.autoCommit = true }
        }
    }

    companion object {
        private const val HOUR_MS = 3_600_000L

        /** Hourly counters are kept this long. */
        const val RETENTION_HOURS = 30 * 24L
    }
}
