package com.example.pinvault.server.store

import kotlinx.serialization.Serializable

/**
 * A CSR-enrolled device: its permanent key (as an SPKI hash) and the
 * certificate currently issued over it.
 */
@Serializable
data class ClientIdentity(
    val clientId: String,
    val configApiId: String,
    /** SHA-256 of the device key's SubjectPublicKeyInfo, Base64 — the same form as a pin. */
    val spkiSha256: String,
    /** Serial of the current certificate, hex. */
    val serial: String,
    val notBefore: String,
    val notAfter: String,
    val keyRegisteredAt: String,
    val lastRenewedAt: String? = null,
    val renewCount: Int = 0,
    val revoked: Boolean = false,
    val deviceAlias: String? = null,
    val deviceUid: String? = null,
    /** What Android Key Attestation said about the key at enrollment (`ENROLLMENT_ATTESTATION`); null = not checked. */
    val attestation: KeyAttestation? = null
)

/**
 * The registry a client-certificate renewal is checked against.
 *
 * Unlike `client_certs`, a row here is never silently replaced: enrolling a
 * client id that was revoked is refused ([register] returns false), and
 * [recordRenewal] touches only the certificate columns — the key and the
 * revoked flag stay what they are.
 *
 * Every key a client id enrolled with is also kept in `client_keys`, so that
 * [forget] can retire them all: a certificate over a retired key is refused
 * on every request ([isRetired]) and the key never enrolls again.
 */
class ClientIdentityStore(private val db: DatabaseManager) {

    /** What [forget] did. */
    enum class Forget { FORGOTTEN, NOT_FOUND, NOT_REVOKED }

    fun get(clientId: String): ClientIdentity? = db.connection().use { conn ->
        conn.prepareStatement("SELECT $COLUMNS FROM client_identities WHERE client_id = ?").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toIdentity() else null
        }
    }

    /**
     * Enrollment: registers the key and the first certificate. An existing
     * row is replaced only while it is not revoked — a fresh enrollment of a
     * revoked client id is refused and the row is left as it is. A retired
     * key is refused too, under any client id.
     *
     * @return false when the client id is revoked or the key retired, or
     *   (with `replaceKey` false) the id is enrolled over another key.
     */
    fun register(
        clientId: String,
        configApiId: String,
        spkiSha256: String,
        serial: String,
        notBefore: String,
        notAfter: String,
        deviceAlias: String?,
        deviceUid: String?,
        now: String,
        /** False: an active identity keeps its key — a different one is refused (open enrollment). */
        replaceKey: Boolean = true,
        /**
         * The `client_certs` row of the same certificate, written in the same
         * transaction and only while that row is not revoked. Written apart, a
         * revocation landing between the two writes was undone by the second
         * (INSERT OR REPLACE with revoked = 0).
         */
        certRecord: CertRecord? = null,
        /** What Android Key Attestation said about the key (`ENROLLMENT_ATTESTATION`); null = not checked. */
        attestation: KeyAttestation? = null
    ): Boolean = db.connection().use { conn ->
        inTransaction(conn) {
            // Re-enrolling an active client id over a new key (a token minted
            // again for the same id) replaces its key: the replaced one is
            // retired, so certificates over it are refused on every request
            // (RevocationGate) and it never enrolls again. A write, so the
            // transaction holds the write lock from its first statement; all of
            // it is rolled back when the registration below is refused.
            conn.prepareStatement(
                """
                INSERT INTO client_keys (client_id, spki_sha256, registered_at, retired_at)
                SELECT client_id, spki_sha256, key_registered_at, ? FROM client_identities
                WHERE client_id = ? AND revoked = 0 AND spki_sha256 <> ?
                ON CONFLICT(client_id, spki_sha256) DO UPDATE SET retired_at = COALESCE(client_keys.retired_at, excluded.retired_at)
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.setString(3, spkiSha256)
                stmt.executeUpdate()
            }
            // ...and any older key of the id that is still live.
            conn.prepareStatement("UPDATE client_keys SET retired_at = ? WHERE client_id = ? AND spki_sha256 <> ? AND retired_at IS NULL").use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.setString(3, spkiSha256)
                stmt.executeUpdate()
            }
            val registered = conn.prepareStatement(
                """
                INSERT INTO client_identities
                    (client_id, config_api_id, spki_sha256, serial, not_before, not_after, key_registered_at,
                     last_renewed_at, renew_count, revoked, device_alias, device_uid,
                     attested, attestation_security_level, attestation_reason)
                SELECT ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM client_keys WHERE spki_sha256 = ? AND retired_at IS NOT NULL)
                ON CONFLICT(client_id) DO UPDATE SET
                    config_api_id = excluded.config_api_id,
                    spki_sha256 = excluded.spki_sha256,
                    serial = excluded.serial,
                    not_before = excluded.not_before,
                    not_after = excluded.not_after,
                    key_registered_at = excluded.key_registered_at,
                    last_renewed_at = NULL,
                    renew_count = 0,
                    device_alias = excluded.device_alias,
                    device_uid = excluded.device_uid,
                    attested = excluded.attested,
                    attestation_security_level = excluded.attestation_security_level,
                    attestation_reason = excluded.attestation_reason
                WHERE client_identities.revoked = 0 AND (? = 1 OR client_identities.spki_sha256 = excluded.spki_sha256)
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, clientId)
                stmt.setString(2, configApiId)
                stmt.setString(3, spkiSha256)
                stmt.setString(4, serial)
                stmt.setString(5, notBefore)
                stmt.setString(6, notAfter)
                stmt.setString(7, now)
                stmt.setString(8, deviceAlias)
                stmt.setString(9, deviceUid)
                if (attestation == null) stmt.setNull(10, java.sql.Types.INTEGER) else stmt.setInt(10, if (attestation.attested) 1 else 0)
                stmt.setString(11, attestation?.securityLevel)
                stmt.setString(12, attestation?.reason)
                stmt.setString(13, spkiSha256)
                stmt.setInt(14, if (replaceKey) 1 else 0)
                stmt.executeUpdate() > 0
            }
            val certWritten = !registered || certRecord == null ||
                conn.prepareStatement(CLIENT_CERT_UPSERT_UNLESS_REVOKED).use { stmt ->
                    bindClientCertUpsert(stmt, clientId, certRecord.commonName, certRecord.fingerprint, now, deviceAlias, deviceUid, certRecord.deviceUidProven)
                    stmt.executeUpdate() > 0
                }
            if (registered && certWritten) {
                conn.prepareStatement("INSERT OR IGNORE INTO client_keys (client_id, spki_sha256, registered_at) VALUES (?, ?, ?)").use { stmt ->
                    stmt.setString(1, clientId)
                    stmt.setString(2, spkiSha256)
                    stmt.setString(3, now)
                    stmt.executeUpdate()
                }
            } else {
                conn.rollback()
            }
            registered && certWritten
        }
    }

    /** The `client_certs` row [register] writes with the identity. */
    data class CertRecord(
        val commonName: String,
        val fingerprint: String,
        /** The device id is proven (V20): see `ClientCertRecord.deviceUidProven`. */
        val deviceUidProven: Boolean = false
    )

    /**
     * A server-made (P12) certificate replaced [clientId]'s CSR identity — a
     * token minted again for the same id, used without a CSR. Every key the
     * identity held is retired and its row deleted, so neither its
     * certificates nor a renewal over its key are accepted any more. A revoked
     * identity is left alone (its enrollment is refused before this).
     *
     * @return how many keys were retired.
     */
    fun supersede(clientId: String, now: String): Int = db.connection().use { conn ->
        inTransaction(conn) {
            conn.prepareStatement(
                """
                INSERT INTO client_keys (client_id, spki_sha256, registered_at, retired_at)
                SELECT client_id, spki_sha256, key_registered_at, ? FROM client_identities
                WHERE client_id = ? AND revoked = 0
                ON CONFLICT(client_id, spki_sha256) DO UPDATE SET retired_at = COALESCE(client_keys.retired_at, excluded.retired_at)
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.executeUpdate()
            }
            val deleted = conn.prepareStatement("DELETE FROM client_identities WHERE client_id = ? AND revoked = 0").use { stmt ->
                stmt.setString(1, clientId)
                stmt.executeUpdate()
            }
            if (deleted == 0) {
                conn.rollback()
                0
            } else {
                conn.prepareStatement("UPDATE client_keys SET retired_at = ? WHERE client_id = ? AND retired_at IS NULL").use { stmt ->
                    stmt.setString(1, now)
                    stmt.setString(2, clientId)
                    stmt.executeUpdate()
                }
                conn.prepareStatement("SELECT COUNT(*) FROM client_keys WHERE client_id = ? AND retired_at = ?").use { stmt ->
                    stmt.setString(1, clientId)
                    stmt.setString(2, now)
                    stmt.executeQuery().use { rs -> if (rs.next()) rs.getInt(1) else 0 }
                }
            }
        }
    }

    /** What revoking or forgetting an identity took from the device(s) it stood for. */
    data class DeviceCleanup(
        /** The device ids cut off: the client id itself and the device ids the identity proved ([recordDeviceProof]). */
        val deviceIds: List<String>,
        /** Vault file tokens of those devices revoked, in every Config API. */
        val vaultTokensRevoked: Int,
        /** E2E keys of those devices deleted, in every Config API. */
        val e2eKeysDeleted: Int,
        /** User-auth keys of those devices deleted, in every Config API. */
        val userAuthKeysDeleted: Int,
        /**
         * Device ids the identity only CLAIMED (the `deviceUid` sent at
         * enrollment) and never proved: left alone, since anyone enrolling can
         * name a victim's device id. An administrator cascades to them
         * deliberately with `cascadeUnverified`.
         */
        val unverifiedDeviceIds: List<String> = emptyList()
    ) {
        val isEmpty: Boolean get() = vaultTokensRevoked == 0 && e2eKeysDeleted == 0 && userAuthKeysDeleted == 0
    }

    /** What [revokeWithDevices] did; [found] is false when no certificate or identity has this id. */
    data class Revocation(val found: Boolean, val cleanup: DeviceCleanup)

    /**
     * Revokes [clientId] in `client_certs` and `client_identities` and cuts the
     * device it stood for off the vault, in one transaction: every vault token
     * of that device is revoked and its E2E and user-auth keys are deleted, in
     * every Config API. Revoking only the certificate left a revoked device
     * downloading token and end_to_end files on a TLS Config API, where no
     * certificate is asked for.
     *
     * The device ids cut off are the ones the identity PROVED: the client id
     * itself (open enrollment uses the device id as client id) and those in
     * `identity_devices` (a device key registered, or a vault token of the
     * device used, over its certificate). The `device_uid` it sent at
     * enrollment is only a claim — someone enrolling with a victim's device id
     * and then getting revoked would otherwise wipe and block the victim — so
     * those ids are returned as [DeviceCleanup.unverifiedDeviceIds] and touched
     * only with [cascadeUnverified]. A device id another active identity is
     * bound to is left alone.
     */
    fun revokeWithDevices(clientId: String, cascadeUnverified: Boolean = false): Revocation = db.connection().use { conn ->
        inTransaction(conn) {
            val certs = conn.prepareStatement("UPDATE client_certs SET revoked = 1 WHERE id = ?").use { stmt ->
                stmt.setString(1, clientId)
                stmt.executeUpdate()
            }
            val identities = conn.prepareStatement("UPDATE client_identities SET revoked = 1 WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                stmt.executeUpdate()
            }
            Revocation(found = certs + identities > 0, cleanup = cutOffDevices(conn, clientId, cascadeUnverified))
        }
    }

    /**
     * [forget], also returning what it took from the device(s) the identity
     * stood for (as [revokeWithDevices]; usually nothing is left by then, but
     * an identity revoked before revocation did this still has its tokens).
     */
    fun forgetWithDevices(clientId: String, now: String, cascadeUnverified: Boolean = false): Pair<Forget, DeviceCleanup?> = db.connection().use { conn ->
        inTransaction(conn) {
            // Write first (see register); rolled back unless the identity qualifies.
            conn.prepareStatement("UPDATE client_keys SET retired_at = ? WHERE client_id = ? AND retired_at IS NULL").use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.executeUpdate()
            }
            val identity = conn.prepareStatement("SELECT spki_sha256, revoked FROM client_identities WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getString("spki_sha256") to (rs.getInt("revoked") == 1) else null
            }
            val certRevoked = conn.prepareStatement("SELECT revoked FROM client_certs WHERE id = ?").use { stmt ->
                stmt.setString(1, clientId)
                val rs = stmt.executeQuery()
                if (rs.next()) rs.getInt("revoked") == 1 else null
            }
            when {
                identity == null && certRevoked == null -> { conn.rollback(); Forget.NOT_FOUND to null }
                identity?.second == false || certRevoked == false -> { conn.rollback(); Forget.NOT_REVOKED to null }
                else -> {
                    // The current key, should it predate client_keys.
                    if (identity != null) {
                        conn.prepareStatement(
                            """
                            INSERT INTO client_keys (client_id, spki_sha256, registered_at, retired_at) VALUES (?, ?, ?, ?)
                            ON CONFLICT(client_id, spki_sha256) DO UPDATE SET retired_at = COALESCE(client_keys.retired_at, excluded.retired_at)
                            """.trimIndent()
                        ).use { stmt ->
                            stmt.setString(1, clientId)
                            stmt.setString(2, identity.first)
                            stmt.setString(3, now)
                            stmt.setString(4, now)
                            stmt.executeUpdate()
                        }
                    }
                    // Read the device ids while the rows still name them.
                    val cleanup = cutOffDevices(conn, clientId, cascadeUnverified)
                    // The proofs go with the identity: a forgotten id blocks no device any more.
                    for (sql in listOf(
                        "DELETE FROM client_identities WHERE client_id = ?",
                        "DELETE FROM client_certs WHERE id = ?",
                        "DELETE FROM identity_devices WHERE client_id = ?"
                    )) {
                        conn.prepareStatement(sql).use { stmt ->
                            stmt.setString(1, clientId)
                            stmt.executeUpdate()
                        }
                    }
                    Forget.FORGOTTEN to cleanup
                }
            }
        }
    }

    /**
     * Whether [deviceId] belongs to a revoked identity and to no active one:
     * a device whose identity an administrator revoked, and which has not
     * enrolled again since. Only bindings the identity proved count (as in
     * [revokeWithDevices]): the client id itself, or an `identity_devices`
     * row. A device id a revoked identity merely claimed is not blocked.
     * Lifted only by an active identity that IS the device or PROVED its
     * device id (V20): any enrollment naming the device id used to lift it.
     */
    fun isDeviceRevoked(deviceId: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement(
            """
            SELECT
                (SELECT COUNT(*) FROM client_certs WHERE id = ? AND revoked = 1) +
                (SELECT COUNT(*) FROM client_identities WHERE client_id = ? AND revoked = 1) +
                (SELECT COUNT(*) FROM identity_devices d WHERE d.device_id = ? AND (
                    EXISTS (SELECT 1 FROM client_certs c WHERE c.id = d.client_id AND c.revoked = 1) OR
                    EXISTS (SELECT 1 FROM client_identities i WHERE i.client_id = d.client_id AND i.revoked = 1))),
                (SELECT COUNT(*) FROM client_certs WHERE (id = ? OR (device_uid = ? AND device_uid_proven = 1)) AND revoked = 0) +
                (SELECT COUNT(*) FROM client_identities WHERE client_id = ? AND revoked = 0)
            """.trimIndent()
        ).use { stmt ->
            (1..6).forEach { stmt.setString(it, deviceId) }
            stmt.executeQuery().use { rs -> rs.next() && rs.getInt(1) > 0 && rs.getInt(2) == 0 }
        }
    }

    /**
     * Records that [clientId]'s certificate proved it acts for [deviceId]
     * ([proof]: `key_over_certificate`, `token_over_certificate`, or
     * `admin_cascade`), so revoking it cuts that device off too. Nothing to
     * record when the device id is the client id itself.
     */
    fun recordDeviceProof(clientId: String, deviceId: String, proof: String, now: String = java.time.Instant.now().toString()) {
        if (clientId == deviceId) return
        db.connection().use { conn ->
            conn.prepareStatement("INSERT OR IGNORE INTO identity_devices (client_id, device_id, proof, recorded_at) VALUES (?, ?, ?, ?)").use { stmt ->
                stmt.setString(1, clientId)
                stmt.setString(2, deviceId)
                stmt.setString(3, proof)
                stmt.setString(4, now)
                stmt.executeUpdate()
            }
        }
    }

    /** The device ids [clientId] proved it acts for (see [recordDeviceProof]). */
    fun provenDevices(clientId: String): List<String> = db.connection().use { conn -> provenDevices(conn, clientId) }

    private fun provenDevices(conn: java.sql.Connection, clientId: String): List<String> =
        conn.prepareStatement("SELECT device_id FROM identity_devices WHERE client_id = ? ORDER BY device_id").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(rs.getString(1)) }
        }

    /**
     * The device ids [clientId] stands for, read only: the ones it proved (its
     * own id and [provenDevices]) and the ones it only claimed at enrollment.
     * What revoke / forget would cut off, and what they would leave unless
     * cascaded — so the dashboard can ask before an irreversible forget.
     */
    fun deviceBindings(clientId: String): Pair<List<String>, List<String>> = db.connection().use { conn ->
        val proven = (listOf(clientId) + provenDevices(conn, clientId)).distinct()
        proven to claimedDevices(conn, clientId).filterNot { it in proven }
    }

    /** The `device_uid`s [clientId] sent at enrollment (claims, not proofs). */
    private fun claimedDevices(conn: java.sql.Connection, clientId: String): List<String> =
        conn.prepareStatement(
            """
            SELECT device_uid FROM client_identities WHERE client_id = ? AND device_uid IS NOT NULL
            UNION SELECT device_uid FROM client_certs WHERE id = ? AND device_uid IS NOT NULL
            """.trimIndent()
        ).use { stmt ->
            stmt.setString(1, clientId)
            stmt.setString(2, clientId)
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(rs.getString(1)) }
        }.distinct()

    /** Revokes the vault tokens and deletes the device keys of the devices [clientId] stood for; inside the caller's transaction. */
    private fun cutOffDevices(conn: java.sql.Connection, clientId: String, cascadeUnverified: Boolean): DeviceCleanup {
        val claimed = claimedDevices(conn, clientId)
        val proven = (listOf(clientId) + provenDevices(conn, clientId)).distinct()
        val unverified = claimed.filterNot { it in proven }
        if (cascadeUnverified) {
            // The administrator chose to: recorded, so the block holds as for a proven id.
            val now = java.time.Instant.now().toString()
            for (deviceId in unverified) {
                conn.prepareStatement("INSERT OR IGNORE INTO identity_devices (client_id, device_id, proof, recorded_at) VALUES (?, ?, 'admin_cascade', ?)").use { stmt ->
                    stmt.setString(1, clientId)
                    stmt.setString(2, deviceId)
                    stmt.setString(3, now)
                    stmt.executeUpdate()
                }
            }
        }
        val candidates = if (cascadeUnverified) proven + unverified else proven
        // A device id another active identity is bound to is that identity's business.
        val deviceIds = candidates.distinct().filterNot { deviceId ->
            conn.prepareStatement(
                """
                SELECT 1 FROM client_certs WHERE (id = ? OR device_uid = ?) AND revoked = 0 AND id <> ?
                UNION ALL SELECT 1 FROM client_identities WHERE (client_id = ? OR device_uid = ?) AND revoked = 0 AND client_id <> ?
                LIMIT 1
                """.trimIndent()
            ).use { stmt ->
                listOf(deviceId, deviceId, clientId, deviceId, deviceId, clientId).forEachIndexed { i, v -> stmt.setString(i + 1, v) }
                stmt.executeQuery().use { it.next() }
            }
        }
        var tokens = 0
        var e2e = 0
        var userAuth = 0
        for (deviceId in deviceIds) {
            tokens += conn.prepareStatement("UPDATE vault_file_tokens SET revoked = 1 WHERE device_id = ? AND revoked = 0").use { stmt ->
                stmt.setString(1, deviceId)
                stmt.executeUpdate()
            }
            e2e += conn.prepareStatement("DELETE FROM ${DevicePublicKeyStore.E2E_TABLE} WHERE device_id = ?").use { stmt ->
                stmt.setString(1, deviceId)
                stmt.executeUpdate()
            }
            userAuth += conn.prepareStatement("DELETE FROM ${DevicePublicKeyStore.USER_AUTH_TABLE} WHERE device_id = ?").use { stmt ->
                stmt.setString(1, deviceId)
                stmt.executeUpdate()
            }
        }
        return DeviceCleanup(deviceIds, tokens, e2e, userAuth, if (cascadeUnverified) emptyList() else unverified)
    }

    /** Whether [spkiSha256] belonged to an identity that was forgotten: never trusted again. */
    fun isRetired(spkiSha256: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("SELECT 1 FROM client_keys WHERE spki_sha256 = ? AND retired_at IS NOT NULL LIMIT 1").use { stmt ->
            stmt.setString(1, spkiSha256)
            stmt.executeQuery().next()
        }
    }

    /**
     * Forgets a revoked identity so that its client id can enroll again — in
     * open enrollment the client id is the device's own id, so without this a
     * revoked device could never enroll again. Every key the client id
     * enrolled with is retired first; then its `client_identities` and
     * `client_certs` rows are deleted and the device's vault tokens and keys
     * go as on revocation ([forgetWithDevices]), in one transaction.
     *
     * An identity that is not revoked is left alone ([Forget.NOT_REVOKED]):
     * revoke first, so that nothing still in use is forgotten.
     */
    fun forget(clientId: String, now: String): Forget = forgetWithDevices(clientId, now).first

    /** Keys [clientId] enrolled with that are retired. */
    fun retiredKeys(clientId: String): Int = db.connection().use { conn ->
        conn.prepareStatement("SELECT COUNT(*) FROM client_keys WHERE client_id = ? AND retired_at IS NOT NULL").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) else 0
        }
    }

    private fun <T> inTransaction(conn: java.sql.Connection, block: () -> T): T {
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

    /**
     * Renewal: a new certificate over the same key. Never changes the key or
     * the revoked flag.
     *
     * @return false when there is no such (unrevoked) identity.
     */
    fun recordRenewal(
        clientId: String, serial: String, notBefore: String, notAfter: String, now: String,
        /**
         * SHA-256 of the renewal's CSR (V20). The same signed request a second
         * time is a replay — a copy of the recovery-door body would otherwise
         * renew the identity again and again — so the update is refused, in the
         * same statement, when it equals the last one accepted.
         */
        csrSha256: String? = null,
        /** The new certificate's PEM, kept so a repeated ask can be answered with it ([certPem]). */
        certPem: String? = null
    ): Boolean =
        db.connection().use { conn ->
            conn.prepareStatement(
                """
                UPDATE client_identities
                SET serial = ?, not_before = ?, not_after = ?, last_renewed_at = ?, renew_count = renew_count + 1,
                    last_renewal_csr_sha256 = COALESCE(?, last_renewal_csr_sha256), cert_pem = COALESCE(?, cert_pem)
                WHERE client_id = ? AND revoked = 0 AND (? IS NULL OR last_renewal_csr_sha256 IS NULL OR last_renewal_csr_sha256 <> ?)
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, serial)
                stmt.setString(2, notBefore)
                stmt.setString(3, notAfter)
                stmt.setString(4, now)
                stmt.setString(5, csrSha256)
                stmt.setString(6, certPem)
                stmt.setString(7, clientId)
                stmt.setString(8, csrSha256)
                stmt.setString(9, csrSha256)
                stmt.executeUpdate() > 0
            }
        }

    /** Whether [csrSha256] is the CSR the last renewal of [clientId] accepted (a replay). */
    fun isReplayedRenewal(clientId: String, csrSha256: String): Boolean = db.connection().use { conn ->
        conn.prepareStatement("SELECT 1 FROM client_identities WHERE client_id = ? AND last_renewal_csr_sha256 = ?").use { stmt ->
            stmt.setString(1, clientId)
            stmt.setString(2, csrSha256)
            stmt.executeQuery().next()
        }
    }

    /** The PEM of the certificate last issued over [clientId]'s key (V20), or null. */
    fun certPem(clientId: String): String? = db.connection().use { conn ->
        conn.prepareStatement("SELECT cert_pem FROM client_identities WHERE client_id = ? AND revoked = 0").use { stmt ->
            stmt.setString(1, clientId)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getString(1) else null
        }
    }

    /** Keeps [pem] as the certificate last issued over [clientId]'s key. */
    fun setCertPem(clientId: String, pem: String) = db.connection().use { conn ->
        conn.prepareStatement("UPDATE client_identities SET cert_pem = ? WHERE client_id = ? AND revoked = 0").use { stmt ->
            stmt.setString(1, pem)
            stmt.setString(2, clientId)
            stmt.executeUpdate()
        }
    }

    fun revoke(clientId: String) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE client_identities SET revoked = 1 WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                stmt.executeUpdate()
            }
        }
    }

    fun getAll(): List<ClientIdentity> = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            val rs = stmt.executeQuery("SELECT $COLUMNS FROM client_identities ORDER BY key_registered_at DESC")
            buildList { while (rs.next()) add(rs.toIdentity()) }
        }
    }

    private fun java.sql.ResultSet.toIdentity() = ClientIdentity(
        clientId = getString("client_id"),
        configApiId = getString("config_api_id"),
        spkiSha256 = getString("spki_sha256"),
        serial = getString("serial"),
        notBefore = getString("not_before"),
        notAfter = getString("not_after"),
        keyRegisteredAt = getString("key_registered_at"),
        lastRenewedAt = getString("last_renewed_at"),
        renewCount = getInt("renew_count"),
        revoked = getInt("revoked") == 1,
        deviceAlias = getString("device_alias"),
        deviceUid = getString("device_uid"),
        attestation = getInt("attested").takeUnless { wasNull() }?.let {
            KeyAttestation(it == 1, getString("attestation_security_level"), getString("attestation_reason"))
        }
    )

    /**
     * A server-made (P12) key was issued to [clientId]: it is recorded in
     * `client_keys` like an enrolled key, so whatever replaces it later — a
     * CSR enrollment ([register]), another P12, a forget — retires it, and a
     * certificate over it is refused from then on ([isRetired]). Every other
     * live key of the id is retired here: the P12 replaced it.
     */
    fun recordServerMadeKey(clientId: String, spkiSha256: String, now: String) = db.connection().use { conn ->
        inTransaction(conn) {
            conn.prepareStatement("UPDATE client_keys SET retired_at = ? WHERE client_id = ? AND spki_sha256 <> ? AND retired_at IS NULL").use { stmt ->
                stmt.setString(1, now)
                stmt.setString(2, clientId)
                stmt.setString(3, spkiSha256)
                stmt.executeUpdate()
            }
            conn.prepareStatement("INSERT OR IGNORE INTO client_keys (client_id, spki_sha256, registered_at) VALUES (?, ?, ?)").use { stmt ->
                stmt.setString(1, clientId)
                stmt.setString(2, spkiSha256)
                stmt.setString(3, now)
                stmt.executeUpdate()
            }
        }
    }

    /**
     * Retires [spkiSha256] as a key [clientId] held: the key of an older
     * self-signed P12 certificate (a per-certificate trust anchor) that a new
     * enrollment of the id replaced. Its certificate is refused from then on
     * ([isRetired]) even where the anchor is still loaded.
     */
    fun retireKey(clientId: String, spkiSha256: String, now: String) = db.connection().use { conn ->
        conn.prepareStatement(
            """
            INSERT INTO client_keys (client_id, spki_sha256, registered_at, retired_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(client_id, spki_sha256) DO UPDATE SET retired_at = COALESCE(client_keys.retired_at, excluded.retired_at)
            """.trimIndent()
        ).use { stmt ->
            stmt.setString(1, clientId)
            stmt.setString(2, spkiSha256)
            stmt.setString(3, now)
            stmt.setString(4, now)
            stmt.executeUpdate()
        }
    }

    private companion object {
        const val COLUMNS = "client_id, config_api_id, spki_sha256, serial, not_before, not_after, key_registered_at, " +
            "last_renewed_at, renew_count, revoked, device_alias, device_uid, attested, attestation_security_level, attestation_reason"
    }
}

/**
 * Writes a `client_certs` row for an enrollment, unless the row is revoked:
 * a revocation is never undone by an enrollment that was already under way
 * (`INSERT OR REPLACE … revoked = 0` used to do exactly that). Bound by
 * [bindClientCertUpsert]. Writes 0 rows when the id is revoked — or when
 * another active identity holds the device id: one active identity per
 * device, decided in the statement that writes, so two enrollments racing
 * for one device cannot both pass a check made before (an open-mode row with
 * a NULL device id and the device id as its client id holds it too).
 */
internal const val CLIENT_CERT_UPSERT_UNLESS_REVOKED = """
    INSERT INTO client_certs (id, common_name, fingerprint, created_at, revoked, device_alias, device_uid, device_uid_proven)
    SELECT ?1, ?2, ?3, ?4, 0, ?5, ?6, ?7
    WHERE ?6 IS NULL OR NOT EXISTS (
        SELECT 1 FROM client_certs o
        WHERE o.revoked = 0 AND o.id <> ?1 AND (o.device_uid = ?6 OR (o.device_uid IS NULL AND o.id = ?6))
    )
    ON CONFLICT(id) DO UPDATE SET
        common_name = excluded.common_name,
        fingerprint = excluded.fingerprint,
        created_at = excluded.created_at,
        device_alias = excluded.device_alias,
        device_uid = excluded.device_uid,
        device_uid_proven = excluded.device_uid_proven
    WHERE client_certs.revoked = 0
"""

/** Binds [CLIENT_CERT_UPSERT_UNLESS_REVOKED]. */
internal fun bindClientCertUpsert(
    stmt: java.sql.PreparedStatement, id: String, commonName: String, fingerprint: String, createdAt: String,
    deviceAlias: String?, deviceUid: String?, deviceUidProven: Boolean
) {
    stmt.setString(1, id)
    stmt.setString(2, commonName)
    stmt.setString(3, fingerprint)
    stmt.setString(4, createdAt)
    stmt.setString(5, deviceAlias)
    stmt.setString(6, deviceUid)
    stmt.setInt(7, if (deviceUidProven) 1 else 0)
}
