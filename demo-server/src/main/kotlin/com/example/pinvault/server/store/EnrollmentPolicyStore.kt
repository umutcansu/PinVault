package com.example.pinvault.server.store

import kotlinx.serialization.Serializable
import java.sql.Connection
import java.sql.ResultSet
import java.time.Duration
import java.time.Instant

/**
 * An enrollment policy as the dashboard sees it: one code many devices enroll
 * with, up to [maxDevices], until [expiresAt], each one approved by an
 * administrator first when [requireApproval] is set. The code is not part of
 * it — it is shown once, when the policy is created.
 */
@Serializable
data class EnrollmentPolicy(
    val id: String,
    /** Prefix of the client ids the policy hands out (`<name>-<6 chars>`). */
    val name: String,
    /** First group of the code, to tell policies apart; it cannot enroll anything. */
    val codePrefix: String,
    val maxDevices: Int,
    /** Devices issued a certificate plus approved ones that have not picked theirs up yet. */
    val usedCount: Int,
    val pendingCount: Int = 0,
    val requireApproval: Boolean,
    val createdAt: String,
    val createdBy: String,
    val expiresAt: String,
    val stoppedAt: String? = null,
    /** `active`, `stopped`, `expired` or `full`, as of the listing. */
    val status: String,
    /**
     * The code-less applications policy (the dashboard's switch): devices ask
     * without a token and every one waits for an administrator. Its code was
     * never shown to anyone.
     */
    val openApplications: Boolean = false,
    /** Whether new devices may ask now; off, the ones already waiting can still be decided. */
    val accepting: Boolean = true
) {
    /** Whether a device may start an enrollment with the code (or, open, ask) now. */
    fun acceptsNewDevices(now: Instant = Instant.now()): Boolean =
        stoppedAt == null && accepting && now.isBefore(Instant.parse(expiresAt)) && usedCount < maxDevices
}

/**
 * A device that came with a policy code, recognised by its key. Status:
 * `pending` (waiting for an administrator), `approved` (a certificate is
 * ready to be picked up), `rejected`, or `issued`.
 */
@Serializable
data class EnrollmentRequest(
    val id: String,
    val policyId: String,
    val policyName: String = "",
    /** The client id the device gets; assigned when it first asks. */
    val clientId: String,
    val spkiSha256: String,
    val status: String,
    val configApiId: String = "",
    val deviceAlias: String? = null,
    val deviceUid: String? = null,
    val sourceIp: String = "",
    val createdAt: String,
    val decidedAt: String? = null,
    val decidedBy: String? = null,
    val issuedAt: String? = null,
    /** Another active identity already enrolled from [deviceUid], if any (admin listing only). */
    val heldBy: String? = null,
    /** Short code from the device key; the device shows the same one (see VerificationCode). */
    val verificationCode: String = "",
    /** Admin listing: how many other requests from the same [deviceUid] are waiting too. */
    val sameDevicePending: Int = 0,
    /** Whether the device asked without a code (code-less applications). */
    val openApplication: Boolean = false,
    /**
     * What Android Key Attestation said about the device key when it asked
     * (`ENROLLMENT_ATTESTATION`): the approver sees "hardware-attested" or
     * "not attested" next to the request. Null = not checked.
     */
    val attestation: KeyAttestation? = null
) {
    companion object {
        const val PENDING = "pending"
        const val APPROVED = "approved"
        const val REJECTED = "rejected"
        const val ISSUED = "issued"
        /** A request nobody decided on in time (ENROLLMENT_REQUEST_TTL_HOURS). */
        const val EXPIRED = "expired"
    }
}

/**
 * Enrollment policies and the devices that enrolled (or asked to) with them.
 *
 * ## The code
 * 25 characters from Crockford's base32 alphabet in five groups
 * (`K7QM2-XRT9V-…`, 125 bits): meant to be typed or scanned on a phone, so
 * case, dashes and spaces do not matter and `O`/`I`/`L` read as `0`/`1`. Only
 * the SHA-256 of the normalised code is stored, like enrollment tokens.
 *
 * ## The device limit
 * [EnrollmentPolicy.usedCount] goes up by one conditional UPDATE when a slot is
 * taken (an approval, or an enrollment without approval), so devices racing
 * for the last slot never get more certificates than the policy allows.
 */
class EnrollmentPolicyStore(private val db: DatabaseManager) {

    private val rng = java.security.SecureRandom()

    class Created(val policy: EnrollmentPolicy, val code: String)

    /** A request [createRequest] stored, or the one the same key already had ([created] false). */
    class Recorded(val request: EnrollmentRequest, val created: Boolean)

    /** What [approve] came to. */
    enum class Approval { APPROVED, NOT_FOUND, NOT_PENDING, POLICY_STOPPED, LIMIT_REACHED }

    fun create(
        name: String,
        maxDevices: Int,
        validFor: Duration,
        requireApproval: Boolean,
        createdBy: String,
        now: Instant = Instant.now(),
        openApplications: Boolean = false
    ): Created {
        val code = newCode()
        val id = randomHex(16)
        db.connection().use { conn ->
            conn.prepareStatement(
                """
                INSERT INTO enrollment_policies
                    (id, name, code_hash, code_prefix, max_devices, used_count, require_approval, created_at, created_by, expires_at,
                     open_applications, accepting)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 1)
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, id)
                stmt.setString(2, name)
                stmt.setString(3, hash(normalizeCode(code)!!))
                stmt.setString(4, code.substringBefore('-'))
                stmt.setInt(5, maxDevices)
                stmt.setInt(6, if (requireApproval) 1 else 0)
                stmt.setString(7, now.toString())
                stmt.setString(8, createdBy)
                stmt.setString(9, now.plus(validFor).toString())
                stmt.setInt(10, if (openApplications) 1 else 0)
                stmt.executeUpdate()
            }
        }
        return Created(get(id, now)!!, code)
    }

    /**
     * The code-less applications policy, if it was ever turned on and not
     * stopped. There is at most one; [openApplications] creates it.
     */
    fun openPolicy(now: Instant = Instant.now()): EnrollmentPolicy? = db.connection().use { conn ->
        conn.prepareStatement("$SELECT_POLICY WHERE p.open_applications = 1 AND p.stopped_at IS NULL ORDER BY p.created_at DESC LIMIT 1").use { stmt ->
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toPolicy(now) else null
        }
    }

    /**
     * Turns code-less applications on or off. On the first time a policy is
     * made for them: prefix [OPEN_NAME], no device limit to speak of, no end
     * date to speak of, approval always. Off keeps the requests already
     * waiting decidable.
     */
    fun openApplications(enabled: Boolean, actor: String, now: Instant = Instant.now()): EnrollmentPolicy? {
        val current = openPolicy(now)
        if (current == null) {
            if (!enabled) return null
            return create(OPEN_NAME, OPEN_MAX_DEVICES, Duration.ofDays(OPEN_VALID_DAYS), requireApproval = true,
                createdBy = actor, now = now, openApplications = true).policy
        }
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE enrollment_policies SET accepting = ? WHERE id = ?").use { stmt ->
                stmt.setInt(1, if (enabled) 1 else 0)
                stmt.setString(2, current.id)
                stmt.executeUpdate()
            }
        }
        return get(current.id, now)
    }

    /**
     * Requests nobody decided on within [ttl] become `expired`: they leave the
     * waiting list and free their place under the cap. The device learns it
     * when it asks again and starts over.
     */
    fun expirePending(ttl: Duration, now: Instant = Instant.now()): Int = db.connection().use { conn ->
        conn.prepareStatement(
            "UPDATE enrollment_requests SET status = ?, decided_at = ?, decided_by = ? WHERE status = ? AND created_at < ?"
        ).use { stmt ->
            stmt.setString(1, EnrollmentRequest.EXPIRED)
            stmt.setString(2, now.toString())
            stmt.setString(3, EXPIRY_DECIDER)
            stmt.setString(4, EnrollmentRequest.PENDING)
            stmt.setString(5, now.minus(ttl).toString())
            stmt.executeUpdate()
        }
    }

    fun get(id: String, now: Instant = Instant.now()): EnrollmentPolicy? = db.connection().use { conn ->
        conn.prepareStatement("$SELECT_POLICY WHERE p.id = ?").use { stmt ->
            stmt.setString(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toPolicy(now) else null
        }
    }

    /** The policy [code] belongs to, whatever its state; null when it is not a policy code. */
    fun findByCode(code: String, now: Instant = Instant.now()): EnrollmentPolicy? {
        val normalized = normalizeCode(code) ?: return null
        return db.connection().use { conn ->
            conn.prepareStatement("$SELECT_POLICY WHERE p.code_hash = ?").use { stmt ->
                stmt.setString(1, hash(normalized))
                val rs = stmt.executeQuery()
                if (rs.next()) rs.toPolicy(now) else null
            }
        }
    }

    fun getAll(now: Instant = Instant.now()): List<EnrollmentPolicy> = db.connection().use { conn ->
        conn.createStatement().use { stmt ->
            val rs = stmt.executeQuery("$SELECT_POLICY ORDER BY p.created_at DESC")
            buildList { while (rs.next()) add(rs.toPolicy(now)) }
        }
    }

    /**
     * Stops the code: no device can start an enrollment with it any more, and
     * the ones still waiting are rejected. Devices already approved can still
     * pick their certificate up — an administrator let each of them in.
     *
     * @return false when there is no such policy or it was already stopped.
     */
    fun stop(id: String, actor: String, now: Instant = Instant.now()): Boolean = db.connection().use { conn ->
        inTransaction(conn) {
            val stopped = conn.prepareStatement(
                "UPDATE enrollment_policies SET stopped_at = ? WHERE id = ? AND stopped_at IS NULL"
            ).use { stmt ->
                stmt.setString(1, now.toString())
                stmt.setString(2, id)
                stmt.executeUpdate() == 1
            }
            if (stopped) {
                conn.prepareStatement(
                    "UPDATE enrollment_requests SET status = ?, decided_at = ?, decided_by = ? WHERE policy_id = ? AND status = ?"
                ).use { stmt ->
                    stmt.setString(1, EnrollmentRequest.REJECTED)
                    stmt.setString(2, now.toString())
                    stmt.setString(3, actor)
                    stmt.setString(4, id)
                    stmt.setString(5, EnrollmentRequest.PENDING)
                    stmt.executeUpdate()
                }
            }
            stopped
        }
    }

    /**
     * Takes one of the policy's device slots, in one statement. False when the
     * policy is full or stopped (or does not exist).
     */
    fun reserveSlot(policyId: String): Boolean = db.connection().use { reserveSlot(it, policyId) }

    /** Gives back a slot [reserveSlot] took for an enrollment that did not happen. */
    fun releaseSlot(policyId: String) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "UPDATE enrollment_policies SET used_count = used_count - 1 WHERE id = ? AND used_count > 0"
            ).use { stmt ->
                stmt.setString(1, policyId)
                stmt.executeUpdate()
            }
        }
    }

    // ── Requests ─────────────────────────────────────────────────────────

    fun getRequest(id: String): EnrollmentRequest? = db.connection().use { conn ->
        conn.prepareStatement("$SELECT_REQUEST WHERE r.id = ?").use { stmt ->
            stmt.setString(1, id)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toRequest() else null
        }
    }

    /** The request a device key already made with a policy, if any. */
    fun findRequest(policyId: String, spkiSha256: String): EnrollmentRequest? = db.connection().use { conn ->
        conn.prepareStatement("$SELECT_REQUEST WHERE r.policy_id = ? AND r.spki_sha256 = ?").use { stmt ->
            stmt.setString(1, policyId)
            stmt.setString(2, spkiSha256)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.toRequest() else null
        }
    }

    /**
     * Records a device that came with [policy]'s code, under a fresh client id
     * `<policy name>-<6 chars>`. When the same key already has a request with
     * this policy (two attempts racing), that one is returned instead.
     *
     * @param status [EnrollmentRequest.PENDING], or [EnrollmentRequest.APPROVED]
     *   for a policy without approval (the caller has taken the slot).
     */
    fun createRequest(
        policy: EnrollmentPolicy,
        spkiSha256: String,
        status: String,
        configApiId: String,
        deviceAlias: String?,
        deviceUid: String?,
        sourceIp: String,
        now: Instant = Instant.now(),
        /** What attestation said about the key (`ENROLLMENT_ATTESTATION`); null = not checked. */
        attestation: KeyAttestation? = null
    ): Recorded {
        repeat(8) {
            val clientId = newClientId(policy.name)
            val id = randomHex(16)
            val inserted = db.connection().use { conn ->
                conn.prepareStatement(
                    """
                    INSERT INTO enrollment_requests
                        (id, policy_id, client_id, spki_sha256, status, config_api_id, device_alias, device_uid,
                         source_ip, created_at, decided_at, decided_by,
                         attested, attestation_security_level, attestation_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """.trimIndent()
                ).use { stmt ->
                    stmt.setString(1, id)
                    stmt.setString(2, policy.id)
                    stmt.setString(3, clientId)
                    stmt.setString(4, spkiSha256)
                    stmt.setString(5, status)
                    stmt.setString(6, configApiId)
                    stmt.setString(7, deviceAlias)
                    stmt.setString(8, deviceUid)
                    stmt.setString(9, sourceIp)
                    stmt.setString(10, now.toString())
                    stmt.setString(11, if (status == EnrollmentRequest.APPROVED) now.toString() else null)
                    stmt.setString(12, if (status == EnrollmentRequest.APPROVED) AUTO_APPROVER else null)
                    if (attestation == null) stmt.setNull(13, java.sql.Types.INTEGER) else stmt.setInt(13, if (attestation.attested) 1 else 0)
                    stmt.setString(14, attestation?.securityLevel)
                    stmt.setString(15, attestation?.reason)
                    stmt.executeUpdate() == 1
                }
            }
            if (inserted) return Recorded(getRequest(id)!!, created = true)
            // Lost a race with the same key, or (1 in 2^30) the client id was taken meanwhile.
            findRequest(policy.id, spkiSha256)?.let { return Recorded(it, created = false) }
        }
        error("Could not record an enrollment request for policy ${policy.id}")
    }

    fun countPending(policyId: String): Int = db.connection().use { conn ->
        conn.prepareStatement("SELECT COUNT(*) FROM enrollment_requests WHERE policy_id = ? AND status = ?").use { stmt ->
            stmt.setString(1, policyId)
            stmt.setString(2, EnrollmentRequest.PENDING)
            val rs = stmt.executeQuery()
            if (rs.next()) rs.getInt(1) else 0
        }
    }

    /**
     * Lets a waiting device in: the request becomes `approved` and takes one
     * of the policy's slots, both or neither.
     */
    fun approve(requestId: String, actor: String, now: Instant = Instant.now()): Approval {
        val request = getRequest(requestId) ?: return Approval.NOT_FOUND
        return db.connection().use { conn ->
            inTransaction(conn) {
                // The write comes first so this transaction holds the write lock
                // from its first statement (no read-then-upgrade deadlock).
                val claimed = conn.prepareStatement(
                    "UPDATE enrollment_requests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = ?"
                ).use { stmt ->
                    stmt.setString(1, EnrollmentRequest.APPROVED)
                    stmt.setString(2, now.toString())
                    stmt.setString(3, actor)
                    stmt.setString(4, requestId)
                    stmt.setString(5, EnrollmentRequest.PENDING)
                    stmt.executeUpdate() == 1
                }
                when {
                    !claimed -> { conn.rollback(); Approval.NOT_PENDING }
                    !reserveSlot(conn, request.policyId) -> {
                        conn.rollback()
                        if (get(request.policyId, now)?.stoppedAt != null) Approval.POLICY_STOPPED else Approval.LIMIT_REACHED
                    }
                    else -> Approval.APPROVED
                }
            }
        }
    }

    /**
     * Turns a device away. A request that was approved but not picked up
     * gives its slot back.
     *
     * @return false when the request is not waiting or approved.
     */
    fun reject(requestId: String, actor: String, now: Instant = Instant.now()): Boolean {
        val request = getRequest(requestId) ?: return false
        return db.connection().use { conn ->
            inTransaction(conn) {
                fun rejectFrom(status: String) = conn.prepareStatement(
                    "UPDATE enrollment_requests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = ?"
                ).use { stmt ->
                    stmt.setString(1, EnrollmentRequest.REJECTED)
                    stmt.setString(2, now.toString())
                    stmt.setString(3, actor)
                    stmt.setString(4, requestId)
                    stmt.setString(5, status)
                    stmt.executeUpdate() == 1
                }
                when {
                    rejectFrom(EnrollmentRequest.APPROVED) -> {
                        conn.prepareStatement(
                            "UPDATE enrollment_policies SET used_count = used_count - 1 WHERE id = ? AND used_count > 0"
                        ).use { stmt ->
                            stmt.setString(1, request.policyId)
                            stmt.executeUpdate()
                        }
                        true
                    }
                    else -> rejectFrom(EnrollmentRequest.PENDING)
                }
            }
        }
    }

    /** The device picked its certificate up (again, after a lost answer, is fine). */
    fun markIssued(requestId: String, now: Instant = Instant.now()) {
        db.connection().use { conn ->
            conn.prepareStatement(
                "UPDATE enrollment_requests SET status = ?, issued_at = COALESCE(issued_at, ?) WHERE id = ? AND status IN (?, ?)"
            ).use { stmt ->
                stmt.setString(1, EnrollmentRequest.ISSUED)
                stmt.setString(2, now.toString())
                stmt.setString(3, requestId)
                stmt.setString(4, EnrollmentRequest.APPROVED)
                stmt.setString(5, EnrollmentRequest.ISSUED)
                stmt.executeUpdate()
            }
        }
    }

    /** Requests, newest first; [status] null = all. */
    fun requests(status: String? = null, limit: Int = 200): List<EnrollmentRequest> = db.connection().use { conn ->
        val where = if (status != null) "WHERE r.status = ?" else ""
        conn.prepareStatement("$SELECT_REQUEST $where ORDER BY r.created_at DESC LIMIT ?").use { stmt ->
            var i = 1
            if (status != null) stmt.setString(i++, status)
            stmt.setInt(i, limit)
            val rs = stmt.executeQuery()
            buildList { while (rs.next()) add(rs.toRequest()) }
        }
    }

    // ── internals ────────────────────────────────────────────────────────

    private fun reserveSlot(conn: Connection, policyId: String): Boolean =
        conn.prepareStatement(
            "UPDATE enrollment_policies SET used_count = used_count + 1 WHERE id = ? AND used_count < max_devices AND stopped_at IS NULL"
        ).use { stmt ->
            stmt.setString(1, policyId)
            stmt.executeUpdate() == 1
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

    /** A client id no certificate, identity or request uses yet. */
    private fun newClientId(prefix: String): String {
        repeat(8) {
            val id = "$prefix-" + (1..6).map { CLIENT_ID_ALPHABET[rng.nextInt(CLIENT_ID_ALPHABET.length)] }.joinToString("")
            val taken = db.connection().use { conn ->
                conn.prepareStatement(
                    """
                    SELECT 1 FROM client_certs WHERE id = ?
                    UNION ALL SELECT 1 FROM client_identities WHERE client_id = ?
                    UNION ALL SELECT 1 FROM enrollment_requests WHERE client_id = ?
                    LIMIT 1
                    """.trimIndent()
                ).use { stmt ->
                    (1..3).forEach { stmt.setString(it, id) }
                    stmt.executeQuery().next()
                }
            }
            if (!taken) return id
        }
        error("No free client id for prefix $prefix")
    }

    private fun newCode(): String =
        (1..CODE_LENGTH).map { CODE_ALPHABET[rng.nextInt(CODE_ALPHABET.length)] }
            .chunked(5).joinToString("-") { it.joinToString("") }

    private fun randomHex(bytes: Int): String =
        ByteArray(bytes).also(rng::nextBytes).joinToString("") { "%02x".format(it) }

    private fun ResultSet.toPolicy(now: Instant): EnrollmentPolicy {
        val stoppedAt = getString("stopped_at")
        val expiresAt = getString("expires_at")
        val used = getInt("used_count")
        val max = getInt("max_devices")
        return EnrollmentPolicy(
            id = getString("id"),
            name = getString("name"),
            codePrefix = getString("code_prefix"),
            maxDevices = max,
            usedCount = used,
            pendingCount = getInt("pending_count"),
            requireApproval = getInt("require_approval") == 1,
            createdAt = getString("created_at"),
            createdBy = getString("created_by"),
            expiresAt = expiresAt,
            stoppedAt = stoppedAt,
            status = when {
                stoppedAt != null -> "stopped"
                !now.isBefore(Instant.parse(expiresAt)) -> "expired"
                used >= max -> "full"
                else -> "active"
            },
            openApplications = getInt("open_applications") == 1,
            accepting = getInt("accepting") == 1
        )
    }

    private fun ResultSet.toRequest() = EnrollmentRequest(
        id = getString("id"),
        policyId = getString("policy_id"),
        policyName = getString("policy_name") ?: "",
        clientId = getString("client_id"),
        spkiSha256 = getString("spki_sha256"),
        status = getString("status"),
        configApiId = getString("config_api_id"),
        deviceAlias = getString("device_alias"),
        deviceUid = getString("device_uid"),
        sourceIp = getString("source_ip"),
        createdAt = getString("created_at"),
        decidedAt = getString("decided_at"),
        decidedBy = getString("decided_by"),
        issuedAt = getString("issued_at"),
        verificationCode = com.example.pinvault.server.service.VerificationCode.ofSpkiSha256(getString("spki_sha256")),
        openApplication = getInt("policy_open") == 1,
        attestation = getInt("attested").takeUnless { wasNull() }?.let {
            KeyAttestation(it == 1, getString("attestation_security_level"), getString("attestation_reason"))
        }
    )

    companion object {
        /** Crockford's base32: no I, L, O, U — nothing to misread on a phone. */
        private const val CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        private const val CODE_LENGTH = 25
        private const val CLIENT_ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"

        /** `decided_by` of a request a policy without approval let in. */
        const val AUTO_APPROVER = "policy"

        /** `decided_by` of a request nobody decided on in time. */
        const val EXPIRY_DECIDER = "timeout"

        /** Prefix of the client ids code-less applications get (`device-7k2m9x`). */
        const val OPEN_NAME = "device"
        private const val OPEN_MAX_DEVICES = 10_000
        private const val OPEN_VALID_DAYS = 36_500L

        private const val SELECT_POLICY =
            "SELECT p.*, (SELECT COUNT(*) FROM enrollment_requests r WHERE r.policy_id = p.id AND r.status = 'pending') AS pending_count " +
                "FROM enrollment_policies p"
        private const val SELECT_REQUEST =
            "SELECT r.*, p.name AS policy_name, COALESCE(p.open_applications, 0) AS policy_open FROM enrollment_requests r LEFT JOIN enrollment_policies p ON p.id = r.policy_id"

        /**
         * The code as stored: upper case, no dashes or spaces, `O`→`0` and
         * `I`/`L`→`1`. Null when [input] cannot be a policy code.
         */
        fun normalizeCode(input: String): String? {
            val s = input.uppercase()
                .filter { it != '-' && !it.isWhitespace() }
                .map { when (it) { 'O' -> '0'; 'I', 'L' -> '1'; else -> it } }
                .joinToString("")
            return s.takeIf { it.length == CODE_LENGTH && it.all { c -> c in CODE_ALPHABET } }
        }

        internal fun hash(normalizedCode: String): String =
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(normalizedCode.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}
