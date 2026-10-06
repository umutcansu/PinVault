package com.example.pinvault.server.plugin

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.util.*
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/** Who made an admin call; stored on the call by [ApiKeyAuth]. */
data class AdminPrincipal(val name: String)

val AdminPrincipalKey = AttributeKey<AdminPrincipal>("PinVaultAdminPrincipal")

/** Set on a call that is the server replaying a change another admin approved. */
val ApprovedReplayKey = AttributeKey<Long>("PinVaultApprovedReplay")

/**
 * Address of the admin whose approval triggered a replay. The replay itself
 * arrives over loopback; [AdminAudit] records this address instead.
 */
val ApprovedReplayIpKey = AttributeKey<String>("PinVaultApprovedReplayIp")

/** The authenticated admin's name, or `anonymous` / `system` when there is none. */
fun ApplicationCall.adminName(): String = attributes.getOrNull(AdminPrincipalKey)?.name ?: "anonymous"

/**
 * Administrators allowed to use the management API, each with their own key.
 *
 *  - `API_KEY` — the single shared key, as before. Its holder is named `admin`.
 *  - `ADMIN_KEYS` — `name:sha256hex` pairs, comma-separated; `ADMIN_KEYS_FILE`
 *    — the same pairs, one per line. Only the SHA-256 of each key is
 *    configured, so the server's environment never holds a usable key.
 *    `scripts/add-admin.sh` in the sample host prints a new key and its line.
 *
 * Named keys are what make the audit log say WHO did something, and what lets
 * `PIN_CHANGE_APPROVALS=2` tell the requester from the approver.
 */
class AdminRegistry(
    private val legacyKey: String?,
    private val named: Map<String, ByteArray>
) {
    val isEmpty: Boolean get() = legacyKey == null && named.isEmpty()

    val names: List<String> get() = listOfNotNull(legacyKey?.let { LEGACY_NAME }) + named.keys

    /** The admin [provided] belongs to, or null. Every entry is compared, in constant time. */
    fun identify(provided: String): String? {
        var match: String? = null
        if (legacyKey != null && constantTimeEquals(provided, legacyKey)) match = LEGACY_NAME
        val digest = MessageDigest.getInstance("SHA-256").digest(provided.toByteArray(Charsets.UTF_8))
        for ((name, hash) in named) {
            if (MessageDigest.isEqual(digest, hash) && match == null) match = name
        }
        return match
    }

    companion object {
        const val LEGACY_NAME = "admin"

        /** Names the audit log uses for non-admins; an admin may not be called that. */
        val RESERVED_NAMES = setOf("system", "unknown", "anonymous")
        private val NAME = Regex("^[A-Za-z0-9._-]{1,32}$")
        private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

        fun fromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): AdminRegistry {
            val legacy = env["API_KEY"]?.takeIf { it.isNotBlank() }
            val lines = env["ADMIN_KEYS"]?.split(',').orEmpty() +
                env["ADMIN_KEYS_FILE"]?.takeIf { it.isNotBlank() }?.let { File(it).readLines() }.orEmpty()
            val named = linkedMapOf<String, ByteArray>()
            for (raw in lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }) {
                val name = raw.substringBefore(':').trim()
                val hash = raw.substringAfter(':', "").trim()
                require(NAME.matches(name)) { "ADMIN_KEYS: invalid admin name '$name' (letters, digits, . _ - up to 32)" }
                require(HEX64.matches(hash)) { "ADMIN_KEYS: '$name' needs the SHA-256 of its key as 64 hex characters" }
                require(name !in named) { "ADMIN_KEYS: '$name' is listed twice" }
                require(name != LEGACY_NAME && name !in RESERVED_NAMES) {
                    "ADMIN_KEYS: '$name' is reserved (${(RESERVED_NAMES + LEGACY_NAME).joinToString()}) — pick another name"
                }
                named[name] = hash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
            return AdminRegistry(legacy, named)
        }
    }
}

/**
 * API Key authentication plugin for management endpoints.
 *
 * Every non-public endpoint requires `X-API-Key` belonging to one of the
 * [AdminRegistry] admins; the admin's name is stored on the call
 * ([AdminPrincipalKey]) for the audit log and the approval workflow. Client
 * endpoints (config download, enrollment, vault) remain unauthenticated.
 */
class ApiKeyAuthConfig {
    /** Admins; default: read from the environment (API_KEY, ADMIN_KEYS, ADMIN_KEYS_FILE). */
    var registry: AdminRegistry = AdminRegistry.fromEnv()

    /** Default: ALLOW_ANONYMOUS_ADMIN=true. */
    var allowAnonymous: Boolean = com.example.pinvault.server.service.ServerEnv.get("ALLOW_ANONYMOUS_ADMIN") == "true"

    /**
     * Whether this listener may serve admin routes without a key when there is
     * none ([allowAnonymous]). True only on the management listener; the
     * Config API listeners face devices on every interface, so there an
     * anonymous caller gets device endpoints and nothing else.
     */
    var anonymousAdminListener: Boolean = true

    /**
     * Anonymous admin: socket peers allowed besides loopback (`ANONYMOUS_ADMIN_PEERS`,
     * comma-separated IPs or CIDRs — a container's gateway, e.g. `172.17.0.1`).
     */
    var anonymousPeers: List<String> = com.example.pinvault.server.service.ServerEnv.get("ANONYMOUS_ADMIN_PEERS").orEmpty()
        .split(',').map { it.trim() }.filter { it.isNotEmpty() }

    /**
     * Invalid admin keys a source address may send per 10 minutes before every
     * admin request from it gets 429 (`ADMIN_AUTH_FAILURE_LIMIT`, default 30; 0 = no limit).
     */
    var failureLimit: Int = (com.example.pinvault.server.service.ServerEnv.get("ADMIN_AUTH_FAILURE_LIMIT")?.toIntOrNull() ?: DEFAULT_ADMIN_AUTH_FAILURE_LIMIT).coerceAtLeast(0)

    /**
     * The counter behind [failureLimit]; null = one of this listener's own. Main.kt
     * hands every listener the same one, so an address cut off on a Config API
     * port is cut off on the management port too.
     */
    var failureLimiter: com.example.pinvault.server.service.RateLimiter? = null
}

/** Invalid admin keys per source address and 10 minutes before 429 (see [ApiKeyAuthConfig.failureLimit]). */
const val DEFAULT_ADMIN_AUTH_FAILURE_LIMIT = 30

/**
 * Which socket peers count as "this machine" for anonymous admin: loopback,
 * and the entries of `ANONYMOUS_ADMIN_PEERS` (IP literals or CIDRs). Only
 * literals are parsed — a peer address comes from the socket, and nothing is
 * ever resolved.
 */
internal object PeerRules {
    private val LITERAL = Regex("^[0-9A-Fa-f.:]+$")

    private fun literal(value: String): java.net.InetAddress? {
        val v = value.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (!LITERAL.matches(v) || (!v.contains('.') && !v.contains(':'))) return null
        return try { java.net.InetAddress.getByName(v) } catch (_: Exception) { null }
    }

    /** True when [peer] (the socket's remote address) is loopback or matches one of [rules]. */
    fun allowed(peer: String, rules: List<String>): Boolean {
        // The Ktor test engine names its peer "localhost"; a real socket gives a literal.
        if (peer == "localhost") return true
        val address = literal(peer) ?: return false
        if (address.isLoopbackAddress) return true
        return rules.any { rule -> matches(address, rule) }
    }

    /** Whether [rule] (an IP literal or `ip/prefix`) is well-formed. */
    fun valid(rule: String): Boolean {
        val base = literal(rule.substringBefore('/')) ?: return false
        val prefix = rule.substringAfter('/', "").ifEmpty { return true }.toIntOrNull() ?: return false
        return prefix in 0..base.address.size * 8
    }

    private fun matches(address: java.net.InetAddress, rule: String): Boolean {
        val base = literal(rule.substringBefore('/')) ?: return false
        val a = address.address
        val b = base.address
        if (a.size != b.size) return false
        val prefix = rule.substringAfter('/', "").ifEmpty { (b.size * 8).toString() }.toIntOrNull() ?: return false
        if (prefix !in 0..b.size * 8) return false
        for (bit in 0 until prefix) {
            val mask = 0x80 ushr (bit % 8)
            if ((a[bit / 8].toInt() and mask) != (b[bit / 8].toInt() and mask)) return false
        }
        return true
    }
}

val ApiKeyAuth = createApplicationPlugin(name = "ApiKeyAuth", ::ApiKeyAuthConfig) {
    val registry = pluginConfig.registry
    val allowAnonymous = pluginConfig.allowAnonymous

    if (registry.isEmpty) {
        if (!allowAnonymous) {
            // Fail-fast: a server that copy-pastes the demo-compose file
            // without setting API_KEY would otherwise come up with admin
            // endpoints wide open. Force operators to either set API_KEY or
            // make the anonymous-admin choice explicit via env var. (C-01)
            error(NO_ADMIN_KEY_MESSAGE)
        }
        val adminListener = pluginConfig.anonymousAdminListener
        val peers = pluginConfig.anonymousPeers
        peers.filterNot(PeerRules::valid).takeIf { it.isNotEmpty() }?.let { bad ->
            error("ANONYMOUS_ADMIN_PEERS: ${bad.joinToString()} is not an IP address or CIDR (e.g. 172.17.0.1 or 172.17.0.0/16)")
        }
        if (adminListener) {
            application.log.warn(
                "API_KEY not set and ALLOW_ANONYMOUS_ADMIN=true — management API " +
                "authentication DISABLED. Admin requests are answered only from this machine" +
                (if (peers.isEmpty()) "" else " and ANONYMOUS_ADMIN_PEERS ${peers.joinToString()}") +
                ". Do not run this configuration on a network you don't control."
            )
        }
        onCall { call ->
            if (isPublicEndpoint(call.request.path(), call.request.httpMethod)) return@onCall
            // A Config API listener binds every interface and is the port devices
            // reach: without a key it would hand the LAN every admin route
            // (PUT /certificate-config, host changes). Admin without a key exists
            // on the management listener only.
            if (!adminListener) {
                return@onCall call.refuseAnonymous("admin_key_required",
                    "This server has no admin keys: admin requests are answered only on the management port, from its own machine.")
            }
            // The Host header is the client's word (AdminBrowserGuard checks it for
            // browsers); the socket's peer is not. With MANAGEMENT_BIND=0.0.0.0 any
            // program on the network could otherwise send `Host: localhost:8090`.
            if (!PeerRules.allowed(call.request.local.remoteAddress, peers)) {
                return@onCall call.refuseAnonymous("peer_not_allowed",
                    "Without an admin key this API answers only connections from this machine. " +
                        "A container gateway can be added with ANONYMOUS_ADMIN_PEERS.")
            }
            call.attributes.put(AdminPrincipalKey, AdminPrincipal("anonymous"))
        }
        return@createApplicationPlugin
    }

    application.log.info("API Key authentication enabled for management endpoints (admins: ${registry.names})")
    val failureLimiter = if (pluginConfig.failureLimit > 0) {
        pluginConfig.failureLimiter ?: com.example.pinvault.server.service.RateLimiter(maxAttempts = pluginConfig.failureLimit, windowMs = 10 * 60_000)
    } else null

    onCall { call ->
        val path = call.request.path()
        val method = call.request.httpMethod

        // Skip auth for client-facing and public endpoints
        if (isPublicEndpoint(path, method)) return@onCall

        // The server replaying a change that another admin approved. The
        // token is single-use, bound to this exact method + path + query,
        // valid for seconds and only accepted over loopback — see ApprovalReplay.
        call.request.header(ApprovalReplay.HEADER)?.let { token ->
            // The socket's own peer address (never a forwarded header, never
            // a reverse-DNS name): only the server itself may replay.
            val grant = ApprovalReplay.redeem(token, method.value, path, call.request.queryString(), call.request.local.remoteAddress)
            if (grant == null) {
                call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid or expired approval replay token"))
                return@onCall
            }
            call.attributes.put(AdminPrincipalKey, AdminPrincipal(grant.actor))
            call.attributes.put(ApprovedReplayKey, grant.changeRequestId)
            if (grant.ip.isNotEmpty()) call.attributes.put(ApprovedReplayIpKey, grant.ip)
            return@onCall
        }

        // An address that kept sending wrong keys is cut off before its next
        // key is compared: guessing keys costs 10 minutes per batch. The socket's
        // own peer, never a forwarded header. Callers with the right key never
        // count — only refusals do.
        val source = com.example.pinvault.server.service.RateLimiter.sourceKey(call.request.local.remoteAddress)
        if (failureLimiter != null && failureLimiter.exceeded(source)) {
            call.response.header(HttpHeaders.RetryAfter, "600")
            call.respond(HttpStatusCode.TooManyRequests, mapOf("error" to "Too many invalid admin keys from this address; try again later"))
            return@onCall
        }

        val providedKey = call.request.header("X-API-Key")
        if (providedKey == null) {
            call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "X-API-Key header required"))
            return@onCall
        }

        val admin = registry.identify(providedKey)
        if (admin == null) {
            // remoteAddress, not remoteHost: remoteHost is a blocking reverse-DNS
            // lookup on the event-loop thread, and a name the caller controls.
            AuthFailures.report(call.request.origin.remoteAddress, method.value, path)
            failureLimiter?.allow(source)
            call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid API key"))
            return@onCall
        }
        call.attributes.put(AdminPrincipalKey, AdminPrincipal(admin))
    }
}

/** Why a server without admin keys does not start (unless `ALLOW_ANONYMOUS_ADMIN=true`). */
const val NO_ADMIN_KEY_MESSAGE: String =
    "API_KEY env var is not set. Refusing to start with anonymous " +
        "admin access. Set API_KEY=<secret> (or ADMIN_KEYS) or, to deliberately run " +
        "without authentication (e.g. local dev), set " +
        "ALLOW_ANONYMOUS_ADMIN=true."

/**
 * Invalid-key attempts, forwarded to whoever registers [listener] (the audit
 * log). A burst of these is someone guessing keys.
 */
object AuthFailures {
    @Volatile
    var listener: ((remoteHost: String, method: String, path: String) -> Unit)? = null

    fun report(remoteHost: String, method: String, path: String) {
        try {
            listener?.invoke(remoteHost, method, path)
        } catch (_: Exception) { /* auditing must never break auth */ }
    }
}

/**
 * One-time tokens that let the server replay an approved change through its
 * own management API, as the requester, without holding anyone's key.
 */
object ApprovalReplay {
    const val HEADER = "X-PinVault-Replay"
    private const val VALIDITY_MS = 30_000L

    /** [ip] is the approver's address, for the audit entries the replay writes. */
    data class Grant(
        val changeRequestId: Long,
        val actor: String,
        val method: String,
        val path: String,
        val query: String,
        val expiresAt: Long,
        val ip: String = ""
    )

    private val grants = ConcurrentHashMap<String, Grant>()
    private val random = SecureRandom()

    private fun isLoopback(address: String): Boolean =
        try {
            // A literal IP from the socket: parsed, not resolved.
            java.net.InetAddress.getByName(address).isLoopbackAddress
        } catch (_: Exception) {
            false
        }

    fun issue(changeRequestId: Long, actor: String, method: String, path: String, query: String, ip: String = ""): String {
        val token = ByteArray(32).also(random::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        grants[token] = Grant(changeRequestId, actor, method.uppercase(), path, query, System.currentTimeMillis() + VALIDITY_MS, ip)
        return token
    }

    /** Consumes [token] if it matches this request; null otherwise. */
    fun redeem(token: String, method: String, path: String, query: String, remoteAddress: String): Grant? {
        val grant = grants.remove(token) ?: return null
        // Expired grants of abandoned replays are dropped here too.
        val now = System.currentTimeMillis()
        grants.entries.removeIf { it.value.expiresAt < now }
        val ok = grant.expiresAt > now &&
            isLoopback(remoteAddress) &&
            grant.method == method.uppercase() && grant.path == path && grant.query == query
        return if (ok) grant else null
    }
}

/** `GET /api/v1/vault/{key}` — the device download path; group 1 is the key. */
private val VAULT_DOWNLOAD_PATH = Regex("/api/v1/vault/([A-Za-z0-9._-]{1,64})")

/**
 * Constant segments under `/api/v1/vault` that are admin or client-report
 * routes rather than file keys. Excluded from the public download rule and
 * rejected as file keys on upload, so a file can never shadow (or be
 * shadowed by) one of these routes.
 */
internal val RESERVED_VAULT_SEGMENTS = setOf("distributions", "stats", "devices", "report", "tokens")

/**
 * Endpoints that do NOT require authentication.
 * These are called by Android devices or are public health/static resources.
 *
 * Kept deliberately narrow: every rule is an exact path or a single-segment
 * pattern. Prefix rules previously exposed admin reads on the Config API
 * ports — `/certificate-config/history/{host}`, `/vault/distributions` and
 * `/vault/stats` all matched a "public" pattern.
 */
internal fun isPublicEndpoint(path: String, method: HttpMethod): Boolean {
    // Health check (Docker probe)
    if (path == "/health") return true

    // Static resources and Web UI
    if (path == "/" || path.startsWith("/static/") || path == "/docs") return true

    // Client endpoints — config download. Exact path only: sub-paths such as
    // /api/v1/certificate-config/history/{hostname} are admin reads.
    if (path.trimEnd('/') == "/api/v1/certificate-config" && method == HttpMethod.Get) return true
    if (path == "/api/v1/signing-key") return true

    // Client endpoints — enrollment
    if (path == "/api/v1/client-certs/enroll" && method == HttpMethod.Post) return true
    // Renewal authenticates itself: the presented client cert, or the CSR
    // signature against the key registered at enrollment.
    if (path == "/api/v1/client-certs/renew" && method == HttpMethod.Post) return true
    if (path.matches(Regex("/api/v1/client-certs/[^/]+/download")) && method == HttpMethod.Get) return true

    // Client endpoints — vault file download and reporting. The download path
    // shares its prefix with constant admin routes (/distributions, /stats, …),
    // which Ktor routes ahead of `{key}`; only a well-formed key that is not a
    // reserved segment is public.
    if (method == HttpMethod.Get) {
        val key = VAULT_DOWNLOAD_PATH.matchEntire(path)?.groupValues?.get(1)
        if (key != null && key !in RESERVED_VAULT_SEGMENTS) return true
    }
    if (path == "/api/v1/vault/report" && method == HttpMethod.Post) return true

    // Client endpoint — device E2E public-key registration. Called by the
    // device (DefaultCertificateConfigApi) so the server can wrap end_to_end
    // files with the device's RSA key, so it must stay open to devices here;
    // the route authenticates itself (audit M-2): a bound client certificate,
    // or on TLS the first key / an end_to_end file token for a replacement.
    // DELETE (resetting a device's key) is not listed: admin only.
    if (path.matches(Regex("/api/v1/vault/devices/[^/]+/public-key")) && method == HttpMethod.Post) return true

    // Client connection report
    if (path == "/api/v1/connection-history/client-report" && method == HttpMethod.Post) return true
    if (path == "/api/v1/connection-history/config-update-report" && method == HttpMethod.Post) return true

    // Enrollment mode check (needed by client before enrollment)
    if (path == "/api/v1/enrollment-mode" && method == HttpMethod.Get) return true

    // Attestation (ATTESTATION.md §2): the challenge and the attestation itself.
    // The route authenticates the device by its own key; the admin API under
    // /api/v1/attestation/… and …/attestation/… is not listed.
    if (path == "/api/v1/attest/challenge" && method == HttpMethod.Get) return true
    if (path == "/api/v1/attest" && method == HttpMethod.Post) return true

    return false
}

/** Constant-time string comparison to prevent timing attacks. */
private fun constantTimeEquals(a: String, b: String): Boolean {
    val aBytes = a.toByteArray()
    val bBytes = b.toByteArray()
    return MessageDigest.isEqual(aBytes, bBytes)
}

/**
 * Shared helpers for route handlers that must re-check the admin key on a
 * path the plugin deliberately allowlists — e.g. `GET /api/v1/vault/{key}`,
 * which devices call without a key but which may serve an `api_key` file.
 */
object ApiKeyPolicy {
    /** The configured admin key, or null when `API_KEY` is unset (anonymous-admin dev mode). */
    fun configuredKey(): String? = com.example.pinvault.server.service.ServerEnv.get("API_KEY")?.takeIf { it.isNotBlank() }

    /** Constant-time comparison of a presented key against the expected one. */
    fun matches(provided: String?, expected: String): Boolean =
        provided != null && constantTimeEquals(provided, expected)

    private val registry by lazy { AdminRegistry.fromEnv() }

    /** True when [provided] is the key of an `ADMIN_KEYS` admin. */
    fun isNamedAdmin(provided: String): Boolean =
        registry.identify(provided).let { it != null && it != AdminRegistry.LEGACY_NAME }

    fun hasNamedAdmins(): Boolean = registry.names.any { it != AdminRegistry.LEGACY_NAME }
}

/** 403 for an anonymous admin request this listener or peer may not make; audited like a browser-guard refusal. */
private suspend fun ApplicationCall.refuseAnonymous(error: String, message: String) {
    try {
        BrowserGuardRefusals.listener?.invoke(request.local.remoteAddress, request.httpMethod.value, request.path(), error)
    } catch (_: Exception) { /* auditing must never break the refusal */ }
    respondText(
        kotlinx.serialization.json.buildJsonObject {
            put("error", kotlinx.serialization.json.JsonPrimitive(error))
            put("message", kotlinx.serialization.json.JsonPrimitive(message))
        }.toString(),
        ContentType.Application.Json, HttpStatusCode.Forbidden
    )
}
