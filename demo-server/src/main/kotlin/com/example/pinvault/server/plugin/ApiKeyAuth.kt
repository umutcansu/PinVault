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

        fun fromEnv(env: Map<String, String> = System.getenv()): AdminRegistry {
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
    var allowAnonymous: Boolean = System.getenv("ALLOW_ANONYMOUS_ADMIN") == "true"
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
            error(
                "API_KEY env var is not set. Refusing to start with anonymous " +
                "admin access. Set API_KEY=<secret> (or ADMIN_KEYS) or, to deliberately run " +
                "without authentication (e.g. local dev), set " +
                "ALLOW_ANONYMOUS_ADMIN=true."
            )
        }
        application.log.warn(
            "API_KEY not set and ALLOW_ANONYMOUS_ADMIN=true — management API " +
            "authentication DISABLED. Do not run this configuration on a " +
            "network you don't control."
        )
        onCall { call ->
            if (!isPublicEndpoint(call.request.path(), call.request.httpMethod)) {
                call.attributes.put(AdminPrincipalKey, AdminPrincipal("anonymous"))
            }
        }
        return@createApplicationPlugin
    }

    application.log.info("API Key authentication enabled for management endpoints (admins: ${registry.names})")

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
            call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid API key"))
            return@onCall
        }
        call.attributes.put(AdminPrincipalKey, AdminPrincipal(admin))
    }
}

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
    // files with the device's RSA key, so it must stay unauthenticated here.
    // NOTE: this route still lacks identity binding (a device can overwrite
    // another device's key) — tracked as audit finding M-2 and fixed
    // separately; the admin API key is the wrong control for it.
    if (path.matches(Regex("/api/v1/vault/devices/[^/]+/public-key")) && method == HttpMethod.Post) return true

    // Client connection report
    if (path == "/api/v1/connection-history/client-report" && method == HttpMethod.Post) return true
    if (path == "/api/v1/connection-history/config-update-report" && method == HttpMethod.Post) return true

    // Enrollment mode check (needed by client before enrollment)
    if (path == "/api/v1/enrollment-mode" && method == HttpMethod.Get) return true

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
    fun configuredKey(): String? = System.getenv("API_KEY")?.takeIf { it.isNotBlank() }

    /** Constant-time comparison of a presented key against the expected one. */
    fun matches(provided: String?, expected: String): Boolean =
        provided != null && constantTimeEquals(provided, expected)

    private val registry by lazy { AdminRegistry.fromEnv() }

    /** True when [provided] is the key of an `ADMIN_KEYS` admin. */
    fun isNamedAdmin(provided: String): Boolean =
        registry.identify(provided).let { it != null && it != AdminRegistry.LEGACY_NAME }

    fun hasNamedAdmins(): Boolean = registry.names.any { it != AdminRegistry.LEGACY_NAME }
}
