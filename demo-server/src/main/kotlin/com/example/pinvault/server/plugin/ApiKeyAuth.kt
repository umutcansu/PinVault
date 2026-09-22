package com.example.pinvault.server.plugin

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.security.MessageDigest

/**
 * API Key authentication plugin for management endpoints.
 *
 * When API_KEY env var is set, management endpoints require X-API-Key header.
 * Client endpoints (config download, enrollment, vault) remain unauthenticated.
 * When API_KEY is empty/null, auth is disabled (development mode).
 */
val ApiKeyAuth = createApplicationPlugin(name = "ApiKeyAuth") {
    val apiKey = System.getenv("API_KEY")?.takeIf { it.isNotBlank() }
    val allowAnonymous = System.getenv("ALLOW_ANONYMOUS_ADMIN") == "true"

    if (apiKey == null) {
        if (!allowAnonymous) {
            // Fail-fast: a server that copy-pastes the demo-compose file
            // without setting API_KEY would otherwise come up with admin
            // endpoints wide open. Force operators to either set API_KEY or
            // make the anonymous-admin choice explicit via env var. (C-01)
            error(
                "API_KEY env var is not set. Refusing to start with anonymous " +
                "admin access. Set API_KEY=<secret> or, to deliberately run " +
                "without authentication (e.g. local dev), set " +
                "ALLOW_ANONYMOUS_ADMIN=true."
            )
        }
        application.log.warn(
            "API_KEY not set and ALLOW_ANONYMOUS_ADMIN=true — management API " +
            "authentication DISABLED. Do not run this configuration on a " +
            "network you don't control."
        )
        return@createApplicationPlugin
    }

    application.log.info("API Key authentication enabled for management endpoints")

    onCall { call ->
        val path = call.request.path()
        val method = call.request.httpMethod

        // Skip auth for client-facing and public endpoints
        if (isPublicEndpoint(path, method)) return@onCall

        val providedKey = call.request.header("X-API-Key")
        if (providedKey == null) {
            call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "X-API-Key header required"))
            return@onCall
        }

        if (!constantTimeEquals(providedKey, apiKey)) {
            call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid API key"))
            return@onCall
        }
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
}
