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

    if (apiKey == null) {
        application.log.warn("API_KEY not set — management API authentication DISABLED")
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

/**
 * Endpoints that do NOT require authentication.
 * These are called by Android devices or are public health/static resources.
 */
private fun isPublicEndpoint(path: String, method: HttpMethod): Boolean {
    // Health check (Docker probe)
    if (path == "/health") return true

    // Static resources and Web UI
    if (path == "/" || path.startsWith("/static/") || path == "/docs") return true

    // Client endpoints — config download
    if (path.startsWith("/api/v1/certificate-config") && method == HttpMethod.Get) return true
    if (path == "/api/v1/signing-key") return true

    // Client endpoints — enrollment
    if (path == "/api/v1/client-certs/enroll" && method == HttpMethod.Post) return true
    if (path.matches(Regex("/api/v1/client-certs/.+/download")) && method == HttpMethod.Get) return true

    // Client endpoints — vault file download and reporting
    if (path.matches(Regex("/api/v1/vault/[^/]+")) && method == HttpMethod.Get) return true
    if (path == "/api/v1/vault/report" && method == HttpMethod.Post) return true

    // Client connection report
    if (path == "/api/v1/connection-history/client-report" && method == HttpMethod.Post) return true

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
