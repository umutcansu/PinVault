package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.attestation.PinVaultToken
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.header
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.util.AttributeKey

/**
 * The reference verifier of `PinVault-Token` (ATTESTATION.md §5): what a
 * backend does on every request from the app.
 *
 * The header must carry an HS256 JWT signed with the secret its `kid` names
 * in [PinVaultTokenAuthConfig.secrets], unexpired (with the leeway), with the
 * `aud` of this backend's Config API when [PinVaultTokenAuthConfig.audience]
 * is set, and every annotation of [PinVaultTokenAuthConfig.requireAnnotations]
 * in its `anno` claim. Anything else is `401` with
 * `WWW-Authenticate: PinVault-Token error="invalid_token", error_description="…"`
 * and `{"error":"invalid_token","reason":"missing|malformed|unknown_kid|signature|expired|audience|annotations"}`
 * — the shape the library's interceptor recognises to re-attest once and
 * retry. `/health` (and [PinVaultTokenAuthConfig.skipPaths]) stays open.
 *
 * The mock TLS/mTLS hosts install it with `MOCK_HOST_REQUIRE_TOKEN=true`.
 * Nothing here calls the PinVault server: the secrets are loaded, the
 * token is checked locally.
 */
class PinVaultTokenAuthConfig {
    /** The secrets by `kid`, every one listed by `GET /api/v1/attestation/token-secrets`; read per request (rotation). */
    var secrets: () -> Map<String, ByteArray> = { emptyMap() }

    /** The Config API id this backend serves; null = any `aud` is accepted. */
    var audience: String? = null

    /** Clock skew tolerated on `exp` (and a future `iat`). */
    var leewaySeconds: Long = 60

    /** Annotations the token must carry (e.g. `staff`); null or empty = none required. */
    var requireAnnotations: Set<String>? = null

    /** Paths served without a token. */
    var skipPaths: Set<String> = setOf("/health")

    /** Seconds since the epoch (tests). */
    var clock: () -> Long = { System.currentTimeMillis() / 1000 }
}

/** The verified claims of the request's token. */
val PinVaultTokenClaimsKey = AttributeKey<PinVaultToken.Claims>("PinVaultTokenClaims")

/** The verified token of this call, or null when the plugin is not installed (or skipped the path). */
fun ApplicationCall.pinVaultToken(): PinVaultToken.Claims? = attributes.getOrNull(PinVaultTokenClaimsKey)

val PinVaultTokenAuth = createApplicationPlugin(name = "PinVaultTokenAuth", ::PinVaultTokenAuthConfig) {
    val secrets = pluginConfig.secrets
    val audience = pluginConfig.audience
    val leeway = pluginConfig.leewaySeconds
    val required = pluginConfig.requireAnnotations.orEmpty()
    val skip = pluginConfig.skipPaths
    val clock = pluginConfig.clock

    onCall { call ->
        if (call.response.isCommitted) return@onCall
        if (call.request.path() in skip) return@onCall
        val token = call.request.header(PinVaultToken.HEADER)?.trim()?.takeIf { it.isNotEmpty() }
            ?: return@onCall call.refuseToken("missing", "Send a PinVault-Token header.")
        when (val result = PinVaultToken.verify(token, secrets(), audience, clock(), leeway)) {
            is PinVaultToken.Result.Invalid -> call.refuseToken(result.reason, when (result.reason) {
                "expired" -> "The token has expired; attest again."
                "unknown_kid" -> "The token was signed with a secret this backend does not know."
                "signature" -> "The token's signature does not verify."
                "audience" -> "The token was issued for another Config API."
                else -> "The token is not a PinVault-Token."
            })
            is PinVaultToken.Result.Valid -> {
                if (required.isNotEmpty() && !result.claims.annotations.containsAll(required)) {
                    return@onCall call.refuseToken("annotations", "The token lacks a required annotation.")
                }
                call.attributes.put(PinVaultTokenClaimsKey, result.claims)
            }
        }
    }
}

private suspend fun ApplicationCall.refuseToken(reason: String, description: String) {
    response.header(HttpHeaders.WWWAuthenticate, "${PinVaultToken.HEADER} error=\"invalid_token\", error_description=\"$description\"")
    respondText("""{"error":"invalid_token","reason":"$reason"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
}
