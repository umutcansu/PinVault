package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.clientCertificate
import com.example.pinvault.server.service.attestation.PinVaultProof
import com.example.pinvault.server.service.attestation.PinVaultToken
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpMethod
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
 * in its `anno` claim. A request that names its device (`X-Device-Id`) must
 * name the token's `did`. With [PinVaultTokenAuthConfig.requireCertBinding]
 * the request must arrive over mTLS with the client certificate the token's
 * `cnf.x5t#S256` names (the one the device attested with). With
 * [PinVaultTokenAuthConfig.requireProof] every request also carries a
 * `PinVault-Proof` made for it with the key the token's `cnf.jkt` names
 * ([PinVaultProof], §5.1). Anything else is `401` with
 * `WWW-Authenticate: PinVault-Token error="invalid_token", error_description="…"`
 * and `{"error":"invalid_token","reason":"missing|malformed|unknown_kid|signature|issuer|expired|audience|annotations|device_mismatch|cert_binding|proof_…"}`
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

    /**
     * `PINVAULT_TOKEN_REQUIRE_CERT_BINDING`: the request must come over mTLS
     * with the client certificate whose SHA-256 the token's `cnf.x5t#S256`
     * carries — a token lifted from the device is then useless without the
     * device's private key. Tokens without that claim (attested over plain
     * TLS, or issued before `cnf`) are refused. Only for a backend that
     * terminates mTLS itself with the identity the app attests with; off,
     * `cnf` is not looked at.
     */
    var requireCertBinding: Boolean = false

    /**
     * `PINVAULT_TOKEN_REQUIRE_PROOF`: every request carries a `PinVault-Proof`
     * (§5.1) for its method and URL, signed by the device key the token's
     * `cnf.jkt` names — a token lifted from the device is useless without
     * that key, behind any proxy. Tokens without `cnf.jkt` are refused.
     */
    var requireProof: Boolean = false

    /** How far a proof's `iat` may lie from now, either way. */
    var proofWindowSeconds: Long = 60

    /**
     * The scheme, host and port clients use to reach this backend
     * (`https://api.example.com`), when a proxy in front of it changes them;
     * null = what the request's `Host` header and connection say.
     */
    var publicOrigin: String? = null

    /** Spent proof `jti`s; one per backend. */
    var proofReplay: PinVaultProof.ReplayCache = PinVaultProof.ReplayCache()

    /** The verified client certificate of the call (tests replace it). */
    var clientCertificate: (ApplicationCall) -> java.security.cert.X509Certificate? = { it.clientCertificate() }

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
    val requireCertBinding = pluginConfig.requireCertBinding
    val certificateOf = pluginConfig.clientCertificate
    val requireProof = pluginConfig.requireProof
    val proofWindow = pluginConfig.proofWindowSeconds
    val publicOrigin = pluginConfig.publicOrigin?.trimEnd('/')?.also {
        require(PinVaultProof.normalizedUrl("$it/") != null) { "publicOrigin must be an http(s) origin, e.g. https://api.example.com" }
    }
    val replay = pluginConfig.proofReplay

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
                "issuer" -> "The token was not issued by PinVault."
                "audience" -> "The token was issued for another Config API."
                else -> "The token is not a PinVault-Token."
            })
            is PinVaultToken.Result.Valid -> {
                if (required.isNotEmpty() && !result.claims.annotations.containsAll(required)) {
                    return@onCall call.refuseToken("annotations", "The token lacks a required annotation.")
                }
                // A request that says which device it is must be that token's device.
                val claimedDevice = call.request.header("X-Device-Id")?.trim()?.takeIf { it.isNotEmpty() }
                if (claimedDevice != null && claimedDevice != result.claims.deviceId) {
                    return@onCall call.refuseToken("device_mismatch", "The token was issued to another device.")
                }
                if (requireCertBinding) {
                    val bound = result.claims.certThumbprint
                    val presented = certificateOf(call)?.let { PinVaultToken.certThumbprint(it.encoded) }
                    if (bound == null || presented == null || !java.security.MessageDigest.isEqual(bound.toByteArray(), presented.toByteArray())) {
                        return@onCall call.refuseToken("cert_binding", "The token is bound to another client certificate, or the request carries none.")
                    }
                }
                if (requireProof) {
                    val proof = PinVaultProof.verify(
                        call.request.header(PinVaultProof.HEADER), call.request.httpMethod.value, requestUrl(call, publicOrigin),
                        token, result.claims.keyThumbprint, replay, clock(), proofWindow
                    )
                    if (proof is PinVaultProof.Result.Invalid) {
                        return@onCall call.refuseToken(proof.reason, when (proof.reason) {
                            "proof_missing" -> "Send a PinVault-Proof header with the token."
                            "proof_key" -> "The proof is not signed by the key the token was issued to."
                            "proof_time" -> "The proof's iat is too far from now."
                            "proof_replay" -> "This proof was already used."
                            "proof_busy" -> "Too many proofs in flight; try again."
                            else -> "The PinVault-Proof does not match this request."
                        })
                    }
                }
                call.attributes.put(PinVaultTokenClaimsKey, result.claims)
            }
        }
    }
}

/** The URL the client asked for, as `htu` names it: [publicOrigin] or the `Host` header's, plus the raw path. */
private fun requestUrl(call: ApplicationCall, publicOrigin: String?): String {
    val origin = publicOrigin ?: call.request.origin.let { o ->
        val host = o.serverHost.let { if (':' in it && !it.startsWith("[")) "[$it]" else it }
        "${o.scheme}://$host:${o.serverPort}"
    }
    return origin + call.request.path()
}

private suspend fun ApplicationCall.refuseToken(reason: String, description: String) {
    response.header(HttpHeaders.WWWAuthenticate, "${PinVaultToken.HEADER} error=\"invalid_token\", error_description=\"$description\"")
    respondText("""{"error":"invalid_token","reason":"$reason"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
}
