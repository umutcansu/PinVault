package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.ApiKeyPolicy
import com.example.pinvault.server.plugin.RESERVED_VAULT_SEGMENTS
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.DevicePublicKeyStore
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.origin
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Instant

private val log = LoggerFactory.getLogger("VaultRoutes")

/**
 * Vault file routes. Every route is scoped to [configApiId] — the same key can
 * exist under different Config APIs independently. All client-facing routes
 * enforce the file's [access_policy] before returning content.
 *
 * Registered once per Config API module in Main.kt, so each listener carries
 * its own scope. The management server does NOT mount these routes — its vault
 * administration lives under `/api/v1/config-apis/{configApiId}/vault/...`
 * ([scopedVaultAdminRoutes]), where the scope is a URL component instead.
 *
 * Because [configApiId] is a parameter (not a URL component) here, the same
 * route path `/api/v1/vault/{key}` resolves to different scopes on different
 * ports.
 */
fun Route.vaultRoutes(
    configApiId: String,
    vaultFileStore: VaultFileStore,
    distStore: VaultDistributionStore,
    tokenStore: VaultFileTokenStore,
    publicKeyStore: DevicePublicKeyStore,
    tokenService: VaultAccessTokenService,
    encryptionService: VaultEncryptionService,
    signingService: ConfigSigningService? = null,
    /**
     * Needed only by the `token_mtls` policy: lets a certificate issued under a
     * token enrollment (where the client id is admin-chosen, not the device's
     * ANDROID_ID) be matched to the `X-Device-Id` recorded at enrollment time.
     * Null falls back to the direct clientId == deviceId rule.
     */
    clientCertStore: com.example.pinvault.server.store.ClientCertStore? = null,
    adminApiKeyRequired: Boolean = true,
    /**
     * Source of the admin key for `api_key`-policy downloads. Defaults to the
     * `API_KEY` env var (same as the ApiKeyAuth plugin); tests inject a value.
     */
    apiKeyProvider: () -> String? = { ApiKeyPolicy.configuredKey() },
    /**
     * The scope's `config_apis.vault_enabled` switch, read per request so a
     * dashboard toggle takes effect without restarting the listener. Default
     * `{ true }` keeps listeners that have no registry row (tests, embedded
     * use) behaving exactly as before.
     *
     * Only the client-facing download is gated — see the route below.
     */
    vaultEnabledProvider: () -> Boolean = { true },
    /**
     * Produces (and, with `CONFIG_SIGNATURE_CACHE`, caches) the vault file
     * signatures. Null = sign per request with [signingService].
     */
    signedConfigService: com.example.pinvault.server.service.SignedConfigService? = null,
    /** Where E2E key registrations, replacements and resets are recorded; null = nowhere. */
    audit: com.example.pinvault.server.service.AuditLog? = null,
    /** Records refused E2E key registrations without flooding the audit log; null = not recorded. */
    keyRefusals: com.example.pinvault.server.service.AuthFailureRecorder? = null,
    /**
     * Counts the E2E keys a source address writes without a client
     * certificate (`DEVICE_KEY_RATE_LIMIT`); null = unlimited. With a
     * certificate a device can only write its own slot, so it is not counted.
     */
    keyLimiter: com.example.pinvault.server.service.RateLimiter? = null,
    /** Most device keys this scope stores (`DEVICE_KEY_LIMIT`); a new device beyond it gets 503. */
    maxDeviceKeys: Int = Int.MAX_VALUE
) {
    val vaultSigner = signedConfigService ?: signingService?.let { com.example.pinvault.server.service.SignedConfigService(it) }
    route("/api/v1/vault") {

        // ── Client-facing: download + report ────────────────────────

        /**
         * Download a vault file. Supports version-based 304.
         *
         * The scope's `vault_enabled` switch is checked FIRST, before the key
         * even resolves: when an operator turns the vault off on a Config API,
         * distribution from that scope must stop immediately. It answers 403
         * for every key, present or not, so a disabled vault does not leak
         * which keys exist.
         *
         * The switch is intentionally *not* applied to the admin routes below
         * (upload, list, policy, delete, tokens, distributions): the reason an
         * operator flips it is usually "a file went out that shouldn't have",
         * and they still need to inspect and delete it afterwards. Nor does it
         * replace the per-file [access_policy] — that stays the authentication
         * boundary; this is the "stop the tap" switch.
         *
         * Access policy enforcement (in order):
         *   - public       → no checks
         *   - api_key      → requires X-API-Key (checked HERE — the ApiKeyAuth
         *                    plugin allowlists this path for device downloads)
         *   - token        → requires X-Device-Id + X-Vault-Token matching
         *                    (configApiId, key, deviceId) triple
         *   - token_mtls   → same as token, plus verifies that the mTLS cert
         *                    CN matches the claimed deviceId
         *
         * If encryption == "end_to_end", the server wraps the content with
         * the device's RSA public key (see VaultEncryptionService).
         */
        get("/{key}") {
            if (!vaultEnabledProvider()) {
                log.warn("Vault download refused — vault disabled on configApi={} (key={})",
                    configApiId, call.parameters["key"])
                return@get call.respond(HttpStatusCode.Forbidden,
                    mapOf("error" to "Vault is disabled for Config API '$configApiId'"))
            }
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            // Defense-in-depth (L-02): vault keys are flat identifiers
            // (alphanumeric, `.`, `_`, `-`). The current storage backend is
            // SQLite with prepared statements so path traversal has no
            // direct effect, but if a future variant writes to disk this
            // check stops `..` segments before they reach the filesystem.
            if (!VAULT_KEY_REGEX.matches(key)) {
                return@get call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "Invalid vault key format"))
            }

            val currentVersion = call.request.queryParameters["version"]?.toIntOrNull() ?: 0
            val entry = vaultFileStore.get(configApiId, key)
                ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found: $key"))

            // Access policy check ────────────────────────────────────
            val deviceId = call.request.header("X-Device-Id")
            when (entry.accessPolicy) {
                "public" -> { /* no-op */ }
                "api_key" -> {
                    // The ApiKeyAuth plugin allowlists GET /api/v1/vault/{key}
                    // for every key (devices fetch public/token files without
                    // an admin key), so the plugin never checked this request.
                    // Enforce the key here; when no API_KEY is configured
                    // (ALLOW_ANONYMOUS_ADMIN dev mode) fail closed rather than
                    // turning an "admin-only" file into a world-readable one.
                    val expected = apiKeyProvider()
                    val provided = call.request.header("X-API-Key")
                    // A named admin (ADMIN_KEYS) may fetch it too, with or without API_KEY.
                    val namedAdmin = provided != null && ApiKeyPolicy.isNamedAdmin(provided)
                    if (expected == null && !namedAdmin && !ApiKeyPolicy.hasNamedAdmins()) {
                        log.warn("api_key file requested but no API_KEY configured: configApi={} key={}",
                            configApiId, key)
                        return@get call.respond(HttpStatusCode.Forbidden,
                            mapOf("error" to "api_key policy requires API_KEY to be configured on the server"))
                    }
                    if (!namedAdmin && (expected == null || !ApiKeyPolicy.matches(provided, expected))) {
                        log.warn("api_key file rejected (missing/invalid X-API-Key): configApi={} key={}",
                            configApiId, key)
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-API-Key header required for api_key policy"))
                    }
                }
                "token", "token_mtls" -> {
                    if (deviceId.isNullOrBlank()) {
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-Device-Id header required for token policy"))
                    }
                    val token = call.request.header("X-Vault-Token")
                        ?: return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-Vault-Token header required"))

                    if (!tokenService.validate(configApiId, key, deviceId, token)) {
                        log.warn("Vault token rejected: configApi={} key={} deviceId={}",
                            configApiId, key, deviceId)
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "Invalid or revoked token"))
                    }

                    if (entry.accessPolicy == "token_mtls") {
                        // The token alone proves "someone holds the secret".
                        // token_mtls additionally requires the request to
                        // arrive over a client-authenticated TLS connection
                        // whose certificate belongs to the same device, so a
                        // leaked token is useless without the private key.
                        val certClientId = call.clientCertId()
                        if (certClientId == null) {
                            log.warn("token_mtls file requested without mTLS cert: configApi={} key={}",
                                configApiId, key)
                            return@get call.respond(HttpStatusCode.Unauthorized,
                                mapOf("error" to "mTLS client certificate required"))
                        }
                        if (!certificateBoundTo(certClientId, deviceId, clientCertStore)) {
                            log.warn("token_mtls deviceId/CN mismatch: certClientId={} claimed={}",
                                certClientId, deviceId)
                            return@get call.respond(HttpStatusCode.Unauthorized,
                                mapOf("error" to "Device identity mismatch"))
                        }
                    }
                }
                else -> {
                    log.error("Unknown access_policy '{}' on {}:{}", entry.accessPolicy, configApiId, key)
                    return@get call.respond(HttpStatusCode.InternalServerError,
                        mapOf("error" to "Misconfigured access policy"))
                }
            }

            // 304 shortcut ───────────────────────────────────────────
            if (entry.version <= currentVersion) {
                call.response.header("X-Vault-Version", entry.version.toString())
                call.response.header("X-Vault-Encryption", entry.encryption)
                call.respond(HttpStatusCode.NotModified)
                return@get
            }

            // Encryption ─────────────────────────────────────────────
            val payload: ByteArray = when (entry.encryption) {
                "plain", "at_rest" -> entry.content
                "end_to_end" -> {
                    val did = deviceId ?: return@get call.respond(HttpStatusCode.Unauthorized,
                        mapOf("error" to "X-Device-Id required for end_to_end encryption"))
                    val pubKey = publicKeyStore.get(did, configApiId)
                        ?: return@get call.respond(HttpStatusCode.PreconditionFailed, mapOf(
                            "error" to "No registered public key for device; call POST /api/v1/vault/devices/{deviceId}/public-key first"))
                    try {
                        encryptionService.encryptForDevice(entry.content, pubKey.publicKeyPem)
                    } catch (e: Exception) {
                        log.error("Encryption failed: configApi={} key={} deviceId={}",
                            configApiId, key, did, e)
                        return@get call.respond(HttpStatusCode.InternalServerError,
                            mapOf("error" to "Encryption failed: ${e.message}"))
                    }
                }
                else -> entry.content
            }

            call.response.header("X-Vault-Version", entry.version.toString())
            call.response.header("X-Vault-Encryption", entry.encryption)
            // Integrity (default-on): sign the PLAINTEXT (entry.content), not the
            // possibly per-device-encrypted wire `payload`, so a single signature
            // covers plain/at_rest/end_to_end and the device verifies whatever
            // plaintext it ends up with. Canonical binds key+version+hash.
            // With several signers (m-of-n) every signature goes into
            // X-Vault-Signatures as `keyId:signature`, comma-separated;
            // X-Vault-Signature keeps the primary one for older clients.
            vaultSigner?.let {
                val signatures = it.vaultSignatures(key, entry.version, entry.content)
                call.response.header("X-Vault-Signature", signatures.first().signature)
                if (signatures.size > 1) {
                    call.response.header(
                        "X-Vault-Signatures",
                        signatures.joinToString(",") { s -> "${s.keyId}:${s.signature}" }
                    )
                }
            }
            call.respondBytes(payload, ContentType.Application.OctetStream)
        }

        /**
         * Register / update a device's public key for E2E encryption.
         *
         * Who may set the key of `{deviceId}` (audit M-2 — it used to be
         * anyone who could reach the port, so a stranger could swap in a key
         * and read what the server then encrypted "for" the device):
         *  - a client certificate was presented (mTLS listener): only one
         *    bound to that device ([certificateBoundTo]); it may replace the
         *    key freely, the certificate is the proof;
         *  - no certificate (TLS listener): the first key is accepted and the
         *    same key again is a no-op. Replacing a registered key needs proof
         *    that the operator handed this device out — a valid vault token,
         *    bound to `{deviceId}`, for an end_to_end file of this scope
         *    (`X-Vault-Key` + `X-Vault-Token`; the library sends it). Without
         *    one: 409, and the registered key stays.
         *
         * Residual on TLS: whoever registers first for a device id that never
         * registered holds the slot until the device shows proof or an
         * administrator removes the key (DELETE below). Files that matter
         * belong on an mTLS Config API.
         *
         * Nothing here asks for a credential on TLS, so a key is only stored
         * when the server could encrypt for it (RSA 2048–4096, re-encoded),
         * a source address writes at most [keyLimiter]'s quota of keys, and a
         * scope holds at most [maxDeviceKeys] of them.
         */
        post("/devices/{deviceId}/public-key") {
            val deviceId = call.parameters["deviceId"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            // Printed in the dashboard and the audit log, matched against X-Device-Id.
            if (!isValidIdentifier(deviceId)) {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "invalid_device_id",
                    "message" to "Letters, digits, '.', '_', ':' and '-' only, at most 64."))
            }
            val body = call.receive<JsonObject>()
            val pem = body["publicKeyPem"]?.jsonPrimitive?.contentOrNull
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "publicKeyPem field required"))
            val algorithm = body["algorithm"]?.jsonPrimitive?.contentOrNull ?: "RSA-OAEP-SHA256"
            if (algorithm != "RSA-OAEP-SHA256") {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "unsupported_algorithm",
                    "message" to "Only RSA-OAEP-SHA256 is supported."))
            }
            val key = canonicalDevicePublicKey(pem)
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "invalid_public_key",
                    "message" to "publicKeyPem must be an RSA public key of 2048 to 4096 bits (X.509 SubjectPublicKeyInfo)."))
            val remote = call.request.origin.remoteAddress

            val certClientId = call.clientCertId()
            val existing = publicKeyStore.get(deviceId, configApiId)
            val changed = existing == null || !samePublicKey(existing.publicKeyPem, key)
            if (certClientId != null) {
                if (!certificateBoundTo(certClientId, deviceId, clientCertStore)) {
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId,
                        reason = "certificate not bound to device $deviceId")
                    return@post call.respond(HttpStatusCode.Forbidden, mapOf(
                        "error" to "device_identity_mismatch",
                        "message" to "The client certificate does not belong to device $deviceId."))
                }
            } else if (existing != null && changed) {
                val proofKey = call.request.header("X-Vault-Key")?.trim()
                val proofToken = call.request.header("X-Vault-Token")?.trim()
                val proven = !proofKey.isNullOrEmpty() && !proofToken.isNullOrEmpty() &&
                    vaultFileStore.get(configApiId, proofKey)?.encryption == "end_to_end" &&
                    tokenService.validate(configApiId, proofKey, deviceId, proofToken)
                if (!proven) {
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId,
                        reason = "key change without proof")
                    return@post call.respond(HttpStatusCode.Conflict, mapOf(
                        "error" to "key_change_requires_proof",
                        "message" to "A different key is already registered for this device. Replacing it over TLS " +
                            "needs the device's token for an end_to_end file (X-Vault-Key + X-Vault-Token), a client " +
                            "certificate bound to the device, or an administrator removing the old key."))
                }
            }

            if (changed) {
                // A device writes its key once, and again only after its data
                // was cleared; a source writing many is making them up.
                if (certClientId == null && keyLimiter?.allow(remote) == false) {
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId, reason = "rate limited")
                    return@post call.respond(HttpStatusCode.TooManyRequests, mapOf(
                        "error" to "rate_limited",
                        "message" to "Too many key registrations from this address. Try again later."))
                }
                if (existing == null && publicKeyStore.count(configApiId) >= maxDeviceKeys) {
                    log.error("E2E key of device {} refused: configApi={} already holds {} device keys (DEVICE_KEY_LIMIT)",
                        deviceId, configApiId, maxDeviceKeys)
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId, reason = "device key limit reached")
                    return@post call.respond(HttpStatusCode.ServiceUnavailable, mapOf(
                        "error" to "device_key_limit_reached",
                        "message" to "This server stores no more device keys. Ask an administrator."))
                }
            }

            publicKeyStore.register(deviceId, configApiId, key, algorithm, Instant.now().toString())
            if (changed) {
                val replaced = existing != null
                audit?.record(
                    if (replaced) "device_key_replaced" else "device_key_registered",
                    "E2E key of device $deviceId ${if (replaced) "replaced" else "registered"}" +
                        (certClientId?.let { " over the certificate of $it" } ?: ""),
                    configApiId, deviceId, actor = certClientId ?: deviceId, ip = remote
                )
            }
            call.respond(HttpStatusCode.OK, mapOf("registered" to "true", "deviceId" to deviceId))
        }

        /**
         * Admin: forget a device's E2E key, so its next registration counts as
         * the first. For a device that lost its key and has no token to prove
         * itself with (a reinstall), or a slot someone else took first.
         */
        delete("/devices/{deviceId}/public-key") {
            val deviceId = call.parameters["deviceId"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            val removed = publicKeyStore.delete(deviceId, configApiId)
            if (removed) {
                audit?.record("device_key_reset", "E2E key of device $deviceId removed by an administrator", configApiId, deviceId)
            }
            call.respond(if (removed) HttpStatusCode.OK else HttpStatusCode.NotFound,
                mapOf("removed" to removed.toString(), "deviceId" to deviceId))
        }

        /** Client reports a vault file download. */
        post("/report") {
            val body = call.receive<JsonObject>()
            val key = body["key"]?.jsonPrimitive?.content ?: ""
            val version = body["version"]?.jsonPrimitive?.intOrNull ?: 0
            val deviceId = body["deviceId"]?.jsonPrimitive?.content ?: "unknown"
            val manufacturer = body["deviceManufacturer"]?.jsonPrimitive?.contentOrNull
            val model = body["deviceModel"]?.jsonPrimitive?.contentOrNull
            val label = body["enrollmentLabel"]?.jsonPrimitive?.contentOrNull
            val deviceAlias = body["deviceAlias"]?.jsonPrimitive?.contentOrNull
            val status = body["status"]?.jsonPrimitive?.content ?: "downloaded"
            val failureReason = body["failureReason"]?.jsonPrimitive?.contentOrNull
            val authMethod = body["authMethod"]?.jsonPrimitive?.contentOrNull
            val timestamp = Instant.now().toString()

            distStore.add(configApiId, key, version, deviceId, manufacturer, model,
                label, status, timestamp, deviceAlias, failureReason, authMethod)
            call.respond(HttpStatusCode.OK, mapOf("recorded" to "true"))
        }

        // ── Admin: file CRUD ────────────────────────────────────────

        /** Upload / update a vault file. Optional policy / encryption fields. */
        put("/{key}") {
            val key = call.parameters["key"]
                ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            // Same shape rule as GET, plus: a key must not collide with a constant
            // admin/report segment (`distributions`, `stats`, …) — Ktor would route
            // its download to that handler and ApiKeyAuth treats those as admin.
            if (!VAULT_KEY_REGEX.matches(key) || key in RESERVED_VAULT_SEGMENTS) {
                return@put call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "Invalid vault key format"))
            }

            val policy = call.request.queryParameters["policy"]
            val encryption = call.request.queryParameters["encryption"]
            val bytes = call.receive<ByteArray>()

            vaultFileStore.put(configApiId, key, bytes, policy, encryption)
            val entry = vaultFileStore.get(configApiId, key)!!

            call.response.header("X-Vault-Version", entry.version.toString())
            call.respond(HttpStatusCode.OK, mapOf(
                "key" to key,
                "version" to entry.version.toString(),
                "access_policy" to entry.accessPolicy,
                "encryption" to entry.encryption
            ))
        }

        /** Update access policy / encryption without changing content. */
        put("/{key}/policy") {
            val key = call.parameters["key"]
                ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val body = call.receive<JsonObject>()
            val policy = body["access_policy"]?.jsonPrimitive?.content
                ?: return@put call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "access_policy field required"))
            val encryption = body["encryption"]?.jsonPrimitive?.content
                ?: return@put call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "encryption field required"))

            require(policy in VALID_POLICIES) { "Invalid access_policy: $policy" }
            require(encryption in VALID_ENCRYPTIONS) { "Invalid encryption: $encryption" }

            val ok = vaultFileStore.updatePolicy(configApiId, key, policy, encryption)
            if (!ok) return@put call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found"))
            call.respond(HttpStatusCode.OK, mapOf("updated" to "true"))
        }

        delete("/{key}") {
            val key = call.parameters["key"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            vaultFileStore.delete(configApiId, key)
            call.respond(HttpStatusCode.OK, mapOf("deleted" to key, "status" to "ok"))
        }

        /** List all files for this Config API scope. */
        get {
            val entries = vaultFileStore.summaries(configApiId).map {
                mapOf(
                    "key" to it.key,
                    "version" to it.version.toString(),
                    "size" to it.size.toString(),
                    "access_policy" to it.accessPolicy,
                    "encryption" to it.encryption
                )
            }
            call.respond(entries)
        }

        // ── Admin: token management ─────────────────────────────────

        /** Issue a new per-device, per-file token. Plaintext returned ONCE. */
        post("/{key}/tokens") {
            val key = call.parameters["key"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val body = call.receive<JsonObject>()
            val deviceId = body["deviceId"]?.jsonPrimitive?.contentOrNull
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "deviceId field required"))

            val generated = tokenService.generate(configApiId, key, deviceId)
            call.respond(HttpStatusCode.OK, mapOf(
                "id" to generated.id.toString(),
                "token" to generated.plaintext,     // shown once to admin
                "deviceId" to generated.deviceId,
                "createdAt" to generated.createdAt
            ))
        }

        /** List tokens for a file (hashes only, no plaintext). */
        get("/{key}/tokens") {
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(tokenStore.listForFile(configApiId, key))
        }

        /** Revoke a token by id. */
        delete("/tokens/{tokenId}") {
            val id = call.parameters["tokenId"]?.toLongOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid tokenId"))
            if (tokenStore.revoke(id)) call.respond(HttpStatusCode.OK, mapOf("revoked" to "true"))
            else call.respond(HttpStatusCode.NotFound, mapOf("error" to "Token not found"))
        }

        // ── Admin: distribution history + stats (scoped) ────────────

        get("/distributions") {
            call.respond(distStore.getAll(configApiId))
        }

        get("/distributions/{key}") {
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(distStore.getByKey(configApiId, key))
        }

        get("/distributions/device/{deviceId}") {
            val deviceId = call.parameters["deviceId"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            call.respond(distStore.getByDevice(configApiId, deviceId))
        }

        get("/stats") {
            call.respond(distStore.getStats(configApiId))
        }
    }
}

private val VALID_POLICIES = setOf("public", "api_key", "token", "token_mtls")
private val VALID_ENCRYPTIONS = setOf("plain", "at_rest", "end_to_end")

/**
 * Whether two PEMs carry the same key: compared on the Base64 body, so line
 * breaks and header spelling do not turn a device's own key into a "change".
 */
private fun samePublicKey(a: String, b: String): Boolean = pemBody(a) == pemBody(b)

private fun pemBody(pem: String) = pem.lineSequence().filterNot { it.trim().startsWith("-----") }
    .joinToString("").filterNot { it.isWhitespace() }

/**
 * [pem] re-encoded the way the library writes it, when it holds a key
 * end_to_end files can be encrypted for: RSA of 2048 to 4096 bits as X.509
 * SubjectPublicKeyInfo. Null for anything else.
 */
private fun canonicalDevicePublicKey(pem: String): String? {
    val key = try {
        java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(pemBody(pem))))
            as? java.security.interfaces.RSAPublicKey
    } catch (_: Exception) {
        null
    } ?: return null
    if (key.modulus.bitLength() !in 2048..4096) return null
    val body = java.util.Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
    return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
}

/** Allowed vault-key shape — alphanumeric plus `.`, `_`, `-`, 1-64 chars. */
private val VAULT_KEY_REGEX = Regex("^[A-Za-z0-9._-]{1,64}$")
