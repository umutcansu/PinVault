package com.example.pinvault.server.route

import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.DevicePublicKeyStore
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.http.*
import io.ktor.server.application.*
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
 * Registered twice in Main.kt:
 *   - once per Config API module (so port 8091/8092 each have their own scope)
 *   - once on the management server (port 8090) for admin endpoints
 *
 * Because [configApiId] is a parameter (not a URL component), the same route
 * path `/api/v1/vault/{key}` resolves to different scopes on different ports.
 */
fun Route.vaultRoutes(
    configApiId: String,
    vaultFileStore: VaultFileStore,
    distStore: VaultDistributionStore,
    tokenStore: VaultFileTokenStore,
    publicKeyStore: DevicePublicKeyStore,
    tokenService: VaultAccessTokenService,
    encryptionService: VaultEncryptionService,
    adminApiKeyRequired: Boolean = true
) {
    route("/api/v1/vault") {

        // ── Client-facing: download + report ────────────────────────

        /**
         * Download a vault file. Supports version-based 304.
         *
         * Access policy enforcement (in order):
         *   - public       → no checks
         *   - api_key      → requires X-API-Key (checked by ApiKeyAuth plugin)
         *   - token        → requires X-Device-Id + X-Vault-Token matching
         *                    (configApiId, key, deviceId) triple
         *   - token_mtls   → same as token, plus verifies that the mTLS cert
         *                    CN matches the claimed deviceId
         *
         * If encryption == "end_to_end", the server wraps the content with
         * the device's RSA public key (see VaultEncryptionService).
         */
        get("/{key}") {
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))

            val currentVersion = call.request.queryParameters["version"]?.toIntOrNull() ?: 0
            val entry = vaultFileStore.get(configApiId, key)
                ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found: $key"))

            // Access policy check ────────────────────────────────────
            val deviceId = call.request.header("X-Device-Id")
            when (entry.accessPolicy) {
                "public" -> { /* no-op */ }
                "api_key" -> {
                    // ApiKeyAuth plugin has already enforced this globally if
                    // the path is not in its public exception list. We still
                    // accept the request here — reaching this code means it
                    // passed the plugin.
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
                        // mTLS cert CN vs deviceId check. In this demo setup
                        // the cert CN is stored on the client cert's
                        // SubjectDN. If Ktor exposes it via request attributes
                        // we check; else we accept (demo limitation, logged).
                        val certCn = extractClientCertCn(call)
                        if (certCn == null) {
                            log.warn("token_mtls file requested without mTLS cert: configApi={} key={}",
                                configApiId, key)
                            return@get call.respond(HttpStatusCode.Unauthorized,
                                mapOf("error" to "mTLS client certificate required"))
                        }
                        if (certCn != deviceId) {
                            log.warn("token_mtls deviceId/CN mismatch: cert={} claimed={}",
                                certCn, deviceId)
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
            call.respondBytes(payload, ContentType.Application.OctetStream)
        }

        /** Register / update a device's public key for E2E encryption. */
        post("/devices/{deviceId}/public-key") {
            val deviceId = call.parameters["deviceId"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            val body = call.receive<JsonObject>()
            val pem = body["publicKeyPem"]?.jsonPrimitive?.contentOrNull
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "publicKeyPem field required"))
            val algorithm = body["algorithm"]?.jsonPrimitive?.contentOrNull ?: "RSA-OAEP-SHA256"

            publicKeyStore.register(deviceId, configApiId, pem, algorithm, Instant.now().toString())
            call.respond(HttpStatusCode.OK, mapOf("registered" to "true", "deviceId" to deviceId))
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
            val entries = vaultFileStore.listForConfigApi(configApiId).map {
                mapOf(
                    "key" to it.key,
                    "version" to it.version.toString(),
                    "size" to it.content.size.toString(),
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
 * Extract the CN of the client cert, if any. Ktor stores the peer principal
 * when mTLS is configured; the CN is inside the X500Principal Distinguished
 * Name string ("CN=foo, O=bar").
 */
private fun extractClientCertCn(call: ApplicationCall): String? {
    // Ktor's tls peer principal lives in attributes as X500Principal. We parse
    // the CN=... fragment with a simple regex; full DN parsing would require
    // javax.naming.ldap.LdapName which is heavier.
    val principal = try {
        val attrKey = io.ktor.util.AttributeKey<javax.security.auth.x500.X500Principal>("TLSPeerPrincipal")
        call.attributes.getOrNull(attrKey)
    } catch (_: Exception) { null } ?: return null
    val dn = principal.name
    return Regex("CN=([^,]+)").find(dn)?.groupValues?.getOrNull(1)?.trim()
}
