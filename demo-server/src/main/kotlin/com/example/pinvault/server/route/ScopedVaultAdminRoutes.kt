package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.receiveLimitedBytes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import java.time.Instant

/**
 * V2 scope-aware admin endpoints for the management server (port 8090).
 *
 * All paths live under `/api/v1/config-apis/{configApiId}/vault/...` so the
 * web UI can operate on one Config API's vault at a time. This mirrors the
 * backend's per-Config-API scoping: the same `key` can exist independently
 * in multiple APIs, so every admin action must name the scope explicitly.
 *
 * This is the ONLY place vault administration is served: the device-facing
 * Config API ports carry the download, the download report and device-key
 * registration, nothing else. Every write here is under two-person approval
 * when it is on (`vault_upload`, `vault_delete`, `vault_policy`,
 * `vault_token_issue`, `vault_token_revoke`, `device_key_reset`) and is
 * audited under its own action.
 *
 * Routes:
 *   GET    /api/v1/config-apis/{id}/vault                      — list files
 *   PUT    /api/v1/config-apis/{id}/vault/{key}?policy=&encryption=  — upload
 *   DELETE /api/v1/config-apis/{id}/vault/{key}                — delete
 *   PUT    /api/v1/config-apis/{id}/vault/{key}/policy         — change policy
 *   GET    /api/v1/config-apis/{id}/vault/{key}/tokens         — list tokens
 *   POST   /api/v1/config-apis/{id}/vault/{key}/tokens         — issue token
 *   DELETE /api/v1/config-apis/{id}/vault/tokens/{tokenId}     — revoke token
 *   GET    /api/v1/config-apis/{id}/vault/distributions        — all distributions
 *   GET    /api/v1/config-apis/{id}/vault/distributions/{key}  — by key
 *   GET    /api/v1/config-apis/{id}/vault/distributions/device/{deviceId} — by device
 *   GET    /api/v1/config-apis/{id}/vault/stats                — stats
 *   DELETE /api/v1/config-apis/{id}/vault/devices/{deviceId}/public-key — reset a device's E2E key
 *          (`?purpose=user_auth`: its user-auth key)
 *   GET    /api/v1/config-apis/{id}/vault/devices/user-auth-keys — user-auth keys with their attestation
 *   GET    /api/v1/config-apis/{id}/vault/devices/{deviceId}/keys — one device's E2E and user-auth key
 */
fun Route.scopedVaultAdminRoutes(
    vaultFileStore: VaultFileStore,
    distStore: VaultDistributionStore,
    tokenStore: VaultFileTokenStore,
    tokenService: VaultAccessTokenService,
    /** Device E2E keys, for the reset endpoint; null = no reset endpoint. */
    publicKeyStore: com.example.pinvault.server.store.DevicePublicKeyStore? = null,
    audit: com.example.pinvault.server.service.AuditLog? = null,
    /** The largest file an upload may carry (`VAULT_MAX_FILE_BYTES`); a larger one gets 413. */
    maxFileBytes: Long = DEFAULT_VAULT_MAX_FILE_BYTES
) {
    fun sha256Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    route("/api/v1/config-apis/{configApiId}/vault") {

        // ── File CRUD ────────────────────────────────────────────────

        /** List all files in this Config API's scope. */
        get {
            val cid = call.pathParameters["configApiId"]!!
            val entries = vaultFileStore.summaries(cid).map {
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

        /** Upload or overwrite a file. `?policy=` and `?encryption=` set metadata. */
        put("/{key}") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
                ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val policy = call.request.queryParameters["policy"]
            val encryption = call.request.queryParameters["encryption"]
            // The same rules as the Config API upload: a key the device route
            // can serve, and only known policy / encryption values.
            vaultUploadError(key, policy, encryption)?.let {
                return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to it))
            }
            // Read into memory whole and stored in one row: capped while reading.
            val bytes = call.receiveLimitedBytes(maxFileBytes) ?: return@put

            val before = vaultFileStore.meta(cid, key)
            vaultFileStore.put(cid, key, bytes, policy, encryption)
            val entry = vaultFileStore.meta(cid, key)!!
            audit?.record(
                "vault_file_uploaded",
                "Vault file $key ${if (before == null) "uploaded" else "replaced (v${before.version} → v${entry.version})"}: " +
                    "${bytes.size} bytes, ${entry.accessPolicy}, ${entry.encryption}",
                cid, key,
                detail = buildJsonObject {
                    put("version", entry.version)
                    put("size", bytes.size)
                    put("sha256", sha256Hex(bytes))
                    put("accessPolicy", entry.accessPolicy)
                    put("encryption", entry.encryption)
                }
            )

            call.response.header("X-Vault-Version", entry.version.toString())
            call.respond(HttpStatusCode.OK, mapOf(
                "key" to key,
                "version" to entry.version.toString(),
                "access_policy" to entry.accessPolicy,
                "encryption" to entry.encryption
            ))
        }

        delete("/{key}") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val before = vaultFileStore.meta(cid, key)
            vaultFileStore.delete(cid, key)
            if (before != null) audit?.record("vault_file_deleted", "Vault file $key (v${before.version}) deleted", cid, key)
            call.respond(HttpStatusCode.OK, mapOf("deleted" to key, "status" to "ok"))
        }

        /** Change access_policy and encryption without changing content. */
        put("/{key}/policy") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
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

            val before = vaultFileStore.meta(cid, key)
            val ok = vaultFileStore.updatePolicy(cid, key, policy, encryption)
            if (!ok) return@put call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found"))
            audit?.record(
                "vault_policy_changed",
                "Vault file $key: access ${before?.accessPolicy ?: "?"} → $policy, encryption ${before?.encryption ?: "?"} → $encryption",
                cid, key,
                detail = buildJsonObject {
                    put("accessPolicy", policy); put("encryption", encryption)
                    before?.let { put("previousAccessPolicy", it.accessPolicy); put("previousEncryption", it.encryption) }
                }
            )
            call.respond(HttpStatusCode.OK, mapOf("updated" to "true"))
        }

        // ── Token management ────────────────────────────────────────

        get("/{key}/tokens") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(tokenStore.listForFile(cid, key))
        }

        post("/{key}/tokens") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val body = call.receive<JsonObject>()
            val deviceId = body["deviceId"]?.jsonPrimitive?.contentOrNull
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "deviceId field required"))

            // Stored, matched against X-Device-Id and printed in the dashboard.
            if (!isValidIdentifier(deviceId)) {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "invalid_device_id", "message" to "Letters, digits, '.', '_', ':' and '-' only, at most 64."))
            }

            val generated = tokenService.generate(cid, key, deviceId)
            audit?.record("vault_token_issued", "Vault token issued to device $deviceId for file $key (replaces any earlier one)",
                cid, key, detail = buildJsonObject { put("deviceId", deviceId); put("tokenId", generated.id) })
            // The token exists in plain text only in this answer.
            call.response.header(HttpHeaders.CacheControl, "no-store")
            call.respond(HttpStatusCode.OK, mapOf(
                "id" to generated.id.toString(),
                "token" to generated.plaintext,     // plaintext shown once
                "deviceId" to generated.deviceId,
                "createdAt" to generated.createdAt
            ))
        }

        delete("/tokens/{tokenId}") {
            val id = call.pathParameters["tokenId"]?.toLongOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid tokenId"))
            val cid = call.pathParameters["configApiId"]!!
            // The id is global: a token of another Config API is not this route's to revoke.
            val token = tokenStore.info(id)?.takeIf { it.configApiId == cid }
                ?: return@delete call.respond(HttpStatusCode.NotFound, mapOf("error" to "Token not found"))
            if (tokenStore.revoke(id)) {
                audit?.record("vault_token_revoked", "Vault token of device ${token.deviceId} for file ${token.vaultKey} revoked",
                    cid, token.vaultKey, detail = buildJsonObject { put("deviceId", token.deviceId); put("tokenId", id) })
                call.respond(HttpStatusCode.OK, mapOf("revoked" to "true"))
            } else call.respond(HttpStatusCode.NotFound, mapOf("error" to "Token not found"))
        }

        // ── Distribution history + stats (scoped) ───────────────────

        get("/distributions") {
            val cid = call.pathParameters["configApiId"]!!
            call.respond(distStore.getAll(cid))
        }

        get("/distributions/{key}") {
            val cid = call.pathParameters["configApiId"]!!
            val key = call.pathParameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(distStore.getByKey(cid, key))
        }

        get("/distributions/device/{deviceId}") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            call.respond(distStore.getByDevice(cid, deviceId))
        }

        get("/stats") {
            val cid = call.pathParameters["configApiId"]!!
            call.respond(distStore.getStats(cid))
        }

        // ── E2E device keys ─────────────────────────────────────────

        /**
         * Forget a device's E2E key in this scope (or with `?purpose=user_auth`
         * its user-auth key), so its next registration counts as the first: a
         * device that lost its key and has no token to prove itself with, or a
         * slot someone else took first.
         */
        /**
         * The user-auth keys of this scope with what Android Key Attestation
         * said about each (`attestation`: null = not checked).
         */
        if (publicKeyStore != null) get("/devices/user-auth-keys") {
            val cid = call.pathParameters["configApiId"]!!
            call.respond(publicKeyStore.userAuthKeys().listForConfigApi(cid))
        }

        /**
         * One device's two keys (`e2e`, `userAuth`; null = none registered),
         * each with its `algorithm` — the MGF1 hash its files are wrapped with
         * (Android `RSA-OAEP-SHA256`, iOS `RSA-OAEP-SHA256-MGF1-SHA256`).
         */
        if (publicKeyStore != null) get("/devices/{deviceId}/keys") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            val e2e = publicKeyStore.get(deviceId, cid)
            val userAuth = publicKeyStore.userAuthKeys().get(deviceId, cid)
            val json = Json { encodeDefaults = true }
            call.respondText(buildJsonObject {
                put("deviceId", deviceId)
                put("e2e", e2e?.let { json.encodeToJsonElement(com.example.pinvault.server.store.DevicePublicKey.serializer(), it) } ?: JsonNull)
                put("userAuth", userAuth?.let { json.encodeToJsonElement(com.example.pinvault.server.store.DevicePublicKey.serializer(), it) } ?: JsonNull)
            }.toString(), ContentType.Application.Json)
        }

        if (publicKeyStore != null) delete("/devices/{deviceId}/public-key") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            // `?purpose=user_auth`: the device's user-auth key instead of its E2E key.
            val purpose = call.request.queryParameters["purpose"] ?: "e2e"
            if (purpose != "e2e" && purpose != "user_auth") {
                return@delete call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "unsupported_purpose",
                    "message" to "purpose must be \"e2e\" or \"user_auth\"."))
            }
            val userAuth = purpose == "user_auth"
            val removed = (if (userAuth) publicKeyStore.userAuthKeys() else publicKeyStore).delete(deviceId, cid)
            if (removed) {
                audit?.record("device_key_reset", "${if (userAuth) "User-auth key" else "E2E key"} of device $deviceId removed by an administrator",
                    cid, deviceId, detail = if (userAuth) buildJsonObject { put("purpose", "user_auth") } else null)
            }
            call.respond(if (removed) HttpStatusCode.OK else HttpStatusCode.NotFound,
                mapOf("removed" to removed.toString(), "deviceId" to deviceId))
        }
    }
}
