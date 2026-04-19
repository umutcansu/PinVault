package com.example.pinvault.server.route

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
 * Endpoints mirror the client-facing + admin subset of [vaultRoutes] but
 * read `configApiId` from the URL instead of having it fixed at mount time.
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
 */
fun Route.scopedVaultAdminRoutes(
    vaultFileStore: VaultFileStore,
    distStore: VaultDistributionStore,
    tokenStore: VaultFileTokenStore,
    tokenService: VaultAccessTokenService
) {
    route("/api/v1/config-apis/{configApiId}/vault") {

        // ── File CRUD ────────────────────────────────────────────────

        /** List all files in this Config API's scope. */
        get {
            val cid = call.parameters["configApiId"]!!
            val entries = vaultFileStore.listForConfigApi(cid).map {
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

        /** Upload or overwrite a file. `?policy=` and `?encryption=` set metadata. */
        put("/{key}") {
            val cid = call.parameters["configApiId"]!!
            val key = call.parameters["key"]
                ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val policy = call.request.queryParameters["policy"]
            val encryption = call.request.queryParameters["encryption"]
            val bytes = call.receive<ByteArray>()

            vaultFileStore.put(cid, key, bytes, policy, encryption)
            val entry = vaultFileStore.get(cid, key)!!

            call.response.header("X-Vault-Version", entry.version.toString())
            call.respond(HttpStatusCode.OK, mapOf(
                "key" to key,
                "version" to entry.version.toString(),
                "access_policy" to entry.accessPolicy,
                "encryption" to entry.encryption
            ))
        }

        delete("/{key}") {
            val cid = call.parameters["configApiId"]!!
            val key = call.parameters["key"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            vaultFileStore.delete(cid, key)
            call.respond(HttpStatusCode.OK, mapOf("deleted" to key, "status" to "ok"))
        }

        /** Change access_policy and encryption without changing content. */
        put("/{key}/policy") {
            val cid = call.parameters["configApiId"]!!
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

            val ok = vaultFileStore.updatePolicy(cid, key, policy, encryption)
            if (!ok) return@put call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found"))
            call.respond(HttpStatusCode.OK, mapOf("updated" to "true"))
        }

        // ── Token management ────────────────────────────────────────

        get("/{key}/tokens") {
            val cid = call.parameters["configApiId"]!!
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(tokenStore.listForFile(cid, key))
        }

        post("/{key}/tokens") {
            val cid = call.parameters["configApiId"]!!
            val key = call.parameters["key"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            val body = call.receive<JsonObject>()
            val deviceId = body["deviceId"]?.jsonPrimitive?.contentOrNull
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "deviceId field required"))

            val generated = tokenService.generate(cid, key, deviceId)
            call.respond(HttpStatusCode.OK, mapOf(
                "id" to generated.id.toString(),
                "token" to generated.plaintext,     // plaintext shown once
                "deviceId" to generated.deviceId,
                "createdAt" to generated.createdAt
            ))
        }

        delete("/tokens/{tokenId}") {
            val id = call.parameters["tokenId"]?.toLongOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid tokenId"))
            if (tokenStore.revoke(id)) call.respond(HttpStatusCode.OK, mapOf("revoked" to "true"))
            else call.respond(HttpStatusCode.NotFound, mapOf("error" to "Token not found"))
        }

        // ── Distribution history + stats (scoped) ───────────────────

        get("/distributions") {
            val cid = call.parameters["configApiId"]!!
            call.respond(distStore.getAll(cid))
        }

        get("/distributions/{key}") {
            val cid = call.parameters["configApiId"]!!
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            call.respond(distStore.getByKey(cid, key))
        }

        get("/distributions/device/{deviceId}") {
            val cid = call.parameters["configApiId"]!!
            val deviceId = call.parameters["deviceId"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            call.respond(distStore.getByDevice(cid, deviceId))
        }

        get("/stats") {
            val cid = call.parameters["configApiId"]!!
            call.respond(distStore.getStats(cid))
        }
    }
}

private val VALID_POLICIES = setOf("public", "api_key", "token", "token_mtls")
private val VALID_ENCRYPTIONS = setOf("plain", "at_rest", "end_to_end")
