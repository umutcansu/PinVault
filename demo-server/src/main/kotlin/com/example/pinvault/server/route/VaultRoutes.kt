package com.example.pinvault.server.route

import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*

fun Route.vaultRoutes(vaultFileStore: VaultFileStore, distStore: VaultDistributionStore) {

    route("/api/v1/vault") {

        /** Download a vault file. Supports version-based 304. */
        get("/{key}") {
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, "Missing key")

            val currentVersion = call.request.queryParameters["version"]?.toIntOrNull() ?: 0

            val entry = vaultFileStore.get(key)
                ?: return@get call.respond(HttpStatusCode.NotFound, "File not found: $key")

            if (entry.version <= currentVersion) {
                call.response.header("X-Vault-Version", entry.version.toString())
                call.respond(HttpStatusCode.NotModified)
                return@get
            }

            call.response.header("X-Vault-Version", entry.version.toString())
            call.respondBytes(entry.content, ContentType.Application.OctetStream)
        }

        /** Upload / update a vault file. */
        put("/{key}") {
            val key = call.parameters["key"]
                ?: return@put call.respond(HttpStatusCode.BadRequest, "Missing key")

            val bytes = call.receive<ByteArray>()
            vaultFileStore.put(key, bytes)
            val entry = vaultFileStore.get(key)!!

            call.response.header("X-Vault-Version", entry.version.toString())
            call.respond(HttpStatusCode.OK, mapOf("key" to key, "version" to entry.version.toString()))
        }

        /** Delete a vault file. */
        delete("/{key}") {
            val key = call.parameters["key"]
                ?: return@delete call.respond(HttpStatusCode.BadRequest, "Missing key")

            vaultFileStore.delete(key)
            call.respond(HttpStatusCode.OK, mapOf("deleted" to key, "status" to "ok"))
        }

        /** List all vault files (metadata only). */
        get {
            val entries = vaultFileStore.listAll().map {
                mapOf("key" to it.key, "version" to it.version.toString(), "size" to it.content.size.toString())
            }
            call.respond(entries)
        }

        // ── Distribution tracking ───────────────────────────────────

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
            val timestamp = java.time.Instant.now().toString()

            distStore.add(key, version, deviceId, manufacturer, model, label, status, timestamp, deviceAlias)
            call.respond(HttpStatusCode.OK, mapOf("recorded" to "true"))
        }

        /** Get all distribution history. */
        get("/distributions") {
            call.respond(distStore.getAll())
        }

        /** Get distribution history for a specific vault key. */
        get("/distributions/{key}") {
            val key = call.parameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, "Missing key")
            call.respond(distStore.getByKey(key))
        }

        /** Get distribution history for a specific device. */
        get("/distributions/device/{deviceId}") {
            val deviceId = call.parameters["deviceId"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, "Missing deviceId")
            call.respond(distStore.getByDevice(deviceId))
        }

        /** Get distribution statistics. */
        get("/stats") {
            call.respond(distStore.getStats())
        }
    }
}
