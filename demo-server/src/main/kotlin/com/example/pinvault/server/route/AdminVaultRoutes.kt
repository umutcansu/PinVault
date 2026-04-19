package com.example.pinvault.server.route

import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DeviceHostAclStore
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import java.time.Instant

/**
 * V2 admin endpoints for the management server (port 8090). These are
 * protected by the ApiKeyAuth plugin — callers need X-API-Key set.
 *
 * Covers:
 *   - Config API vault toggle
 *   - Per-device host ACL CRUD
 *   - Default host ACL CRUD
 *   - Device public key inspection
 *
 * Per-file token/policy endpoints are inside [vaultRoutes] because they live
 * under /api/v1/vault/{...}; the ones here are "cross-scope" admin actions.
 */
fun Route.adminVaultRoutes(
    db: DatabaseManager,
    deviceHostAclStore: DeviceHostAclStore
) {

    // ── Config API: vault_enabled toggle ────────────────────────────

    /**
     * Enable or disable the vault subsystem on a given Config API.
     * Body: {"enabled": true | false}
     */
    put("/api/v1/config-apis/{id}/vault-enabled") {
        val id = call.parameters["id"]
            ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing id"))
        val body = call.receive<JsonObject>()
        val enabled = body["enabled"]?.jsonPrimitive?.booleanOrNull
            ?: return@put call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "'enabled' boolean required"))

        db.connection().use { conn ->
            conn.prepareStatement("UPDATE config_apis SET vault_enabled = ? WHERE id = ?").use { stmt ->
                stmt.setInt(1, if (enabled) 1 else 0)
                stmt.setString(2, id)
                val affected = stmt.executeUpdate()
                if (affected == 0) {
                    return@put call.respond(HttpStatusCode.NotFound,
                        mapOf("error" to "Config API '$id' not found"))
                }
            }
        }
        call.respond(HttpStatusCode.OK, mapOf("id" to id, "vault_enabled" to enabled.toString()))
    }

    get("/api/v1/config-apis/{id}/vault-enabled") {
        val id = call.parameters["id"]
            ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing id"))
        db.connection().use { conn ->
            conn.prepareStatement("SELECT vault_enabled FROM config_apis WHERE id = ?").use { stmt ->
                stmt.setString(1, id)
                val rs = stmt.executeQuery()
                if (!rs.next()) {
                    return@get call.respond(HttpStatusCode.NotFound,
                        mapOf("error" to "Config API '$id' not found"))
                }
                val enabled = rs.getInt("vault_enabled") == 1
                call.respond(mapOf("id" to id, "vault_enabled" to enabled.toString()))
            }
        }
    }

    // ── Per-device host ACL ─────────────────────────────────────────

    /**
     * Returns the host list this device is authorized to see from a specific
     * Config API. Does NOT include default ACL fallback — that's a separate
     * concept; use /acl/effective to see the union.
     */
    get("/api/v1/config-apis/{configApiId}/devices/{deviceId}/host-acl") {
        val configApiId = call.parameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.parameters["deviceId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
        call.respond(deviceHostAclStore.listForDevice(configApiId, deviceId))
    }

    /**
     * Overwrite the device's ACL with exactly [body.hostnames]. Grants added,
     * stale entries removed. Idempotent.
     *
     * Body: {"hostnames": ["a.com", "b.com"]}
     */
    put("/api/v1/config-apis/{configApiId}/devices/{deviceId}/host-acl") {
        val configApiId = call.parameters["configApiId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.parameters["deviceId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
        val body = call.receive<JsonObject>()
        val desired = body["hostnames"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }?.toSet()
            ?: return@put call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "'hostnames' string array required"))

        val current = deviceHostAclStore.listForDevice(configApiId, deviceId).toSet()
        val now = Instant.now().toString()
        val toAdd = desired - current
        val toRemove = current - desired
        toAdd.forEach { deviceHostAclStore.grant(configApiId, deviceId, it, now) }
        toRemove.forEach { deviceHostAclStore.revoke(configApiId, deviceId, it) }
        call.respond(HttpStatusCode.OK, mapOf(
            "configApiId" to configApiId,
            "deviceId" to deviceId,
            "granted" to deviceHostAclStore.listForDevice(configApiId, deviceId).joinToString(","),
            "added" to toAdd.size.toString(),
            "removed" to toRemove.size.toString()
        ))
    }

    /** Effective ACL: per-device ACL ∪ default ACL. Read-only diagnostic. */
    get("/api/v1/config-apis/{configApiId}/devices/{deviceId}/host-acl/effective") {
        val configApiId = call.parameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.parameters["deviceId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
        call.respond(deviceHostAclStore.getAllowed(configApiId, deviceId))
    }

    // ── Default host ACL (per Config API) ───────────────────────────

    get("/api/v1/config-apis/{configApiId}/default-host-acl") {
        val configApiId = call.parameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        call.respond(deviceHostAclStore.listDefault(configApiId))
    }

    /** Body: {"hostnames": ["a.com", …]} — replaces the default set. */
    put("/api/v1/config-apis/{configApiId}/default-host-acl") {
        val configApiId = call.parameters["configApiId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val body = call.receive<JsonObject>()
        val desired = body["hostnames"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }?.toSet()
            ?: return@put call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "'hostnames' string array required"))

        val current = deviceHostAclStore.listDefault(configApiId).toSet()
        val toAdd = desired - current
        val toRemove = current - desired
        toAdd.forEach { deviceHostAclStore.addDefault(configApiId, it) }
        toRemove.forEach { deviceHostAclStore.removeDefault(configApiId, it) }
        call.respond(HttpStatusCode.OK, mapOf(
            "configApiId" to configApiId,
            "hostnames" to deviceHostAclStore.listDefault(configApiId).joinToString(","),
            "added" to toAdd.size.toString(),
            "removed" to toRemove.size.toString()
        ))
    }
}
