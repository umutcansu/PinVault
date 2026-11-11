package com.example.pinvault.server.route

import com.example.pinvault.server.store.ConfigApiRegistry
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
    deviceHostAclStore: DeviceHostAclStore,
    configApiRegistry: ConfigApiRegistry = ConfigApiRegistry(db),
    /** Where the vault switch and host ACL changes are recorded; null = nowhere. */
    audit: com.example.pinvault.server.service.AuditLog? = null
) {

    // ── Config API: vault_enabled toggle ────────────────────────────

    /**
     * Enable or disable the vault subsystem on a given Config API.
     * Body: {"enabled": true | false}
     *
     * The flag now actually stops distribution: the scope's vault download
     * route reads it per request and answers 403 while it is off. Admin
     * routes (upload / list / delete / tokens) stay reachable so the operator
     * can clean up after flipping the switch.
     *
     * 404 for a Config API with no `config_apis` row. Every scope the server
     * serves gets one at boot (Main.kt → ConfigApiRegistry.ensureRegistered),
     * including the default one it mounts directly.
     */
    put("/api/v1/config-apis/{id}/vault-enabled") {
        val id = call.pathParameters["id"]
            ?: return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing id"))
        val body = call.receive<JsonObject>()
        val enabled = body["enabled"]?.jsonPrimitive?.booleanOrNull
            ?: return@put call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "'enabled' boolean required"))

        val before = configApiRegistry.vaultEnabledOrNull(id)
        if (!configApiRegistry.setVaultEnabled(id, enabled)) {
            return@put call.respond(HttpStatusCode.NotFound,
                mapOf("error" to "Config API '$id' not found"))
        }
        if (before != enabled) {
            audit?.record("vault_enabled_changed", "Vault downloads turned ${if (enabled) "ON" else "OFF"} for Config API $id",
                id, detail = buildJsonObject { put("enabled", enabled) })
        }
        call.respond(HttpStatusCode.OK, mapOf("id" to id, "vault_enabled" to enabled.toString()))
    }

    get("/api/v1/config-apis/{id}/vault-enabled") {
        val id = call.pathParameters["id"]
            ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing id"))
        val enabled = configApiRegistry.vaultEnabledOrNull(id)
            ?: return@get call.respond(HttpStatusCode.NotFound,
                mapOf("error" to "Config API '$id' not found"))
        call.respond(mapOf("id" to id, "vault_enabled" to enabled.toString()))
    }

    // ── Per-device host ACL ─────────────────────────────────────────

    /**
     * The device ids a per-device host ACL can be written for: the ids devices
     * send as `X-Device-Id` (ANDROID_ID / identifierForVendor), as this Config
     * API has seen them — a per-device ACL, an attestation, a vault download,
     * a registered device key. The dashboard's ACL manager listed the
     * connection reports' `manufacturer_model` names instead, which no device
     * sends, so an ACL written from there never applied (E09 finding).
     *
     * Answer: `[{"deviceId": "…", "sources": ["acl", "attestation", "vault", "key"], "label": "…"}]`,
     * newest first, at most [MAX_DEVICE_IDS].
     */
    get("/api/v1/config-apis/{configApiId}/device-ids") {
        val configApiId = call.pathParameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val rows = db.connection().use { conn ->
            conn.prepareStatement(
                """SELECT device_id, source, MAX(seen) AS seen, MAX(label) AS label FROM (
                     SELECT device_id, 'acl' AS source, MAX(granted_at) AS seen, NULL AS label FROM device_host_acl WHERE config_api_id = ? GROUP BY device_id
                     UNION ALL SELECT device_id, 'attestation', MAX(last_seen), NULL FROM attested_devices WHERE config_api_id = ? GROUP BY device_id
                     UNION ALL SELECT device_id, 'vault', MAX(timestamp), MAX(COALESCE(device_manufacturer, '') || ' ' || COALESCE(device_model, ''))
                               FROM vault_distributions WHERE config_api_id = ? GROUP BY device_id
                     UNION ALL SELECT device_id, 'key', MAX(registered_at), NULL FROM device_public_keys WHERE config_api_id = ? GROUP BY device_id
                   ) GROUP BY device_id, source"""
            ).use { stmt ->
                repeat(4) { stmt.setString(it + 1, configApiId) }
                val rs = stmt.executeQuery()
                buildList { while (rs.next()) add(listOf(rs.getString(1), rs.getString(2), rs.getString(3) ?: "", rs.getString(4)?.trim().orEmpty())) }
            }
        }
        val byDevice = rows.groupBy { it[0] }.map { (id, entries) ->
            Triple(id, entries.map { it[1] }.distinct().sorted(), entries.maxOf { it[2] }) to entries.firstOrNull { it[3].isNotEmpty() }?.get(3)
        }.sortedByDescending { it.first.third }.take(MAX_DEVICE_IDS)
        call.respondText(buildJsonArray {
            byDevice.forEach { (row, label) ->
                add(buildJsonObject {
                    put("deviceId", row.first)
                    putJsonArray("sources") { row.second.forEach { add(JsonPrimitive(it)) } }
                    label?.let { put("label", it) }
                })
            }
        }.toString(), ContentType.Application.Json)
    }

    /**
     * Returns the host list this device is authorized to see from a specific
     * Config API. Does NOT include default ACL fallback — that's a separate
     * concept; use /acl/effective to see the union.
     */
    get("/api/v1/config-apis/{configApiId}/devices/{deviceId}/host-acl") {
        val configApiId = call.pathParameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.pathParameters["deviceId"] ?: return@get call.respond(
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
        val configApiId = call.pathParameters["configApiId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.pathParameters["deviceId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
        val body = call.receive<JsonObject>()
        // Planned by the code the approval card is built with (HostAclChange):
        // every name is a host name, and what is granted and taken away here
        // is what the card listed.
        val change = try {
            com.example.pinvault.server.service.HostAclChange.plan(deviceHostAclStore.listForDevice(configApiId, deviceId), body)
        } catch (e: com.example.pinvault.server.service.HostAclChange.BadBody) {
            return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to (e.message ?: "invalid hostnames")))
        }
        val now = Instant.now().toString()
        val toAdd = change.added
        val toRemove = change.removed
        toAdd.forEach { deviceHostAclStore.grant(configApiId, deviceId, it, now) }
        toRemove.forEach { deviceHostAclStore.revoke(configApiId, deviceId, it) }
        if (toAdd.isNotEmpty() || toRemove.isNotEmpty()) {
            audit?.record(
                "host_acl_changed",
                "Hosts device $deviceId may reach: +${toAdd.size} −${toRemove.size}" +
                    (if (toAdd.isNotEmpty()) " (added ${toAdd.take(10).joinToString()})" else "") +
                    (if (toRemove.isNotEmpty()) " (removed ${toRemove.take(10).joinToString()})" else ""),
                configApiId, deviceId,
                detail = buildJsonObject {
                    putJsonArray("added") { toAdd.forEach { add(it) } }
                    putJsonArray("removed") { toRemove.forEach { add(it) } }
                }
            )
        }
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
        val configApiId = call.pathParameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val deviceId = call.pathParameters["deviceId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
        call.respond(deviceHostAclStore.getAllowed(configApiId, deviceId))
    }

    // ── Default host ACL (per Config API) ───────────────────────────

    get("/api/v1/config-apis/{configApiId}/default-host-acl") {
        val configApiId = call.pathParameters["configApiId"] ?: return@get call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        call.respond(deviceHostAclStore.listDefault(configApiId))
    }

    /** Body: {"hostnames": ["a.com", …]} — replaces the default set. */
    put("/api/v1/config-apis/{configApiId}/default-host-acl") {
        val configApiId = call.pathParameters["configApiId"] ?: return@put call.respond(
            HttpStatusCode.BadRequest, mapOf("error" to "Missing configApiId"))
        val body = call.receive<JsonObject>()
        // As above: the plan the approval card showed.
        val change = try {
            com.example.pinvault.server.service.HostAclChange.plan(deviceHostAclStore.listDefault(configApiId), body)
        } catch (e: com.example.pinvault.server.service.HostAclChange.BadBody) {
            return@put call.respond(HttpStatusCode.BadRequest, mapOf("error" to (e.message ?: "invalid hostnames")))
        }
        val toAdd = change.added
        val toRemove = change.removed
        toAdd.forEach { deviceHostAclStore.addDefault(configApiId, it) }
        toRemove.forEach { deviceHostAclStore.removeDefault(configApiId, it) }
        if (toAdd.isNotEmpty() || toRemove.isNotEmpty()) {
            audit?.record(
                "host_acl_changed",
                "Default hosts every device may reach: +${toAdd.size} −${toRemove.size}" +
                    (if (toAdd.isNotEmpty()) " (added ${toAdd.take(10).joinToString()})" else "") +
                    (if (toRemove.isNotEmpty()) " (removed ${toRemove.take(10).joinToString()})" else ""),
                configApiId, "default",
                detail = buildJsonObject {
                    putJsonArray("added") { toAdd.forEach { add(it) } }
                    putJsonArray("removed") { toRemove.forEach { add(it) } }
                }
            )
        }
        call.respond(HttpStatusCode.OK, mapOf(
            "configApiId" to configApiId,
            "hostnames" to deviceHostAclStore.listDefault(configApiId).joinToString(","),
            "added" to toAdd.size.toString(),
            "removed" to toRemove.size.toString()
        ))
    }
}

/** The most device ids the ACL manager lists (newest first). */
private const val MAX_DEVICE_IDS = 500
