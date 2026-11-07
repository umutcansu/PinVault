package com.example.pinvault.server.route

import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.PinConfigRules
import com.example.pinvault.server.service.PinDiff
import com.example.pinvault.server.service.PinRestore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import com.example.pinvault.server.store.PinSnapshotStore
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.time.Instant

/**
 * The pin sets a Config API has served and the one-click way back to one of
 * them (management listener, admin key):
 *
 * - `GET /api/v1/pin-snapshots?configApiId=` — newest first, with what each changed
 * - `GET /api/v1/pin-snapshots/{id}` — the stored set and its difference from now
 * - `GET /api/v1/hosts/{hostname}/pin-versions?configApiId=` — every set one host had
 * - `POST /api/v1/pin-snapshots/{id}/restore?configApiId=` `{"hostname": …}` —
 *   publishes the stored pins as a NEW version (whole scope, or one host).
 *   Gated like a pin update: two-person approval and the live certificate
 *   check apply; the audit log gets `pins_restored` plus the usual diff.
 */
fun Route.pinSnapshotRoutes(
    snapshots: PinSnapshotStore,
    pinConfigStore: PinConfigStore,
    historyStore: PinConfigHistoryStore,
    liveGate: LiveCertificateGate? = null,
    audit: AuditLog? = null
) {
    fun io.ktor.server.application.ApplicationCall.scope(): String =
        request.queryParameters["configApiId"]?.takeIf { it.isNotBlank() } ?: "default-tls"

    get("/api/v1/pin-snapshots") {
        val list = snapshots.list(call.scope())
        call.respondText(buildJsonArray {
            list.forEach { s ->
                add(buildJsonObject {
                    put("id", s.id); put("configApiId", s.configApiId); put("takenAt", s.takenAt); put("actor", s.actor)
                    put("hostCount", s.hostCount); put("version", s.version)
                    putJsonArray("changed") { s.changedHosts.forEach { add(JsonPrimitive(it)) } }
                })
            }
        }.toString(), ContentType.Application.Json)
    }

    get("/api/v1/pin-snapshots/{id}") {
        val id = call.pathParameters["id"]?.toLongOrNull()
        val snap = id?.let { snapshots.get(it) }
            ?: return@get call.respondText("""{"error":"snapshot_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
        val current = pinConfigStore.load(snap.configApiId)
        val planned = PinRestore.plan(current, snap, null)
        call.respondText(buildJsonObject {
            put("id", snap.id); put("configApiId", snap.configApiId); put("takenAt", snap.takenAt); put("actor", snap.actor)
            put("config", Json.encodeToJsonElement(com.example.pinvault.server.model.PinConfig.serializer(), snap.config))
            put("restoreDiff", PinDiff.of(current, planned).toJson())
        }.toString(), ContentType.Application.Json)
    }

    get("/api/v1/hosts/{hostname}/pin-versions") {
        val hostname = call.pathParameters["hostname"] ?: ""
        val versions = snapshots.versionsOf(call.scope(), hostname)
        call.respondText(buildJsonArray {
            versions.forEach { v ->
                add(buildJsonObject {
                    put("snapshotId", v.snapshotId); put("hostname", v.hostname); put("version", v.version)
                    putJsonArray("sha256") { v.sha256.forEach { add(JsonPrimitive(it)) } }
                    put("mtls", v.mtls); v.clientCertVersion?.let { put("clientCertVersion", it) }
                    put("forceUpdate", v.forceUpdate); put("takenAt", v.takenAt); put("actor", v.actor)
                })
            }
        }.toString(), ContentType.Application.Json)
    }

    post("/api/v1/pin-snapshots/{id}/restore") {
        val id = call.pathParameters["id"]?.toLongOrNull()
        val snap = id?.let { snapshots.get(it) }
            ?: return@post call.respondText("""{"error":"snapshot_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
        // The approval card and the state hash are computed for the query's
        // scope: it must be the snapshot's own.
        val querySope = call.request.queryParameters["configApiId"]
        if (querySope != null && querySope != snap.configApiId) {
            return@post call.respondText("""{"error":"scope_mismatch"}""", ContentType.Application.Json, HttpStatusCode.Conflict)
        }
        val body = call.receiveText()
        val hostname = runCatching { Json.parseToJsonElement(body).jsonObject["hostname"]?.jsonPrimitive?.content }.getOrNull()
            ?.trim()?.takeIf { it.isNotEmpty() }
        val scope = snap.configApiId
        val current = pinConfigStore.load(scope)
        val planned = try {
            PinRestore.plan(current, snap, hostname)
        } catch (e: PinRestore.Refused) {
            return@post call.respondText(buildJsonObject { put("error", e.message ?: "refused") }.toString(), ContentType.Application.Json, HttpStatusCode.NotFound)
        }
        val errors = PinConfigRules.errors(planned.pins) + PinConfigRules.trustRootErrors(planned.trustRoots)
        if (errors.isNotEmpty()) {
            return@post call.respondText(buildJsonObject { putJsonArray("errors") { errors.forEach { add(JsonPrimitive(it)) } } }.toString(),
                ContentType.Application.Json, HttpStatusCode.BadRequest)
        }
        val diff = PinDiff.of(current, planned)
        if (diff.isEmpty) {
            return@post call.respondText(buildJsonObject { put("restored", false); put("snapshotId", snap.id); put("unchanged", true) }.toString(),
                ContentType.Application.Json)
        }
        if (!call.passesLiveGate(scope, current, planned, liveGate, audit)) return@post

        val saved = pinConfigStore.save(scope, planned)
        val now = Instant.now().toString()
        val before = current.pins.associateBy { it.hostname }
        saved.pins.forEach { pin ->
            val old = before[pin.hostname]
            if (old == null || old != pin) {
                historyStore.add(scope, PinConfigHistoryEntry(pin.hostname, pin.version, now, "pins_restored", pin.sha256.firstOrNull()?.take(12) ?: ""))
            }
        }
        before.keys.filter { host -> saved.pins.none { it.hostname == host } }.forEach { host ->
            historyStore.add(scope, PinConfigHistoryEntry(host, before.getValue(host).version, now, "host_removed"))
        }
        audit?.record(
            "pins_restored",
            "$scope: ${if (hostname != null) "$hostname restored" else "pin set restored"} from snapshot ${snap.id} (${snap.takenAt.take(19)}): ${diff.summary()}",
            configApiId = scope, target = hostname ?: diff.hosts().joinToString(","),
            detail = buildJsonObject { put("snapshotId", snap.id); put("snapshotTakenAt", snap.takenAt); hostname?.let { put("hostname", it) } }
        )
        call.respondText(buildJsonObject {
            put("restored", true); put("snapshotId", snap.id); put("configApiId", scope)
            put("version", saved.computedVersion())
            putJsonArray("hosts") { diff.hosts().forEach { add(JsonPrimitive(it)) } }
        }.toString(), ContentType.Application.Json)
    }
}
