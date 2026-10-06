package com.example.pinvault.server.route

import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ServerEnv
import com.example.pinvault.server.service.ServerSettingsCatalog
import com.example.pinvault.server.service.ServerSettingsStore
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.RoutingCall
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The setup wizard's settings (management listener, admin key):
 *
 * - `GET /api/v1/server-settings`: every setting the dashboard may change —
 *   what the server runs with now, what is saved for the next start, and
 *   which ones the environment fixes (those cannot be changed here).
 * - `PUT /api/v1/server-settings` `{"values": {"KEY": "value" | ""}}`: saves
 *   for the next start (`""` = back to the server default). Refused when the
 *   server would not start with it. Waits for a second admin with approvals
 *   on (`PinAffectingRoutes`): one admin must not turn approvals off alone.
 * - `POST /api/v1/server-settings/restart`: exits the process so its
 *   supervisor (Docker) starts it again with the saved values; only where
 *   `PINVAULT_RESTART_ON_EXIT=true` says one exists.
 * - `DELETE /api/v1/server-settings/rejected`: forgets the note about a saved
 *   set that stopped the server from starting.
 */
fun Route.serverSettingsRoutes(
    store: ServerSettingsStore,
    audit: AuditLog?,
    restartSupervised: Boolean,
    exit: () -> Unit = { kotlin.system.exitProcess(0) }
) {
    get("/api/v1/server-settings") {
        call.respondJson(HttpStatusCode.OK, settingsView(store, restartSupervised))
    }

    put("/api/v1/server-settings") {
        val body = runCatching { Json.parseToJsonElement(call.receiveText()).jsonObject }.getOrNull()
        val values = body?.get("values") as? JsonObject
            ?: return@put call.respondError(HttpStatusCode.BadRequest, "invalid_body", listOf("Expected {\"values\": {...}}"))
        val saved = store.values().toMutableMap()
        val errors = mutableListOf<String>()
        val changed = linkedMapOf<String, Pair<String?, String?>>()
        for ((key, element) in values) {
            val setting = ServerSettingsCatalog.find(key)
            if (setting == null) { errors += "$key: not a setting the dashboard may change"; continue }
            if (ServerEnv.lockedByEnvironment(key)) { errors += "$key: set in the environment; change it there"; continue }
            val value = (element as? JsonPrimitive)?.takeIf { element !is JsonNull }?.contentOrNull?.trim().orEmpty()
            if (value.isEmpty()) {
                if (saved.remove(key) != null) changed[key] = null to null
                continue
            }
            val problem = setting.problem(value)
            if (problem != null) { errors += "$key: $problem"; continue }
            if (saved[key] != value) changed[key] = saved[key] to value
            saved[key] = value
        }
        if (errors.isNotEmpty()) return@put call.respondError(HttpStatusCode.BadRequest, "invalid_settings", errors)

        // What the next start reads: the environment, saved values where it is empty.
        val env = System.getenv()
        val effective = LinkedHashMap(env).apply { saved.forEach { (k, v) -> if (env[k].isNullOrBlank()) put(k, v) } }
        val problems = ServerSettingsCatalog.startProblems(effective)
        if (problems.isNotEmpty()) return@put call.respondError(HttpStatusCode.BadRequest, "would_not_start", problems)

        store.save(saved)
        if (changed.isNotEmpty()) {
            audit?.record(
                "server_settings_update",
                "Server settings saved for the next start: ${changed.keys.joinToString()}",
                detail = buildJsonObject {
                    changed.forEach { (k, v) -> putJsonObject(k) { put("before", v.first); put("after", v.second) } }
                }
            )
        }
        call.respondJson(HttpStatusCode.OK, settingsView(store, restartSupervised))
    }

    post("/api/v1/server-settings/restart") {
        if (!restartSupervised) {
            return@post call.respondError(
                HttpStatusCode.Conflict, "not_supervised",
                listOf("Nothing restarts this process when it exits; restart the server yourself")
            )
        }
        audit?.record("server_restart", "Server restart requested from the dashboard")
        call.respondJson(HttpStatusCode.Accepted, buildJsonObject { put("restarting", true) })
        // Let the answer leave before the process goes.
        Thread {
            Thread.sleep(700)
            exit()
        }.apply { isDaemon = true }.start()
    }

    delete("/api/v1/server-settings/rejected") {
        store.clearRejected()
        call.respondJson(HttpStatusCode.OK, settingsView(store, restartSupervised))
    }
}

private fun settingsView(store: ServerSettingsStore, restartSupervised: Boolean): JsonObject {
    val content = store.read()
    val saved = store.values()
    var pending = false
    val body = buildJsonObject {
        put("restartSupervised", restartSupervised)
        putJsonArray("settings") {
            ServerSettingsCatalog.all.forEach { s ->
                val locked = ServerEnv.lockedByEnvironment(s.key)
                // What this process started with (env, or the saved value it loaded then).
                val running = ServerEnv.get(s.key)?.trim()?.takeIf { it.isNotEmpty() }
                val next = if (locked) running else saved[s.key]
                val isPending = !locked && next != running
                if (isPending) pending = true
                add(buildJsonObject {
                    put("key", s.key)
                    put("group", s.group)
                    put("kind", s.kind.name.lowercase())
                    put("default", s.default)
                    if (s.choices.isNotEmpty()) put("choices", JsonArray(s.choices.map(::JsonPrimitive)))
                    if (s.kind == com.example.pinvault.server.service.ServerSetting.Kind.NUMBER) { put("min", s.min); put("max", s.max) }
                    put("running", running)
                    put("saved", saved[s.key])
                    put("locked", locked)
                    put("pending", isPending)
                })
            }
        }
        content.rejected?.let { r ->
            putJsonObject("rejected") {
                put("reason", r.reason)
                put("at", r.at)
                putJsonObject("values") { r.values.forEach { (k, v) -> put(k, v) } }
            }
        }
    }
    return JsonObject(body + ("pendingRestart" to JsonPrimitive(pending)))
}

private suspend fun RoutingCall.respondJson(status: HttpStatusCode, body: JsonObject) =
    respondText(body.toString(), ContentType.Application.Json, status)

private suspend fun RoutingCall.respondError(status: HttpStatusCode, error: String, details: List<String>) =
    respondJson(status, buildJsonObject {
        put("error", error)
        put("details", JsonArray(details.map(::JsonPrimitive)))
    })
