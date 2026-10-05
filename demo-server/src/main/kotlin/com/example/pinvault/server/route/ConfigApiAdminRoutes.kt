package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.ApprovedReplayKey
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigApiManager
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.ConfigApiRegistry
import com.example.pinvault.server.store.HostStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.io.File

/** The modes a Config API listener runs in. */
internal val CONFIG_API_MODES = setOf("tls", "mtls")

/**
 * Why the body of a Config API start/stop/delete is refused, or null. One
 * check for the handler and for the approval description: `id` is an
 * identifier (it names a scope, a database row and the approval card), `mode`
 * is `tls` or `mtls`, `port` 1–65535.
 */
internal fun configApiRequestError(json: JsonObject?, start: Boolean): String? {
    val id = (json?.get("id") as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (json == null) return "A JSON body is required"
    if (id == null && !start) return "id gerekli"
    if (id != null && !isValidIdentifier(id)) return "id: letters, digits, '.', '_', ':' and '-' only, at most 64"
    if (start) {
        val port = (json["port"] as? JsonPrimitive)?.intOrNull ?: return "port gerekli"
        if (port !in 1..65535) return "port must be 1..65535"
        val mode = (json["mode"] as? JsonPrimitive)?.content ?: "tls"
        if (mode !in CONFIG_API_MODES) return "mode must be \"tls\" or \"mtls\""
    }
    return null
}

/**
 * Management endpoints that start, stop and delete Config API listeners, and
 * the listings the dashboard draws them from. (Moved out of Main.kt so the
 * tests can mount them.)
 *
 * Every answer is built as JSON, never by pasting values into a template: an
 * id used to be interpolated as it came, so a body could inject fields into
 * every later listing.
 */
fun Route.configApiAdminRoutes(
    configApiManager: ConfigApiManager,
    pinConfigStore: PinConfigStore,
    certService: CertificateService,
    configApiRegistry: ConfigApiRegistry,
    hostStore: HostStore,
    mockServerManager: MockServerManager,
    auditLog: AuditLog,
    serverKeystorePath: File,
    /** The routing module of a Config API listener (Main's `configApiModuleFor`). */
    moduleFor: (id: String, mode: String) -> Application.() -> Unit
) {
    fun instanceJson(api: ConfigApiManager.ConfigApiInstance, running: Boolean) = buildJsonObject {
        put("id", api.id); put("port", api.port); put("mode", api.mode); put("running", running)
    }

    // Tüm API'lerin config'lerini döner (Web UI sidebar için)
    get("/api/v1/all-configs") {
        val allConfigs = pinConfigStore.loadAll()
        val body = buildJsonArray {
            fun addApi(api: ConfigApiManager.ConfigApiInstance, running: Boolean) {
                val config = allConfigs[api.id]
                add(buildJsonObject {
                    put("id", api.id); put("port", api.port); put("mode", api.mode)
                    putJsonArray("pins") {
                        config?.pins?.forEach { pin ->
                            add(buildJsonObject {
                                put("hostname", pin.hostname)
                                putJsonArray("sha256") { pin.sha256.forEach { add(it) } }
                                put("version", pin.version)
                                put("forceUpdate", pin.forceUpdate)
                            })
                        }
                    }
                    put("version", config?.computedVersion() ?: 0)
                    put("running", running)
                })
            }
            configApiManager.getAll().forEach { addApi(it, true) }
            configApiManager.getAllStopped().forEach { addApi(it, false) }
        }
        call.respondText(body.toString(), ContentType.Application.Json)
    }

    get("/api/v1/config-apis") {
        call.respondText(buildJsonArray { configApiManager.getAll().forEach { add(instanceJson(it, true)) } }.toString(), ContentType.Application.Json)
    }

    // Starting one on a port another API holds stops that one: the port then
    // serves this scope's pins (the approval card says so).
    post("/api/v1/config-apis/start") {
        val json = call.jsonBodyOrNull()
        configApiRequestError(json, start = true)?.let { return@post call.respondConfigApiError(HttpStatusCode.BadRequest, it) }
        val id = (json!!["id"] as? JsonPrimitive)?.content ?: "api-${System.currentTimeMillis()}"
        val port = (json["port"] as JsonPrimitive).intOrNull!!
        val mode = (json["mode"] as? JsonPrimitive)?.content ?: "tls"

        val trustPath = if (mode == "mtls") certService.getTrustStoreFile().absolutePath.takeIf { certService.getTrustStoreFile().exists() } else null
        if (mode == "mtls" && trustPath == null) {
            return@post call.respondConfigApiError(HttpStatusCode.BadRequest, "mTLS için önce client sertifika oluşturun")
        }

        try {
            pinConfigStore.ensureConfigExists(id)
            val instance = configApiManager.start(id, port, mode, serverKeystorePath.absolutePath, trustPath, moduleFor(id, mode))
            // DB'ye kaydet (auto_start). INSERT OR REPLACE yerine
            // ensureRegistered: REPLACE satırı silip yeniden yazdığı
            // için vault_enabled sütunu varsayılanına (1) dönüyordu —
            // yani operatörün kapattığı vault, API her yeniden
            // başlatıldığında sessizce geri açılıyordu.
            configApiRegistry.ensureRegistered(id, port, mode)
            call.respondText(instanceJson(instance, true).toString(), ContentType.Application.Json)
        } catch (e: Exception) {
            call.respondConfigApiError(HttpStatusCode.InternalServerError, e.message ?: e.javaClass.simpleName)
        }
    }

    post("/api/v1/config-apis/stop") {
        val json = call.jsonBodyOrNull()
        configApiRequestError(json, start = false)?.let { return@post call.respondConfigApiError(HttpStatusCode.BadRequest, it) }
        val id = (json!!["id"] as JsonPrimitive).content
        configApiManager.stop(id)
        call.respondText(buildJsonObject { put("id", id); put("stopped", true) }.toString(), ContentType.Application.Json)
    }

    post("/api/v1/config-apis/delete") {
        val json = call.jsonBodyOrNull()
        configApiRequestError(json, start = false)?.let { return@post call.respondConfigApiError(HttpStatusCode.BadRequest, it) }
        val id = (json!!["id"] as JsonPrimitive).content

        // Sunucuyu durdur ve stopped listesinden de kaldır
        configApiManager.stop(id)
        configApiManager.removeStopped(id)

        // DB'den temizle: API'ye ait her şey (bkz. ConfigApiRegistry.purge).
        // Yalnızca pin tabloları siliniyordu; config_apis satırı kaldığı
        // için API sonraki açılışta geri geliyor, vault dosyaları, tokenlar
        // ve ACL'ler aynı adla açılan yeni API'ye kalıyordu.
        val purged = configApiRegistry.purge(id, keepChangeRequest = call.attributes.getOrNull(ApprovedReplayKey))
        // Mock sunucular hostname başına global: yalnızca başka bir
        // API'de kaydı kalmayan hostların sunucusunu durdur.
        purged.hostnames.filter { hostStore.getAnyByHostname(it) == null }
            .forEach { mockServerManager.stopAll(it) }
        for (cr in purged.cancelledChangeRequests) {
            auditLog.record("change_rejected", "#$cr rejected: Config API $id deleted", id, actor = "system")
        }

        call.respondText(buildJsonObject { put("id", id); put("deleted", true) }.toString(), ContentType.Application.Json)
    }
}

private suspend fun ApplicationCall.jsonBodyOrNull(): JsonObject? =
    try { Json.parseToJsonElement(receiveText()) as? JsonObject } catch (_: Exception) { null }

private suspend fun ApplicationCall.respondConfigApiError(status: HttpStatusCode, error: String) =
    respondText(buildJsonObject { put("error", error) }.toString(), ContentType.Application.Json, status)
