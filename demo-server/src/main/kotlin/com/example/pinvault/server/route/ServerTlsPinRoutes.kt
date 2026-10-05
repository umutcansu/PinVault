package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.DEFAULT_ADMIN_BODY_MAX_BYTES
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertPlan
import com.example.pinvault.server.service.CertificateService
import io.ktor.http.ContentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File

/**
 * The pins of the Config API's own TLS certificate — what apps carry as
 * bootstrap pins — and the keystore behind them (`certs/<certId>.jks`).
 */
class ServerTlsPins(
    private val certService: CertificateService,
    private val pinsFile: File,
    val certId: String,
    initial: List<String>
) {
    @Volatile
    var pins: List<String> = initial
        private set

    /** Installs [plan] (its keystores, when it has any) and publishes its pins. */
    @Synchronized
    fun apply(plan: CertPlan) {
        if (plan.keystore != null) certService.install(certId, plan)
        pinsFile.writeText(plan.pins.joinToString("\n"))
        pins = plan.pins
    }
}

/**
 * `/api/v1/server-tls-pins…`: read the bootstrap pins, and change the
 * certificate behind them (regenerate, switch to the stored backup key,
 * upload, or take the pins a URL serves). (Moved out of Main.kt so the tests
 * can mount them.)
 *
 * Every change is made as a [CertPlan] first — see [certPlan]: with
 * two-person approval the approver is shown the plan's pins and exactly that
 * plan is applied; nothing is generated or fetched a second time.
 */
fun Route.serverTlsPinRoutes(
    state: ServerTlsPins,
    planner: CertChangePlanner,
    httpsPort: Int,
    audit: AuditLog? = null,
    maxUploadBytes: Long = DEFAULT_ADMIN_BODY_MAX_BYTES
) {
    fun answer(plan: CertPlan?, extra: JsonObject = buildJsonObject { }): String = buildJsonObject {
        put("primaryPin", state.pins.getOrNull(0) ?: "")
        put("backupPin", state.pins.getOrNull(1) ?: "")
        extra.forEach { (name, value) -> put(name, value) }
        // A new certificate is served only by a listener started after it was installed.
        if (plan?.keystore != null) put("restartRequired", true)
    }.toString()

    get("/api/v1/server-tls-pins") {
        call.respondText(
            answer(null, buildJsonObject { put("httpsPort", httpsPort); put("hostname", CertChangePlanner.BOOTSTRAP_HOST) }),
            ContentType.Application.Json
        )
    }

    fun Route.change(path: String, kind: CertChangePlanner.Kind, done: String, extra: (CertPlan) -> JsonObject = { buildJsonObject { } }) =
        post("/api/v1/server-tls-pins/$path") {
            val plan = call.certPlan(planner, kind, "", null, maxUploadBytes) ?: return@post
            val before = state.pins
            state.apply(plan)
            audit?.record(
                "bootstrap_pins_changed",
                "Config API TLS certificate ${plan.source}: bootstrap pins ${before.joinToString { it.take(12) + "…" }.ifEmpty { "(none)" }} → " +
                    plan.pins.joinToString { it.take(12) + "…" },
                detail = buildJsonObject { put("certificate", plan.publicJson()) }
            )
            call.respondText(
                answer(plan, JsonObject(mapOf(done to JsonPrimitive(true)) + extra(plan))),
                ContentType.Application.Json
            )
        }

    change("regenerate", CertChangePlanner.Kind.BOOTSTRAP_REGENERATE, "regenerated")

    // Yedek anahtara geçiş (config sunucusunun kendi sertifikası):
    // uygulamalar bu sertifikanın iki pin'ini başlangıç pini olarak
    // taşır, yedeğe geçmek uygulama güncellemesi istemez. Yeni asıl
    // pin eski yedek olur; yeni yedeğin pin'i sonraki sürüme gömülür.
    change("rotate-to-backup", CertChangePlanner.Kind.BOOTSTRAP_ROTATE, "rotated")

    change("upload", CertChangePlanner.Kind.BOOTSTRAP_UPLOAD, "uploaded")

    // Fetch sadece pin'leri alır, keystore oluşturmaz — pin'leri kaydeder.
    change("fetch-from-url", CertChangePlanner.Kind.BOOTSTRAP_FETCH, "fetched") { plan ->
        buildJsonObject { put("hostname", plan.fetchedFrom?.substringBefore(' ') ?: "") }
    }
}
