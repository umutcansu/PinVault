package com.example.pinvault.server.route

import com.example.pinvault.server.model.HostActionResponse
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.store.HostRecord
import com.example.pinvault.server.store.HostStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json

/**
 * Management-server routes that name the Config API in the PATH
 * (`/api/v1/config/{configApiId}/…`, `/api/v1/management/hosts/{configApiId}/…`).
 *
 * The scope is read with `pathParameters` only: `call.parameters` puts query
 * values first, so `POST /api/v1/config/x/update?configApiId=default-tls`
 * wrote default-tls while the approval gate and its description looked at
 * `x`. (Moved out of Main.kt so the tests can mount them.)
 */
fun Route.managementConfigRoutes(
    pinConfigStore: PinConfigStore,
    historyStore: PinConfigHistoryStore,
    hostStore: HostStore,
    certService: CertificateService,
    liveGate: LiveCertificateGate? = null,
    audit: AuditLog? = null,
    planner: CertChangePlanner = CertChangePlanner(certService, pinConfigStore, hostStore)
) {
    // Config API bazlı config fetch (Web UI için)
    get("/api/v1/config/{configApiId}") {
        val configApiId = call.pathParameters["configApiId"] ?: "default-tls"
        val config = pinConfigStore.load(configApiId)
        val encoder = Json { encodeDefaults = true }
        call.respondText(encoder.encodeToString(PinConfig.serializer(), config), ContentType.Application.Json)
    }

    // configApiId bazlı config güncelleme (Web UI'dan)
    // Same write as PUT /api/v1/certificate-config?configApiId=… — validation,
    // per-host versioning, live gate, history. It used to store the body
    // as sent, versions included, with none of those checks.
    post("/api/v1/config/{configApiId}/update") {
        val configApiId = call.pathParameters["configApiId"] ?: "default-tls"
        call.applyPinConfigUpdate(configApiId, pinConfigStore, historyStore, liveGate, audit)
    }

    // configApiId bazlı host yönetimi (Web UI'dan)
    post("/api/v1/management/hosts/{configApiId}/generate-cert") {
        val configApiId = call.pathParameters["configApiId"] ?: "default-tls"
        // The same plan-then-apply as POST /api/v1/hosts/generate-cert (live gate included).
        val plan = call.certPlan(planner, CertChangePlanner.Kind.ADD_GENERATED, configApiId, null) ?: return@post
        call.addPlannedHost(configApiId, plan, "cert_generated", pinConfigStore, historyStore = historyStore, hostStore = hostStore,
            certService = certService, planner = planner, liveGate = liveGate, audit = audit)
    }
}
