package com.example.pinvault.server.route

import com.example.pinvault.server.service.SetupCertificateFacts
import com.example.pinvault.server.service.SetupCertificateReport
import io.ktor.http.ContentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * `GET /api/v1/setup/certificates` (management listener, admin key): the
 * setup wizard's "Certificates" step — every certificate the operator has
 * to decide on before production, with a checklist. Read-only; public facts.
 */
fun Route.setupCertificatesRoute(facts: () -> SetupCertificateFacts) {
    get("/api/v1/setup/certificates") {
        val f = facts()
        val body = buildJsonObject {
            putJsonArray("checks") {
                SetupCertificateReport.checks(f).forEach { c ->
                    add(buildJsonObject {
                        put("id", c.id); put("level", c.level.name.lowercase()); put("current", c.current)
                        c.action?.let { put("action", it) }
                        c.configApiId?.let { put("configApiId", it) }
                        c.hostname?.let { put("hostname", it) }
                        c.key?.let { put("key", it) }
                    })
                }
            }
            f.configApiCert?.let { c ->
                put("configApiCert", buildJsonObject {
                    put("subject", c.subject); put("issuer", c.issuer); put("selfSigned", c.selfSigned)
                    putJsonArray("subjectAltNames") { c.subjectAltNames.forEach { add(JsonPrimitive(it)) } }
                    put("notAfter", c.notAfter); put("backupKey", c.backupKey)
                    putJsonArray("pins") { c.pins.forEach { add(JsonPrimitive(it)) } }
                })
            }
            putJsonArray("listeners") {
                f.listeners.forEach { l -> add(buildJsonObject { put("id", l.id); put("port", l.port); put("mode", l.mode); put("running", l.running) }) }
            }
            f.publicHost?.let { put("publicHost", it) }
            f.clientCa?.let { put("clientCa", buildJsonObject { put("subject", it.subject); put("notAfter", it.notAfter); put("pin", it.pin) }) }
            put("clientCertTtlDays", f.clientCertTtlDays)
            put("enrollmentMode", f.enrollmentMode)
            put("activeIdentities", f.activeIdentities)
            put("p12Enrollment", f.p12Enrollment)
            f.serverCa?.let { put("serverCa", buildJsonObject { put("subject", it.subject); put("notAfter", it.notAfter); put("pin", it.pin) }) }
            f.recoveryPort?.let { put("recoveryPort", it) }
            put("recoveryRunning", f.recoveryRunning)
            putJsonArray("hosts") {
                f.hosts.forEach { h ->
                    add(buildJsonObject {
                        put("hostname", h.hostname); put("configApiId", h.configApiId); put("source", h.source)
                        put("servedHere", h.servedHere); h.notAfter?.let { put("notAfter", it) }
                        put("backupKey", h.backupKey); put("pinCount", h.pinCount); put("mtls", h.mtls)
                        h.clientCertNotAfter?.let { put("clientCertNotAfter", it) }
                    })
                }
            }
            putJsonArray("vaultFiles") {
                f.vaultFiles.forEach { v -> add(buildJsonObject { put("configApiId", v.configApiId); put("key", v.key); put("expiresAt", v.expiresAt) }) }
            }
            put("warnDays", f.warnDays)
        }
        call.respondText(body.toString(), ContentType.Application.Json)
    }
}
