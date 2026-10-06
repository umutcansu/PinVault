package com.example.pinvault.server.route

import com.example.pinvault.server.service.SetupReport
import io.ktor.http.ContentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * What the setup wizard needs to write an app's PinVault configuration:
 * public values only (pins, public keys, ports, modes). Gathered by Main at
 * request time, so a rotated pin or key shows at once.
 */
data class SetupFacts(
    val configApis: List<Api>,
    /** The host name the Config API certificate is issued for (bootstrap pins are filed under it). */
    val bootstrapHost: String,
    val bootstrapPins: List<String>,
    /** Base64 X.509 public keys the server signs configs with (`signaturePublicKeys`). */
    val signingKeys: List<String>,
    /** How many of them a config carries (`requiredSignatures`). */
    val requiredSignatures: Int,
    /** `RECOVERY_PUBLIC_KEYS`: the app's `recoveryPublicKeys` (public halves; empty = key sets off). */
    val recoveryKeys: List<String>,
    /** SPKI SHA-256 of the client CA that signs device certificates (`clientCaPins`). */
    val clientCaPin: String?,
    /** The recovery door (renewal of an expired certificate); null = off. */
    val recoveryPort: Int?,
    val recoveryPins: List<String>,
    val enrollmentMode: String,
    val attestationMode: String,
    val integrityMode: String,
    val configTtlSeconds: Long
) {
    data class Api(val id: String, val port: Int, val mode: String, val running: Boolean)
}

/**
 * `GET /api/v1/setup` (management listener, admin key): the production
 * checklist ([SetupReport]) and the [SetupFacts] the dashboard's setup wizard
 * turns into the app's configuration code. Read-only: the wizard shows which
 * `.env` lines to change; it never changes the server.
 */
fun Route.setupRoutes(env: () -> Map<String, String>, facts: () -> SetupFacts) {
    get("/api/v1/setup") {
        val f = facts()
        val body = buildJsonObject {
            putJsonArray("checks") {
                SetupReport.checks(env()).forEach { c ->
                    add(buildJsonObject {
                        put("id", c.id)
                        put("level", c.level.name.lowercase())
                        put("current", c.current)
                        c.fix?.let { put("fix", it) }
                    })
                }
            }
            putJsonArray("configApis") {
                f.configApis.forEach { api ->
                    add(buildJsonObject {
                        put("id", api.id); put("port", api.port); put("mode", api.mode); put("running", api.running)
                    })
                }
            }
            put("bootstrapHost", f.bootstrapHost)
            put("bootstrapPins", JsonArray(f.bootstrapPins.map(::JsonPrimitive)))
            put("signingKeys", JsonArray(f.signingKeys.map(::JsonPrimitive)))
            put("requiredSignatures", f.requiredSignatures)
            put("recoveryKeys", JsonArray(f.recoveryKeys.map(::JsonPrimitive)))
            f.clientCaPin?.let { put("clientCaPin", it) }
            f.recoveryPort?.let { put("recoveryPort", it) }
            put("recoveryPins", JsonArray(f.recoveryPins.map(::JsonPrimitive)))
            put("enrollmentMode", f.enrollmentMode)
            put("attestationMode", f.attestationMode)
            put("integrityMode", f.integrityMode)
            put("configTtlSeconds", f.configTtlSeconds)
        }
        call.respondText(body.toString(), ContentType.Application.Json)
    }
}
