package com.example.pinvault.server.route

import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.SignedConfig
import com.example.pinvault.server.plugin.receiveLimitedJson
import com.example.pinvault.server.plugin.receiveLimitedText
import com.example.pinvault.server.service.AuditContext
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.attestation.AttestationPolicy
import com.example.pinvault.server.service.attestation.AttestationService
import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.AttestationTokenSecretStore
import com.example.pinvault.server.store.AttestedDevice
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.DeviceHostAclStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.route
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.util.Base64

/**
 * How many attestations a source address, and a device, may make per window
 * (`ATTESTATION_RATE_LIMIT`, `ATTESTATION_DEVICE_RATE_LIMIT`); null = no limit.
 * The challenge is counted on its own table at twice the address quota, so a
 * flood of challenge requests costs nothing but a MAC each and never uses up
 * the attestations of the devices behind the same address.
 */
class AttestationLimits(
    private val perAddress: RateLimiter? = null,
    private val challengePerAddress: RateLimiter? = null,
    private val perDevice: RateLimiter? = null
) {
    companion object {
        /** From the two env values; 0 = no limit. */
        fun of(perAddress: Int, perDevice: Int): AttestationLimits = AttestationLimits(
            perAddress = if (perAddress > 0) RateLimiter(maxAttempts = perAddress, windowMs = WINDOW_MS) else null,
            challengePerAddress = if (perAddress > 0) RateLimiter(maxAttempts = perAddress * 2, windowMs = WINDOW_MS) else null,
            perDevice = if (perDevice > 0) RateLimiter(maxAttempts = perDevice, windowMs = WINDOW_MS) else null
        )

        private const val WINDOW_MS = 10 * 60_000L
    }

    fun allowChallenge(remote: String): Boolean = challengePerAddress?.allow(RateLimiter.sourceKey(remote)) != false
    fun allowAddress(remote: String): Boolean = perAddress?.allow(RateLimiter.sourceKey(remote)) != false
    fun allowDevice(configApiId: String, deviceId: String): Boolean = perDevice?.allow("$configApiId|$deviceId") != false
}

private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

private suspend fun ApplicationCall.respondAttestRateLimited() = respondText(
    """{"error":"rate_limited","message":"Too many attestations. Try again later."}""",
    ContentType.Application.Json, HttpStatusCode.TooManyRequests
)

/**
 * The device side of ATTESTATION.md §2 on a Config API listener:
 * `GET /api/v1/attest/challenge` and `POST /api/v1/attest`. Both are on the
 * public allowlist, counted by the refusal limiter and capped by the device
 * body limit; the body is the device's proof (its key signs the nonce and
 * the report).
 */
fun Route.attestationRoutes(
    configApiId: String,
    service: AttestationService,
    pinConfigStore: PinConfigStore,
    signedConfigService: SignedConfigService,
    deviceHostAclStore: DeviceHostAclStore? = null,
    limits: AttestationLimits? = null,
    clock: () -> Long = System::currentTimeMillis
) {
    get("/api/v1/attest/challenge") {
        val remote = call.request.origin.remoteAddress
        if (limits != null && !limits.allowChallenge(remote)) return@get call.respondAttestRateLimited()
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respondText(buildJsonObject {
            put("nonce", service.nonces.issue())
            put("expiresIn", service.nonces.ttlSeconds)
            put("serverTime", clock())
            // This server takes v2 verdicts (App Attest over the report, Play Integrity bound to the
            // device; ATTESTATION.md §11, §12): a client sends them only to a server that says so.
            put("verdictBinding", 2)
        }.toString(), ContentType.Application.Json)
    }

    post("/api/v1/attest") {
        val remote = call.request.origin.remoteAddress
        // The address is counted before the body is read: nothing the caller sends can make up more windows.
        if (limits != null && !limits.allowAddress(remote)) return@post call.respondAttestRateLimited()
        val body = call.receiveLimitedJson() ?: return@post
        // ...and the device id it claims, once there is a well-formed one.
        val claimedDevice = (body["deviceId"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { AttestationService.DEVICE_ID.matches(it) }
        if (claimedDevice != null && limits != null && !limits.allowDevice(configApiId, claimedDevice)) return@post call.respondAttestRateLimited()

        // Over mTLS the token names the connection's certificate (cnf.x5t#S256, ATTESTATION.md §5).
        val outcome = service.attest(configApiId, body, remote, clientCertificate = call.clientCertificate()?.encoded)
        call.response.header(HttpHeaders.CacheControl, "no-store")
        when (outcome) {
            is AttestationService.Outcome.Refused -> call.respondText(outcome.body(), ContentType.Application.Json, outcome.status)
            is AttestationService.Outcome.Decided -> {
                // A passing device that is behind gets the signed config it would
                // get from GET /api/v1/certificate-config, scoped the same way; a
                // rejected one keeps what it has until it expires. The library
                // sends `hosts` (and, on its GET, X-Device-Id) only for a block
                // with wantPinsFor; without `hosts` this is the legacy unscoped
                // call, so the device id does not switch ACL filtering on here either.
                var config: SignedConfig? = null
                if (outcome.passed) {
                    try {
                        fun view(): PinConfig = servedPinConfig(call, configApiId, pinConfigStore, deviceHostAclStore, outcome.hosts,
                            claimedDeviceId = outcome.deviceId.takeIf { outcome.hosts != null })
                        val now = clock()
                        val current = view()
                        val behind = outcome.currentConfigVersion == null || current.version != outcome.currentConfigVersion ||
                            // An envelope past half its lifetime is refreshed through this channel too.
                            (outcome.currentIssuedAt != null && now - outcome.currentIssuedAt > signedConfigService.ttlMs / 2)
                        if (behind) {
                            val envelope = signEnvelope(signedConfigService, configApiId, redelivery = true, load = ::view)
                            // The cached envelope the device already holds is no news (it would see a replay).
                            val issuedAt = runCatching { Json.parseToJsonElement(envelope.payload).jsonObject["issuedAt"]?.let { (it as? JsonPrimitive)?.longOrNull } }.getOrNull()
                            if (issuedAt == null || issuedAt != outcome.currentIssuedAt) config = envelope
                        }
                    } catch (e: Exception) {
                        // The verdict stands; the device fetches its config the usual way.
                        System.err.println("Attestation of ${outcome.deviceId} in $configApiId: config not embedded, signing failed: ${e.message}")
                    }
                }
                call.respondText(outcome.toJson(config, config != null).toString(), ContentType.Application.Json)
            }
        }
    }
}

/** An annotation as the token carries it (`anno`): short, printable, no quotes. */
private val ANNOTATION = Regex("^[A-Za-z0-9._:@/ +-]{1,64}$")
private const val MAX_ANNOTATIONS = 16
private const val ADMIN_BODY_MAX = 64L * 1024

/**
 * The admin API of ATTESTATION.md §6 (management port; Config API ports with
 * `CONFIG_API_ADMIN_ROUTES=on`): the policy and devices of a Config API,
 * its stats, and the token secrets. Writes are under two-person approval
 * when it is on (`attestation_policy`, `attestation_device`,
 * `attestation_token_secrets` (requester-run), `attestation_token_secret_rotate`,
 * `attestation_token_secret_delete`).
 */
fun Route.attestationAdminRoutes(
    service: AttestationService,
    policies: AttestationPolicyStore,
    devices: AttestedDeviceStore,
    secrets: AttestationTokenSecretStore,
    audit: AuditLog? = null
) {
    fun deviceJson(device: AttestedDevice): JsonObject {
        val base = json.encodeToJsonElement(AttestedDevice.serializer(), device).jsonObject
        val report = device.lastReport?.let { runCatching { Json.parseToJsonElement(it) }.getOrNull() }
        return JsonObject(base.filterKeys { it != "lastReport" } + ("lastReport" to (report ?: JsonNull)))
    }

    route("/api/v1/config-apis/{configApiId}/attestation") {

        get("/policy") {
            val cid = call.pathParameters["configApiId"]!!
            call.respondText(service.policyFor(cid).toJson(), ContentType.Application.Json)
        }

        put("/policy") {
            val cid = call.pathParameters["configApiId"]!!
            val text = call.receiveLimitedText(ADMIN_BODY_MAX) ?: return@put
            val current = service.policyFor(cid)
            val parsed = AttestationPolicy.parse(text, current).getOrElse { e ->
                return@put call.respondText(buildJsonObject { put("error", "invalid_policy"); put("message", e.message ?: "invalid policy") }.toString(),
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            val unchanged = current.version > 0 && parsed.copy(version = current.version) == current
            val stored = if (unchanged) current else policies.put(cid, parsed, AuditContext.actor())
            if (!unchanged) {
                val changedFlags = parsed.flags.filter { (k, v) -> current.flags[k] != v }
                audit?.record("attestation_policy_updated",
                    "Attestation policy of $cid is now v${stored.version}" +
                        (if (changedFlags.isEmpty()) "" else ": " + changedFlags.entries.joinToString { "${it.key}=${it.value}" }) +
                        (if (parsed.revealReasons != current.revealReasons) ", revealReasons=${parsed.revealReasons}" else "") +
                        (if (parsed.tokenTtlSeconds != current.tokenTtlSeconds) ", tokenTtl=${parsed.tokenTtlSeconds}s" else "") +
                        (if (parsed.attestIntervalSeconds != current.attestIntervalSeconds) ", interval=${parsed.attestIntervalSeconds}s" else ""),
                    cid, "policy", detail = Json.parseToJsonElement(stored.toJson()))
            }
            call.respondText(stored.toJson(), ContentType.Application.Json)
        }

        get("/devices") {
            val cid = call.pathParameters["configApiId"]!!
            val result = call.request.queryParameters["result"]?.takeIf { it == "pass" || it == "reject" }
            val page = call.request.queryParameters["page"]?.toIntOrNull() ?: 1
            val pageSize = call.request.queryParameters["pageSize"]?.toIntOrNull() ?: 50
            val listing = devices.list(cid, result, call.request.queryParameters["q"]?.take(128), page, pageSize)
            call.respondText(buildJsonObject {
                put("items", buildJsonArray { listing.items.forEach { add(json.encodeToJsonElement(AttestedDevice.serializer(), it)) } })
                put("total", listing.total)
                put("page", listing.page)
                put("pageSize", listing.pageSize)
            }.toString(), ContentType.Application.Json)
        }

        get("/devices/{deviceId}") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            val device = devices.get(cid, deviceId, withReport = true)
                ?: return@get call.respondText("""{"error":"device_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            call.respondText(deviceJson(device).toString(), ContentType.Application.Json)
        }

        put("/devices/{deviceId}") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            if (!AttestationService.DEVICE_ID.matches(deviceId)) {
                return@put call.respondText("""{"error":"invalid_device_id","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            val body = call.receiveLimitedJson(ADMIN_BODY_MAX) ?: return@put
            val before = devices.get(cid, deviceId)
            val forcePass = (body["forcePass"] as? JsonPrimitive)?.booleanOrNull ?: before?.forcePass ?: false
            val forceFail = (body["forceFail"] as? JsonPrimitive)?.booleanOrNull ?: before?.forceFail ?: false
            val annotations = when (val element = body["annotations"]) {
                null, JsonNull -> before?.annotations ?: emptyList()
                is JsonArray -> element.map { item ->
                    (item as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.takeIf { ANNOTATION.matches(it) }
                        ?: return@put call.respondText("""{"error":"invalid_annotation","message":"Each annotation: letters, digits, . _ : @ / + - and spaces, at most 64 characters."}""",
                            ContentType.Application.Json, HttpStatusCode.BadRequest)
                }.distinct()
                else -> return@put call.respondText("""{"error":"invalid_annotation","message":"annotations must be an array of strings."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            if (annotations.size > MAX_ANNOTATIONS) {
                return@put call.respondText("""{"error":"invalid_annotation","message":"At most $MAX_ANNOTATIONS annotations."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            if (forcePass && forceFail) {
                return@put call.respondText("""{"error":"conflicting_overrides","message":"forcePass and forceFail cannot both be set."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            val device = devices.annotate(cid, deviceId, forcePass, forceFail, annotations)
            val changed = before == null || before.forcePass != forcePass || before.forceFail != forceFail || before.annotations != annotations
            if (changed) {
                audit?.record("attestation_device_annotated",
                    "Device $deviceId: " + listOfNotNull(
                        "forcePass".takeIf { forcePass }, "forceFail".takeIf { forceFail },
                        if (annotations.isEmpty()) "no annotations" else "annotations ${annotations.joinToString()}"
                    ).joinToString(", "),
                    cid, deviceId, detail = buildJsonObject {
                        put("forcePass", forcePass); put("forceFail", forceFail)
                        put("annotations", buildJsonArray { annotations.forEach { add(JsonPrimitive(it)) } })
                        before?.let {
                            put("previousForcePass", it.forcePass); put("previousForceFail", it.forceFail)
                            put("previousAnnotations", buildJsonArray { it.annotations.forEach { a -> add(JsonPrimitive(a)) } })
                        }
                    })
            }
            call.respondText(deviceJson(device).toString(), ContentType.Application.Json)
        }

        delete("/devices/{deviceId}") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            val before = devices.get(cid, deviceId)
            if (before == null || !devices.forget(cid, deviceId)) {
                return@delete call.respondText("""{"error":"device_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            }
            audit?.record("attestation_device_forgotten",
                "Device $deviceId forgotten: ${if (before.registered) "its key may register again" else "it had no key yet"}" +
                    (if (before.keyMismatches > 0) " (${before.keyMismatches} key mismatch(es) seen)" else ""),
                cid, deviceId, detail = buildJsonObject {
                    put("registered", before.registered)
                    before.spkiSha256?.let { put("spkiSha256", it) }
                    put("keyMismatches", before.keyMismatches)
                })
            call.respondText(buildJsonObject { put("forgotten", true); put("deviceId", deviceId) }.toString(), ContentType.Application.Json)
        }

        /**
         * A backend reports the device's tokens used abnormally (§5.2): from
         * too many addresses, or faster than a person. Its next rounds raise
         * `token_anomaly` for ATTESTATION_ANOMALY_TTL_SECONDS. Body:
         * `{"reason": "…", "addresses"?: n, "requests"?: n, "windowSeconds"?: n}`.
         */
        post("/devices/{deviceId}/anomaly") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            val body = call.receiveLimitedJson(ADMIN_BODY_MAX) ?: return@post
            val reason = (body["reason"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.takeIf { it.isNotEmpty() && it.length <= 200 }
                ?: return@post call.respondText("""{"error":"invalid_reason","message":"reason: a string of 1–200 characters."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            val detail = buildJsonObject {
                put("reason", reason)
                for (name in listOf("addresses", "requests", "windowSeconds")) {
                    (body[name] as? JsonPrimitive)?.longOrNull?.let { put(name, it) }
                }
                put("reportedBy", AuditContext.actor())
            }
            if (!service.reportAnomaly(cid, deviceId, reason, detail, actor = null, ip = null)) {
                return@post call.respondText("""{"error":"device_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            }
            call.respondText(deviceJson(devices.get(cid, deviceId)!!).toString(), ContentType.Application.Json)
        }

        /** Clears a device's token anomaly: its rounds no longer raise `token_anomaly`. */
        delete("/devices/{deviceId}/anomaly") {
            val cid = call.pathParameters["configApiId"]!!
            val deviceId = call.pathParameters["deviceId"]!!
            if (!devices.clearAnomaly(cid, deviceId)) {
                return@delete call.respondText("""{"error":"no_anomaly"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            }
            audit?.record("attestation_token_anomaly_cleared", "Device $deviceId: token anomaly cleared", cid, deviceId)
            call.respondText(deviceJson(devices.get(cid, deviceId)!!).toString(), ContentType.Application.Json)
        }

        get("/stats") {
            val cid = call.pathParameters["configApiId"]!!
            call.respondText(buildJsonObject {
                put("last24h", json.encodeToJsonElement(com.example.pinvault.server.store.AttestationWindowStats.serializer(), devices.windowStats(cid, 24)))
                put("last7d", json.encodeToJsonElement(com.example.pinvault.server.store.AttestationWindowStats.serializer(), devices.windowStats(cid, 7 * 24)))
                put("devices", json.encodeToJsonElement(com.example.pinvault.server.store.AttestedDeviceCounts.serializer(), devices.counts(cid)))
                put("policyVersion", service.policyFor(cid).version)
            }.toString(), ContentType.Application.Json)
        }
    }

    route("/api/v1/attestation/token-secrets") {

        /** Active and previous secrets, in the clear: what a backend loads by kid. */
        get {
            val active = secrets.active()
            call.response.header(HttpHeaders.CacheControl, "no-store")
            call.respondText(buildJsonObject {
                put("active", active.kid)
                put("secrets", buildJsonArray {
                    secrets.all().forEach { s ->
                        add(buildJsonObject {
                            put("kid", s.kid)
                            put("secret", Base64.getEncoder().encodeToString(s.secret))
                            put("active", s.active)
                            put("createdAt", s.createdAt)
                            put("createdBy", s.createdBy)
                        })
                    }
                })
            }.toString(), ContentType.Application.Json)
        }

        post("/rotate") {
            val previous = secrets.all().firstOrNull { it.active }?.kid
            val fresh = secrets.rotate(AuditContext.actor())
            audit?.record("attestation_token_secret_rotated",
                "PinVault-Token secret rotated: ${fresh.kid} is active" + (previous?.let { "; $it stays for verification" } ?: ""),
                target = fresh.kid, detail = buildJsonObject { put("kid", fresh.kid); previous?.let { put("previous", it) } })
            call.respondText(buildJsonObject { put("kid", fresh.kid); put("active", true); put("createdAt", fresh.createdAt) }.toString(),
                ContentType.Application.Json)
        }

        delete("/{kid}") {
            val kid = call.pathParameters["kid"]!!
            when (secrets.delete(kid)) {
                AttestationTokenSecretStore.Deletion.NotFound ->
                    call.respondText("""{"error":"secret_not_found"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
                AttestationTokenSecretStore.Deletion.Active ->
                    call.respondText("""{"error":"secret_active","message":"The active secret cannot be deleted; rotate first."}""",
                        ContentType.Application.Json, HttpStatusCode.Conflict)
                AttestationTokenSecretStore.Deletion.Deleted -> {
                    audit?.record("attestation_token_secret_deleted", "PinVault-Token secret $kid deleted: tokens signed with it no longer verify",
                        target = kid, detail = buildJsonObject { put("kid", kid) })
                    call.respondText(buildJsonObject { put("deleted", kid) }.toString(), ContentType.Application.Json)
                }
            }
        }
    }
}
