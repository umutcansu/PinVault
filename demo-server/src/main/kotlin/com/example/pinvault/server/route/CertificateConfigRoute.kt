package com.example.pinvault.server.route

import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.model.SignedConfig
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.store.ClientDeviceStore
import com.example.pinvault.server.store.ConnectionHistoryStore
import com.example.pinvault.server.store.DeviceHostAclStore
import com.example.pinvault.server.store.HostClientCertStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.Base64

private val configJson = Json { encodeDefaults = true }
private val aclLog = LoggerFactory.getLogger("CertificateConfigACL")

/**
 * Lifetime of a signed config response in milliseconds. After this window
 * elapses, clients reject the payload regardless of signature validity —
 * caps the replay opportunity for any captured signed bytes.
 *
 * Configurable via `CONFIG_TTL_SECONDS` env var; default 24h. The PinVault
 * client refreshes pins every 12h by default, so 24h leaves a safety margin
 * for transient offline periods.
 */
private val CONFIG_TTL_MS: Long =
    System.getenv("CONFIG_TTL_SECONDS")?.toLongOrNull()?.times(1000L)
        ?: (24L * 60 * 60 * 1000)

/**
 * Allowed shape for client-report identifier fields (hostname, model,
 * manufacturer). Permissive enough to accept real Android device strings
 * ("Google Pixel 7a", "Mi 9T", "api.example.com:8443") but rejects HTML
 * metacharacters that would otherwise reach the admin web UI's innerHTML
 * interpolations.
 */
private val CLIENT_REPORT_IDENT_REGEX = Regex("^[A-Za-z0-9._:\\- ]{1,128}$")

fun Route.certificateConfigRoutes(
    configApiId: String,
    store: PinConfigStore,
    historyStore: PinConfigHistoryStore,
    connectionStore: ConnectionHistoryStore,
    signingService: ConfigSigningService,
    clientDeviceStore: ClientDeviceStore,
    certService: com.example.pinvault.server.service.CertificateService? = null,
    enrollmentTokenStore: com.example.pinvault.server.store.EnrollmentTokenStore? = null,
    clientCertStore: com.example.pinvault.server.store.ClientCertStore? = null,
    mockServerManager: com.example.pinvault.server.service.MockServerManager? = null,
    hostClientCertStore: HostClientCertStore? = null,
    onClientCertEnrolled: (() -> Unit)? = null,
    enrollmentMode: String = "token",
    configApiMode: String = "tls",
    /**
     * V2: per-device pin scoping. When a device sends `?hosts=a,b,c` (or
     * identifies itself via `X-Device-Id`), the returned PinConfig is filtered
     * to the intersection of requested hosts and the device's ACL.
     *
     * If [deviceHostAclStore] is null, the legacy "return everything" behavior
     * is preserved. This keeps existing tests and demo flows working until
     * the library starts sending `?hosts=…`.
     */
    deviceHostAclStore: DeviceHostAclStore? = null
) {

    // Enrollment endpoint — Config API üzerinden client cert dağıtımı
    //
    // Güvenlik modları (ENROLLMENT_MODE):
    //   "token"  → Sadece enrollment token ile kayıt (varsayılan, üretim için önerilir)
    //   "open"   → Token veya deviceId ile kayıt (sadece demo/test için)
    //
    // Üretimde her zaman token modu kullanılmalıdır. Token'lar management API'den
    // oluşturulur ve tek kullanımlıktır.
    if (certService != null) {
        post("/api/v1/client-certs/enroll") {
            val body = call.receiveText()
            val json = try { Json.parseToJsonElement(body).jsonObject } catch (_: Exception) { null }
            val token = json?.get("token")?.jsonPrimitive?.content
            val deviceId = json?.get("deviceId")?.jsonPrimitive?.content

            val deviceAlias = json?.get("deviceAlias")?.jsonPrimitive?.content
            val deviceUid = json?.get("deviceUid")?.jsonPrimitive?.content

            val clientId: String
            if (token != null && enrollmentTokenStore != null) {
                clientId = enrollmentTokenStore.validate(token)
                    ?: return@post call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
                enrollmentTokenStore.markUsed(token)
            } else if (deviceId != null && enrollmentMode == "open") {
                // deviceId-only enrollment — sadece ENROLLMENT_MODE=open iken aktif
                // Üretimde kullanılmamalıdır: deviceId tahmin edilebilir, kimlik doğrulama yok
                clientId = deviceId
            } else if (deviceId != null) {
                return@post call.respondText(
                    """{"error":"Token required for enrollment. Generate a token via management API (POST /api/v1/enrollment-tokens/generate). To allow deviceId-only enrollment (not recommended for production), set ENROLLMENT_MODE=open"}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            } else {
                return@post call.respondText("""{"error":"token gerekli — management API'den token oluşturun"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            val result = certService.generateClientCertificate(clientId)
            clientCertStore?.add(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString(),
                deviceAlias = deviceAlias, deviceUid = deviceUid)

            // mTLS mock server'ları ve Config API'leri yeniden başlat (yeni truststore ile)
            mockServerManager?.restartMtlsServers(certService)
            onClientCertEnrolled?.invoke()

            val p12Hash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(result.p12Bytes)
                .let { java.util.Base64.getEncoder().encodeToString(it) }
            call.response.header("X-P12-SHA256", p12Hash)
            call.respondBytes(result.p12Bytes, ContentType.Application.OctetStream)
        }
    }

    // Host client cert download — Android PinVault syncHostClientCerts() bunu çağırır
    //
    // Güvenlik: Host-specific client cert'ler sadece mTLS Config API üzerinden sunulmalıdır.
    // TLS Config API'den erişim reddedilir — önce default enrollment yapıp mTLS API kullanın.
    if (hostClientCertStore != null) {
        get("/api/v1/client-certs/{hostname}/download") {
            if (configApiMode == "tls") {
                return@get call.respondText(
                    """{"error":"Host client certs are only available via mTLS Config API. Enroll first to get a default client cert, then use the mTLS endpoint to download host-specific certs."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }
            val hostname = call.parameters["hostname"] ?: ""
            val p12 = hostClientCertStore.getP12(hostname, configApiId)
                ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            call.respondBytes(p12, ContentType.Application.OctetStream)
        }
    }

    route("/api/v1/certificate-config") {

        get {
            val config = store.load(configApiId)

            // ── Pin scoping (V2): filter config.pins to the intersection of
            // requested hosts and the device's ACL.
            //
            // Legacy behavior preserved when both `hosts` and `X-Device-Id`
            // are absent OR when no ACL store is wired — returns full config.
            val requested = call.request.queryParameters["hosts"]
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
            val deviceId = call.request.header("X-Device-Id")
                ?: extractCertCn(call)

            val filtered = if (deviceHostAclStore != null && (requested != null || deviceId != null)) {
                val decision = deviceHostAclStore.resolve(configApiId, deviceId ?: "anonymous", requested)
                if (decision.hasUnauthorized) {
                    aclLog.warn("Unauthorized host request: configApi={} deviceId={} denied={}",
                        configApiId, deviceId ?: "anonymous", decision.denied)
                }
                if (requested != null) {
                    // Explicit ?hosts= filter — keep only pins in `granted`.
                    config.copy(pins = config.pins.filter { it.hostname in decision.granted })
                } else {
                    // No explicit request, but deviceId known — filter to ACL.
                    config.copy(pins = config.pins.filter { it.hostname in decision.granted })
                }
            } else {
                config
            }

            val signed = call.request.queryParameters["signed"] != "false"
            if (signed) {
                // Stamp issuedAt/expiresAt right before signing so the
                // freshness window is anchored to the server's wall clock at
                // response time. The client rejects payloads where
                // expiresAt <= now, so this TTL bounds how long a captured
                // signed config remains replayable.
                val now = System.currentTimeMillis()
                val stamped = filtered.copy(
                    issuedAt = now,
                    expiresAt = now + CONFIG_TTL_MS
                )
                val payload = configJson.encodeToString(stamped)
                val signature = signingService.sign(payload)
                call.respond(SignedConfig(payload = payload, signature = signature))
            } else {
                call.respond(filtered)
            }
        }

        put {
            val incoming = call.receive<PinConfig>()
            val current = store.load(configApiId)

            // Aynı hostname birden fazla kez eklenemez
            val duplicates = incoming.pins.groupBy { it.hostname }.filter { it.value.size > 1 }.keys
            if (duplicates.isNotEmpty()) {
                call.respond(HttpStatusCode.Conflict, mapOf("errors" to duplicates.map { "$it: zaten mevcut" }))
                return@put
            }

            // Per-host versioning: sadece değişen host'ların versiyonunu artır
            val currentPinMap = current.pins.associateBy { it.hostname }
            val updatedPins = incoming.pins.map { newPin ->
                val oldPin = currentPinMap[newPin.hostname]
                when {
                    oldPin == null -> newPin.copy(version = 1) // yeni host
                    oldPin.sha256 != newPin.sha256 -> newPin.copy(version = oldPin.version + 1) // pin değişti
                    else -> newPin.copy(version = oldPin.version) // değişmedi
                }
            }
            val updated = incoming.copy(pins = updatedPins)

            val errors = validatePinConfig(updated)
            if (errors.isNotEmpty()) {
                call.respond(HttpStatusCode.BadRequest, mapOf("errors" to errors))
                return@put
            }

            // Hangi host'lar değişti, eklendi, silindi?
            val oldHostnames = current.pins.map { it.hostname }.toSet()
            val newHostnames = updated.pins.map { it.hostname }.toSet()

            val added = newHostnames - oldHostnames
            val removed = oldHostnames - newHostnames
            val kept = newHostnames.intersect(oldHostnames)

            store.save(configApiId, updated)
            val now = Instant.now().toString()

            added.forEach { hostname ->
                val pin = updated.pins.first { it.hostname == hostname }
                historyStore.add(configApiId, PinConfigHistoryEntry(
                    hostname = hostname, version = pin.version, timestamp = now,
                    event = "host_added", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
                ))
            }

            removed.forEach { hostname ->
                val oldPin = currentPinMap[hostname]
                historyStore.add(configApiId, PinConfigHistoryEntry(
                    hostname = hostname, version = oldPin?.version ?: 0, timestamp = now,
                    event = "host_removed", pinPrefix = ""
                ))
            }

            kept.forEach { hostname ->
                val oldPin = current.pins.first { it.hostname == hostname }
                val newPin = updated.pins.first { it.hostname == hostname }
                if (oldPin.sha256 != newPin.sha256) {
                    historyStore.add(configApiId, PinConfigHistoryEntry(
                        hostname = hostname, version = newPin.version, timestamp = now,
                        event = "pins_updated", pinPrefix = newPin.sha256.firstOrNull()?.take(12) ?: ""
                    ))
                }
            }

            call.respond(HttpStatusCode.OK, updated)
        }

        // Host bazlı geçmiş
        get("history/{hostname}") {
            val hostname = call.parameters["hostname"] ?: ""
            call.respond(historyStore.getByHostname(hostname))
        }

        // Per-host force update
        post("force-update/{hostname}") {
            val hostname = call.parameters["hostname"] ?: ""
            val current = store.load(configApiId)
            val updated = current.copy(
                pins = current.pins.map { if (it.hostname == hostname) it.copy(forceUpdate = true) else it }
            )
            store.save(configApiId, updated)
            val pin = updated.pins.find { it.hostname == hostname }
            if (pin != null) {
                historyStore.add(configApiId, PinConfigHistoryEntry(
                    hostname = hostname, version = pin.version, timestamp = Instant.now().toString(),
                    event = "force_update", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
                ))
            }
            call.respond(HttpStatusCode.OK, updated)
        }

        post("clear-force/{hostname}") {
            val hostname = call.parameters["hostname"] ?: ""
            val current = store.load(configApiId)
            val updated = current.copy(
                pins = current.pins.map { if (it.hostname == hostname) it.copy(forceUpdate = false) else it }
            )
            store.save(configApiId, updated)
            call.respond(HttpStatusCode.OK, updated)
        }

        // Global force (backward compat)
        post("force-update") {
            val current = store.load(configApiId)
            val updated = current.copy(
                pins = current.pins.map { it.copy(forceUpdate = true) }
            )
            store.save(configApiId, updated)
            current.pins.forEach { pin ->
                historyStore.add(configApiId, PinConfigHistoryEntry(
                    hostname = pin.hostname, version = pin.version, timestamp = Instant.now().toString(),
                    event = "force_update", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
                ))
            }
            call.respond(HttpStatusCode.OK, updated)
        }

        post("clear-force") {
            val current = store.load(configApiId)
            val updated = current.copy(
                forceUpdate = false,
                pins = current.pins.map { it.copy(forceUpdate = false) }
            )
            store.save(configApiId, updated)
            call.respond(HttpStatusCode.OK, updated)
        }
    }

    get("/api/v1/signing-key") {
        call.respond(mapOf("publicKey" to signingService.publicKeyBase64))
    }

    get("/api/v1/connection-history") {
        call.respond(connectionStore.getAll())
    }

    post("/api/v1/connection-history/web") {
        val body = call.receive<JsonObject>()
        connectionStore.addWebCheck(
            hostname = body["hostname"]?.jsonPrimitive?.content ?: "",
            timestamp = Instant.now().toString(),
            status = body["status"]?.jsonPrimitive?.content ?: "unknown",
            responseTimeMs = body["responseTimeMs"]?.jsonPrimitive?.longOrNull ?: 0,
            errorMessage = body["errorMessage"]?.jsonPrimitive?.content
        )
        call.respond(mapOf("saved" to true))
    }

    post("/api/v1/connection-history/client-report") {
        val body = call.receive<JsonObject>()
        val hostname = body["hostname"]?.jsonPrimitive?.content ?: ""
        val status = body["status"]?.jsonPrimitive?.content ?: "unknown"
        val manufacturer = body["deviceManufacturer"]?.jsonPrimitive?.content
        val model = body["deviceModel"]?.jsonPrimitive?.content
        val pinVersion = body["pinVersion"]?.jsonPrimitive?.intOrNull ?: 0
        val timestamp = body["timestamp"]?.jsonPrimitive?.content ?: Instant.now().toString()

        // M-04: this endpoint is public, so an attacker can post arbitrary
        // values that the admin web UI later renders. Hostname / model /
        // manufacturer must look like hostnames / identifiers, not HTML.
        // We reject the report rather than silently sanitizing so logs flag
        // the abuse instead of swallowing it.
        if (hostname.isNotBlank() && !CLIENT_REPORT_IDENT_REGEX.matches(hostname)) {
            return@post call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "Invalid hostname format"))
        }
        if (manufacturer != null && !CLIENT_REPORT_IDENT_REGEX.matches(manufacturer)) {
            return@post call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "Invalid deviceManufacturer format"))
        }
        if (model != null && !CLIENT_REPORT_IDENT_REGEX.matches(model)) {
            return@post call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "Invalid deviceModel format"))
        }

        connectionStore.addClientReport(
            hostname = hostname,
            timestamp = timestamp,
            status = status,
            responseTimeMs = body["responseTimeMs"]?.jsonPrimitive?.longOrNull ?: 0,
            serverCertPin = body["serverCertPin"]?.jsonPrimitive?.content,
            storedPin = body["storedPin"]?.jsonPrimitive?.content,
            pinMatched = body["pinMatched"]?.jsonPrimitive?.booleanOrNull,
            pinVersion = pinVersion,
            deviceManufacturer = manufacturer,
            deviceModel = model,
            errorMessage = body["errorMessage"]?.jsonPrimitive?.content
        )

        // client_devices tablosunu güncelle
        if (hostname.isNotBlank() && manufacturer != null && model != null) {
            val deviceId = "${manufacturer}_${model}".lowercase().replace(" ", "_")
            clientDeviceStore.upsert(hostname, deviceId, manufacturer, model, pinVersion, status, timestamp)
        }

        call.respond(mapOf("saved" to true))
    }

    post("/api/v1/connection-history/config-update-report") {
        val body = call.receive<JsonObject>()
        val status = body["status"]?.jsonPrimitive?.content ?: "unknown"
        val manufacturer = body["deviceManufacturer"]?.jsonPrimitive?.content
        val model = body["deviceModel"]?.jsonPrimitive?.content
        val pinVersion = body["pinVersion"]?.jsonPrimitive?.intOrNull
        val failureReason = body["failureReason"]?.jsonPrimitive?.content
        val timestamp = body["timestamp"]?.jsonPrimitive?.content ?: Instant.now().toString()

        // Same M-04 hardening as /client-report: device identifiers must look
        // like identifiers, not HTML — the admin UI renders them later.
        if (manufacturer != null && !CLIENT_REPORT_IDENT_REGEX.matches(manufacturer)) {
            return@post call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "Invalid deviceManufacturer format"))
        }
        if (model != null && !CLIENT_REPORT_IDENT_REGEX.matches(model)) {
            return@post call.respond(HttpStatusCode.BadRequest,
                mapOf("error" to "Invalid deviceModel format"))
        }

        connectionStore.addConfigUpdateReport(
            timestamp = timestamp,
            status = status,
            pinVersion = pinVersion,
            deviceManufacturer = manufacturer,
            deviceModel = model,
            failureReason = failureReason
        )

        call.respond(mapOf("saved" to true))
    }

    get("/api/v1/connection-history/{hostname}") {
        val hostname = call.parameters["hostname"] ?: ""
        call.respond(connectionStore.getByHostname(hostname))
    }

    get("/api/v1/hosts/{hostname}/clients") {
        val hostname = call.parameters["hostname"] ?: ""
        call.respond(clientDeviceStore.getByHostname(hostname))
    }
}

private fun validatePinConfig(config: PinConfig): List<String> {
    val errors = mutableListOf<String>()

    config.pins.forEach { pin ->
        if (pin.hostname.isBlank()) {
            errors.add("Hostname bos olamaz")
        }

        if (pin.sha256.size < 2) {
            errors.add("${pin.hostname}: en az 2 pin olmali (primary + backup), mevcut: ${pin.sha256.size}")
        }

        pin.sha256.forEachIndexed { index, hash ->
            if (hash.isBlank()) {
                errors.add("${pin.hostname}[$index]: hash bos olamaz")
                return@forEachIndexed
            }
            if (hash.length != 44) {
                errors.add("${pin.hostname}[$index]: gecersiz uzunluk ${hash.length} (beklenen: 44)")
                return@forEachIndexed
            }
            try {
                val decoded = Base64.getDecoder().decode(hash)
                if (decoded.size != 32) {
                    errors.add("${pin.hostname}[$index]: decode edilince ${decoded.size} byte (beklenen: 32)")
                }
            } catch (e: IllegalArgumentException) {
                errors.add("${pin.hostname}[$index]: gecersiz Base64 formati")
            }
        }
    }

    return errors
}

/**
 * Extract CN from the mTLS client cert's SubjectDN, if one is present on the
 * call. Used for deriving deviceId when X-Device-Id header is not sent.
 */
private fun extractCertCn(call: io.ktor.server.application.ApplicationCall): String? {
    val principal = try {
        val attrKey = io.ktor.util.AttributeKey<javax.security.auth.x500.X500Principal>("TLSPeerPrincipal")
        call.attributes.getOrNull(attrKey)
    } catch (_: Exception) { null } ?: return null
    return Regex("CN=([^,]+)").find(principal.name)?.groupValues?.getOrNull(1)?.trim()
}
