package com.example.pinvault.server.route

import com.example.pinvault.server.model.*
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.HostClientCertStore
import com.example.pinvault.server.store.HostRecord
import com.example.pinvault.server.store.HostStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.time.Instant

fun Route.hostRoutes(
    configApiId: String,
    pinConfigStore: PinConfigStore,
    hostStore: HostStore,
    historyStore: PinConfigHistoryStore,
    certService: CertificateService,
    mockServerManager: MockServerManager,
    hostClientCertStore: HostClientCertStore? = null
) {

    route("/api/v1/hosts") {

        post("generate-cert") {
            val body = call.receive<Map<String, String>>()
            val hostname = body["hostname"]?.trim()
                ?: return@post call.respondText("{\"error\":\"hostname gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

            val config = pinConfigStore.load(configApiId)
            if (config.pins.any { it.hostname == hostname }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: $hostname\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            val id = hostname.replace(".", "_")
            val result = certService.generateCertificate(id, hostname)

            hostStore.save(HostRecord(hostname, configApiId, result.keystorePath, result.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(hostname, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            pinConfigStore.save(configApiId, updated)

            historyStore.add(configApiId, PinConfigHistoryEntry(hostname, newPin.version, Instant.now().toString(), "cert_generated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, newPin.version))
        }

        post("fetch-from-url") {
            val body = call.receive<Map<String, String>>()
            val url = body["url"]?.trim()
                ?: return@post call.respondText("{\"error\":\"url gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

            val result = try {
                certService.fetchFromUrl(url)
            } catch (e: Exception) {
                return@post call.respondText("{\"error\":\"Baglanti hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            val config = pinConfigStore.load(configApiId)
            if (config.pins.any { it.hostname == result.hostname }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: ${result.hostname}\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            hostStore.save(HostRecord(result.hostname, configApiId, null, result.certInfo.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(result.hostname, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            pinConfigStore.save(configApiId, updated)

            historyStore.add(configApiId, PinConfigHistoryEntry(result.hostname, newPin.version, Instant.now().toString(), "fetched_from_url", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(result.hostname, result.sha256Pins, result.certInfo.validUntil, newPin.version))
        }

        post("upload-cert") {
            val multipart = call.receiveMultipart()
            var fileBytes: ByteArray? = null
            var password = "changeit"
            var format = "jks"
            var hostname: String? = null

            multipart.forEachPart { part ->
                when (part) {
                    is PartData.FileItem -> fileBytes = part.streamProvider().readBytes()
                    is PartData.FormItem -> when (part.name) {
                        "password" -> password = part.value
                        "format" -> format = part.value
                        "hostname" -> hostname = part.value.trim()
                    }
                    else -> {}
                }
                part.dispose()
            }

            val bytes = fileBytes ?: return@post call.respondText("{\"error\":\"Dosya gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
            val host = hostname ?: return@post call.respondText("{\"error\":\"hostname gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

            val config = pinConfigStore.load(configApiId)
            if (config.pins.any { it.hostname == host }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: $host\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            val id = host.replace(".", "_")
            val result = try {
                certService.importCertificate(id, bytes, password, format)
            } catch (e: Exception) {
                return@post call.respondText("{\"error\":\"Import hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            hostStore.save(HostRecord(host, configApiId, result.keystorePath, result.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(host, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            pinConfigStore.save(configApiId, updated)

            historyStore.add(configApiId, PinConfigHistoryEntry(host, newPin.version, Instant.now().toString(), "cert_uploaded", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(host, result.sha256Pins, result.validUntil, newPin.version))
        }

        route("{hostname}") {

            get("cert-info") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@get call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val keystorePath = hostRecord.keystorePath
                    ?: return@get call.respondText("{\"error\":\"Keystore yok\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val config = pinConfigStore.load(configApiId)
                val pins = config.pins.find { it.hostname == hostname }?.sha256 ?: emptyList()
                val info = certService.readCertInfo(keystorePath, pins)

                call.respond(CertInfoResponse(
                    info.subject, info.issuer, info.serialNumber,
                    info.validFrom, info.validUntil, info.signatureAlgorithm,
                    info.publicKeyAlgorithm, info.publicKeyBits,
                    info.subjectAltNames, info.sha256Fingerprint,
                    info.primaryPin, info.backupPin
                ))
            }

            post("regenerate-cert") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val id = hostname.replace(".", "_")
                val result = certService.generateCertificate(id, hostname)

                hostStore.save(hostRecord.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil))

                val config = pinConfigStore.load(configApiId)
                val oldPin = config.pins.find { it.hostname == hostname }
                val newVersion = (oldPin?.version ?: 0) + 1
                val updated = config.copy(
                    pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, result.sha256Pins, newVersion) else it }
                )
                pinConfigStore.save(configApiId, updated)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_regenerated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                if (mockServerManager.isRunning(hostname)) {
                    val port = mockServerManager.getPort(hostname) ?: 8443
                    mockServerManager.start(hostname, port, result.keystorePath)
                }

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, newVersion))
            }

            post("upload-cert") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val multipart = call.receiveMultipart()
                var fileBytes: ByteArray? = null
                var password = "changeit"
                var format = "jks"

                multipart.forEachPart { part ->
                    when (part) {
                        is PartData.FileItem -> fileBytes = part.streamProvider().readBytes()
                        is PartData.FormItem -> when (part.name) {
                            "password" -> password = part.value
                            "format" -> format = part.value
                        }
                        else -> {}
                    }
                    part.dispose()
                }

                val bytes = fileBytes ?: return@post call.respondText("{\"error\":\"Dosya gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val id = hostname.replace(".", "_")
                val result = try {
                    certService.importCertificate(id, bytes, password, format)
                } catch (e: Exception) {
                    return@post call.respondText("{\"error\":\"Import hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                hostStore.save(hostRecord.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil))

                val config = pinConfigStore.load(configApiId)
                val oldPin = config.pins.find { it.hostname == hostname }
                val newVersion = (oldPin?.version ?: 0) + 1
                val updated = config.copy(
                    pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, result.sha256Pins, newVersion) else it }
                )
                pinConfigStore.save(configApiId, updated)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_uploaded", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                if (mockServerManager.isRunning(hostname)) {
                    val port = mockServerManager.getPort(hostname) ?: 8443
                    mockServerManager.start(hostname, port, result.keystorePath)
                }

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, newVersion))
            }

            post("fetch-cert-url") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val body = call.receive<Map<String, String>>()
                val url = body["url"]?.trim()
                    ?: return@post call.respondText("{\"error\":\"url gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val fetchResult = try {
                    certService.fetchFromUrl(url)
                } catch (e: Exception) {
                    return@post call.respondText("{\"error\":\"Baglanti hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                hostStore.save(hostRecord.copy(certValidUntil = fetchResult.certInfo.validUntil))

                val config = pinConfigStore.load(configApiId)
                val oldPin = config.pins.find { it.hostname == hostname }
                val newVersion = (oldPin?.version ?: 0) + 1
                val updated = config.copy(
                    pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, fetchResult.sha256Pins, newVersion) else it }
                )
                pinConfigStore.save(configApiId, updated)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_fetched", fetchResult.sha256Pins.firstOrNull()?.take(12) ?: ""))

                call.respond(HostActionResponse(hostname, fetchResult.sha256Pins, fetchResult.certInfo.validUntil, newVersion))
            }

            // mTLS toggle — host'u mTLS olarak işaretle/kaldır
            post("toggle-mtls") {
                val hostname = call.parameters["hostname"] ?: ""
                val body = call.receive<kotlinx.serialization.json.JsonObject>()
                val mtls = body["mtls"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Boolean>(), it) } ?: false

                val config = pinConfigStore.load(configApiId)
                val pin = config.pins.find { it.hostname == hostname }
                    ?: return@post call.respondText("""{"error":"Host bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname) it.copy(mtls = mtls)
                        else it
                    }
                )
                pinConfigStore.save(configApiId, updated)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, pin.version, Instant.now().toString(), if (mtls) "mtls_enabled" else "mtls_disabled"))

                call.respond(mapOf("hostname" to hostname, "mtls" to mtls))
            }

            // Upload host-specific client cert (P12)
            post("upload-client-cert") {
                if (hostClientCertStore == null) {
                    return@post call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                hostStore.get(hostname, configApiId)
                    ?: return@post call.respondText("""{"error":"Host bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                val multipart = call.receiveMultipart()
                var fileBytes: ByteArray? = null
                var password = "changeit"

                multipart.forEachPart { part ->
                    when (part) {
                        is PartData.FileItem -> fileBytes = part.streamProvider().readBytes()
                        is PartData.FormItem -> when (part.name) {
                            "password" -> password = part.value
                        }
                        else -> {}
                    }
                    part.dispose()
                }

                val bytes = fileBytes ?: return@post call.respondText("""{"error":"Dosya gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                // P12 olarak yükle/doğrula
                val ks = try {
                    java.security.KeyStore.getInstance("PKCS12").also { it.load(bytes.inputStream(), password.toCharArray()) }
                } catch (e: Exception) {
                    return@post call.respondText("""{"error":"Gecersiz P12: ${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                val alias = ks.aliases().toList().firstOrNull()
                val cert = alias?.let { ks.getCertificate(it) as? java.security.cert.X509Certificate }
                val cn = cert?.subjectX500Principal?.name?.substringAfter("CN=")?.substringBefore(",")
                val fingerprint = cert?.let {
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(it.publicKey.encoded)
                    java.util.Base64.getEncoder().encodeToString(digest)
                }

                // Version bump
                val config = pinConfigStore.load(configApiId)
                val pin = config.pins.find { it.hostname == hostname }
                val newCertVersion = (pin?.clientCertVersion ?: 0) + 1

                hostClientCertStore.save(hostname, configApiId, bytes, newCertVersion, cn, fingerprint)

                // Pin config'e clientCertVersion ve mtls ekle
                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname) it.copy(mtls = true, clientCertVersion = newCertVersion)
                        else it
                    }
                )
                pinConfigStore.save(configApiId, updated)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, pin?.version ?: 1, Instant.now().toString(), "client_cert_uploaded", fingerprint?.take(12) ?: ""))

                call.respond(mapOf("hostname" to hostname, "clientCertVersion" to newCertVersion, "commonName" to cn, "fingerprint" to fingerprint))
            }

            // Download host-specific client cert (P12) — Android calls this
            get("client-cert/download") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                val p12 = hostClientCertStore.getP12(hostname, configApiId)
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                call.respondBytes(p12, ContentType.Application.OctetStream)
            }

            // Get host client cert info
            get("client-cert/info") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                val record = hostClientCertStore.get(hostname, configApiId)
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                call.respond(record)
            }

            post("start-mock") {
                val hostname = call.parameters["hostname"] ?: ""
                val body = call.receive<kotlinx.serialization.json.JsonObject>()
                val port = body["port"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Int>(), it) } ?: 8443
                val mtls = body["mtls"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Boolean>(), it) } ?: false

                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val keystorePath = hostRecord.keystorePath
                    ?: return@post call.respondText("{\"error\":\"Keystore yok\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val trustStoreFile = if (mtls) certService.getTrustStoreFile() else null
                val trustStorePath = if (mtls && trustStoreFile?.exists() == true) trustStoreFile.absolutePath else null
                if (mtls && trustStorePath == null) {
                    return@post call.respondText("{\"error\":\"mTLS icin client cert gerekli — once client cert uretin\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                try {
                    mockServerManager.start(hostname, port, keystorePath, trustStorePath)
                    hostStore.updateMockPort(hostname, configApiId, port)
                    call.respond(MockServerResponse(hostname, port, true))
                } catch (e: Exception) {
                    call.respondText("{\"error\":\"Mock server baslatılamadı: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }
            }

            post("stop-mock") {
                val hostname = call.parameters["hostname"] ?: ""
                mockServerManager.stopAll(hostname)
                hostStore.updateMockPort(hostname, configApiId, null)
                call.respond(MockServerResponse(hostname, null, false))
            }

            get("status") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, configApiId)
                    ?: return@get call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val tlsPort = mockServerManager.getTlsPort(hostname)
                val mtlsPort = mockServerManager.getMtlsPort(hostname)
                call.respond(HostStatusResponse(
                    hostname = hostname,
                    keystorePath = hostRecord.keystorePath,
                    certValidUntil = hostRecord.certValidUntil,
                    mockServerRunning = mockServerManager.isRunning(hostname),
                    mockServerPort = tlsPort ?: mtlsPort,
                    mockServerMode = mockServerManager.getMode(hostname) ?: "tls",
                    mockTlsPort = tlsPort,
                    mockMtlsPort = mtlsPort,
                    createdAt = hostRecord.createdAt
                ))
            }
        }
    }
}
