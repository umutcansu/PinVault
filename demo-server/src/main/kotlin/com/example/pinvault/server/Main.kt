package com.example.pinvault.server

import com.example.pinvault.server.model.HostActionResponse
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.store.HostRecord
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigApiManager
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.ClientDeviceStore
import com.example.pinvault.server.store.EnrollmentTokenStore
import com.example.pinvault.server.store.ConnectionHistoryStore
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.HostStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.http.content.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore

fun main() {
    val dbPath = System.getenv("DB_PATH") ?: "pinvault.db"
    val db = DatabaseManager(dbPath)
    val pinConfigStore = PinConfigStore(db)
    val historyStore = PinConfigHistoryStore(db)
    val connectionStore = ConnectionHistoryStore(db)
    val clientDeviceStore = ClientDeviceStore(db)
    val hostStore = HostStore(db)
    val signingKeyFile = File("signing-key.pem")
    var signingService = ConfigSigningService(signingKeyFile)
    val certService = CertificateService(File("certs"))
    val mockServerManager = MockServerManager()
    val httpPort = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val httpsPort = System.getenv("HTTPS_PORT")?.toIntOrNull() ?: (httpPort + 1)

    // Demo server sertifikası üret (yoksa)
    val serverCertId = "demo-server"
    val serverKeystorePath = File("certs/$serverCertId.jks")
    val serverCertResult = if (!serverKeystorePath.exists()) {
        println("Generating demo server TLS certificate...")
        certService.generateCertificate(serverCertId, "localhost")
    } else null

    // Server TLS pin'lerini oku/kaydet
    val serverPinsFile = File("certs/$serverCertId.pins")
    var serverTlsPins: List<String> = if (serverCertResult != null) {
        // İlk üretim — pin'leri dosyaya kaydet
        serverPinsFile.writeText(serverCertResult.sha256Pins.joinToString("\n"))
        serverCertResult.sha256Pins
    } else if (serverPinsFile.exists()) {
        serverPinsFile.readLines().filter { it.isNotBlank() }
    } else {
        // Pin dosyası yok — keystore'dan primary oku
        val ks = KeyStore.getInstance("JKS")
        FileInputStream(serverKeystorePath).use { ks.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
        val cert = ks.getCertificate("server")
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
        listOf(java.util.Base64.getEncoder().encodeToString(digest))
    }

    // Config API manager (dinamik TLS/mTLS sunucuları)
    val configApiManager = ConfigApiManager()
    val clientCertStore = ClientCertStore(db)
    val hostClientCertStore = com.example.pinvault.server.store.HostClientCertStore(db)
    val enrollmentTokenStore = EnrollmentTokenStore(db)

    // Shutdown hook
    Runtime.getRuntime().addShutdownHook(Thread {
        mockServerManager.stopAll()
        configApiManager.stopAll()
    })

    // Config API routing modülü — her API kendi configApiId'siyle scoped
    fun configApiModuleFor(configApiId: String): Application.() -> Unit = {
        routing {
            certificateConfigRoutes(configApiId, pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, certService, enrollmentTokenStore, clientCertStore, mockServerManager, hostClientCertStore)
            hostRoutes(configApiId, pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore)
            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }
        }
    }

    // Varsayılan TLS config API başlat
    pinConfigStore.ensureConfigExists("default-tls")
    configApiManager.start(
        id = "default-tls",
        port = httpsPort,
        mode = "tls",
        keystorePath = serverKeystorePath.absolutePath,
        configModule = configApiModuleFor("default-tls")
    )

    // HTTP management server
    embeddedServer(Netty, port = httpPort) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                encodeDefaults = true
                ignoreUnknownKeys = true
            })
        }
        install(CallLogging)
        install(StatusPages) {
            exception<Throwable> { call, cause ->
                call.respond(
                    HttpStatusCode.InternalServerError,
                    mapOf("error" to (cause.message ?: "Internal server error"))
                )
            }
        }

        routing {
            // Management server: tüm config API'lerin verilerine erişim
            // configApiId query param ile scoped: ?configApiId=default-tls
            certificateConfigRoutes("default-tls", pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, hostClientCertStore = hostClientCertStore)
            hostRoutes("default-tls", pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore)

            // Tüm API'lerin config'lerini döner (Web UI sidebar için)
            get("/api/v1/all-configs") {
                val allConfigs = pinConfigStore.loadAll()
                val apis = configApiManager.getAll()
                val stoppedApis = configApiManager.getAllStopped()

                fun buildApiJson(api: com.example.pinvault.server.service.ConfigApiManager.ConfigApiInstance, running: Boolean): String {
                    val config = allConfigs[api.id]
                    val pinsJson = config?.pins?.joinToString(",") { pin ->
                        val hashesJson = pin.sha256.joinToString(",") { "\"$it\"" }
                        """{"hostname":"${pin.hostname}","sha256":[$hashesJson],"version":${pin.version},"forceUpdate":${pin.forceUpdate}}"""
                    } ?: ""
                    return """{"id":"${api.id}","port":${api.port},"mode":"${api.mode}","pins":[$pinsJson],"version":${config?.computedVersion() ?: 0},"running":$running}"""
                }

                val result = apis.map { buildApiJson(it, true) } + stoppedApis.map { buildApiJson(it, false) }
                call.respondText("[${result.joinToString(",")}]", ContentType.Application.Json)
            }

            // Config API bazlı config fetch (Web UI için)
            get("/api/v1/config/{configApiId}") {
                val configApiId = call.parameters["configApiId"] ?: "default-tls"
                val config = pinConfigStore.load(configApiId)
                val encoder = Json { encodeDefaults = true }
                call.respondText(encoder.encodeToString(com.example.pinvault.server.model.PinConfig.serializer(), config), ContentType.Application.Json)
            }

            // configApiId bazlı config güncelleme (Web UI'dan)
            post("/api/v1/config/{configApiId}/update") {
                val configApiId = call.parameters["configApiId"] ?: "default-tls"
                val incoming = call.receive<com.example.pinvault.server.model.PinConfig>()
                pinConfigStore.save(configApiId, incoming)
                call.respond(incoming)
            }

            // configApiId bazlı host yönetimi (Web UI'dan)
            post("/api/v1/management/hosts/{configApiId}/generate-cert") {
                val configApiId = call.parameters["configApiId"] ?: "default-tls"
                val body = call.receive<Map<String, String>>()
                val hostname = body["hostname"]?.trim()
                    ?: return@post call.respondText("""{"error":"hostname gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val config = pinConfigStore.load(configApiId)
                if (config.pins.any { it.hostname == hostname }) {
                    return@post call.respondText("""{"error":"Bu hostname zaten mevcut: $hostname"}""", ContentType.Application.Json, HttpStatusCode.Conflict)
                }

                val id = hostname.replace(".", "_")
                val result = certService.generateCertificate(id, hostname)
                hostStore.save(HostRecord(hostname, configApiId, result.keystorePath, result.validUntil, null, java.time.Instant.now().toString()))

                val newPin = HostPin(hostname, result.sha256Pins, version = 1)
                val updated = config.copy(pins = config.pins + newPin)
                pinConfigStore.save(configApiId, updated)
                pinConfigStore.ensureConfigExists(configApiId)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, newPin.version, java.time.Instant.now().toString(), "cert_generated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, newPin.version))
            }

            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }

            get("/api/v1/server-tls-pins") {
                val primary = serverTlsPins.getOrNull(0) ?: ""
                val backup = serverTlsPins.getOrNull(1) ?: ""
                call.respondText(
                    """{"primaryPin":"$primary","backupPin":"$backup","httpsPort":$httpsPort,"hostname":"localhost"}""",
                    ContentType.Application.Json
                )
            }

            post("/api/v1/signing-key/regenerate") {
                signingKeyFile.delete()
                signingService = ConfigSigningService(signingKeyFile)
                call.respondText(
                    """{"publicKey":"${signingService.publicKeyBase64}","regenerated":true}""",
                    ContentType.Application.Json
                )
            }

            post("/api/v1/server-tls-pins/regenerate") {
                serverKeystorePath.delete()
                serverPinsFile.delete()
                val newCert = certService.generateCertificate(serverCertId, "localhost")
                serverPinsFile.writeText(newCert.sha256Pins.joinToString("\n"))
                serverTlsPins = newCert.sha256Pins
                val primary = newCert.sha256Pins.getOrNull(0) ?: ""
                val backup = newCert.sha256Pins.getOrNull(1) ?: ""
                call.respondText(
                    """{"primaryPin":"$primary","backupPin":"$backup","regenerated":true,"restartRequired":true}""",
                    ContentType.Application.Json
                )
            }

            post("/api/v1/server-tls-pins/upload") {
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

                val bytes = fileBytes
                    ?: return@post call.respondText("""{"error":"Dosya gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                try {
                    val result = certService.importCertificate(serverCertId, bytes, password, format)
                    serverPinsFile.writeText(result.sha256Pins.joinToString("\n"))
                    serverTlsPins = result.sha256Pins
                    val primary = result.sha256Pins.getOrNull(0) ?: ""
                    val backup = result.sha256Pins.getOrNull(1) ?: ""
                    call.respondText(
                        """{"primaryPin":"$primary","backupPin":"$backup","uploaded":true,"restartRequired":true}""",
                        ContentType.Application.Json
                    )
                } catch (e: Exception) {
                    call.respondText("""{"error":"Import hatası: ${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
            }

            post("/api/v1/server-tls-pins/fetch-from-url") {
                val body = call.receiveText()
                val url = try {
                    kotlinx.serialization.json.Json.parseToJsonElement(body)
                        .jsonObject["url"]?.jsonPrimitive?.content
                } catch (_: Exception) { null }
                    ?: return@post call.respondText("""{"error":"url gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                try {
                    val result = certService.fetchFromUrl(url)
                    // Fetch sadece pin'leri alır, keystore oluşturmaz — pin'leri kaydet
                    val pins = result.sha256Pins
                    serverPinsFile.writeText(pins.joinToString("\n"))
                    serverTlsPins = pins
                    val primary = pins.getOrNull(0) ?: ""
                    val backup = pins.getOrNull(1) ?: ""
                    call.respondText(
                        """{"primaryPin":"$primary","backupPin":"$backup","hostname":"${result.hostname}","fetched":true}""",
                        ContentType.Application.Json
                    )
                } catch (e: Exception) {
                    call.respondText("""{"error":"Bağlantı hatası: ${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
            }

            // ── Config API Management ────────────────────────

            get("/api/v1/config-apis") {
                val apis = configApiManager.getAll().map { api ->
                    """{"id":"${api.id}","port":${api.port},"mode":"${api.mode}","running":true}"""
                }
                call.respondText("[${apis.joinToString(",")}]", ContentType.Application.Json)
            }

            post("/api/v1/config-apis/start") {
                val body = call.receiveText()
                val json = Json.parseToJsonElement(body).jsonObject
                val id = json["id"]?.jsonPrimitive?.content ?: "api-${System.currentTimeMillis()}"
                val port = json["port"]?.jsonPrimitive?.intOrNull ?: return@post call.respondText("""{"error":"port gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                val mode = json["mode"]?.jsonPrimitive?.content ?: "tls"

                val trustPath = if (mode == "mtls") certService.getTrustStoreFile().absolutePath.takeIf { certService.getTrustStoreFile().exists() } else null

                if (mode == "mtls" && trustPath == null) {
                    return@post call.respondText("""{"error":"mTLS için önce client sertifika oluşturun"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                try {
                    pinConfigStore.ensureConfigExists(id)
                    val instance = configApiManager.start(id, port, mode, serverKeystorePath.absolutePath, trustPath, configApiModuleFor(id))
                    call.respondText(
                        """{"id":"${instance.id}","port":${instance.port},"mode":"${instance.mode}","running":true}""",
                        ContentType.Application.Json
                    )
                } catch (e: Exception) {
                    call.respondText("""{"error":"${e.message}"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }
            }

            post("/api/v1/config-apis/stop") {
                val body = call.receiveText()
                val id = Json.parseToJsonElement(body).jsonObject["id"]?.jsonPrimitive?.content
                    ?: return@post call.respondText("""{"error":"id gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                configApiManager.stop(id)
                call.respondText("""{"id":"$id","stopped":true}""", ContentType.Application.Json)
            }

            post("/api/v1/config-apis/delete") {
                val body = call.receiveText()
                val id = Json.parseToJsonElement(body).jsonObject["id"]?.jsonPrimitive?.content
                    ?: return@post call.respondText("""{"error":"id gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                // Sunucuyu durdur ve stopped listesinden de kaldır
                configApiManager.stop(id)
                configApiManager.removeStopped(id)

                // DB'den temizle: pin_config, pin_hashes, hosts, pin_history
                db.connection().use { conn ->
                    conn.autoCommit = false
                    try {
                        conn.prepareStatement("DELETE FROM pin_config WHERE config_api_id = ?").use { it.setString(1, id); it.executeUpdate() }
                        conn.prepareStatement("DELETE FROM pin_hashes WHERE config_api_id = ?").use { it.setString(1, id); it.executeUpdate() }
                        conn.prepareStatement("DELETE FROM hosts WHERE config_api_id = ?").use { it.setString(1, id); it.executeUpdate() }
                        conn.prepareStatement("DELETE FROM pin_history WHERE config_api_id = ?").use { it.setString(1, id); it.executeUpdate() }
                        conn.commit()
                    } catch (e: Exception) {
                        conn.rollback()
                        throw e
                    }
                }

                call.respondText("""{"id":"$id","deleted":true}""", ContentType.Application.Json)
            }

            // ── mTLS Client Cert Management ──────────────────

            get("/api/v1/mtls-status") {
                val certs = clientCertStore.getAll()
                val apis = configApiManager.getAll()
                val mtlsApis = apis.filter { it.mode == "mtls" }
                call.respondText(
                    """{"mtlsApiCount":${mtlsApis.size},"tlsApiCount":${apis.size - mtlsApis.size},"clientCerts":${certs.size},"activeCerts":${certs.count { !it.revoked }}}""",
                    ContentType.Application.Json
                )
            }

            get("/api/v1/client-certs") {
                call.respond(clientCertStore.getAll())
            }

            post("/api/v1/client-certs/generate") {
                val body = call.receiveText()
                val clientId = try {
                    Json.parseToJsonElement(body).jsonObject["clientId"]?.jsonPrimitive?.content
                } catch (_: Exception) { null }
                    ?: "client-${System.currentTimeMillis()}"

                val result = certService.generateClientCertificate(clientId)
                clientCertStore.add(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString())

                call.response.header("Content-Disposition", "attachment; filename=\"$clientId.p12\"")
                call.respondBytes(result.p12Bytes, io.ktor.http.ContentType.Application.OctetStream)
            }

            post("/api/v1/client-certs/upload") {
                val multipart = call.receiveMultipart()
                var fileBytes: ByteArray? = null
                var clientId: String? = null

                multipart.forEachPart { part ->
                    when (part) {
                        is PartData.FileItem -> fileBytes = part.streamProvider().readBytes()
                        is PartData.FormItem -> if (part.name == "clientId") clientId = part.value
                        else -> {}
                    }
                    part.dispose()
                }

                val bytes = fileBytes
                    ?: return@post call.respondText("""{"error":"Dosya gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                val id = clientId ?: "uploaded-${System.currentTimeMillis()}"

                try {
                    val fingerprint = certService.importClientCertificate(id, bytes)
                    clientCertStore.add(id, "Uploaded: $id", fingerprint, java.time.Instant.now().toString())
                    call.respondText("""{"id":"$id","fingerprint":"$fingerprint","uploaded":true}""", ContentType.Application.Json)
                } catch (e: Exception) {
                    call.respondText("""{"error":"Import hatası: ${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
            }

            delete("/api/v1/client-certs/{id}") {
                val id = call.parameters["id"] ?: ""
                clientCertStore.revoke(id)
                certService.removeFromTrustStore(id)
                call.respondText("""{"id":"$id","revoked":true}""", ContentType.Application.Json)
            }

            // ── Enrollment Token Management ─────────────────

            post("/api/v1/enrollment-tokens/generate") {
                val body = call.receiveText()
                val clientId = try {
                    Json.parseToJsonElement(body).jsonObject["clientId"]?.jsonPrimitive?.content
                } catch (_: Exception) { null }
                    ?: "device-${System.currentTimeMillis()}"

                val token = enrollmentTokenStore.create(clientId)
                call.respondText(
                    """{"token":"$token","clientId":"$clientId"}""",
                    ContentType.Application.Json
                )
            }

            get("/api/v1/enrollment-tokens") {
                call.respond(enrollmentTokenStore.getAll())
            }

            post("/api/v1/client-certs/enroll") {
                val body = call.receiveText()
                val token = try {
                    Json.parseToJsonElement(body).jsonObject["token"]?.jsonPrimitive?.content
                } catch (_: Exception) { null }
                    ?: return@post call.respondText("""{"error":"token gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val clientId = enrollmentTokenStore.validate(token)
                    ?: return@post call.respondText("""{"error":"Geçersiz veya kullanılmış token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)

                val result = certService.generateClientCertificate(clientId)
                clientCertStore.add(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString())
                enrollmentTokenStore.markUsed(token)

                call.response.header("Content-Disposition", "attachment; filename=\"$clientId.p12\"")
                call.respondBytes(result.p12Bytes, io.ktor.http.ContentType.Application.OctetStream)
            }

            // Web UI
            get("/") {
                val html = Thread.currentThread().contextClassLoader
                    ?.getResourceAsStream("static/index.html")
                    ?.readBytes()?.toString(Charsets.UTF_8)
                    ?: "<h1>index.html not found</h1>"
                call.respondText(html, ContentType.Text.Html)
            }
            staticResources("/static", "static")
        }
    }.also {
        println("=".repeat(60))
        println("PinVault Demo Server")
        println("=".repeat(60))
        println("HTTP:         http://localhost:$httpPort")
        println("Config API:   https://localhost:$httpsPort (TLS)")
        println("Web UI:       http://localhost:$httpPort")
        println("Database:     $dbPath")
        println("=".repeat(60))
        println("Pin Config Endpoints:")
        println("  GET  /api/v1/certificate-config")
        println("  PUT  /api/v1/certificate-config")
        println("  POST /api/v1/certificate-config/force-update")
        println("  GET  /api/v1/certificate-config/history/{hostname}")
        println("  GET  /api/v1/signing-key")
        println("")
        println("Host Management Endpoints:")
        println("  POST /api/v1/hosts/generate-cert")
        println("  POST /api/v1/hosts/fetch-from-url")
        println("  POST /api/v1/hosts/upload-cert")
        println("  GET  /api/v1/hosts/{hostname}/cert-info")
        println("  GET  /api/v1/hosts/{hostname}/status")
        println("  POST /api/v1/hosts/{hostname}/regenerate-cert")
        println("  POST /api/v1/hosts/{hostname}/start-mock")
        println("  POST /api/v1/hosts/{hostname}/stop-mock")
        println("")
        println("Connection History:")
        println("  GET  /api/v1/connection-history")
        println("  POST /api/v1/connection-history/web")
        println("  POST /api/v1/connection-history/client-report")
        println("=".repeat(60))
        println("ECDSA Public Key: ${signingService.publicKeyBase64}")
        if (serverCertResult != null) {
            println("Server TLS Pins: ${serverCertResult.sha256Pins}")
        }
        println("=".repeat(60))
    }.start(wait = true)
}
