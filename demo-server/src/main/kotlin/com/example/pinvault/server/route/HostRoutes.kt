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
    defaultConfigApiId: String,
    pinConfigStore: PinConfigStore,
    hostStore: HostStore,
    historyStore: PinConfigHistoryStore,
    certService: CertificateService,
    mockServerManager: MockServerManager,
    hostClientCertStore: HostClientCertStore? = null
) {

    // Management server'da birden fazla Config API'nin host'larını yönetebilmek
    // için ?configApiId=<id> query param ile scope geçilebilir. Config API
    // kendi portuna mount edildiğinde param gönderilmediği için `defaultConfigApiId`
    // kullanılır.
    fun io.ktor.server.application.ApplicationCall.scopedApiId(): String =
        request.queryParameters["configApiId"] ?: defaultConfigApiId

    // A host's certificate is global, so every Config API that PINS the host
    // must get its new pins, or that scope's devices fail with a pin mismatch.
    // That includes a scope that pins the host without a host record of its
    // own (pins written straight to the scope). Only the pins and the version
    // change: the host's mTLS flag, client-cert version and force flag stay.
    // Returns the new version in [primaryScope] (0 when it does not pin the host).
    fun propagateHostPins(
        hostname: String,
        primaryScope: String,
        pins: List<String>,
        reason: String,
        updateRecord: (HostRecord) -> HostRecord
    ): Int {
        var primaryNewVersion = 0
        for (scope in hostStore.listConfigApisFor(hostname)) {
            hostStore.get(hostname, scope)?.let { hostStore.save(updateRecord(it)) }

            val config = pinConfigStore.load(scope)
            if (config.pins.none { it.hostname == hostname }) continue
            val saved = pinConfigStore.save(scope, config.copy(
                pins = config.pins.map { if (it.hostname == hostname) it.copy(sha256 = pins, version = it.version + 1) else it }
            ))
            val newVersion = saved.pins.first { it.hostname == hostname }.version
            historyStore.add(scope, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), reason, pins.firstOrNull()?.take(12) ?: ""))

            if (scope == primaryScope) primaryNewVersion = newVersion
        }
        return primaryNewVersion
    }

    route("/api/v1/hosts") {

        post("generate-cert") {
            val body = call.receive<Map<String, String>>()
            val hostname = body["hostname"]?.trim()
                ?: return@post call.respondText("{\"error\":\"hostname gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

            val config = pinConfigStore.load(call.scopedApiId())
            if (config.pins.any { it.hostname == hostname }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: $hostname\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            val id = hostname.replace(".", "_")
            val result = certService.generateCertificate(id, hostname)

            hostStore.save(HostRecord(hostname, call.scopedApiId(), result.keystorePath, result.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(hostname, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            val savedPin = pinConfigStore.save(call.scopedApiId(), updated).pins.first { it.hostname == newPin.hostname }

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, savedPin.version, Instant.now().toString(), "cert_generated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, savedPin.version))
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

            val config = pinConfigStore.load(call.scopedApiId())
            if (config.pins.any { it.hostname == result.hostname }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: ${result.hostname}\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            hostStore.save(HostRecord(result.hostname, call.scopedApiId(), null, result.certInfo.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(result.hostname, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            val savedPin = pinConfigStore.save(call.scopedApiId(), updated).pins.first { it.hostname == newPin.hostname }

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(result.hostname, savedPin.version, Instant.now().toString(), "fetched_from_url", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(result.hostname, result.sha256Pins, result.certInfo.validUntil, savedPin.version))
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

            val config = pinConfigStore.load(call.scopedApiId())
            if (config.pins.any { it.hostname == host }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: $host\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            val id = host.replace(".", "_")
            val result = try {
                certService.importCertificate(id, bytes, password, format)
            } catch (e: Exception) {
                return@post call.respondText("{\"error\":\"Import hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            hostStore.save(HostRecord(host, call.scopedApiId(), result.keystorePath, result.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(host, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            val savedPin = pinConfigStore.save(call.scopedApiId(), updated).pins.first { it.hostname == newPin.hostname }

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(host, savedPin.version, Instant.now().toString(), "cert_uploaded", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(host, result.sha256Pins, result.validUntil, savedPin.version))
        }

        route("{hostname}") {

            get("cert-info") {
                val hostname = call.parameters["hostname"] ?: ""
                // Keystore fiziksel dosya; scope'a bağlı değil. Fallback ile başka
                // scope'tan da okunabilir (salt okunur cert bilgisi).
                val hostRecord = hostStore.get(hostname, call.scopedApiId())
                    ?: hostStore.getAnyByHostname(hostname)
                    ?: return@get call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val keystorePath = hostRecord.keystorePath
                    ?: return@get call.respondText("{\"error\":\"Keystore yok\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val config = pinConfigStore.load(call.scopedApiId())
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
                val primaryScope = call.scopedApiId()
                hostStore.get(hostname, primaryScope)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val id = hostname.replace(".", "_")
                val result = certService.generateCertificate(id, hostname)

                // Mock host cert'i global — bu hostu pinleyen TÜM Config API
                // scope'ları yeni pin'leri almalı (propagateHostPins).
                val primaryNewVersion = propagateHostPins(hostname, primaryScope, result.sha256Pins, "cert_regenerated") {
                    it.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil)
                }

                if (mockServerManager.isRunning(hostname)) {
                    val port = mockServerManager.getPort(hostname) ?: 8443
                    mockServerManager.start(hostname, port, result.keystorePath)
                }

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, primaryNewVersion))
            }

            // Yedek anahtara geçiş: sertifika saklı yedek anahtarla yeniden
            // üretilir ve yeni bir yedek hazırlanır. Cihazlar yedeğin pin'ini
            // zaten tuttuğu için bağlantı hiç kesilmez; yayımlanan yeni liste
            // {eski yedek, yeni yedek} olur ve eski asıl anahtar listeden düşer.
            post("rotate-to-backup") {
                val hostname = call.parameters["hostname"] ?: ""
                val primaryScope = call.scopedApiId()
                hostStore.get(hostname, primaryScope)
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val id = hostname.replace(".", "_")
                val backupPin = certService.backupPin(id)
                    ?: return@post call.respond(HttpStatusCode.Conflict, mapOf("reason" to "no_backup_key", "error" to
                        "No stored backup key for $hostname: its certificate was uploaded or fetched, or generated before " +
                        "backup keys were kept. Regenerate the certificate to get one."))
                val published = pinConfigStore.load(primaryScope).pins.find { it.hostname == hostname }?.sha256.orEmpty()
                if (backupPin !in published) {
                    return@post call.respond(HttpStatusCode.Conflict, mapOf("reason" to "backup_not_published", "error" to
                        "The stored backup key's pin is not in $hostname's pin list, so devices would reject it. " +
                        "Publish it first, or regenerate the certificate."))
                }

                val result = certService.rotateToBackup(id, hostname)
                val primaryNewVersion = propagateHostPins(hostname, primaryScope, result.sha256Pins, "cert_rotated_to_backup") {
                    it.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil)
                }

                if (mockServerManager.isRunning(hostname)) {
                    val port = mockServerManager.getPort(hostname) ?: 8443
                    mockServerManager.start(hostname, port, result.keystorePath)
                }

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, primaryNewVersion))
            }

            post("upload-cert") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, call.scopedApiId())
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

                // Mock host cert global — bu hostu pinleyen tüm scope'lar yeni
                // pin'leri alır (aksi halde o scope'un client'ları pin mismatch alir).
                val primaryScope = call.scopedApiId()
                val primaryNewVersion = propagateHostPins(hostname, primaryScope, result.sha256Pins, "cert_uploaded") {
                    it.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil)
                }

                if (mockServerManager.isRunning(hostname)) {
                    val port = mockServerManager.getPort(hostname) ?: 8443
                    mockServerManager.start(hostname, port, result.keystorePath)
                }

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, primaryNewVersion))
            }

            post("fetch-cert-url") {
                val hostname = call.parameters["hostname"] ?: ""
                val hostRecord = hostStore.get(hostname, call.scopedApiId())
                    ?: return@post call.respondText("{\"error\":\"Host bulunamadi\"}", ContentType.Application.Json, HttpStatusCode.NotFound)

                val body = call.receive<Map<String, String>>()
                val url = body["url"]?.trim()
                    ?: return@post call.respondText("{\"error\":\"url gerekli\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)

                val fetchResult = try {
                    certService.fetchFromUrl(url)
                } catch (e: Exception) {
                    return@post call.respondText("{\"error\":\"Baglanti hatasi: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }

                // Remote host cert global (tek public cert) — pinleyen tum scope'lari guncelle.
                val primaryScope = call.scopedApiId()
                val primaryNewVersion = propagateHostPins(hostname, primaryScope, fetchResult.sha256Pins, "cert_fetched") {
                    it.copy(certValidUntil = fetchResult.certInfo.validUntil)
                }

                call.respond(HostActionResponse(hostname, fetchResult.sha256Pins, fetchResult.certInfo.validUntil, primaryNewVersion))
            }

            // mTLS toggle — host'u mTLS olarak işaretle/kaldır
            //
            // Bumps the host's pin version. `mtls` is part of the config the
            // device caches, and the client's change detection is version
            // based: without the bump a device that already holds the config
            // gets AlreadyCurrent from SSLCertificateUpdater.updateNow and
            // never learns the host became mTLS — only a device whose data was
            // wiped would see the flag. PinConfigStore.save keeps its
            // watermark semantics (version is taken as given for a host that
            // already exists in the scope), so read the stored value back.
            post("toggle-mtls") {
                val hostname = call.parameters["hostname"] ?: ""
                val body = call.receive<kotlinx.serialization.json.JsonObject>()
                val mtls = body["mtls"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Boolean>(), it) } ?: false

                val config = pinConfigStore.load(call.scopedApiId())
                val pin = config.pins.find { it.hostname == hostname }
                    ?: return@post call.respondText("""{"error":"Host bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname) it.copy(mtls = mtls, version = it.version + 1)
                        else it
                    }
                )
                val savedVersion = pinConfigStore.save(call.scopedApiId(), updated)
                    .pins.first { it.hostname == hostname }.version

                historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, savedVersion, Instant.now().toString(), if (mtls) "mtls_enabled" else "mtls_disabled"))

                call.respondText("""{"hostname":"$hostname","mtls":$mtls,"version":$savedVersion}""", ContentType.Application.Json)
            }

            // Upload host-specific client cert (P12)
            post("upload-client-cert") {
                if (hostClientCertStore == null) {
                    return@post call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                hostStore.get(hostname, call.scopedApiId())
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
                val config = pinConfigStore.load(call.scopedApiId())
                val pin = config.pins.find { it.hostname == hostname }
                val newCertVersion = (pin?.clientCertVersion ?: 0) + 1

                hostClientCertStore.save(hostname, call.scopedApiId(), bytes, newCertVersion, cn, fingerprint)

                // Pin config'e clientCertVersion ve mtls ekle.
                //
                // The host's pin version is bumped alongside clientCertVersion:
                // the client only re-reads a host's entry (and therefore only
                // runs syncHostClientCerts for it) when the config as a whole
                // reports a change. Leaving the pin version untouched made the
                // new certificate invisible to every device that already had
                // the config.
                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname)
                            it.copy(mtls = true, clientCertVersion = newCertVersion, version = it.version + 1)
                        else it
                    }
                )
                val savedVersion = pinConfigStore.save(call.scopedApiId(), updated)
                    .pins.firstOrNull { it.hostname == hostname }?.version ?: ((pin?.version ?: 0) + 1)

                historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, savedVersion, Instant.now().toString(), "client_cert_uploaded", fingerprint?.take(12) ?: ""))

                call.respondText("""{"hostname":"$hostname","clientCertVersion":$newCertVersion,"version":$savedVersion,"commonName":"${cn ?: ""}","fingerprint":"${fingerprint ?: ""}"}""", ContentType.Application.Json)
            }

            // Download host-specific client cert (P12) — Android calls this
            get("client-cert/download") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                val p12 = hostClientCertStore.getP12(hostname, call.scopedApiId())
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                call.respondBytes(p12, ContentType.Application.OctetStream)
            }

            // Get host client cert info
            get("client-cert/info") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.parameters["hostname"] ?: ""
                val record = hostClientCertStore.get(hostname, call.scopedApiId())
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                call.respond(record)
            }

            post("start-mock") {
                val hostname = call.parameters["hostname"] ?: ""
                val body = call.receive<kotlinx.serialization.json.JsonObject>()
                val port = body["port"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Int>(), it) } ?: 8443
                val mtls = body["mtls"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Boolean>(), it) } ?: false

                val hostRecord = hostStore.get(hostname, call.scopedApiId())
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
                    hostStore.updateMockPort(hostname, call.scopedApiId(), port)
                    call.respond(MockServerResponse(hostname, port, true))
                } catch (e: Exception) {
                    call.respondText("{\"error\":\"Mock server baslatılamadı: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }
            }

            post("stop-mock") {
                val hostname = call.parameters["hostname"] ?: ""
                mockServerManager.stopAll(hostname)
                hostStore.updateMockPort(hostname, call.scopedApiId(), null)
                call.respond(MockServerResponse(hostname, null, false))
            }

            get("status") {
                val hostname = call.parameters["hostname"] ?: ""
                // Mock server + keystore hostname başına global; scope'ta kayıt yoksa
                // diğer scope'lardaki kayda fallback et (UI'da "host bulunamadı" toast'ı
                // yerine gerçek mock durumunu göstermek için). Pin listesinde olup
                // hostStore'da hiç kaydı olmayan host'lar (URL'den çekilmiş, elle pin
                // girilmiş) için 404 yerine minimal status döndürüyoruz — UI sidebar
                // her host için /status çağırıyor, 404 sadece konsol gürültüsü.
                val hostRecord = hostStore.get(hostname, call.scopedApiId())
                    ?: hostStore.getAnyByHostname(hostname)

                val tlsPort = mockServerManager.getTlsPort(hostname)
                val mtlsPort = mockServerManager.getMtlsPort(hostname)
                call.respond(HostStatusResponse(
                    hostname = hostname,
                    keystorePath = hostRecord?.keystorePath,
                    certValidUntil = hostRecord?.certValidUntil,
                    mockServerRunning = mockServerManager.isRunning(hostname),
                    mockServerPort = tlsPort ?: mtlsPort,
                    mockServerMode = mockServerManager.getMode(hostname) ?: "tls",
                    mockTlsPort = tlsPort,
                    mockMtlsPort = mtlsPort,
                    createdAt = hostRecord?.createdAt
                ))
            }

            // Web UI'dan mock server'a bağlantı testi
            post("test-connection") {
                val hostname = call.parameters["hostname"] ?: ""
                if (!mockServerManager.isRunning(hostname)) {
                    return@post call.respondText("""{"success":false,"error":"Mock server calismiyorr"}""", ContentType.Application.Json)
                }

                val port = mockServerManager.getTlsPort(hostname) ?: mockServerManager.getMtlsPort(hostname) ?: 8443
                val url = "https://localhost:$port/health"

                try {
                    // Trust-all client ile mock server'a bağlan
                    val trustManager = object : javax.net.ssl.X509TrustManager {
                        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                    }
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())

                    val client = okhttp3.OkHttpClient.Builder()
                        .sslSocketFactory(sslContext.socketFactory, trustManager)
                        .hostnameVerifier { _, _ -> true }
                        .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                        .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                        .build()

                    val start = System.currentTimeMillis()
                    val response = client.newCall(okhttp3.Request.Builder().url(url).build()).execute()
                    val elapsed = System.currentTimeMillis() - start

                    val body = response.body?.string() ?: ""
                    response.close()

                    call.respondText(
                        """{"success":true,"httpCode":${response.code},"responseTimeMs":$elapsed,"body":${body.take(500)}}""",
                        ContentType.Application.Json
                    )
                } catch (e: Exception) {
                    call.respondText(
                        """{"success":false,"error":"${e.message?.replace("\"", "'")}","responseTimeMs":0}""",
                        ContentType.Application.Json
                    )
                }
            }

            // Remote reachability check — harici host'un gerçekten ayakta olup olmadığını
            // ve cert'inin pin config ile eşleşip eşleşmediğini kontrol eder.
            //
            // TCP kontrolü `nc` ile, SPKI pin çıkarma `openssl s_client` + `openssl x509`
            // ile yapılır. JVM raw socket bazı ortamlarda (Little Snitch, VPN vb.)
            // NoRouteToHost throw edebildiği için subprocess yaklaşımı tercih edildi —
            // terminal araçlarının gördüğü ağ durumu API ile aynı olmalı.
            //
            // Query: ?port=9443  (opsiyonel — verilmezse yaygın TLS portları sırayla denenir)
            // Response: { reachable, port, pinMatch, actualPin, expectedPins[], error?, elapsedMs }
            get("ping-remote") {
                val hostname = call.parameters["hostname"] ?: ""
                // The value is handed to external processes (`nc`, `openssl`) as an
                // argument, so it must be a plain hostname / IPv4 literal: no shell
                // metacharacters, no path separators, no leading '-' (option injection).
                if (!PROBE_HOSTNAME_REGEX.matches(hostname)) {
                    return@get call.respondText(
                        """{"reachable":false,"pinMatch":false,"error":"Invalid hostname"}""",
                        ContentType.Application.Json, HttpStatusCode.BadRequest
                    )
                }
                val explicit = call.request.queryParameters["port"]?.toIntOrNull()
                val mockPort = mockServerManager.getTlsPort(hostname)
                    ?: mockServerManager.getMtlsPort(hostname)
                val portsToTry = listOfNotNull(explicit, mockPort, 443, 9443, 8443, 9444, 8444)
                    .distinct()

                val expectedPins = pinConfigStore.load(call.scopedApiId()).pins
                    .find { it.hostname == hostname }?.sha256 ?: emptyList()
                val start = System.currentTimeMillis()

                /**
                 * Runs an external command with a hard timeout. Stream is read asynchronously
                 * so `destroyForcibly()` actually returns even if the child is stuck in a
                 * blocking syscall (e.g. `nc` on a silently dropped SYN — `-w/-G` flags are
                 * unreliable in some macOS environments).
                 */
                fun runCmd(vararg cmd: String, timeoutSec: Long = 5): Pair<Int, String> {
                    val pb = ProcessBuilder(*cmd).redirectErrorStream(true)
                    val proc = pb.start()
                    proc.outputStream.close()
                    val outBuf = StringBuilder()
                    val readerThread = Thread {
                        try {
                            proc.inputStream.bufferedReader().use { r ->
                                r.lineSequence().forEach { outBuf.appendLine(it) }
                            }
                        } catch (_: Exception) {}
                    }.apply { isDaemon = true; start() }

                    val finished = proc.waitFor(timeoutSec, java.util.concurrent.TimeUnit.SECONDS)
                    if (!finished) {
                        proc.destroyForcibly()
                        proc.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)
                        readerThread.join(500)
                        return -1 to "timeout"
                    }
                    readerThread.join(500)
                    return proc.exitValue() to outBuf.toString()
                }

                var lastError: String? = null
                for (port in portsToTry) {
                    try {
                        // 1. TCP reachable? `nc -z -w 2 host port` — -w is the read/operation
                        //    timeout, supported by both BSD nc (macOS) and OpenBSD netcat
                        //    (Linux). The previously-used -G connect-timeout flag is BSD-only
                        //    and breaks inside Linux containers shipping netcat-openbsd.
                        //    Hard-timeout the whole call at 3s via runCmd so unreachable hosts
                        //    don't block for minutes if the kernel/firewall silently drops SYN.
                        val (ncExit, ncOut) = runCmd(
                            "nc", "-z", "-w", "2", hostname, port.toString(),
                            timeoutSec = 3
                        )
                        if (ncExit != 0) {
                            lastError = "TCP unreachable on :$port (${ncOut.trim().take(80)})"
                            continue
                        }

                        // 2. TLS handshake: `openssl s_client` runs from an argv list (no
                        //    shell) and the SPKI pin is computed in-process from the PEM
                        //    leaf it prints. The previous `sh -c "… $hostname …"` pipeline
                        //    let a crafted {hostname} path segment run arbitrary commands
                        //    as the server user. runCmd closes stdin, which makes
                        //    s_client exit right after the handshake (what `echo Q |`
                        //    used to do). Its exit code is ignored on purpose: it is 0
                        //    even when chain verification fails, so "no certificate in
                        //    the output" is the reliable failure signal.
                        val (_, sslOut) = runCmd(
                            "openssl", "s_client", "-connect", "$hostname:$port", "-servername", hostname,
                            timeoutSec = 6
                        )
                        val actualPin = spkiPinFromSClientOutput(sslOut)
                        if (actualPin == null) {
                            lastError = "TLS handshake failed on port $port"
                            continue
                        }

                        val pinMatch = expectedPins.contains(actualPin)
                        val elapsed = System.currentTimeMillis() - start
                        val expectedJson = expectedPins.joinToString(",") { "\"$it\"" }
                        call.respondText(
                            """{"reachable":true,"port":$port,"pinMatch":$pinMatch,"actualPin":"$actualPin","expectedPins":[$expectedJson],"elapsedMs":$elapsed}""",
                            ContentType.Application.Json
                        )
                        return@get
                    } catch (e: Exception) {
                        lastError = "${e.javaClass.simpleName}: ${e.message ?: ""}".take(160)
                    }
                }

                val elapsed = System.currentTimeMillis() - start
                val expectedJson = expectedPins.joinToString(",") { "\"$it\"" }
                val portsJson = portsToTry.joinToString(",")
                val errMsg = (lastError ?: "Hiçbir port erişilebilir değil").replace("\"", "'")
                call.respondText(
                    """{"reachable":false,"pinMatch":false,"triedPorts":[$portsJson],"expectedPins":[$expectedJson],"error":"$errMsg","elapsedMs":$elapsed}""",
                    ContentType.Application.Json
                )
            }
        }
    }
}

/**
 * Shape accepted by `ping-remote` for the `{hostname}` path segment: a plain
 * hostname or IPv4 literal. Anything else (shell metacharacters, `/`, a
 * leading `-`) is rejected before the value reaches a subprocess argv.
 */
internal val PROBE_HOSTNAME_REGEX = Regex("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")

/**
 * Extracts the first certificate PEM block from `openssl s_client` output
 * (the server's leaf) and returns its SPKI SHA-256 pin, Base64-encoded — the
 * same value `HostPin.sha256` carries. Returns null when the output has no
 * parseable certificate (handshake failed, port not TLS, timeout).
 */
internal fun spkiPinFromSClientOutput(output: String): String? {
    val pem = Regex("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
        .find(output)?.value ?: return null
    return try {
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(pem.byteInputStream()) as java.security.cert.X509Certificate
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
        java.util.Base64.getEncoder().encodeToString(digest)
    } catch (e: Exception) {
        null
    }
}
