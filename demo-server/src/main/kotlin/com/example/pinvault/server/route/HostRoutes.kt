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
            pinConfigStore.save(call.scopedApiId(), updated)

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, newPin.version, Instant.now().toString(), "cert_generated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

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

            val config = pinConfigStore.load(call.scopedApiId())
            if (config.pins.any { it.hostname == result.hostname }) {
                return@post call.respondText("{\"error\":\"Bu hostname zaten mevcut: ${result.hostname}\"}", ContentType.Application.Json, HttpStatusCode.Conflict)
            }

            hostStore.save(HostRecord(result.hostname, call.scopedApiId(), null, result.certInfo.validUntil, null, Instant.now().toString()))

            val newPin = HostPin(result.hostname, result.sha256Pins, version = 1)
            val updated = config.copy(pins = config.pins + newPin)
            pinConfigStore.save(call.scopedApiId(), updated)

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(result.hostname, newPin.version, Instant.now().toString(), "fetched_from_url", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

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
            pinConfigStore.save(call.scopedApiId(), updated)

            historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(host, newPin.version, Instant.now().toString(), "cert_uploaded", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

            call.respond(HostActionResponse(host, result.sha256Pins, result.validUntil, newPin.version))
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

                // Mock host cert'i global — bu hostu barındıran TÜM Config API
                // scope'larının pin_hashes'ı güncellenmeli. Aksi halde güncellenmeyen
                // scope'un client'ları pin mismatch alır.
                val affectedScopes = hostStore.listConfigApisFor(hostname)
                var primaryNewVersion = 0
                for (scope in affectedScopes) {
                    val record = hostStore.get(hostname, scope) ?: continue
                    hostStore.save(record.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil))

                    val config = pinConfigStore.load(scope)
                    val oldPin = config.pins.find { it.hostname == hostname }
                    val newVersion = (oldPin?.version ?: 0) + 1
                    val updated = config.copy(
                        pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, result.sha256Pins, newVersion) else it }
                    )
                    pinConfigStore.save(scope, updated)
                    historyStore.add(scope, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_regenerated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                    if (scope == primaryScope) primaryNewVersion = newVersion
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

                // Mock host cert global — tüm scope'ların pin_hashes'ını güncelle
                // (aksi halde güncellenmeyen scope'un client'ları pin mismatch alir).
                val primaryScope = call.scopedApiId()
                val affectedScopes = hostStore.listConfigApisFor(hostname)
                var primaryNewVersion = 0
                for (scope in affectedScopes) {
                    val record = hostStore.get(hostname, scope) ?: continue
                    hostStore.save(record.copy(keystorePath = result.keystorePath, certValidUntil = result.validUntil))

                    val config = pinConfigStore.load(scope)
                    val oldPin = config.pins.find { it.hostname == hostname }
                    val newVersion = (oldPin?.version ?: 0) + 1
                    val updated = config.copy(
                        pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, result.sha256Pins, newVersion) else it }
                    )
                    pinConfigStore.save(scope, updated)
                    historyStore.add(scope, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_uploaded", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                    if (scope == primaryScope) primaryNewVersion = newVersion
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

                // Remote host cert global (tek public cert) — tum scope'lari guncelle.
                val primaryScope = call.scopedApiId()
                val affectedScopes = hostStore.listConfigApisFor(hostname)
                var primaryNewVersion = 0
                for (scope in affectedScopes) {
                    val record = hostStore.get(hostname, scope) ?: continue
                    hostStore.save(record.copy(certValidUntil = fetchResult.certInfo.validUntil))

                    val config = pinConfigStore.load(scope)
                    val oldPin = config.pins.find { it.hostname == hostname }
                    val newVersion = (oldPin?.version ?: 0) + 1
                    val updated = config.copy(
                        pins = config.pins.map { if (it.hostname == hostname) HostPin(hostname, fetchResult.sha256Pins, newVersion) else it }
                    )
                    pinConfigStore.save(scope, updated)
                    historyStore.add(scope, PinConfigHistoryEntry(hostname, newVersion, Instant.now().toString(), "cert_fetched", fetchResult.sha256Pins.firstOrNull()?.take(12) ?: ""))

                    if (scope == primaryScope) primaryNewVersion = newVersion
                }

                call.respond(HostActionResponse(hostname, fetchResult.sha256Pins, fetchResult.certInfo.validUntil, primaryNewVersion))
            }

            // mTLS toggle — host'u mTLS olarak işaretle/kaldır
            post("toggle-mtls") {
                val hostname = call.parameters["hostname"] ?: ""
                val body = call.receive<kotlinx.serialization.json.JsonObject>()
                val mtls = body["mtls"]?.let { kotlinx.serialization.json.Json.decodeFromJsonElement(kotlinx.serialization.serializer<Boolean>(), it) } ?: false

                val config = pinConfigStore.load(call.scopedApiId())
                val pin = config.pins.find { it.hostname == hostname }
                    ?: return@post call.respondText("""{"error":"Host bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname) it.copy(mtls = mtls)
                        else it
                    }
                )
                pinConfigStore.save(call.scopedApiId(), updated)

                historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, pin.version, Instant.now().toString(), if (mtls) "mtls_enabled" else "mtls_disabled"))

                call.respondText("""{"hostname":"$hostname","mtls":$mtls}""", ContentType.Application.Json)
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

                // Pin config'e clientCertVersion ve mtls ekle
                val updated = config.copy(
                    pins = config.pins.map {
                        if (it.hostname == hostname) it.copy(mtls = true, clientCertVersion = newCertVersion)
                        else it
                    }
                )
                pinConfigStore.save(call.scopedApiId(), updated)

                historyStore.add(call.scopedApiId(), PinConfigHistoryEntry(hostname, pin?.version ?: 1, Instant.now().toString(), "client_cert_uploaded", fingerprint?.take(12) ?: ""))

                call.respondText("""{"hostname":"$hostname","clientCertVersion":$newCertVersion,"commonName":"${cn ?: ""}","fingerprint":"${fingerprint ?: ""}"}""", ContentType.Application.Json)
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
                // yerine gerçek mock durumunu göstermek için).
                val hostRecord = hostStore.get(hostname, call.scopedApiId())
                    ?: hostStore.getAnyByHostname(hostname)
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
                        // 1. TCP reachable? `nc -z -G 2 -w 2 host port` — -G = connect timeout (BSD nc).
                        //    Hard-timeout the whole call at 3s via runCmd so unreachable hosts
                        //    don't block for minutes if the kernel/firewall silently drops SYN.
                        val (ncExit, ncOut) = runCmd(
                            "nc", "-z", "-G", "2", "-w", "2", hostname, port.toString(),
                            timeoutSec = 3
                        )
                        if (ncExit != 0) {
                            lastError = "TCP unreachable on :$port (${ncOut.trim().take(80)})"
                            continue
                        }

                        // 2. TLS handshake + cert çıkar: `openssl s_client -connect host:port -servername host`
                        val (sslExit, sslOut) = runCmd(
                            "sh", "-c",
                            "echo Q | openssl s_client -connect $hostname:$port -servername $hostname 2>/dev/null " +
                            "| openssl x509 -noout -pubkey 2>/dev/null " +
                            "| openssl pkey -pubin -outform DER 2>/dev/null " +
                            "| openssl dgst -sha256 -binary " +
                            "| openssl base64 -A",
                            timeoutSec = 6
                        )
                        val actualPin = sslOut.trim()
                        if (sslExit != 0 || actualPin.isEmpty() || actualPin.length < 40) {
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
