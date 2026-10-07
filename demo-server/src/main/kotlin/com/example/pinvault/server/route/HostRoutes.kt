package com.example.pinvault.server.route

import com.example.pinvault.server.model.*
import com.example.pinvault.server.plugin.DEFAULT_ADMIN_BODY_MAX_BYTES
import com.example.pinvault.server.plugin.MissingApprovedPlan
import com.example.pinvault.server.plugin.approvedCertPlan
import com.example.pinvault.server.plugin.receiveLimitedBytes
import com.example.pinvault.server.plugin.receiveMultipartForm
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertPlan
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.EgressFilter
import com.example.pinvault.server.service.EgressRefusedException
import com.example.pinvault.server.service.HostPatternRules
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.PlanRefused
import com.example.pinvault.server.service.NoSecondCertificateException
import com.example.pinvault.server.service.P12Transfer
import io.ktor.server.application.*
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
    hostClientCertStore: HostClientCertStore? = null,
    /** Checks the pins a certificate change publishes against what the host serves now; null = off. */
    liveGate: LiveCertificateGate? = null,
    /** Where gate decisions and downloads of key material are recorded; null = nowhere. */
    audit: AuditLog? = null,
    /** Turns a certificate request into the plan that is applied (and, with approvals, shown first). */
    planner: CertChangePlanner = CertChangePlanner(certService, pinConfigStore, hostStore),
    /** The largest keystore or JSON body these routes read (`ADMIN_UPLOAD_MAX_BYTES`). */
    maxUploadBytes: Long = DEFAULT_ADMIN_BODY_MAX_BYTES,
    /** Where `ping-remote` may connect (`FETCH_ALLOW_PRIVATE_TARGETS`). */
    egress: EgressFilter = EgressFilter.fromEnv()
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

    /**
     * Gives the existing host [hostname] the certificate of [plan] in every
     * Config API that pins it (see [propagateHostPins]). The live gate runs
     * before anything is written, once: the pins are the same in every scope.
     */
    suspend fun ApplicationCall.changeHostCertificate(primaryScope: String, hostname: String, plan: CertPlan, reason: String) {
        // The planner checked them; a stored plan replayed after an upgrade is
        // checked again: every scope that pins the host gets exactly these pins,
        // and an entry the library would refuse takes its whole config down.
        com.example.pinvault.server.service.PinConfigRules.hostErrors(hostname, plan.pins).takeIf { it.isNotEmpty() }?.let { errors ->
            return respond(HttpStatusCode.BadRequest, mapOf("errors" to errors))
        }
        val gateScope = (listOf(primaryScope) + hostStore.listConfigApisFor(hostname))
            .firstOrNull { scope -> pinConfigStore.load(scope).pins.any { it.hostname == hostname } }
        if (gateScope != null) {
            val config = pinConfigStore.load(gateScope)
            val updated = config.copy(pins = config.pins.map { if (it.hostname == hostname) it.copy(sha256 = plan.pins) else it })
            if (!passesLiveGate(gateScope, config, updated, liveGate, audit)) return
        }

        // A fetched certificate has no keystore: the host keeps serving its own.
        val installed = plan.keystore?.let { certService.install(planner.keystoreId(hostname), plan) }
        val primaryNewVersion = propagateHostPins(hostname, primaryScope, plan.pins, reason) {
            it.copy(keystorePath = installed?.keystorePath ?: it.keystorePath, certValidUntil = plan.notAfter)
        }

        if (installed != null && mockServerManager.isRunning(hostname)) {
            val port = mockServerManager.getPort(hostname) ?: 8443
            mockServerManager.start(hostname, port, installed.keystorePath)
        }

        respond(HostActionResponse(hostname, plan.pins, plan.notAfter, primaryNewVersion))
    }

    route("/api/v1/hosts") {

        post("generate-cert") {
            val scope = call.scopedApiId()
            val plan = call.certPlan(planner, CertChangePlanner.Kind.ADD_GENERATED, scope, null, maxUploadBytes) ?: return@post
            call.addPlannedHost(scope, plan, "cert_generated", pinConfigStore, hostStore, historyStore, certService, planner, liveGate, audit)
        }

        // The host name is the URL's: a `hostname` field in the body is not read.
        post("fetch-from-url") {
            val scope = call.scopedApiId()
            val plan = call.certPlan(planner, CertChangePlanner.Kind.ADD_FETCHED, scope, null, maxUploadBytes) ?: return@post
            call.addPlannedHost(scope, plan, "fetched_from_url", pinConfigStore, hostStore, historyStore, certService, planner, liveGate, audit)
        }

        post("upload-cert") {
            val scope = call.scopedApiId()
            val plan = call.certPlan(planner, CertChangePlanner.Kind.ADD_UPLOADED, scope, null, maxUploadBytes) ?: return@post
            call.addPlannedHost(scope, plan, "cert_uploaded", pinConfigStore, hostStore, historyStore, certService, planner, liveGate, audit)
        }

        route("{hostname}") {

            get("cert-info") {
                val hostname = call.pathParameters["hostname"] ?: ""
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

            // Mock host cert'i global — bu hostu pinleyen TÜM Config API
            // scope'ları yeni pin'leri almalı (propagateHostPins).
            post("regenerate-cert") {
                val hostname = call.pathParameters["hostname"] ?: ""
                val scope = call.scopedApiId()
                val plan = call.certPlan(planner, CertChangePlanner.Kind.REGENERATE, scope, hostname, maxUploadBytes) ?: return@post
                call.changeHostCertificate(scope, hostname, plan, "cert_regenerated")
            }

            // Yedek anahtara geçiş: sertifika saklı yedek anahtarla yeniden
            // üretilir ve yeni bir yedek hazırlanır. Cihazlar yedeğin pin'ini
            // zaten tuttuğu için bağlantı hiç kesilmez; yayımlanan yeni liste
            // {eski yedek, yeni yedek} olur ve eski asıl anahtar listeden düşer.
            post("rotate-to-backup") {
                val hostname = call.pathParameters["hostname"] ?: ""
                val scope = call.scopedApiId()
                val plan = call.certPlan(planner, CertChangePlanner.Kind.ROTATE, scope, hostname, maxUploadBytes) ?: return@post
                call.changeHostCertificate(scope, hostname, plan, "cert_rotated_to_backup")
            }

            // Mock host cert global — bu hostu pinleyen tüm scope'lar yeni
            // pin'leri alır (aksi halde o scope'un client'ları pin mismatch alir).
            post("upload-cert") {
                val hostname = call.pathParameters["hostname"] ?: ""
                val scope = call.scopedApiId()
                val plan = call.certPlan(planner, CertChangePlanner.Kind.UPLOAD, scope, hostname, maxUploadBytes) ?: return@post
                call.changeHostCertificate(scope, hostname, plan, "cert_uploaded")
            }

            // Remote host cert global (tek public cert) — pinleyen tum scope'lari guncelle.
            post("fetch-cert-url") {
                val hostname = call.pathParameters["hostname"] ?: ""
                val scope = call.scopedApiId()
                val plan = call.certPlan(planner, CertChangePlanner.Kind.FETCH, scope, hostname, maxUploadBytes) ?: return@post
                call.changeHostCertificate(scope, hostname, plan, "cert_fetched")
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
                val hostname = call.pathParameters["hostname"] ?: ""
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

                val hostname = call.pathParameters["hostname"] ?: ""
                hostStore.get(hostname, call.scopedApiId())
                    ?: return@post call.respondText("""{"error":"Host bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                // One bounded read, one parser (the approver's description reads the same bytes).
                val form = call.receiveMultipartForm(maxUploadBytes) ?: return@post
                val password = form.fields["password"] ?: "changeit"

                val bytes = form.file ?: return@post call.respondText("""{"error":"Dosya gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

                // P12 olarak yükle/doğrula — exactly one private key: the entry the
                // approver was shown is the one devices get (see hostClientKeyEntry).
                val cert = try {
                    certService.hostClientKeyEntry(bytes, password).second
                } catch (e: IllegalArgumentException) {
                    return@post call.respondText(buildJsonObject { put("error", e.message ?: "Gecersiz P12") }.toString(), ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
                val cn = cert.subjectX500Principal?.name?.substringAfter("CN=")?.substringBefore(",")
                val fingerprint = cert.let {
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(it.publicKey.encoded)
                    java.util.Base64.getEncoder().encodeToString(digest)
                }

                // Version bump
                val config = pinConfigStore.load(call.scopedApiId())
                val pin = config.pins.find { it.hostname == hostname }
                val newCertVersion = (pin?.clientCertVersion ?: 0) + 1

                // Kept under the server's own password; each download is re-wrapped
                // for its recipient (P12Transfer), so no app needs the upload password.
                // Only that entry is kept: nothing else in the file reaches a device.
                val stored = certService.rewrapP12(bytes, password, CertificateService.KEYSTORE_PASSWORD, keyEntryOnly = true)
                hostClientCertStore.save(hostname, call.scopedApiId(), stored, newCertVersion, cn, fingerprint)

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

                call.respondText(buildJsonObject {
                    put("hostname", hostname); put("clientCertVersion", newCertVersion); put("version", savedVersion)
                    put("commonName", cn ?: ""); put("fingerprint", fingerprint)
                }.toString(), ContentType.Application.Json)
            }

            // Download host-specific client cert (P12) — Android calls this
            get("client-cert/download") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.pathParameters["hostname"] ?: ""
                val p12 = hostClientCertStore.getP12(hostname, call.scopedApiId())
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                // A private key leaves the server: who took it, and for which host.
                audit?.record("private_key_downloaded", "Client certificate (with its private key) of host $hostname downloaded by an administrator",
                    call.scopedApiId(), hostname)
                P12Transfer.respondStored(call, certService, p12)
            }

            // Get host client cert info
            get("client-cert/info") {
                if (hostClientCertStore == null) {
                    return@get call.respondText("""{"error":"Host client cert store not available"}""", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }

                val hostname = call.pathParameters["hostname"] ?: ""
                val record = hostClientCertStore.get(hostname, call.scopedApiId())
                    ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)

                call.respond(record)
            }

            post("start-mock") {
                val hostname = call.pathParameters["hostname"] ?: ""
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
                    hostStore.updateMockPort(hostname, call.scopedApiId(), port, mtls = trustStorePath != null)
                    call.respond(MockServerResponse(hostname, port, true))
                } catch (e: Exception) {
                    call.respondText("{\"error\":\"Mock server baslatılamadı: ${e.message}\"}", ContentType.Application.Json, HttpStatusCode.InternalServerError)
                }
            }

            post("stop-mock") {
                val hostname = call.pathParameters["hostname"] ?: ""
                mockServerManager.stopAll(hostname)
                hostStore.updateMockPort(hostname, call.scopedApiId(), null)
                call.respond(MockServerResponse(hostname, null, false))
            }

            get("status") {
                val hostname = call.pathParameters["hostname"] ?: ""
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
                val hostname = call.pathParameters["hostname"] ?: ""
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
                val hostname = call.pathParameters["hostname"] ?: ""
                // The value is handed to external processes (`nc`, `openssl`) as an
                // argument, so it must be a plain hostname / IPv4 literal: no shell
                // metacharacters, no path separators, no leading '-' (option injection).
                if (!PROBE_HOSTNAME_REGEX.matches(hostname) || HostPatternRules.error(hostname) != null) {
                    return@get call.respondText(
                        """{"reachable":false,"pinMatch":false,"error":"Invalid hostname"}""",
                        ContentType.Application.Json, HttpStatusCode.BadRequest
                    )
                }
                // A GET that connects somewhere: a page in the admin's browser could
                // aim an <img> at it (with no admin key the API answers this
                // machine's browser). The dashboard marks its requests; a cross-site
                // request can neither add the header nor hide Sec-Fetch-Site.
                pingRemoteRefusal(call)?.let { (status, error) ->
                    return@get call.respondText("""{"reachable":false,"pinMatch":false,"error":"$error"}""", ContentType.Application.Json, status)
                }
                val scopePins = pinConfigStore.load(call.scopedApiId()).pins
                // Only a host this server knows — pinned in the scope (also as
                // `host:port`) or registered — is probed, on the ports it may serve:
                // the common TLS ports, its mock listeners, the ports of its pin
                // entries. The probe used to take any name and any ?port=, a port
                // scanner aimed from inside the server's network.
                val pinnedPorts = scopePins.filter { it.hostname.substringBeforeLast(':').equals(hostname, ignoreCase = true) && ':' in it.hostname }
                    .mapNotNull { it.hostname.substringAfterLast(':').toIntOrNull() }
                val known = scopePins.any { it.hostname.substringBeforeLast(':').equals(hostname, ignoreCase = true) } ||
                    hostStore.getAnyByHostname(hostname) != null
                if (!known) {
                    return@get call.respondText("""{"reachable":false,"pinMatch":false,"error":"Unknown host: only hosts pinned or registered here are probed"}""",
                        ContentType.Application.Json, HttpStatusCode.NotFound)
                }
                val mockPorts = listOfNotNull(mockServerManager.getTlsPort(hostname), mockServerManager.getMtlsPort(hostname))
                val allowedPorts = (mockPorts + pinnedPorts + PROBE_DEFAULT_PORTS).distinct()
                val explicitRaw = call.request.queryParameters["port"]
                val explicit = explicitRaw?.toIntOrNull()
                if (explicitRaw != null && (explicit == null || explicit !in allowedPorts)) {
                    return@get call.respondText(
                        buildJsonObject { put("reachable", false); put("pinMatch", false); put("error", "Port not allowed: " + allowedPorts.joinToString(",") + " (the host's pinned and mock ports and the common TLS ports)") }.toString(),
                        ContentType.Application.Json, HttpStatusCode.BadRequest
                    )
                }
                val portsToTry = (listOfNotNull(explicit) + allowedPorts).distinct()
                // Resolved once and checked like a certificate fetch (no metadata or
                // link-local address; private ones with FETCH_ALLOW_PRIVATE_TARGETS);
                // nc and openssl get the checked address, never the name again.
                val address = try {
                    egress.resolveChecked(hostname)
                } catch (e: EgressRefusedException) {
                    return@get call.respondText(
                        buildJsonObject { put("reachable", false); put("pinMatch", false); put("error", e.message ?: "target not allowed") }.toString(),
                        ContentType.Application.Json, HttpStatusCode.BadRequest
                    )
                }
                val connectHost = address.hostAddress.let { if (':' in it) "[$it]" else it }
                val sniName = hostname.takeIf { name -> name.any { it.isLetter() } }

                val expectedPins = scopePins
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
                            "nc", "-z", "-w", "2", address.hostAddress, port.toString(),
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
                            *(listOf("openssl", "s_client", "-connect", "$connectHost:$port") +
                                (sniName?.let { listOf("-servername", it) } ?: emptyList())).toTypedArray(),
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
 * The plan this call applies: the one its approver was shown (a replayed,
 * approved change — nothing is fetched or generated again), or one made now
 * from the request. Null after an answer was sent (a refusal).
 */
internal suspend fun ApplicationCall.certPlan(
    planner: CertChangePlanner, kind: CertChangePlanner.Kind, scope: String, hostname: String?,
    maxUploadBytes: Long = DEFAULT_ADMIN_BODY_MAX_BYTES
): CertPlan? = try {
    planner.check(kind, scope, hostname)
    val approved = approvedCertPlan()
    if (approved != null) {
        // The stored plan belongs to this very request (the replay token is bound to its path).
        if (kind.adds) planner.checkNew(scope, approved.hostname)
        if (kind.host && !kind.adds && approved.hostname != hostname) throw MissingApprovedPlan(-1)
        approved
    } else {
        receiveLimitedBytes(maxUploadBytes)?.let { body ->
            // Planning may fetch a certificate or generate keys: off the event loop.
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                planner.plan(kind, scope, hostname, request.header(HttpHeaders.ContentType), body)
            }
        }
    }
} catch (e: PlanRefused) {
    respondText(e.body.toString(), ContentType.Application.Json, e.status)
    null
} catch (e: MissingApprovedPlan) {
    respond(HttpStatusCode.Conflict, mapOf("error" to (e.message ?: "no stored plan")))
    null
}

/**
 * Adds the host of [plan] to [scope] with the plan's pins: the live gate
 * first, then the keystore (if the plan carries one), the host record, the
 * pins and the history.
 */
internal suspend fun ApplicationCall.addPlannedHost(
    scope: String, plan: CertPlan, event: String,
    pinConfigStore: PinConfigStore, hostStore: HostStore, historyStore: PinConfigHistoryStore,
    certService: CertificateService, planner: CertChangePlanner,
    liveGate: LiveCertificateGate?, audit: AuditLog?
) {
    val host = plan.hostname
    val config = pinConfigStore.load(scope)
    val updated = config.copy(pins = config.pins + HostPin(host, plan.pins, version = 1))
    if (!passesLiveGate(scope, config, updated, liveGate, audit)) return

    val keystorePath = plan.keystore?.let { certService.install(planner.keystoreId(host), plan).keystorePath }
    hostStore.save(HostRecord(host, scope, keystorePath, plan.notAfter, null, Instant.now().toString()))
    val savedPin = pinConfigStore.save(scope, updated).pins.first { it.hostname == host }
    pinConfigStore.ensureConfigExists(scope)
    historyStore.add(scope, PinConfigHistoryEntry(host, savedPin.version, Instant.now().toString(), event, plan.pins.firstOrNull()?.take(12) ?: ""))

    respond(HostActionResponse(host, plan.pins, plan.notAfter, savedPin.version))
}

/**
 * Shape accepted by `ping-remote` for the `{hostname}` path segment: a plain
 * hostname or IPv4 literal. Anything else (shell metacharacters, `/`, a
 * leading `-`) is rejected before the value reaches a subprocess argv.
 */
internal val PROBE_HOSTNAME_REGEX = Regex("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")

/** Ports `ping-remote` tries for any known host: the common TLS ports (explicit ones must be among these or the host's own). */
internal val PROBE_DEFAULT_PORTS = listOf(443, 9443, 8443, 9444, 8444)

/**
 * Why `ping-remote` refuses [call] as a possible cross-site request, or null.
 * It is a GET that opens connections, so the browser-guard rule for writes
 * applies: no `Sec-Fetch-Site: cross-site|same-site`, and a header a page on
 * another site cannot add (`X-PinVault-Admin`, which the dashboard sends, or
 * `X-API-Key`).
 */
internal fun pingRemoteRefusal(call: ApplicationCall): Pair<HttpStatusCode, String>? {
    when (call.request.header("Sec-Fetch-Site")?.trim()?.lowercase()) {
        "cross-site", "same-site" -> return HttpStatusCode.Forbidden to "cross_site_request"
    }
    if (call.request.header("X-PinVault-Admin") == null && call.request.header("X-API-Key") == null) {
        return HttpStatusCode.Forbidden to "admin_header_required"
    }
    return null
}

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

/**
 * 422 for a site that served its certificate alone: there is no issuer whose
 * pin could be the backup (see [NoSecondCertificateException]).
 */
internal suspend fun ApplicationCall.respondNoSecondCertificate(e: NoSecondCertificateException) =
    respond(HttpStatusCode.UnprocessableEntity, mapOf("reason" to "no_second_certificate", "error" to (e.message ?: "")))
