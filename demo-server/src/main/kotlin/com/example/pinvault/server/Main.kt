package com.example.pinvault.server

import com.example.pinvault.server.model.HostActionResponse
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.signingAdminRoutes
import com.example.pinvault.server.route.governanceRoutes
import com.example.pinvault.server.route.applyPinConfigUpdate
import com.example.pinvault.server.route.respondNoSecondCertificate
import com.example.pinvault.server.plugin.adminName
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
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
import io.ktor.server.plugins.defaultheaders.*
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
    val certsDir = File(System.getenv("CERTS_DIR") ?: "certs")
    val signingKeyFile = File(System.getenv("SIGNING_KEY_PATH") ?: "signing-key.pem")
    // Signers come from CONFIG_SIGNERS (default: the local key file above).
    val signingService = ConfigSigningService.fromEnv(signingKeyFile)
    val signingKeySetService = com.example.pinvault.server.service.SigningKeySetService.fromEnv(
        com.example.pinvault.server.store.SigningKeySetStore(db), signingService
    )
    val signedConfigService = com.example.pinvault.server.service.SignedConfigService(signingService, signingKeySetService)
    // ── Governance: who, what, when — and who else has to agree ─────────
    // Admin identities (API_KEY / ADMIN_KEYS), the hash-chained audit log,
    // webhook notifications, the live certificate gate and two-person
    // approval. Each one is off or inert until its env vars are set.
    val adminRegistry = com.example.pinvault.server.plugin.AdminRegistry.fromEnv()
    val auditStore = com.example.pinvault.server.store.AuditLogStore(db)
    val auditLog = com.example.pinvault.server.service.AuditLog(
        auditStore, com.example.pinvault.server.service.WebhookNotifier.fromEnv()
    )
    val liveGate = com.example.pinvault.server.service.LiveCertificateGate.fromEnv()
    val approvalsRequired = com.example.pinvault.server.service.ApprovalService.requiredFromEnv()
    if (approvalsRequired > 1) {
        val personal = adminRegistry.names.count { it != com.example.pinvault.server.plugin.AdminRegistry.LEGACY_NAME }
        check(!adminRegistry.isEmpty) {
            "PIN_CHANGE_APPROVALS=$approvalsRequired cannot work without admin keys (anonymous admin mode)."
        }
        check(personal >= approvalsRequired - 1) {
            "PIN_CHANGE_APPROVALS=$approvalsRequired needs at least ${approvalsRequired - 1} personal admin key(s) in " +
                "ADMIN_KEYS to approve changes (found $personal). A shared API_KEY cannot approve."
        }
    }

    // Pin writes: pre-sign the new config (signature cache) and record the
    // diff. Every pin-writing route funnels through PinConfigStore.save.
    pinConfigStore.onSaved = { scope, before, after ->
        // After the commit: drop every cached signature FIRST, then pre-sign.
        // A device request that loaded the old pins can then no longer cache
        // an envelope under the same generation as the new ones.
        signedConfigService.invalidate()
        signedConfigService.prewarm(scope) { pinConfigStore.load(scope).let { it.copy(forceUpdate = it.hasAnyForceUpdate()) } }
        auditLog.recordPinChange(scope, before, after)
    }

    // Invalid API keys: the first one is recorded (and notified) at once, the
    // rest of that minute are summed into one entry — visible, but no way to
    // flood the append-only log or the webhook from the device-facing ports.
    val authFailures = com.example.pinvault.server.service.AuthFailureRecorder(auditLog)
    com.example.pinvault.server.plugin.AuthFailures.listener = { remoteAddress, method, path ->
        authFailures.report(remoteAddress, method, path)
    }

    fun stateHash(scope: String): String {
        val config = pinConfigStore.load(scope)
        val canonical = config.pins.sortedBy { it.hostname }.joinToString("\n") { pin ->
            "${pin.hostname}|${pin.version}|${pin.sha256.sorted().joinToString(",")}|${pin.forceUpdate}|${pin.mtls}|${pin.clientCertVersion}"
        } + "\nforce=${config.forceUpdate}"
        return java.security.MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    // What a pending change does, in words an approver can judge.
    fun describeChange(op: String, path: String, query: String, body: ByteArray): com.example.pinvault.server.service.ApprovalService.Description {
        val params = io.ktor.http.parseQueryString(query)
        val scope = params["configApiId"]
            ?: Regex("^/api/v1/config/([^/]+)/update$").find(path)?.groupValues?.get(1)
            ?: Regex("^/api/v1/management/hosts/([^/]+)/generate-cert$").find(path)?.groupValues?.get(1)
            ?: "default-tls"
        val lenient = Json { ignoreUnknownKeys = true }
        fun bodyField(name: String): String? = runCatching {
            Json.parseToJsonElement(body.decodeToString()).jsonObject[name]?.jsonPrimitive?.content
        }.getOrNull()
        val detail = kotlinx.serialization.json.buildJsonObject { put("operation", kotlinx.serialization.json.JsonPrimitive(op)) }
        return when (op) {
            "pins_update" -> {
                val incoming = lenient.decodeFromString(com.example.pinvault.server.model.PinConfig.serializer(), body.decodeToString())
                val current = pinConfigStore.load(scope)
                val byHost = current.pins.associateBy { it.hostname }
                // The same versioning the write applies, so the diff shows real changes only.
                val versioned = incoming.copy(pins = incoming.pins.map { pin ->
                    val old = byHost[pin.hostname]
                    when {
                        old == null -> pin.copy(version = 1)
                        old.sha256 != pin.sha256 -> pin.copy(version = old.version + 1)
                        else -> pin.copy(version = old.version)
                    }
                })
                val diff = com.example.pinvault.server.service.PinDiff.of(current, versioned)
                val live = if (liveGate.enabled) liveGate.check(current, versioned) else null
                com.example.pinvault.server.service.ApprovalService.Description(
                    configApiId = scope,
                    summary = "$scope: " + diff.summary().ifEmpty { "no pin change" },
                    detail = kotlinx.serialization.json.JsonObject(
                        detail + diff.toJson() + (live?.let {
                            mapOf("liveCheck" to Json.encodeToJsonElement(com.example.pinvault.server.service.LiveCertificateGate.Result.serializer(), it))
                        } ?: emptyMap())
                    ),
                    baseHash = stateHash(scope)
                )
            }
            "force_on", "force_off" -> {
                val host = Regex("^/api/v1/certificate-config/(?:force-update|clear-force)/([^/]+)$").find(path)?.groupValues?.get(1)
                val what = if (op == "force_on") "Force update ON" else "Force update OFF"
                com.example.pinvault.server.service.ApprovalService.Description(scope, "$scope: $what for ${host ?: "every host"}", detail)
            }
            "host_add" -> com.example.pinvault.server.service.ApprovalService.Description(
                scope, "$scope: add host ${bodyField("hostname") ?: bodyField("url") ?: "(uploaded certificate)"} (${path.substringAfterLast('/')})", detail
            )
            "host_cert" -> {
                val host = Regex("^/api/v1/hosts/([^/]+)/").find(path)?.groupValues?.get(1) ?: "?"
                com.example.pinvault.server.service.ApprovalService.Description(
                    scope, "$host: ${path.substringAfterLast('/')} (every Config API that pins it)", detail
                )
            }
            "config_api_delete" -> com.example.pinvault.server.service.ApprovalService.Description(
                bodyField("id") ?: "", "Delete Config API ${bodyField("id")} and all of its pins", detail
            )
            "bootstrap_pins" -> com.example.pinvault.server.service.ApprovalService.Description(
                "", "Change the Config API TLS certificate (${path.substringAfterLast('/')}) — apps hold its pins as bootstrap pins", detail
            )
            "config_api_lifecycle" -> com.example.pinvault.server.service.ApprovalService.Description(
                bodyField("id") ?: "",
                "${if (path.endsWith("/start")) "Start" else "Stop"} Config API ${bodyField("id") ?: "?"}" +
                    (bodyField("port")?.let { " on port $it" } ?: "") + " — decides which scope's pins that port serves",
                detail
            )
            "signing_key" -> com.example.pinvault.server.service.ApprovalService.Description(
                "", "Replace the primary config-signing key", detail
            )
            "signing_keyset" -> {
                val payload = bodyField("payload")
                val version = payload?.let { runCatching { Json.parseToJsonElement(it).jsonObject["version"]?.jsonPrimitive?.content }.getOrNull() }
                com.example.pinvault.server.service.ApprovalService.Description("", "Publish signing-key set v${version ?: "?"}", detail)
            }
            else -> com.example.pinvault.server.service.ApprovalService.Description(scope, "$op $path", detail)
        }
    }

    val approvalService = com.example.pinvault.server.service.ApprovalService(
        store = com.example.pinvault.server.store.ChangeRequestStore(db),
        audit = auditLog,
        required = approvalsRequired,
        ttlHours = System.getenv("APPROVAL_TTL_HOURS")?.toLongOrNull()?.coerceAtLeast(1) ?: 24,
        managementPort = System.getenv("PORT")?.toIntOrNull() ?: 8080,
        describe = ::describeChange,
        stateHash = ::stateHash
    )

    // Governance plugins for every listener: the audit context (and cache
    // invalidation on admin writes) and, with approvals on, the approval gate.
    fun Application.installGovernance(management: Boolean) {
        install(com.example.pinvault.server.plugin.AdminAudit) {
            audit = auditLog
            onAdminWrite = { signedConfigService.invalidate() }
        }
        install(com.example.pinvault.server.plugin.ApprovalGate) {
            approvals = approvalService
            managementListener = management
        }
    }
    val certService = CertificateService(certsDir)
    val mockServerManager = MockServerManager()
    val certExpiryMonitor = com.example.pinvault.server.service.CertExpiryMonitor(hostStore)
    val httpPort = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val httpsPort = System.getenv("HTTPS_PORT")?.toIntOrNull() ?: (httpPort + 1)
    val enrollmentMode = System.getenv("ENROLLMENT_MODE")?.lowercase() ?: "token"

    // Demo server sertifikası üret (yoksa)
    val serverCertId = "demo-server"
    val serverKeystorePath = File(certsDir, "$serverCertId.jks")

    // Keystores written under an older password (the old "changeit" default,
    // or KEYSTORE_PASSWORD_PREVIOUS) move to KEYSTORE_PASSWORD before anything
    // opens them.
    run {
        val keystores = buildList {
            add(serverKeystorePath)
            add(File(certsDir, "$serverCertId.backup.jks"))
            add(File(certsDir, "client-truststore.jks"))
            hostStore.getAll().mapNotNull { it.keystorePath }.forEach { path ->
                add(File(path))
                add(File(path.removeSuffix(".jks") + ".backup.jks"))
            }
        }
        val report = com.example.pinvault.server.service.KeystoreRekey(certService)
            .run(keystores, com.example.pinvault.server.store.HostClientCertStore(db))
        if (report.rekeyed.isNotEmpty()) println("KEYSTORE_PASSWORD: re-encrypted ${report.rekeyed.joinToString()}")
        if (report.unreadable.isNotEmpty()) {
            System.err.println("KEYSTORE_PASSWORD: ${report.unreadable.joinToString()} open with neither the current, the previous " +
                "(KEYSTORE_PASSWORD_PREVIOUS) nor the old default password; left as they are")
        }
    }
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
    val vaultFileStore = com.example.pinvault.server.store.VaultFileStore(db)
    // end_to_end files stored before they were kept encrypted on disk.
    vaultFileStore.encryptStoredDeviceFiles().takeIf { it > 0 }?.let { println("Vault: encrypted $it per-device file(s) on disk") }
    val vaultDistStore = com.example.pinvault.server.store.VaultDistributionStore(db)
    val vaultTokenStore = com.example.pinvault.server.store.VaultFileTokenStore(db)
    val devicePublicKeyStore = com.example.pinvault.server.store.DevicePublicKeyStore(db)
    val deviceHostAclStore = com.example.pinvault.server.store.DeviceHostAclStore(db)
    val vaultTokenService = com.example.pinvault.server.service.VaultAccessTokenService(vaultTokenStore)
    val configApiRegistry = com.example.pinvault.server.store.ConfigApiRegistry(db)
    val vaultEncryptionService = com.example.pinvault.server.service.VaultEncryptionService()

    // Shutdown hook
    Runtime.getRuntime().addShutdownHook(Thread {
        mockServerManager.stopAll()
        configApiManager.stopAll()
    })

    // Background cert expiry check (every 6 hours). Expiring and expired
    // certificates are also audited — and pushed to the webhook — once a day
    // per host, so nobody has to be looking at the dashboard to hear about it.
    val lastExpiryNotice = java.util.concurrent.ConcurrentHashMap<String, java.time.LocalDate>()
    fun checkCertExpiry() {
        certExpiryMonitor.logWarnings()
        val today = java.time.LocalDate.now()
        certExpiryMonitor.checkAll().filter { it.level != "ok" }.forEach { cert ->
            val key = "${cert.configApiId}|${cert.hostname}"
            if (lastExpiryNotice.put(key, today) != today) {
                auditLog.record(
                    "cert_expiring",
                    if (cert.level == "expired") "${cert.hostname}: certificate EXPIRED (${cert.validUntil})"
                    else "${cert.hostname}: certificate expires in ${cert.daysRemaining} day(s) (${cert.validUntil})",
                    configApiId = cert.configApiId, target = cert.hostname, actor = "system"
                )
            }
        }
    }
    Thread {
        while (true) {
            try { Thread.sleep(6 * 60 * 60 * 1000L) } catch (_: InterruptedException) { break }
            try { checkCertExpiry() } catch (e: Exception) { println("Cert expiry check failed: ${e.message}") }
        }
    }.apply { isDaemon = true; name = "cert-expiry-checker" }.start()
    // Initial check on startup
    try { checkCertExpiry() } catch (e: Exception) { println("Cert expiry check failed: ${e.message}") }

    // Restarts every running mTLS listener against the current truststore file.
    //
    // A listener reads the truststore once, at start: adding a certificate to
    // the file afterwards does not make the running listener trust it, and
    // removing one does not make it stop. Enrollment and revocation already did
    // this; `POST /api/v1/client-certs/generate` and `/upload` wrote the file
    // and stopped there, so a client connecting with a certificate the operator
    // had just downloaded was rejected with "certificate unknown" until someone
    // restarted the server. All four paths now go through here.
    //
    // `restartMocks = false` is for callers that already restarted the mock
    // mTLS hosts themselves (the enrollment route does).
    //
    // Declared as a captured `var` and assigned right after `configApiModuleFor`
    // below: the helper needs that function, and the enrollment callback inside
    // that function needs the helper. Kotlin local functions cannot
    // forward-reference, so the two are tied together through this holder.
    var refreshMtlsTrust: (reason: String, restartMocks: Boolean) -> Unit = { _, _ -> }

    // Config API routing modülü — her API kendi configApiId ve mode'uyla scoped
    fun configApiModuleFor(configApiId: String, mode: String = "tls"): Application.() -> Unit = {
        installGovernance(management = false)
        routing {
            certificateConfigRoutes(configApiId, pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, certService, enrollmentTokenStore, clientCertStore, mockServerManager, hostClientCertStore, onClientCertEnrolled = {
                // Enrollment sonrası mTLS Config API'leri restart et (yeni truststore ile).
                // Mock mTLS sunucularını enrollment route'u kendisi yeniden
                // başlattığı için burada tekrar edilmiyor.
                refreshMtlsTrust("new truststore", false)
            }, enrollmentMode = enrollmentMode, configApiMode = mode,
                deviceHostAclStore = deviceHostAclStore,
                signedConfigService = signedConfigService, keySetService = signingKeySetService,
                liveGate = liveGate, audit = auditLog)
            hostRoutes(configApiId, pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore)
            vaultRoutes(configApiId, vaultFileStore, vaultDistStore, vaultTokenStore,
                devicePublicKeyStore, vaultTokenService, vaultEncryptionService, signingService,
                // token_mtls: binds the presented client cert to X-Device-Id.
                clientCertStore = clientCertStore,
                // Dashboard's "vault enabled" switch. Read per request so the
                // toggle takes effect without restarting this listener.
                vaultEnabledProvider = { configApiRegistry.isVaultEnabled(configApiId) },
                signedConfigService = signedConfigService)
            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }
        }
    }

    // See the declaration above for why this is assigned here rather than
    // declared as a local function.
    refreshMtlsTrust = { reason, restartMocks ->
        configApiManager.getAll().filter { it.mode == "mtls" }.forEach { api ->
            println("Restarting mTLS Config API: ${api.id} ($reason)")
            configApiManager.start(
                api.id, api.port, api.mode, api.keystorePath,
                certService.getTrustStoreFile()?.absolutePath,
                configApiModuleFor(api.id, api.mode)
            )
        }
        if (restartMocks) mockServerManager.restartMtlsServers(certService)
    }

    // Varsayılan TLS config API başlat
    pinConfigStore.ensureConfigExists("default-tls")
    // The default listener is mounted directly here rather than through
    // POST /api/v1/config-apis/start, so nothing ever created its config_apis
    // row. Without one, per-scope settings keyed on that table — today the
    // vault_enabled switch — had nothing to update and answered 404 on the
    // very scope the sample app uses (E2E C09). Registering it here keeps the
    // registry complete; an existing row's vault_enabled is preserved.
    configApiRegistry.ensureRegistered("default-tls", httpsPort, "tls")
    configApiManager.start(
        id = "default-tls",
        port = httpsPort,
        mode = "tls",
        keystorePath = serverKeystorePath.absolutePath,
        configModule = configApiModuleFor("default-tls", "tls")
    )

    // DB'deki config API'leri ve mock server'ları auto-start et
    data class ApiToStart(val id: String, val port: Int, val mode: String)
    data class MockToStart(val hostname: String, val keystorePath: String, val port: Int)

    val apisToStart = mutableListOf<ApiToStart>()
    val mocksToStart = mutableListOf<MockToStart>()

    db.connection().use { conn ->
        conn.prepareStatement("SELECT id, port, mode FROM config_apis WHERE auto_start = 1").use { stmt ->
            val rs = stmt.executeQuery()
            while (rs.next()) apisToStart.add(ApiToStart(rs.getString("id"), rs.getInt("port"), rs.getString("mode")))
        }
        conn.prepareStatement("SELECT hostname, keystore_path, mock_server_port FROM hosts WHERE mock_server_port IS NOT NULL AND keystore_path IS NOT NULL").use { stmt ->
            val rs = stmt.executeQuery()
            while (rs.next()) mocksToStart.add(MockToStart(rs.getString("hostname"), rs.getString("keystore_path"), rs.getInt("mock_server_port")))
        }
    }

    for (api in apisToStart) {
        if (api.id != "default-tls" && !configApiManager.isRunning(api.id)) {
            try {
                val trustPath = if (api.mode == "mtls") certService.getTrustStoreFile()?.absolutePath?.takeIf { File(it).exists() } else null
                pinConfigStore.ensureConfigExists(api.id)
                configApiManager.start(api.id, api.port, api.mode, serverKeystorePath.absolutePath, trustPath, configApiModuleFor(api.id, api.mode))
                println("Auto-started config API: ${api.id} on port ${api.port} (${api.mode})")
            } catch (e: Exception) {
                println("Failed to auto-start config API ${api.id}: ${e.message}")
            }
        }
    }

    for (mock in mocksToStart) {
        if (!mockServerManager.isRunning(mock.hostname)) {
            try {
                mockServerManager.start(mock.hostname, mock.port, mock.keystorePath)
                println("Auto-started mock server: ${mock.hostname} on port ${mock.port}")
            } catch (e: Exception) {
                println("Failed to auto-start mock ${mock.hostname}: ${e.message}")
            }
        }
    }

    // HTTP management server
    embeddedServer(Netty, port = httpPort) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                encodeDefaults = true
                ignoreUnknownKeys = true
            })
        }
        // Security headers (M-05). CSP is intentionally permissive on
        // 'style-src' because the admin UI inlines a few utility styles;
        // 'script-src self' still kills the H-02 stored-XSS payload class.
        install(DefaultHeaders) {
            header("X-Content-Type-Options", "nosniff")
            header("X-Frame-Options", "DENY")
            header("Referrer-Policy", "no-referrer")
            header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "connect-src 'self'; frame-ancestors 'none'"
            )
        }
        install(CallLogging)
        install(com.example.pinvault.server.plugin.ApiKeyAuth)
        installGovernance(management = true)
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
            certificateConfigRoutes("default-tls", pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, hostClientCertStore = hostClientCertStore, enrollmentMode = enrollmentMode, deviceHostAclStore = deviceHostAclStore,
                signedConfigService = signedConfigService, keySetService = signingKeySetService,
                liveGate = liveGate, audit = auditLog)
            signingAdminRoutes(
                signingService, signedConfigService, signingKeySetService,
                actorOf = { it.adminName() },
                onKeysChanged = { event, summary, actor -> auditLog.record(event, summary, actor = actor) }
            )
            governanceRoutes(adminRegistry, auditLog, auditStore, approvalService, liveGate, signedConfigService)
            hostRoutes("default-tls", pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore)
            // V2: per-Config-API scoped vault admin endpoints under
            // /api/v1/config-apis/{configApiId}/vault/...  — no more global
            // "default-tls"-fixed vault mount on the management server.
            scopedVaultAdminRoutes(vaultFileStore, vaultDistStore, vaultTokenStore, vaultTokenService)
            adminVaultRoutes(db, deviceHostAclStore, configApiRegistry)

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
            // Same write as PUT /api/v1/certificate-config?configApiId=… — validation,
            // per-host versioning, live gate, history. It used to store the body
            // as sent, versions included, with none of those checks.
            post("/api/v1/config/{configApiId}/update") {
                val configApiId = call.parameters["configApiId"] ?: "default-tls"
                call.applyPinConfigUpdate(configApiId, pinConfigStore, historyStore, liveGate, auditLog)
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
                val savedPin = pinConfigStore.save(configApiId, updated).pins.first { it.hostname == newPin.hostname }
                pinConfigStore.ensureConfigExists(configApiId)

                historyStore.add(configApiId, PinConfigHistoryEntry(hostname, savedPin.version, java.time.Instant.now().toString(), "cert_generated", result.sha256Pins.firstOrNull()?.take(12) ?: ""))

                call.respond(HostActionResponse(hostname, result.sha256Pins, result.validUntil, savedPin.version))
            }

            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }

            get("/api/v1/enrollment-mode") {
                call.respondText(
                    """{"mode":"$enrollmentMode","tokenRequired":${enrollmentMode != "open"}}""",
                    ContentType.Application.Json
                )
            }

            get("/api/v1/server-tls-pins") {
                val primary = serverTlsPins.getOrNull(0) ?: ""
                val backup = serverTlsPins.getOrNull(1) ?: ""
                call.respondText(
                    """{"primaryPin":"$primary","backupPin":"$backup","httpsPort":$httpsPort,"hostname":"localhost"}""",
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

            // Yedek anahtara geçiş (config sunucusunun kendi sertifikası):
            // uygulamalar bu sertifikanın iki pin'ini başlangıç pini olarak
            // taşır, yedeğe geçmek uygulama güncellemesi istemez. Yeni asıl
            // pin eski yedek olur; yeni yedeğin pin'i sonraki sürüme gömülür.
            post("/api/v1/server-tls-pins/rotate-to-backup") {
                val backupPin = certService.backupPin(serverCertId)
                    ?: return@post call.respond(HttpStatusCode.Conflict, mapOf("reason" to "no_backup_key", "error" to
                        "No stored backup key for the config server certificate: its pins were fetched from a URL, or it was " +
                        "generated before backup keys were kept. Regenerate it to get one (apps then need the new pins)."))
                if (backupPin !in serverTlsPins) {
                    return@post call.respond(HttpStatusCode.Conflict, mapOf("reason" to "backup_not_published", "error" to
                        "The stored backup key's pin is not among the current bootstrap pins, so apps would reject it."))
                }
                val rotated = certService.rotateToBackup(serverCertId, "localhost")
                serverPinsFile.writeText(rotated.sha256Pins.joinToString("\n"))
                serverTlsPins = rotated.sha256Pins
                call.respondText(
                    """{"primaryPin":"${rotated.sha256Pins[0]}","backupPin":"${rotated.sha256Pins[1]}","rotated":true,"restartRequired":true}""",
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
                    val result = certService.importCertificate(serverCertId, bytes, password, format, "localhost")
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
                } catch (e: com.example.pinvault.server.service.NoSecondCertificateException) {
                    call.respondNoSecondCertificate(e)
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
                    val instance = configApiManager.start(id, port, mode, serverKeystorePath.absolutePath, trustPath, configApiModuleFor(id, mode))
                    // DB'ye kaydet (auto_start). INSERT OR REPLACE yerine
                    // ensureRegistered: REPLACE satırı silip yeniden yazdığı
                    // için vault_enabled sütunu varsayılanına (1) dönüyordu —
                    // yani operatörün kapattığı vault, API her yeniden
                    // başlatıldığında sessizce geri açılıyordu.
                    configApiRegistry.ensureRegistered(id, port, mode)
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

                val wrapping = com.example.pinvault.server.service.P12Transfer.wrappingFor(call)
                val result = certService.generateClientCertificate(clientId, wrapping.password)
                clientCertStore.add(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString())

                // The certificate is in the truststore file now, but the running
                // mTLS listeners still hold the one they started with — without
                // this the operator downloads a P12 the server will answer
                // "certificate unknown" to.
                refreshMtlsTrust("client cert generated: $clientId", true)

                call.response.header("Content-Disposition", "attachment; filename=\"$clientId.p12\"")
                com.example.pinvault.server.service.P12Transfer.respond(call, result.p12Bytes, wrapping)
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
                    // Same reason as /generate: the truststore file changed, the
                    // running listeners have not.
                    refreshMtlsTrust("client cert uploaded: $id", true)
                    call.respondText("""{"id":"$id","fingerprint":"$fingerprint","uploaded":true}""", ContentType.Application.Json)
                } catch (e: Exception) {
                    call.respondText("""{"error":"Import hatası: ${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
            }

            delete("/api/v1/client-certs/{id}") {
                val id = call.parameters["id"] ?: ""
                clientCertStore.revoke(id)
                certService.removeFromTrustStore(id)
                // The running mTLS listeners hold the truststore they were
                // started with; without a restart a revoked certificate keeps
                // working until the next server restart. Enrollment already
                // restarts them for the opposite reason (new cert trusted).
                refreshMtlsTrust("certificate revoked: $id", true)
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

                val wrapping = com.example.pinvault.server.service.P12Transfer.wrappingFor(call)
                val result = certService.generateClientCertificate(clientId, wrapping.password)
                clientCertStore.add(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString())
                enrollmentTokenStore.markUsed(token)

                // Integrity header (H-05). The library refuses to install a P12
                // that arrives without X-P12-SHA256, so this management-port
                // copy of the enrollment endpoint must send it just like the
                // Config API copy in CertificateConfigRoute does — otherwise a
                // client pointed at :8090 fails enrollment outright.
                call.response.header("Content-Disposition", "attachment; filename=\"$clientId.p12\"")
                com.example.pinvault.server.service.P12Transfer.respond(call, result.p12Bytes, wrapping)
            }

            // Scope-based device list, keyed by the identifier the per-device
            // host ACL uses (X-Device-Id / ANDROID_ID) rather than by hostname.
            // The Device-ACL manager in the dashboard called this endpoint
            // before it existed and silently rendered an empty table; the
            // per-host list (/api/v1/hosts/{h}/clients) answers a different
            // question and cannot fill it.
            //
            // Admin-only: X-API-Key required (not in the ApiKeyAuth allowlist).
            get("/api/v1/client-devices") {
                val configApiId = call.request.queryParameters["configApiId"] ?: "default-tls"
                call.respond(clientDeviceStore.getByConfigApi(configApiId))
            }

            // API documentation
            get("/docs") { call.respondRedirect("/static/docs.html") }

            // Certificate expiry monitoring
            get("/api/v1/cert-expiry") {
                call.respond(certExpiryMonitor.checkAll())
            }
            // Rich health. The response used to be built from nested
            // `mapOf(...)` with mixed String / Int / Map values, which
            // kotlinx.serialization cannot serialize without a declared
            // serializer — the endpoint answered 500 with
            // "Serializing collections of different element types is not yet
            // supported" on every call. It was never exercised (the Docker
            // probe hits the bare /health, and the dashboard did not use it),
            // so the failure went unnoticed. Typed response below.
            get("/api/v1/health") {
                val statuses = certExpiryMonitor.checkAll()
                val certStatus = certExpiryMonitor.getOverallStatus()
                call.respond(ServerHealth(
                    status = certStatus,
                    database = "connected",
                    configApis = ConfigApiHealth(
                        running = configApiManager.getAll().size,
                        stopped = configApiManager.getAllStopped().size
                    ),
                    certs = CertHealth(
                        status = certStatus,
                        nearExpiry = statuses.count { it.level != "ok" },
                        total = statuses.size
                    )
                ))
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
        if (enrollmentMode == "open") {
            println("Enrollment:   OPEN (WARNING — deviceId enrollment aktif, üretimde kullanmayın!)")
        } else {
            println("Enrollment:   TOKEN (güvenli — sadece enrollment token ile kayıt)")
        }
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
        println("  POST /api/v1/connection-history/config-update-report")
        println("=".repeat(60))
        println("ECDSA Public Key: ${signingService.publicKeyBase64}")
        signingService.signers.forEach { println("  signer ${it.name}: ${it.description} — keyId ${it.keyId}") }
        if (serverCertResult != null) {
            println("Server TLS Pins: ${serverCertResult.sha256Pins}")
        }
        println("=".repeat(60))
    }.start(wait = true)
}

/**
 * Response of `GET /api/v1/health` — the richer sibling of the bare `/health`
 * probe. Declared as serializable types rather than nested `mapOf`, which
 * kotlinx.serialization rejects when the values are of mixed types.
 */
@kotlinx.serialization.Serializable
data class ServerHealth(
    /** Overall status derived from certificate expiry: ok / degraded / critical. */
    val status: String,
    val database: String,
    val configApis: ConfigApiHealth,
    val certs: CertHealth
)

@kotlinx.serialization.Serializable
data class ConfigApiHealth(val running: Int, val stopped: Int)

@kotlinx.serialization.Serializable
data class CertHealth(
    /** Same value as [ServerHealth.status]; kept for clients reading this block alone. */
    val status: String,
    /** Certificates in `warning` or `expired` state. */
    val nearExpiry: Int,
    val total: Int
)
