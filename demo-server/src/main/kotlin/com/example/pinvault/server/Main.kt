package com.example.pinvault.server

import com.example.pinvault.server.model.HostActionResponse
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.route.setupRoutes
import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertAdminRoutes
import com.example.pinvault.server.route.configApiAdminRoutes
import com.example.pinvault.server.route.serverTlsPinRoutes
import com.example.pinvault.server.route.clientCertRenewalRoute
import com.example.pinvault.server.route.clientCertRevocationRoutes
import com.example.pinvault.server.route.signingAdminRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.route.governanceRoutes
import com.example.pinvault.server.route.applyPinConfigUpdate
import com.example.pinvault.server.route.respondNoSecondCertificate
import com.example.pinvault.server.plugin.adminName
import com.example.pinvault.server.plugin.genericErrors
import com.example.pinvault.server.plugin.receiveLimitedText
import com.example.pinvault.server.route.string
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.route.managementConfigRoutes
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
import io.ktor.server.plugins.origin
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
    // Before anything is read, written or listened on: no start without admin
    // keys (unless ALLOW_ANONYMOUS_ADMIN — it used to be noticed only after the
    // device listeners were already up), and none with the passwords that are
    // printed in the source code (unless ALLOW_DEMO_SECRETS).
    check(!com.example.pinvault.server.plugin.AdminRegistry.fromEnv().isEmpty || System.getenv("ALLOW_ANONYMOUS_ADMIN") == "true") {
        com.example.pinvault.server.plugin.NO_ADMIN_KEY_MESSAGE
    }
    com.example.pinvault.server.service.StartupSecrets.check()?.let { System.err.println(it) }
    // After the passwords: a guessable shared key is refused too (ALLOW_DEMO_SECRETS for local runs).
    com.example.pinvault.server.service.AdminKeyStrength.check()?.let { System.err.println(it) }
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
    if (signedConfigService.cacheForced) {
        println("CONFIG_SIGNATURE_CACHE turned on: an external signer is configured (${signingService.signers.joinToString { it.type }}); " +
            "every client is served the cached envelope, one signing per distinct content")
    }
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

    // What a pending change does, in words an approver can judge — and, for a
    // certificate change, the plan that is applied (see ChangeDescriber). It
    // needs stores that are created further down, hence the holder.
    var changeDescriber: com.example.pinvault.server.service.ChangeDescriber? = null

    // The largest vault file an administrator may upload: read into memory whole.
    val vaultMaxFileBytes = (System.getenv("VAULT_MAX_FILE_BYTES")?.toLongOrNull()
        ?: com.example.pinvault.server.route.DEFAULT_VAULT_MAX_FILE_BYTES).coerceIn(1, Int.MAX_VALUE.toLong() - 64)
    // ...and the largest JSON body, keystore or certificate.
    val adminUploadMaxBytes = (System.getenv("ADMIN_UPLOAD_MAX_BYTES")?.toLongOrNull()
        ?: com.example.pinvault.server.plugin.DEFAULT_ADMIN_BODY_MAX_BYTES).coerceIn(1024, 64L * 1024 * 1024)

    val approvalService = com.example.pinvault.server.service.ApprovalService(
        // Bodies and plans wait encrypted: an uploaded P12 and its password, a generated key.
        store = com.example.pinvault.server.store.ChangeRequestStore(db, com.example.pinvault.server.service.VaultAtRestCipher.fromEnv()),
        audit = auditLog,
        required = approvalsRequired,
        ttlHours = System.getenv("APPROVAL_TTL_HOURS")?.toLongOrNull()?.coerceAtLeast(1) ?: 24,
        managementPort = System.getenv("PORT")?.toIntOrNull() ?: 8080,
        describe = { input -> (changeDescriber ?: error("The server is still starting")).describe(input) },
        stateHash = ::stateHash,
        exempt = com.example.pinvault.server.service.ApprovalService.exemptFromEnv().also { exempt ->
            if (exempt.isNotEmpty() && approvalsRequired > 1) {
                System.err.println("WARNING: APPROVAL_EXEMPT_OPERATIONS — these run WITHOUT a second admin: ${exempt.joinToString()}")
            }
        }
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
            maxBodyBytes = { operation -> if (operation == "vault_upload") vaultMaxFileBytes else adminUploadMaxBytes }
        }
    }
    val certService = CertificateService(certsDir)
    val mockServerManager = MockServerManager()
    val certExpiryMonitor = com.example.pinvault.server.service.CertExpiryMonitor(hostStore)
    val httpPort = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val httpsPort = System.getenv("HTTPS_PORT")?.toIntOrNull() ?: (httpPort + 1)
    // Certificate-renewal door for expired devices (TLS, no client cert, CA-pinned). 0 = off.
    val recoveryPort = System.getenv("RECOVERY_PORT")?.toIntOrNull() ?: (httpPort + 3)
    val enrollmentMode = System.getenv("ENROLLMENT_MODE")?.lowercase() ?: "token"
    // Lifetime of certificates issued over device-held keys (CSR enrollment).
    val clientCertTtlDays = (System.getenv("CLIENT_CERT_TTL_DAYS")?.toLongOrNull() ?: 90L).coerceIn(1, 3650)
    // E2E keys a source address may write over TLS per 10 minutes (0 = no limit), and
    // the most a Config API stores. Key registration asks for no credential there.
    val deviceKeyRateLimit = (System.getenv("DEVICE_KEY_RATE_LIMIT")?.toIntOrNull() ?: 30).coerceAtLeast(0)
    val deviceKeyLimit = (System.getenv("DEVICE_KEY_LIMIT")?.toIntOrNull() ?: 100_000).coerceAtLeast(1)
    // Refusals (400/401/403/404/409/411/413) a source address may collect per 10 minutes
    // on enrollment, key registration and the downloads before it is cut off with 429
    // (0 = no limit). Requests that are served are not counted.
    val deviceRefusalRateLimit = (System.getenv("DEVICE_REFUSAL_RATE_LIMIT")?.toIntOrNull() ?: 300).coerceAtLeast(0)
    // Reports (vault downloads, connections, config updates) a source address and a
    // device may file per 10 minutes (0 = no limit). They ask for no credential.
    val reportRateLimit = (System.getenv("REPORT_RATE_LIMIT")?.toIntOrNull() ?: 600).coerceAtLeast(0)
    val reportDeviceRateLimit = (System.getenv("REPORT_DEVICE_RATE_LIMIT")?.toIntOrNull() ?: 120).coerceAtLeast(0)
    // The least time between two restarts of the mTLS listeners (a server-made P12
    // enrollment or revocation changes the truststore they read at start).
    val mtlsRestartMinIntervalMs = (System.getenv("MTLS_RESTART_MIN_INTERVAL_SECONDS")?.toLongOrNull() ?: 5L).coerceIn(0, 3600) * 1000
    // User-auth keys: Android Key Attestation (USER_AUTH_ATTESTATION=off|warn|enforce,
    // ATTESTATION_PACKAGE_NAMES, ATTESTATION_SIGNER_SHA256, ATTESTATION_REQUIRE_VERIFIED_BOOT,
    // ATTESTATION_REVOKED_SERIALS_FILE). An unknown mode is a startup error.
    val userAuthAttestationMode = com.example.pinvault.server.service.UserAuthAttestationMode.parse(System.getenv("USER_AUTH_ATTESTATION"))
    // Also USER_AUTH_REQUIRE_PER_USE, ATTESTATION_MIN_PATCH_LEVEL and ATTESTATION_STATUS_MAX_AGE_HOURS.
    val userAuthAttestation = com.example.pinvault.server.service.AndroidKeyAttestation.fromEnv()
    println("USER_AUTH_ATTESTATION=${userAuthAttestationMode.name.lowercase()}" +
        (if (userAuthAttestation.packageNames.isEmpty()) "" else " — packages ${userAuthAttestation.packageNames.joinToString()}") +
        (if (userAuthAttestation.signerDigests.isEmpty()) "" else ", ${userAuthAttestation.signerDigests.size} signer digest(s)") +
        (if (userAuthAttestation.revokedSerials.isEmpty()) "" else ", ${userAuthAttestation.revokedSerials.size} revoked serial(s)") +
        (if (userAuthAttestation.requireVerifiedBoot) "" else ", verified boot NOT required") +
        (if (userAuthAttestation.requirePerUse) ", per-use user-auth keys only" else "") +
        (userAuthAttestation.minPatchLevel?.let { ", security patch $it or newer" } ?: ""))
    // enforce without the package + signer binding refuses to start; warn without it
    // lets no attestation count (replacement then needs an administrator's reset).
    com.example.pinvault.server.service.UserAuthAttestationMode.startupCheck(userAuthAttestationMode, userAuthAttestation)
        ?.let { System.err.println(it) }
    // The attestation revocation list is re-read when its file changes (an
    // operator's cron job fetches Google's list; the server never goes to the
    // network): looked at on every verification and every 10 minutes here.
    userAuthAttestation.revocationListFile?.let { file ->
        println("ATTESTATION_REVOKED_SERIALS_FILE=${file.path} — re-read when it changes" +
            (System.getenv("ATTESTATION_STATUS_MAX_AGE_HOURS")?.let { "; no attestation passes once it is older than $it h" } ?: ""))
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "attestation-revocation-list").apply { isDaemon = true } }
            .scheduleAtFixedRate({ runCatching { userAuthAttestation.refreshRevocationList() } }, 10, 10, java.util.concurrent.TimeUnit.MINUTES)
    }
    // Client identity keys: Android Key Attestation of every CSR enrollment
    // (ENROLLMENT_ATTESTATION=off|warn|enforce, default warn), same verifier settings.
    val enrollmentAttestationMode = com.example.pinvault.server.service.EnrollmentAttestationMode.parse(System.getenv("ENROLLMENT_ATTESTATION"))
    com.example.pinvault.server.service.EnrollmentAttestationMode.startupCheck(enrollmentAttestationMode, userAuthAttestation)
        ?.let { System.err.println(it) }
    val enrollmentAttestation = com.example.pinvault.server.service.EnrollmentAttestation(enrollmentAttestationMode) { userAuthAttestation }
    // enforce without Google's revocation list: a phone whose attestation key was revoked still passes.
    if ((enrollmentAttestationMode == com.example.pinvault.server.service.EnrollmentAttestationMode.ENFORCE ||
            userAuthAttestationMode == com.example.pinvault.server.service.UserAuthAttestationMode.ENFORCE) &&
        userAuthAttestation.revocationListFile == null) {
        System.err.println("WARNING: attestation is enforced without ATTESTATION_REVOKED_SERIALS_FILE — keys from phones whose attestation " +
            "key Google revoked still pass. Fetch the list with scripts/fetch-attestation-status.sh and set ATTESTATION_STATUS_MAX_AGE_HOURS.")
    }
    // Server-made keys (P12): ENROLLMENT_P12=on (default, for older apps) | off.
    // Off — and under ENROLLMENT_ATTESTATION=enforce — no private key is made here.
    val enrollmentP12 = when (System.getenv("ENROLLMENT_P12")?.trim()?.lowercase()) {
        null, "", "on", "true" -> true
        "off", "false" -> false
        else -> error("ENROLLMENT_P12 must be on or off (got '${System.getenv("ENROLLMENT_P12")}')")
    }
    // The enrolling device's integrity verdict (Play Integrity or a RASP product's
    // attestation): INTEGRITY_VERIFICATION=off|warn|enforce (default off), decoded
    // by INTEGRITY_VERIFIER_COMMAND. Bound to the request's CSR and device id.
    val integrityMode = com.example.pinvault.server.service.IntegrityVerificationMode.parse(System.getenv("INTEGRITY_VERIFICATION"))
    val integrityVerifier = com.example.pinvault.server.service.CommandIntegrityVerifier.fromEnv(System::getenv)
    com.example.pinvault.server.service.IntegrityVerificationMode.startupCheck(integrityMode, integrityVerifier)
        ?.let { System.err.println(it) }
    val enrollmentIntegrity = com.example.pinvault.server.service.EnrollmentIntegrity(integrityMode, integrityVerifier)
    println("INTEGRITY_VERIFICATION=${integrityMode.name.lowercase()}" +
        (if (integrityVerifier != null) " (verifier command set)" else ""))
    val serverMadeKeys = enrollmentP12 && !enrollmentAttestation.refusesServerMadeKeys && !enrollmentIntegrity.refusesServerMadeKeys
    println("ENROLLMENT_ATTESTATION=${enrollmentAttestationMode.name.lowercase()}, ENROLLMENT_P12=${if (enrollmentP12) "on" else "off"}" +
        (if (serverMadeKeys) "" else " — no server-made keys: devices enroll over a CSR only"))
    // Test-only endpoints (short certificate lifetimes for the Espresso suite). Never in production.
    val allowTestHooks = System.getenv("ALLOW_TEST_HOOKS") == "true"
    if (allowTestHooks) System.err.println("WARNING: ALLOW_TEST_HOOKS=true — test-only endpoints are enabled")

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
            add(certService.clientCaFile())
            add(certService.serverCaFile())
            add(certService.serverCaBackupFile())
            add(certService.recoveryKeystoreFile())
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
    // The client CA that signs CSR-enrolled device certificates; every mTLS
    // listener trusts it through the client truststore.
    run {
        val fresh = !certService.clientCaFile().exists()
        val ca = certService.ensureClientCa()
        println("${if (fresh) "Generated" else "Loaded"} client CA — SPKI ${certService.spkiSha256(ca.publicKey)}, valid until ${ca.notAfter.toInstant()}")
    }
    // The server CA behind the recovery listener; apps pin these two keys for <host>:RECOVERY_PORT.
    val serverCa = if (recoveryPort > 0) certService.ensureServerCa().also {
        println("Server CA (recovery door) pins: ${it.pins.joinToString()} — valid until ${it.certificate.notAfter.toInstant()}")
    } else null
    val serverCertResult = if (!serverKeystorePath.exists()) {
        println("Generating demo server TLS certificate...")
        certService.generateCertificate(serverCertId, "localhost")
    } else null

    // Server TLS pin'lerini oku/kaydet
    val serverPinsFile = File("certs/$serverCertId.pins")
    val initialServerTlsPins: List<String> = if (serverCertResult != null) {
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
    val serverTlsPins = com.example.pinvault.server.route.ServerTlsPins(certService, serverPinsFile, serverCertId, initialServerTlsPins)
    // One planner for every certificate-changing route and for the description
    // an approver is shown: what is shown is what is installed.
    val certPlanner = com.example.pinvault.server.service.CertChangePlanner(
        certService, pinConfigStore, hostStore, serverCertId, bootstrapPins = { serverTlsPins.pins }
    )

    // Config API manager (dinamik TLS/mTLS sunucuları)
    val configApiManager = ConfigApiManager()
    // Invalid admin keys: one counter for every listener (ADMIN_AUTH_FAILURE_LIMIT, 0 = off).
    val adminAuthFailureLimit = (System.getenv("ADMIN_AUTH_FAILURE_LIMIT")?.toIntOrNull()
        ?: com.example.pinvault.server.plugin.DEFAULT_ADMIN_AUTH_FAILURE_LIMIT).coerceAtLeast(0)
    val adminFailureLimiter = if (adminAuthFailureLimit > 0) {
        com.example.pinvault.server.service.RateLimiter(maxAttempts = adminAuthFailureLimit, windowMs = 10 * 60_000)
    } else null
    configApiManager.adminFailureLimiter = adminFailureLimiter
    val clientCertStore = ClientCertStore(db)
    val hostClientCertStore = com.example.pinvault.server.store.HostClientCertStore(db)
    val enrollmentTokenStore = EnrollmentTokenStore(db)
    // Codes many devices enroll with (a device limit, an end date, optional approval).
    val enrollmentPolicyStore = com.example.pinvault.server.store.EnrollmentPolicyStore(db)
    // Requests nobody decides on lapse after this; code-less applications (the
    // dashboard's switch) may have this many waiting, and a source address may
    // make this many new ones per 10 minutes (0 = no limit).
    val enrollmentRequestTtl = java.time.Duration.ofHours((System.getenv("ENROLLMENT_REQUEST_TTL_HOURS")?.toLongOrNull() ?: 24L).coerceIn(1, 720))
    val openMaxPending = (System.getenv("OPEN_ENROLLMENT_MAX_PENDING")?.toIntOrNull() ?: 50).coerceIn(1, 10_000)
    val openRateLimit = (System.getenv("OPEN_ENROLLMENT_RATE_LIMIT")?.toIntOrNull() ?: 20).coerceAtLeast(0)
    val openLimiter = if (openRateLimit > 0) com.example.pinvault.server.service.RateLimiter(maxAttempts = openRateLimit, windowMs = 10 * 60_000) else null
    // Anyone holding a shared code can cause these; one entry a minute at most.
    val policyRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "client_cert_enroll_refused", what = "Enrollment with an enrollment code refused",
        attemptsLabel = "refused enrollment-code"
    )
    // The same for enrollments with a one-time token (or none, in open mode):
    // the token is not spent by a refusal, so its holder can repeat it at will.
    val enrollRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "client_cert_enroll_refused", what = "Enrollment refused",
        attemptsLabel = "refused enrollment"
    )
    // The management port's copy of enrollment: refusals with a valid token per client id, as on the Config APIs.
    val managementEnrollRefusals = com.example.pinvault.server.route.EnrollRefusalLog(auditLog, enrollRefusals, "")
    val clientIdentityStore = com.example.pinvault.server.store.ClientIdentityStore(db)
    // Renewal refusals per source address, and renewals per identity: two
    // tables. One shared table let a flood from new addresses fill it and shut
    // out every identity's renewal; identities fail open when it is full.
    val renewLimiter = com.example.pinvault.server.service.RateLimiter()
    val renewIdentityLimiter = com.example.pinvault.server.service.RateLimiter(overflow = com.example.pinvault.server.service.RateLimiter.Overflow.FAIL_OPEN)
    // Certificates per client id, pickups, key replacements per identity
    // (ISSUANCE_RATE_LIMIT, PICKUP_RATE_LIMIT, PICKUP_SOURCE_RATE_LIMIT, KEY_REPLACEMENT_RATE_LIMIT).
    val enrollmentLimits = com.example.pinvault.server.service.EnrollmentLimits.fromEnv()
    val renewFailures = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "client_cert_auth_failed", what = "Client certificate renewal refused",
        attemptsLabel = "refused client certificate renewal"
    )
    val keyRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "device_key_refused", what = "E2E key registration refused",
        attemptsLabel = "refused E2E key registration"
    )
    val revokedRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "client_cert_revoked_refused", what = "Request with a revoked client certificate refused",
        attemptsLabel = "revoked client certificate"
    )
    val deviceIdRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "device_id_refused", what = "Request naming another device refused",
        attemptsLabel = "foreign X-Device-Id"
    )
    val keyLimiter = if (deviceKeyRateLimit > 0) {
        com.example.pinvault.server.service.RateLimiter(maxAttempts = deviceKeyRateLimit, windowMs = 10 * 60_000)
    } else null
    // One counter for every listener: an address cut off on one port is cut off on all.
    val refusalLimiter = if (deviceRefusalRateLimit > 0) {
        com.example.pinvault.server.service.RateLimiter(maxAttempts = deviceRefusalRateLimit, windowMs = 10 * 60_000)
    } else null
    val refusalCutOffs = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "device_rate_limited", what = "Device endpoint cut off",
        attemptsLabel = "rate-limited device endpoint"
    )
    val reportLimits = com.example.pinvault.server.route.ReportLimits(
        perAddress = if (reportRateLimit > 0) com.example.pinvault.server.service.RateLimiter(maxAttempts = reportRateLimit, windowMs = 10 * 60_000) else null,
        perDevice = if (reportDeviceRateLimit > 0) com.example.pinvault.server.service.RateLimiter(maxAttempts = reportDeviceRateLimit, windowMs = 10 * 60_000) else null
    )
    // Vault downloads served at once per source address, on every listener
    // (VAULT_DOWNLOAD_CONCURRENCY, default 4; 0 = unlimited).
    val vaultDownloadSlots = ((System.getenv("VAULT_DOWNLOAD_CONCURRENCY")?.toIntOrNull() ?: 4).coerceAtLeast(0))
        .takeIf { it > 0 }?.let { com.example.pinvault.server.service.ConcurrencyLimiter(it) }
    // One-shot certificate lifetimes armed by the test hook, consumed by the next issuance.
    val testTtlOverrides = java.util.concurrent.ConcurrentHashMap<String, java.time.Duration>()
    val testTtlOverride: ((String) -> java.time.Duration?)? =
        if (allowTestHooks) { clientId -> testTtlOverrides.remove(clientId) } else null
    val vaultFileStore = com.example.pinvault.server.store.VaultFileStore(db)
    // Every at_rest / end_to_end file ends up under the current VAULT_AT_REST_PASSWORD.
    vaultFileStore.secureStoredFiles().let { report ->
        if (report.encrypted.isNotEmpty()) println("Vault: encrypted ${report.encrypted.size} file(s) stored in the clear: ${report.encrypted.joinToString()}")
        if (report.rekeyed.isNotEmpty()) println("VAULT_AT_REST_PASSWORD: re-encrypted ${report.rekeyed.size} vault file(s): ${report.rekeyed.joinToString()}")
        if (report.unreadable.isNotEmpty()) {
            System.err.println("VAULT_AT_REST_PASSWORD: ${report.unreadable.joinToString()} open with neither the current, the previous " +
                "(VAULT_AT_REST_PASSWORD_PREVIOUS) nor the demo password; downloads of them fail until one is supplied or they are uploaded again")
        }
    }
    val vaultDistStore = com.example.pinvault.server.store.VaultDistributionStore(db)
    val vaultTokenStore = com.example.pinvault.server.store.VaultFileTokenStore(db)
    val devicePublicKeyStore = com.example.pinvault.server.store.DevicePublicKeyStore(db)
    val deviceHostAclStore = com.example.pinvault.server.store.DeviceHostAclStore(db)
    val vaultTokenService = com.example.pinvault.server.service.VaultAccessTokenService(vaultTokenStore)
    changeDescriber = com.example.pinvault.server.service.ChangeDescriber(
        pinConfigStore, certPlanner, liveGate, ::stateHash, vaultFileStore, vaultTokenStore, audit = auditLog,
        // Which running API a start on a port would stop.
        portHolder = { port -> configApiManager.getAll().firstOrNull { it.port == port }?.id },
        // The upload handler's own refusal, made when the upload is requested.
        clientIdInUse = { id ->
            when {
                clientCertStore.get(id)?.revoked == false || clientIdentityStore.get(id)?.revoked == false ->
                    "Client id $id is an active identity: revoke and forget it first, or use another id"
                certService.getTrustStore()?.containsAlias(id.lowercase()) == true ->
                    "The mTLS truststore already has an entry under $id: use another id"
                else -> null
            }
        }
    )
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
    // `restartMocks` is kept for the callers' signature; the mock mTLS hosts
    // are always restarted with the Config APIs now (see the assignment below).
    //
    // Declared as a captured `var` and assigned right after `configApiModuleFor`
    // below: the helper needs that function, and the enrollment callback inside
    // that function needs the helper. Kotlin local functions cannot
    // forward-reference, so the two are tied together through this holder.
    var refreshMtlsTrust: (reason: String, restartMocks: Boolean) -> Unit = { _, _ -> }

    // Who is refused on every listener that trusts the client CA: a revoked
    // identity, or a certificate over a key retired with a forgotten one. The
    // handshake accepts any certificate the CA issued until it expires, so the
    // mTLS Config APIs and the mock mTLS hosts check it on every request.
    val revocationGate: com.example.pinvault.server.plugin.RevocationGateConfig.() -> Unit = {
        isRevoked = { id -> clientCertStore.get(id)?.revoked == true || clientIdentityStore.get(id)?.revoked == true }
        isRetiredKey = { cert -> clientIdentityStore.isRetired(certService.spkiSha256(cert.publicKey)) }
        // The CN is believed only for the certificate on record for that id: a leaf
        // signed by an old per-certificate anchor naming another id is refused.
        isOnRecord = { id, cert -> com.example.pinvault.server.route.presentedLeafOnRecord(id, cert, clientCertStore, clientIdentityStore) }
        refusals = revokedRefusals
    }
    mockServerManager.revocationGate = revocationGate

    // Config API routing modülü — her API kendi configApiId ve mode'uyla scoped
    fun configApiModuleFor(configApiId: String, mode: String = "tls"): Application.() -> Unit = {
        // An address that keeps being refused is cut off before anything is read or parsed.
        install(com.example.pinvault.server.plugin.DeviceRefusalLimit) {
            limiter = refusalLimiter
            refusals = refusalCutOffs
        }
        // Device-facing bodies are a few hundred bytes; refuse big ones unread.
        install(com.example.pinvault.server.plugin.ClientBodyLimit)
        // The handshake trusts the client CA, revocation is checked here, per request.
        if (mode == "mtls") install(com.example.pinvault.server.plugin.RevocationGate, revocationGate)
        // ...and X-Device-Id may only name the device the certificate belongs to.
        if (mode == "mtls") install(com.example.pinvault.server.plugin.DeviceIdBinding) {
            isBound = { certClientId, deviceId -> com.example.pinvault.server.route.certificateBoundTo(certClientId, deviceId, clientCertStore) }
            refusals = deviceIdRefusals
        }
        installGovernance(management = false)
        routing {
            certificateConfigRoutes(configApiId, pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, certService, enrollmentTokenStore, clientCertStore, mockServerManager, hostClientCertStore, onClientCertEnrolled = {
                // Enrollment sonrası mTLS Config API'leri ve mock mTLS sunucularını
                // restart et (yeni truststore ile) — art arda gelen kayıtlar tek bir
                // restart'ta birleştirilir (CoalescedRestart).
                refreshMtlsTrust("new truststore", true)
            }, enrollmentMode = enrollmentMode, configApiMode = mode,
                deviceHostAclStore = deviceHostAclStore,
                signedConfigService = signedConfigService, keySetService = signingKeySetService,
                liveGate = liveGate, audit = auditLog,
                clientIdentityStore = clientIdentityStore,
                clientCertTtl = { java.time.Duration.ofDays(clientCertTtlDays) },
                testTtlOverride = testTtlOverride,
                renewLimiter = renewLimiter, renewFailures = renewFailures,
                policyEnrollment = com.example.pinvault.server.route.PolicyEnrollment(
                    configApiId, enrollmentPolicyStore, certService, clientIdentityStore, clientCertStore,
                    auditLog, policyRefusals,
                    ttlFor = { id -> testTtlOverride?.invoke(id) ?: java.time.Duration.ofDays(clientCertTtlDays) },
                    pendingTtl = enrollmentRequestTtl, openMaxPending = openMaxPending, openLimiter = openLimiter,
                    attestation = enrollmentAttestation, limits = enrollmentLimits,
                    integrity = enrollmentIntegrity
                ),
                reportLimits = reportLimits, enrollRefusals = enrollRefusals,
                enrollmentAttestation = enrollmentAttestation, enrollmentIntegrity = enrollmentIntegrity,
                p12Enrollment = enrollmentP12,
                enrollmentLimits = enrollmentLimits, renewIdentityLimiter = renewIdentityLimiter)
            hostRoutes(configApiId, pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore,
                liveGate = liveGate, audit = auditLog, planner = certPlanner, maxUploadBytes = adminUploadMaxBytes)
            vaultRoutes(configApiId, vaultFileStore, vaultDistStore, vaultTokenStore,
                devicePublicKeyStore, vaultTokenService, vaultEncryptionService, signingService,
                // token_mtls: binds the presented client cert to X-Device-Id.
                clientCertStore = clientCertStore,
                // Dashboard's "vault enabled" switch. Read per request so the
                // toggle takes effect without restarting this listener.
                vaultEnabledProvider = { configApiRegistry.isVaultEnabled(configApiId) },
                signedConfigService = signedConfigService,
                // E2E key registration: who set or replaced which device's key.
                audit = auditLog, keyRefusals = keyRefusals,
                keyLimiter = keyLimiter, maxDeviceKeys = deviceKeyLimit,
                // A certificate alternating keys: per identity.
                keyReplacementLimiter = enrollmentLimits.keyReplacements,
                // A revoked device gets no token, end_to_end or user_auth file, on any listener.
                deviceRevoked = { id -> clientIdentityStore.isDeviceRevoked(id) },
                // User-auth keys: Android Key Attestation (USER_AUTH_ATTESTATION).
                userAuthAttestation = userAuthAttestation, userAuthAttestationMode = userAuthAttestationMode,
                // Device ids a certificate proved it acts for: what revocation cuts off.
                deviceProven = { clientId, deviceId, proof -> clientIdentityStore.recordDeviceProof(clientId, deviceId, proof) },
                // Downloads at once per source address (VAULT_DOWNLOAD_CONCURRENCY, 0 = unlimited).
                downloadSlots = vaultDownloadSlots,
                reportLimits = reportLimits, maxFileBytes = vaultMaxFileBytes)
            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }
        }
    }

    // See the declaration above for why this is assigned here rather than
    // declared as a local function.
    //
    // Every request goes through one CoalescedRestart: the first runs at once,
    // those that follow within MTLS_RESTART_MIN_INTERVAL_SECONDS are folded into
    // a single restart when the interval is over. A run of server-made P12
    // enrollments (each one changes the truststore) used to restart every mTLS
    // listener once per request, and could keep them down. Mock mTLS hosts are
    // always restarted with the Config APIs — they read the same truststore.
    val mtlsRestarts = com.example.pinvault.server.service.CoalescedRestart(minIntervalMs = mtlsRestartMinIntervalMs) { reason ->
        configApiManager.getAll().filter { it.mode == "mtls" }.forEach { api ->
            println("Restarting mTLS Config API: ${api.id} ($reason)")
            configApiManager.start(
                api.id, api.port, api.mode, api.keystorePath,
                certService.getTrustStoreFile()?.absolutePath,
                configApiModuleFor(api.id, api.mode)
            )
        }
        mockServerManager.restartMtlsServers(certService)
    }
    refreshMtlsTrust = { reason, _ -> mtlsRestarts.request(reason) }

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

    // Recovery listener: renewal only, its own CA-signed certificate. Checked
    // twice a day; a certificate within 30 days of expiry is reissued and the
    // listener restarted — apps pin the CA, so nothing changes for them.
    val recoveryListener = if (recoveryPort > 0) {
        com.example.pinvault.server.service.RecoveryListener(certService, recoveryPort) {
            clientCertRenewalRoute(
                "recovery", certService, clientIdentityStore,
                { clientId: String -> testTtlOverride?.invoke(clientId) ?: java.time.Duration.ofDays(clientCertTtlDays) },
                renewLimiter, renewFailures, auditLog, identityLimiter = renewIdentityLimiter
            )
        }.also { listener ->
            listener.start()
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "recovery-cert-refresh").apply { isDaemon = true } }
                .scheduleAtFixedRate({ runCatching { listener.refresh() }.onFailure { it.printStackTrace() } }, 12, 12, java.util.concurrent.TimeUnit.HOURS)
        }
    } else null

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

    // Management server: dashboard, admin API and the device report endpoints.
    // With MANAGEMENT_HTTPS_PORT set, the same application also listens over TLS
    // with the server's own certificate — the one apps already pin — so devices
    // send their reports, and remote admins reach the dashboard, without
    // anything crossing the network in the clear. The sample host then
    // publishes the plain HTTP port on this machine only.
    val managementHttpsPort = System.getenv("MANAGEMENT_HTTPS_PORT")?.toIntOrNull()?.takeIf { it > 0 }
    // Without admin keys the network is the only thing between a stranger and
    // the admin API: listen on this machine only, unless MANAGEMENT_BIND says
    // where else (a container needs 0.0.0.0 and a host-side publish on
    // 127.0.0.1). With keys the default stays every interface.
    val anonymousAdmin = adminRegistry.isEmpty
    val managementBind = System.getenv("MANAGEMENT_BIND")?.trim()?.takeIf { it.isNotEmpty() }
        ?: if (anonymousAdmin) "127.0.0.1" else "0.0.0.0"
    val bindsEverywhere = runCatching { java.net.InetAddress.getByName(managementBind).isAnyLocalAddress }.getOrDefault(false)
    val bindsLoopback = runCatching { java.net.InetAddress.getByName(managementBind).isLoopbackAddress }.getOrDefault(false)
    if (anonymousAdmin && !bindsLoopback) {
        System.err.println("WARNING: ALLOW_ANONYMOUS_ADMIN=true with MANAGEMENT_BIND=$managementBind — the admin API has no key and is not " +
            "limited to this machine by its address. It answers only connections from loopback (or ANONYMOUS_ADMIN_PEERS, e.g. a container's gateway) " +
            "addressed to localhost (or MANAGEMENT_ALLOWED_HOSTS); the Config API ports serve no admin route.")
    }
    // Refused cross-site / wrong-Host admin requests: one audit entry a minute at most.
    val browserRefusals = com.example.pinvault.server.service.AuthFailureRecorder(
        auditLog, action = "admin_request_refused", what = "Admin request refused",
        attemptsLabel = "refused admin request"
    )
    com.example.pinvault.server.plugin.BrowserGuardRefusals.listener = { remote, method, path, reason ->
        browserRefusals.report(remote, method, path, reason = reason)
    }
    embeddedServer(Netty, applicationEnvironment {}, configure = {
        connector { host = managementBind; port = httpPort }
        // A specific address leaves loopback out: the approval replay and the
        // container health check still reach the server on 127.0.0.1.
        if (!bindsEverywhere && !bindsLoopback) connector { host = "127.0.0.1"; port = httpPort }
        if (managementHttpsPort != null) {
            val keyStore = KeyStore.getInstance("JKS")
            FileInputStream(serverKeystorePath).use { keyStore.load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
            sslConnector(
                keyStore = keyStore,
                keyAlias = "server",
                keyStorePassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() },
                privateKeyPassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() }
            ) { host = managementBind; port = managementHttpsPort }
            println("Management API also on https://$managementBind:$managementHttpsPort (server certificate)")
        }
    }) {
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
        // Markup that still slips into the page can neither submit a form
        // anywhere nor re-point relative URLs (form-action, base-uri); every
        // dashboard form is handled in script.
        install(DefaultHeaders) {
            header("X-Content-Type-Options", "nosniff")
            header("X-Frame-Options", "DENY")
            header("Referrer-Policy", "no-referrer")
            header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
            )
        }
        install(CallLogging)
        // Before anything that decides on the path (auth allowlist, approval gate).
        install(com.example.pinvault.server.plugin.EncodedPathGuard)
        // This server also listens on plain HTTP: the device endpoints that take a
        // token or hand out a key (the enrollment copy below) are served over TLS
        // only — MANAGEMENT_HTTPS_PORT, or a Config API port — or to this machine.
        install(com.example.pinvault.server.plugin.CleartextGuard)
        install(com.example.pinvault.server.plugin.DeviceRefusalLimit) {
            limiter = refusalLimiter
            refusals = refusalCutOffs
        }
        install(com.example.pinvault.server.plugin.ClientBodyLimit)
        // Other pages in an admin's browser: cross-site writes, form posts, and —
        // without admin keys — DNS rebinding (the Host must name this machine).
        install(com.example.pinvault.server.plugin.AdminBrowserGuard) {
            requireLocalHost = anonymousAdmin
            listenerPorts = setOfNotNull(httpPort, managementHttpsPort)
            allowedHosts = System.getenv("MANAGEMENT_ALLOWED_HOSTS").orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            allowedOrigins = System.getenv("ADMIN_ALLOWED_ORIGINS").orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        }
        install(com.example.pinvault.server.plugin.ApiKeyAuth) {
            failureLimit = adminAuthFailureLimit
            failureLimiter = adminFailureLimiter
        }
        installGovernance(management = true)
        // A generic answer with an error id; the detail goes to the log (ErrorPages.kt).
        install(StatusPages) { genericErrors() }

        routing {
            // Management server: tüm config API'lerin verilerine erişim
            // configApiId query param ile scoped: ?configApiId=default-tls
            certificateConfigRoutes("default-tls", pinConfigStore, historyStore, connectionStore, signingService, clientDeviceStore, hostClientCertStore = hostClientCertStore, enrollmentMode = enrollmentMode, deviceHostAclStore = deviceHostAclStore,
                signedConfigService = signedConfigService, keySetService = signingKeySetService,
                liveGate = liveGate, audit = auditLog, reportLimits = reportLimits)
            signingAdminRoutes(
                signingService, signedConfigService, signingKeySetService,
                actorOf = { it.adminName() },
                onKeysChanged = { event, summary, actor -> auditLog.record(event, summary, actor = actor) }
            )
            governanceRoutes(adminRegistry, auditLog, auditStore, approvalService, liveGate, signedConfigService)
            hostRoutes("default-tls", pinConfigStore, hostStore, historyStore, certService, mockServerManager, hostClientCertStore,
                liveGate = liveGate, audit = auditLog, planner = certPlanner, maxUploadBytes = adminUploadMaxBytes)
            // V2: per-Config-API scoped vault admin endpoints under
            // /api/v1/config-apis/{configApiId}/vault/...  — no more global
            // "default-tls"-fixed vault mount on the management server.
            scopedVaultAdminRoutes(vaultFileStore, vaultDistStore, vaultTokenStore, vaultTokenService,
                publicKeyStore = devicePublicKeyStore, audit = auditLog, maxFileBytes = vaultMaxFileBytes)
            adminVaultRoutes(db, deviceHostAclStore, configApiRegistry, audit = auditLog)

            // /api/v1/config/{configApiId}[/update], /api/v1/management/hosts/{configApiId}/generate-cert
            managementConfigRoutes(pinConfigStore, historyStore, hostStore, certService, liveGate, auditLog, certPlanner)

            get("/health") {
                call.respond(mapOf("status" to "ok"))
            }

            get("/api/v1/enrollment-mode") {
                call.respondText(
                    """{"mode":"$enrollmentMode","tokenRequired":${enrollmentMode != "open"},"openApplications":${enrollmentPolicyStore.openPolicy()?.acceptsNewDevices() == true}}""",
                    ContentType.Application.Json
                )
            }

            // The Config API's own TLS certificate and its pins (the apps' bootstrap pins).
            serverTlsPinRoutes(serverTlsPins, certPlanner, httpsPort, auditLog, adminUploadMaxBytes)

            // The setup wizard: production checklist from the environment, and the
            // public values (pins, keys, ports) an app's PinVault config is made of.
            setupRoutes(env = { System.getenv() }) {
                com.example.pinvault.server.route.SetupFacts(
                    configApis = configApiManager.getAll().map { com.example.pinvault.server.route.SetupFacts.Api(it.id, it.port, it.mode, true) } +
                        configApiManager.getAllStopped().map { com.example.pinvault.server.route.SetupFacts.Api(it.id, it.port, it.mode, false) },
                    bootstrapHost = com.example.pinvault.server.service.CertChangePlanner.BOOTSTRAP_HOST,
                    bootstrapPins = serverTlsPins.pins,
                    signingKeys = signingService.signers.map { it.publicKeyBase64 },
                    requiredSignatures = signingKeySetService.status().requiredSignatures,
                    recoveryKeys = System.getenv("RECOVERY_PUBLIC_KEYS")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty(),
                    clientCaPin = runCatching { certService.spkiSha256(certService.ensureClientCa().publicKey) }.getOrNull(),
                    recoveryPort = recoveryPort.takeIf { recoveryListener != null },
                    recoveryPins = serverCa?.pins.orEmpty(),
                    enrollmentMode = enrollmentMode,
                    attestationMode = enrollmentAttestationMode.name.lowercase(),
                    integrityMode = integrityMode.name.lowercase(),
                    configTtlSeconds = System.getenv("CONFIG_TTL_SECONDS")?.toLongOrNull() ?: 86_400
                )
            }

            // ── Config API Management ────────────────────────

            // Start, stop and delete Config API listeners; the listings the dashboard draws them from.
            configApiAdminRoutes(
                configApiManager, pinConfigStore, certService, configApiRegistry, hostStore, mockServerManager, auditLog,
                serverKeystorePath, moduleFor = { id, mode -> configApiModuleFor(id, mode) }
            )

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

            // What an app needs to reach the recovery door: port, the CA pins
            // to put under `<host>:<port>`, and how long its certificate lives.
            get("/api/v1/recovery-door") {
                val leaf = recoveryListener?.leaf
                val body = kotlinx.serialization.json.buildJsonObject {
                    put("enabled", kotlinx.serialization.json.JsonPrimitive(recoveryListener != null))
                    put("running", kotlinx.serialization.json.JsonPrimitive(recoveryListener?.isRunning == true))
                    put("port", kotlinx.serialization.json.JsonPrimitive(recoveryPort))
                    put("caPins", kotlinx.serialization.json.JsonArray(serverCa?.pins.orEmpty().map { kotlinx.serialization.json.JsonPrimitive(it) }))
                    put("caNotAfter", kotlinx.serialization.json.JsonPrimitive(serverCa?.certificate?.notAfter?.toInstant()?.toString()))
                    put("certificateNotAfter", kotlinx.serialization.json.JsonPrimitive(leaf?.notAfter?.toInstant()?.toString()))
                    put("clientCertTtlDays", kotlinx.serialization.json.JsonPrimitive(clientCertTtlDays))
                }
                call.respondText(body.toString(), ContentType.Application.Json)
            }

            // Server-made P12s, uploaded certificates and one-time enrollment tokens.
            clientCertAdminRoutes(
                certService, clientCertStore, clientIdentityStore, enrollmentTokenStore, auditLog,
                refreshMtlsTrust = { reason -> refreshMtlsTrust(reason, true) }, maxUploadBytes = adminUploadMaxBytes,
                serverMadeKeys = serverMadeKeys
            )

            // Revoke / forget a client identity; both also cut the device off the
            // vault (its tokens and keys) — see ClientCertRevocationRoutes.
            clientCertRevocationRoutes(clientCertStore, clientIdentityStore, certService, auditLog) { reason, restartMocks ->
                refreshMtlsTrust(reason, restartMocks)
            }

            // Enrollment codes many devices share, and the devices waiting for approval.
            enrollmentPolicyRoutes(enrollmentPolicyStore, clientCertStore, auditLog, enrollmentRequestTtl, openMaxPending, openRateLimit,
                approvalsRequired = approvalsRequired)

            // Test hook (ALLOW_TEST_HOOKS=true): the next certificate issued to
            // a client id gets this lifetime, so the Espresso suite can watch a
            // certificate run out in seconds instead of months.
            if (allowTestHooks) post("/api/v1/test-hooks/client-cert-ttl") {
                val json = try { Json.parseToJsonElement(call.receiveText()).jsonObject } catch (_: Exception) { null }
                val clientId = json?.get("clientId")?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }
                val ttlSeconds = json?.get("ttlSeconds")?.jsonPrimitive?.content?.toLongOrNull()
                if (clientId == null || !com.example.pinvault.server.route.isValidIdentifier(clientId) ||
                    ttlSeconds == null || ttlSeconds !in 30L..86_400L) {
                    return@post call.respondText("""{"error":"clientId and ttlSeconds (30..86400) are required"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
                testTtlOverrides[clientId] = java.time.Duration.ofSeconds(ttlSeconds)
                auditLog.record("test_hook_used", "Next certificate for $clientId will live $ttlSeconds s", target = clientId)
                call.respondText("""{"clientId":"$clientId","ttlSeconds":$ttlSeconds,"armed":true}""", ContentType.Application.Json)
            }

            // The management copy of enrollment (server-made P12, one-time token).
            // Never over plain HTTP from another machine: CleartextGuard answers
            // 403 tls_required before this runs — the token, the private key and
            // its password would cross the network readable (D2).
            post("/api/v1/client-certs/enroll") {
                // Server-made keys only: none at all with ENROLLMENT_P12=off or
                // ENROLLMENT_ATTESTATION=enforce — before the body is even read.
                if (!serverMadeKeys) {
                    return@post call.respondText(com.example.pinvault.server.route.CSR_REQUIRED_NO_P12, ContentType.Application.Json, HttpStatusCode.Forbidden)
                }
                // Read up to the body cap, whatever the headers declared (ClientBodyLimit).
                val body = call.receiveLimitedText() ?: return@post
                val json = try { Json.parseToJsonElement(body) as? kotlinx.serialization.json.JsonObject } catch (_: Exception) { null }
                    ?: return@post call.respondText("""{"error":"token gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                val token = json.string("token")
                    ?: return@post call.respondText("""{"error":"token gerekli"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
                val deviceAlias = json.string("deviceAlias")
                var deviceUid = json.string("deviceUid")

                val clientId = enrollmentTokenStore.validate(token)
                    ?: return@post call.respondText("""{"error":"Geçersiz veya kullanılmış token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
                val remote = call.request.origin.remoteAddress
                // As on the Config API copy: a token bound to a device (V20) enrolls that device only.
                val boundUid = enrollmentTokenStore.boundDeviceUid(token)
                if (boundUid != null) {
                    if (deviceUid == null) deviceUid = boundUid
                    if (deviceUid != boundUid) {
                        managementEnrollRefusals.refused(remote, clientId, "Enrollment of $clientId refused: the token is bound to another device", authenticated = true)
                        return@post call.respondText("""{"error":"device_uid_mismatch","message":"This token was issued for another device."}""",
                            ContentType.Application.Json, HttpStatusCode.Forbidden)
                    }
                }

                // Same rules as the Config API copy, all before the token is
                // spent: the device id is stored and matched against
                // X-Device-Id; a revoked id stays revoked (client_certs.add
                // would otherwise un-revoke it); one active identity per device.
                // Without the device id, an mTLS listener would refuse the
                // device's own X-Device-Id (DeviceIdBinding).
                if (deviceUid != null && !com.example.pinvault.server.route.isValidIdentifier(deviceUid)) {
                    return@post call.respondText("""{"error":"invalid_device_uid","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}""",
                        ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
                if (clientCertStore.get(clientId)?.revoked == true || clientIdentityStore.get(clientId)?.revoked == true) {
                    // The token was valid: per client id, as the Config API copy does.
                    managementEnrollRefusals.refused(remote, clientId, "Enrollment of revoked client id $clientId refused", authenticated = true)
                    return@post call.respondText(
                        """{"error":"revoked","message":"This client id was revoked. Ask an administrator for a new one."}""",
                        ContentType.Application.Json, HttpStatusCode.Forbidden
                    )
                }
                val holder = deviceUid?.let { clientCertStore.activeHolderOf(it, exceptId = clientId) }
                if (holder != null) {
                    managementEnrollRefusals.refused(remote, clientId, "Enrollment of $clientId refused: device $deviceUid is enrolled as $holder", authenticated = true)
                    return@post call.respondText(
                        """{"error":"device_already_enrolled","message":"This device is enrolled under another client id. Ask an administrator to revoke it, then retry with the same token."}""",
                        ContentType.Application.Json, HttpStatusCode.Conflict
                    )
                }
                // Spent before anything is issued, in one statement: a second
                // request racing with the same token gets 401, not a second P12.
                if (!enrollmentTokenStore.consume(token)) {
                    return@post call.respondText("""{"error":"Geçersiz veya kullanılmış token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
                }

                val wrapping = com.example.pinvault.server.service.P12Transfer.wrappingFor(call)
                // Issued by the client CA: nothing is added to the truststore.
                val result = certService.generateClientCertificate(clientId, wrapping.password)
                // Never over a revoked row: a revocation that landed after the checks above stays.
                if (!clientCertStore.addUnlessRevoked(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString(),
                        deviceAlias = deviceAlias, deviceUid = deviceUid,
                        // Proven only by the token's binding or the device id as the client id (V20).
                        deviceUidProven = deviceUid != null && (deviceUid == clientId || deviceUid == boundUid))) {
                    deviceUid?.let { clientCertStore.activeHolderOf(it, exceptId = clientId) }?.let { racing ->
                        return@post call.respondText(
                            """{"error":"device_already_enrolled","message":"This device is enrolled under another client id ($racing). Ask an administrator to revoke it, then retry."}""",
                            ContentType.Application.Json, HttpStatusCode.Conflict
                        )
                    }
                    return@post call.respondText(
                        """{"error":"revoked","message":"This client id was revoked. Ask an administrator for a new one."}""",
                        ContentType.Application.Json, HttpStatusCode.Forbidden
                    )
                }
                val p12Now = java.time.Instant.now().toString()
                // Replacing a CSR identity of the same id: its key is retired (as on the Config API copy).
                clientIdentityStore.supersede(clientId, p12Now).takeIf { it > 0 }?.let { retired ->
                    auditLog.record("client_cert_key_replaced", "$clientId re-enrolled with a server-made P12: its $retired previous key(s) retired",
                        target = clientId, actor = clientId, ip = call.request.origin.remoteAddress)
                }
                clientIdentityStore.recordServerMadeKey(clientId, result.spkiSha256, p12Now)
                // An older self-signed P12 of the id (its own trust anchor) leaves the truststore.
                if (com.example.pinvault.server.route.retireLegacyAnchor(certService, clientIdentityStore, clientId, result.spkiSha256, p12Now)) {
                    refreshMtlsTrust("old client certificate anchor removed: $clientId", true)
                }

                // Integrity header (H-05). The library refuses to install a P12
                // that arrives without X-P12-SHA256, so this management-port
                // copy of the enrollment endpoint must send it just like the
                // Config API copy in CertificateConfigRoute does — otherwise a
                // client pointed at :8090 fails enrollment outright.
                // A private key was made here and is leaving the server (as on the Config API copy).
                auditLog.record("client_cert_issued", "Certificate issued to $clientId as a server-made P12 (valid until ${result.validUntil})",
                    target = clientId, actor = clientId, ip = call.request.origin.remoteAddress,
                    detail = kotlinx.serialization.json.buildJsonObject {
                        put("format", kotlinx.serialization.json.JsonPrimitive("p12"))
                        put("fingerprint", kotlinx.serialization.json.JsonPrimitive(result.fingerprint))
                        put("notAfter", kotlinx.serialization.json.JsonPrimitive(result.validUntil))
                    })
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
        println("HTTP:         http://localhost:$httpPort (listening on $managementBind)")
        println("Config API:   https://localhost:$httpsPort (TLS)")
        println("Web UI:       http://localhost:$httpPort")
        println("Database:     $dbPath")
        if (enrollmentMode == "open") {
            println("Enrollment:   OPEN (WARNING — deviceId enrollment aktif, üretimde kullanmayın!)")
        } else {
            println("Enrollment:   TOKEN (güvenli — sadece enrollment token ile kayıt)")
        }
        println("Client certs: CSR over device keys, $clientCertTtlDays-day lifetime, renewal at POST /api/v1/client-certs/renew")
        if (recoveryPort > 0) println("Recovery:     https://localhost:$recoveryPort (TLS, renewal only — pin the server CA for <host>:$recoveryPort)")
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
