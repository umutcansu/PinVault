package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.plugin.AdminAudit
import com.example.pinvault.server.plugin.AdminRegistry
import com.example.pinvault.server.plugin.ApiKeyAuth
import com.example.pinvault.server.plugin.ApprovalGate
import com.example.pinvault.server.route.ServerTlsPins
import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertAdminRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.route.governanceRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.route.managementConfigRoutes
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.serverTlsPinRoutes
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ChangeDescriber
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.EgressFilter
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.store.*
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest

/**
 * The management listener as Main.kt builds it — API keys, the audit context,
 * the approval gate with the REAL change describer, and every route that is
 * under two-person approval — on a real socket, because an approval replays
 * the stored request through the server's own port.
 */
class GovernanceHarness(
    val dir: File,
    required: Int = 2,
    exempt: Set<String> = emptySet(),
    val liveGate: LiveCertificateGate = LiveCertificateGate(LiveCertificateGate.Mode.OFF),
    adminBodyMax: Long = 1L * 1024 * 1024,
    vaultMax: Long = 4L * 1024 * 1024
) : AutoCloseable {
    val scope = "default-tls"
    val db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
    val pins = PinConfigStore(db)
    val history = PinConfigHistoryStore(db)
    val hosts = HostStore(db)
    val auditStore = AuditLogStore(db)
    val audit = AuditLog(auditStore, null)
    val certService = CertificateService(File(dir, "certs").also { it.mkdirs() }, egress = EgressFilter(allowPrivate = true))
    val clientCerts = ClientCertStore(db)
    val identities = ClientIdentityStore(db)
    val enrollmentTokens = EnrollmentTokenStore(db)
    val policies = EnrollmentPolicyStore(db)
    val vaultFiles = VaultFileStore(db)
    val vaultTokens = VaultFileTokenStore(db)
    val deviceKeys = DevicePublicKeyStore(db)
    val registry = ConfigApiRegistry(db)
    val changeRequests = ChangeRequestStore(db)
    val serverPins = ServerTlsPins(certService, File(dir, "server.pins"), "demo-server", emptyList())
    val planner = CertChangePlanner(certService, pins, hosts, "demo-server") { serverPins.pins }
    val trustRefreshes = mutableListOf<String>()
    val port: Int = java.net.ServerSocket(0).use { it.localPort }

    private fun stateOf(scope: String): String =
        pins.load(scope).pins.sortedBy { it.hostname }.joinToString("\n") { "${it.hostname}|${it.version}|${it.sha256.sorted()}" }

    val describer = ChangeDescriber(pins, planner, liveGate, ::stateOf, vaultFiles, vaultTokens, audit = audit)
    val approvals = ApprovalService(
        store = changeRequests, audit = audit, required = required, managementPort = port,
        describe = describer::describe, stateHash = ::stateOf, exempt = exempt
    )

    private val signing = ConfigSigningService(File(dir, "k.pem"))
    private val server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(ApiKeyAuth) { registry = admins(); allowAnonymous = false }
        install(AdminAudit) { this.audit = this@GovernanceHarness.audit }
        install(ApprovalGate) {
            this.approvals = this@GovernanceHarness.approvals
            maxBodyBytes = { op -> if (op == "vault_upload") vaultMax else adminBodyMax }
        }
        routing {
            certificateConfigRoutes(scope, pins, history, ConnectionHistoryStore(db), signing, ClientDeviceStore(db), liveGate = liveGate, audit = audit)
            governanceRoutes(admins(), audit, auditStore, approvals, liveGate, SignedConfigService(signing))
            hostRoutes(scope, pins, hosts, history, certService, MockServerManager(), HostClientCertStore(db),
                liveGate = liveGate, audit = audit, planner = planner, maxUploadBytes = adminBodyMax)
            managementConfigRoutes(pins, history, hosts, certService, liveGate, audit, planner)
            serverTlsPinRoutes(serverPins, planner, 8443, audit, adminBodyMax)
            clientCertAdminRoutes(certService, clientCerts, identities, enrollmentTokens, audit, { trustRefreshes += it }, adminBodyMax)
            enrollmentPolicyRoutes(policies, clientCerts, audit, approvalsRequired = approvals.required)
            scopedVaultAdminRoutes(vaultFiles, VaultDistributionStore(db), vaultTokens, VaultAccessTokenService(vaultTokens),
                publicKeyStore = deviceKeys, audit = audit, maxFileBytes = vaultMax)
            adminVaultRoutes(db, DeviceHostAclStore(db), registry, audit)
        }
    }.start(wait = false)

    override fun close() {
        server.stop(100, 1000)
    }

    class Answer(val status: Int, val body: String, val bytes: ByteArray, val headers: java.net.http.HttpHeaders) {
        val json: JsonObject get() = Json.parseToJsonElement(body).jsonObject
        val changeRequestId: Long get() = json["changeRequestId"]!!.jsonPrimitive.long
    }

    private val http = HttpClient.newHttpClient()

    fun call(
        method: String, path: String, key: String, body: ByteArray? = null,
        contentType: String = "application/json", headers: Map<String, String> = emptyMap()
    ): Answer {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$port$path"))
            .header("X-API-Key", key)
            .apply { if (body != null) header("Content-Type", contentType) }
            .apply { headers.forEach { (n, v) -> header(n, v) } }
            .method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofByteArray(body))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        return Answer(response.statusCode(), response.body().toString(Charsets.UTF_8), response.body(), response.headers())
    }

    fun call(method: String, path: String, key: String, json: String): Answer = call(method, path, key, json.toByteArray())

    fun approve(id: Long, key: String = BOB): Answer = call("POST", "/api/v1/change-requests/$id/approve", key)

    fun changeRequest(id: Long): ChangeRequest = changeRequests.get(id)!!

    fun detail(id: Long): JsonObject = Json.parseToJsonElement(changeRequest(id).detail).jsonObject

    fun actions(): List<String> = auditStore.page(200, 0).map { it.action }

    fun seedHost(hostname: String, vararg scopes: String = arrayOf(scope)): List<String> {
        val generated = certService.generateCertificate(hostname.replace(".", "_"), hostname)
        for (s in scopes) {
            hosts.save(HostRecord(hostname, s, generated.keystorePath, generated.validUntil, null, "2026-01-01T00:00:00Z"))
            val config = pins.load(s)
            pins.save(s, config.copy(pins = config.pins + HostPin(hostname, generated.sha256Pins, version = 1)))
        }
        return generated.sha256Pins
    }

    fun pinsOf(hostname: String, scope: String = this.scope): List<String>? =
        pins.load(scope).pins.find { it.hostname == hostname }?.sha256

    companion object {
        const val ALICE = "alice-key"
        const val BOB = "bob-key"
        const val SHARED = "shared-key"

        private fun sha256Hex(text: String) =
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        fun admins() = AdminRegistry.fromEnv(
            mapOf("API_KEY" to SHARED, "ADMIN_KEYS" to "alice:${sha256Hex(ALICE)},bob:${sha256Hex(BOB)}")
        )

        /** A `multipart/form-data` body: text fields and one file part. */
        fun multipart(fields: Map<String, String>, file: ByteArray?, fileName: String = "upload.bin"): Pair<String, ByteArray> {
            val boundary = "----pinvault-test-${System.nanoTime()}"
            val out = java.io.ByteArrayOutputStream()
            for ((name, value) in fields) {
                out.write("--$boundary\r\nContent-Disposition: form-data; name=\"$name\"\r\n\r\n$value\r\n".toByteArray())
            }
            if (file != null) {
                out.write("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$fileName\"\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray())
                out.write(file)
                out.write("\r\n".toByteArray())
            }
            out.write("--$boundary--\r\n".toByteArray())
            return "multipart/form-data; boundary=$boundary" to out.toByteArray()
        }

        fun emptyConfig() = PinConfig(pins = emptyList())
    }
}

/** Minimal PKI and a TLS listener whose chain can be swapped while it runs. */
object TestPki {
    class Ca(val keys: java.security.KeyPair, val cert: java.security.cert.X509Certificate)

    fun keys(): java.security.KeyPair = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    fun ca(name: String): Ca = keys().let { k -> Ca(k, build(name, k.public, name, k.private, ca = true)) }

    fun pin(cert: java.security.cert.X509Certificate): String = java.util.Base64.getEncoder()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    fun pem(cert: java.security.cert.X509Certificate): ByteArray =
        ("-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
            "\n-----END CERTIFICATE-----\n").toByteArray()

    /**
     * A certificate for [key]. [ca]: basicConstraints CA + keyCertSign. [keyCertSign] alone: an end-entity
     * that may sign certificates. [eku]: extended key usages (OIDs); null = none.
     */
    fun build(
        subject: String, key: java.security.PublicKey, issuer: String, signer: java.security.PrivateKey,
        ca: Boolean = false, keyCertSign: Boolean = ca, eku: List<String>? = null, basicConstraints: Boolean = true,
        notAfter: java.util.Date = java.util.Date(System.currentTimeMillis() + 86_400_000)
    ): java.security.cert.X509Certificate {
        val builder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            org.bouncycastle.asn1.x500.X500Name(issuer), java.math.BigInteger.valueOf(System.nanoTime()),
            java.util.Date(System.currentTimeMillis() - 120_000), notAfter,
            org.bouncycastle.asn1.x500.X500Name(subject), key
        )
        if (basicConstraints) builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(ca))
        if (keyCertSign) builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
            org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign or org.bouncycastle.asn1.x509.KeyUsage.digitalSignature))
        if (eku != null) builder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false,
            org.bouncycastle.asn1.x509.ExtendedKeyUsage(eku.map { org.bouncycastle.asn1.x509.KeyPurposeId.getInstance(org.bouncycastle.asn1.ASN1ObjectIdentifier(it)) }.toTypedArray()))
        val holder = builder.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(signer))
        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder)
    }

    /** A leaf for `localhost` issued by [issuer], with its key. */
    fun leaf(issuer: Ca, name: String = "CN=localhost"): Pair<java.security.KeyPair, java.security.cert.X509Certificate> {
        val k = keys()
        return k to build(name, k.public, issuer.cert.subjectX500Principal.name, issuer.keys.private)
    }

    /** Accepts TLS handshakes on a loopback port, serving whatever [serve] was last given; counts them. */
    class SwitchableTlsServer : AutoCloseable {
        @Volatile private var context: javax.net.ssl.SSLContext? = null
        private val plain = java.net.ServerSocket(0, 20, java.net.InetAddress.getByName("127.0.0.1"))
        val handshakes = java.util.concurrent.atomic.AtomicInteger()
        val port: Int get() = plain.localPort
        val url: String get() = "https://127.0.0.1:$port"

        fun serve(key: java.security.PrivateKey, chain: Array<java.security.cert.X509Certificate>) {
            val ks = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null); setKeyEntry("s", key, "pw".toCharArray(), chain) }
            val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "pw".toCharArray()) }
            context = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        }

        init {
            Thread {
                while (!plain.isClosed) {
                    try {
                        val socket = plain.accept()
                        handshakes.incrementAndGet()
                        (context!!.socketFactory.createSocket(socket, null, socket.port, true) as javax.net.ssl.SSLSocket).use {
                            it.useClientMode = false
                            it.startHandshake()
                        }
                    } catch (_: Exception) { }
                }
            }.apply { isDaemon = true }.start()
        }

        override fun close() = plain.close()
    }
}
