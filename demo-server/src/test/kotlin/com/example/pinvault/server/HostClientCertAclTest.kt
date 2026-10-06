package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import kotlin.test.*

/**
 * The host client certificate download honours the device host ACL (D3). It
 * handed every host's client private key in the scope to any enrolled device,
 * whatever hosts that device was allowed pins for.
 */
class HostClientCertAclTest {

    private val scope = "mtls-api"
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var acl: DeviceHostAclStore
    private lateinit var hostCerts: HostClientCertStore
    private lateinit var clientCerts: ClientCertStore
    private lateinit var signingFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-hostacl-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        acl = DeviceHostAclStore(db)
        hostCerts = HostClientCertStore(db)
        clientCerts = ClientCertStore(db)
        signingFile = File.createTempFile("pinvault-hostacl-signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        for (host in listOf("payments.bank.example", "hr.bank.example")) {
            hostCerts.save(host, scope, "p12 of $host".toByteArray(), 1, "CN=$host", "fp")
        }
        hostCerts.save("payments.bank.example", "other-api", "p12 of another scope".toByteArray(), 1, "CN=x", "fp")
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); signingFile.delete() }

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    /** An mTLS Config API as [clientId]'s certificate sees it. */
    private fun ApplicationTestBuilder.configureApp(clientId: String, requireGrant: Boolean = false) {
        val presented = clientCert(clientId)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(createApplicationPlugin("FakePeerCert") {
            onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
        })
        routing {
            certificateConfigRoutes(scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(signingFile), ClientDeviceStore(db), clientCertStore = clientCerts,
                hostClientCertStore = hostCerts, configApiMode = "mtls", deviceHostAclStore = acl,
                requireHostCertGrant = requireGrant)
        }
    }

    private suspend fun ApplicationTestBuilder.download(host: String) = client.get("/api/v1/client-certs/$host/download")

    @Test
    fun `a device downloads the client certificate of the hosts its ACL allows, and no other`() = testApplication {
        // The scope's default ACL allows every device the payments host; HR is granted per device.
        acl.addDefault(scope, "payments.bank.example")
        acl.grant(scope, "android-hr-1", "hr.bank.example", Instant.now().toString())
        clientCerts.add("field-tablet", "PinVault Client: field-tablet", "fp", Instant.now().toString(), deviceUid = "android-field-7")
        configureApp("field-tablet")

        val allowed = download("payments.bank.example")
        assertEquals(HttpStatusCode.OK, allowed.status)
        assertEquals("p12 of payments.bank.example", allowed.bodyAsText())

        val denied = download("hr.bank.example")
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertTrue(denied.bodyAsText().contains("host_not_allowed"))
        assertFalse(denied.bodyAsText().contains("p12 of"))
        // A host that has no certificate is the same 403: the answer does not list the scope's hosts.
        assertEquals(HttpStatusCode.Forbidden, download("no-such-host.example").status)
    }

    @Test
    fun `a per-device grant counts for the certificate's device id and for its client id`() {
        testApplication {
            // Token enrollment: the client id is the administrator's, the grant is on the
            // device id — which counts only when it is proven (V20: a token bound to it,
            // an attested key).
            acl.grant(scope, "android-hr-1", "hr.bank.example", Instant.now().toString())
            clientCerts.addUnlessRevoked("hr-tablet", "PinVault Client: hr-tablet", "fp", Instant.now().toString(), deviceUid = "android-hr-1", deviceUidProven = true)
            configureApp("hr-tablet")
            assertEquals(HttpStatusCode.OK, download("hr.bank.example").status)
            assertEquals(HttpStatusCode.Forbidden, download("payments.bank.example").status)
        }
        testApplication {
            // A certificate whose enrollment only NAMED the device does not inherit its grants.
            clientCerts.add("claimer", "PinVault Client: claimer", "fp", Instant.now().toString(), deviceUid = "android-hr-2")
            acl.grant(scope, "android-hr-2", "hr.bank.example", Instant.now().toString())
            configureApp("claimer")
            assertEquals(HttpStatusCode.Forbidden, download("hr.bank.example").status)
        }
        testApplication {
            // Open enrollment: the client id is the device id.
            configureApp("android-hr-1")
            assertEquals(HttpStatusCode.OK, download("hr.bank.example").status)
        }
        testApplication {
            // A revoked certificate's device id counts for nothing else here: another device asks.
            configureApp("someone-else")
            assertEquals(HttpStatusCode.Forbidden, download("hr.bank.example").status)
        }
    }

    @Test
    fun `the device id header cannot widen what the certificate is allowed`() = testApplication {
        acl.grant(scope, "android-hr-1", "hr.bank.example", Instant.now().toString())
        configureApp("field-tablet")
        val response = client.get("/api/v1/client-certs/hr.bank.example/download") { header("X-Device-Id", "android-hr-1") }
        assertEquals(HttpStatusCode.Forbidden, response.status)
    }

    @Test
    fun `a scope without any ACL keeps serving every enrolled device`() = testApplication {
        // An ACL in another scope does not switch this one on.
        acl.addDefault("other-api", "payments.bank.example")
        assertFalse(acl.isConfigured(scope))
        configureApp("field-tablet")
        assertEquals(HttpStatusCode.OK, download("payments.bank.example").status)
        assertEquals(HttpStatusCode.OK, download("hr.bank.example").status)
        assertEquals(HttpStatusCode.NotFound, download("no-such-host.example").status)
    }

    @Test
    fun `with HOST_CLIENT_CERT_REQUIRE_GRANT a scope without any ACL serves the certificate to nobody`() {
        testApplication {
            // No ACL in this scope: the host's shared private key stays on the server,
            // and the refusal is the same 403 whether or not the host has a certificate.
            assertFalse(acl.isConfigured(scope))
            configureApp("field-tablet", requireGrant = true)
            val refused = download("payments.bank.example")
            assertEquals(HttpStatusCode.Forbidden, refused.status)
            assertTrue(refused.bodyAsText().contains("host_not_allowed"))
            assertFalse(refused.bodyAsText().contains("p12 of"))
            assertEquals(HttpStatusCode.Forbidden, download("no-such-host.example").status)
        }
        testApplication {
            // With an ACL the grants decide, exactly as without the switch.
            acl.addDefault(scope, "payments.bank.example")
            configureApp("field-tablet", requireGrant = true)
            assertEquals(HttpStatusCode.OK, download("payments.bank.example").status)
            assertEquals(HttpStatusCode.Forbidden, download("hr.bank.example").status)
        }
    }

    @Test
    fun `isConfigured sees default entries and per-device grants, per scope`() {
        assertFalse(acl.isConfigured(scope))
        acl.grant(scope, "android-1", "a.example", Instant.now().toString())
        assertTrue(acl.isConfigured(scope))
        acl.revoke(scope, "android-1", "a.example")
        assertFalse(acl.isConfigured(scope))
        acl.addDefault(scope, "a.example")
        assertTrue(acl.isConfigured(scope))
        assertFalse(acl.isConfigured("other-api"))
    }
}
