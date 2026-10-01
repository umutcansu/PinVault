package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.certificateBoundTo
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.DatabaseManager
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.test.*

/**
 * On an mTLS listener `X-Device-Id` may only name the device the client
 * certificate belongs to. It picks the per-device host ACL of a config fetch
 * and the device a `token` download is checked against, so a foreign id used
 * to show one enrolled device another's pins (pentest finding 6).
 */
class DeviceIdBindingTest {

    private val now = "2026-10-01T00:00:00Z"

    private lateinit var dbFile: File
    private lateinit var certs: ClientCertStore
    private lateinit var auditStore: AuditLogStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-device-id-", ".db").also { it.deleteOnExit() }
        val db = DatabaseManager(dbFile.absolutePath)
        certs = ClientCertStore(db)
        auditStore = AuditLogStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val start = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(start), Date(start - 60_000), Date(start + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    /** An mTLS listener as Main.kt wires it, with [presented] as the verified client certificate. */
    private fun ApplicationTestBuilder.listener(presented: X509Certificate?) {
        if (presented != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
            })
        }
        install(DeviceIdBinding) {
            isBound = { certClientId, deviceId -> certificateBoundTo(certClientId, deviceId, certs) }
            refusals = AuthFailureRecorder(AuditLog(auditStore, null), action = "device_id_refused")
        }
        routing {
            get("/api/v1/certificate-config") { call.respondText("pins") }
            get("/api/v1/vault/{key}") { call.respondText("file") }
        }
    }

    private suspend fun ApplicationTestBuilder.config(deviceId: String?) =
        client.get("/api/v1/certificate-config") { deviceId?.let { header("X-Device-Id", it) } }

    @Test
    fun `a device may name the device id it enrolled with`() = testApplication {
        certs.add("tablet-07", "PinVault Client: tablet-07", "fp", now, deviceUid = "3f2a9c0d81b4e6a7")
        listener(clientCert("tablet-07"))
        assertEquals("pins", config("3f2a9c0d81b4e6a7").bodyAsText())
    }

    @Test
    fun `another device's id is refused on config and file requests`() = testApplication {
        certs.add("tablet-07", "PinVault Client: tablet-07", "fp", now, deviceUid = "3f2a9c0d81b4e6a7")
        certs.add("tablet-08", "PinVault Client: tablet-08", "fp", now, deviceUid = "9b1e44c07d2a5f10")
        listener(clientCert("tablet-08"))

        val pins = config("3f2a9c0d81b4e6a7")
        assertEquals(HttpStatusCode.Forbidden, pins.status)
        assertTrue(pins.bodyAsText().contains("device_identity_mismatch"))
        val file = client.get("/api/v1/vault/model") { header("X-Device-Id", "3f2a9c0d81b4e6a7") }
        assertEquals(HttpStatusCode.Forbidden, file.status)
        assertEquals(listOf("device_id_refused"), auditStore.page(10, 0).map { it.action })
    }

    @Test
    fun `under auto-enrollment the client id is the device id`() = testApplication {
        listener(clientCert("3f2a9c0d81b4e6a7"))
        assertEquals("pins", config("3f2a9c0d81b4e6a7").bodyAsText())
        assertEquals(HttpStatusCode.Forbidden, config("9b1e44c07d2a5f10").status)
    }

    @Test
    fun `a certificate without a recorded device may only name its client id`() = testApplication {
        certs.add("legacy-1", "PinVault Client: legacy-1", "fp", now)
        listener(clientCert("legacy-1"))
        assertEquals("pins", config("legacy-1").bodyAsText())
        assertEquals(HttpStatusCode.Forbidden, config("3f2a9c0d81b4e6a7").status)
    }

    @Test
    fun `a revoked certificate names no device`() = testApplication {
        certs.add("tablet-07", "PinVault Client: tablet-07", "fp", now, deviceUid = "3f2a9c0d81b4e6a7")
        certs.revoke("tablet-07")
        listener(clientCert("tablet-07"))
        assertEquals(HttpStatusCode.Forbidden, config("3f2a9c0d81b4e6a7").status)
    }

    @Test
    fun `a malformed id is refused and kept out of the audit log`() = testApplication {
        listener(clientCert("tablet-08"))
        assertEquals(HttpStatusCode.Forbidden, config("<img src=x onerror=alert(1)>").status)
        val entry = auditStore.page(10, 0).single()
        assertFalse(entry.summary.contains("<img"))
        assertTrue(entry.summary.contains("malformed X-Device-Id"))
    }

    @Test
    fun `without the header the routes decide`() = testApplication {
        listener(clientCert("tablet-08"))
        assertEquals("pins", config(null).bodyAsText())
    }

    @Test
    fun `without a certificate the header is the device's own claim`() = testApplication {
        listener(null)
        assertEquals("pins", config("3f2a9c0d81b4e6a7").bodyAsText())
    }
}
