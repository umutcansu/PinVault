package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ClientCertRenewalResponse
import io.github.umutcansu.pinvault.model.ClientCertRenewalResult
import io.github.umutcansu.pinvault.model.ClientCertRenewalVia
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.SecurePreferences
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLHandshakeException

/**
 * The renewal decision and the renewal round trip, with a BouncyCastle
 * "server CA" standing in for the demo server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ClientCertRenewerTest {

    private val label = "renew-" + System.nanoTime()
    private val key = ClientIdentityKeyProvider.software(label)
    private lateinit var store: ClientCertSecureStore
    private lateinit var ca: KeyPair
    private lateinit var caCert: X509Certificate
    private var now = System.currentTimeMillis()
    private var reloads = 0

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) Security.addProvider(BouncyCastleProvider())
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences(label, Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, label, "ns", SoftwarePrefsCipher()))
        ca = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        caCert = sign(X500Name("CN=PinVault Client CA"), ca.public, notBefore = now - DAY, notAfter = now + 3650 * DAY, issuer = X500Name("CN=PinVault Client CA"))
        key.clear()
        key.ensureKeyPair()
    }

    private fun block(threshold: Double = 1.0 / 3, renewalUrl: String? = null, enabled: Boolean = true) =
        ConfigApiBlock(
            id = "blk", configUrl = "https://config.test/", bootstrapPins = emptyList(), clientCertLabel = label,
            clientCertRenewalThreshold = threshold, renewalUrl = renewalUrl, clientCertRenewalEnabled = enabled
        )

    private fun sign(
        subject: X500Name, publicKey: PublicKey, notBefore: Long, notAfter: Long,
        issuer: X500Name = X500Name("CN=PinVault Client CA"), signerKey: KeyPair = ca
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()), Date(notBefore), Date(notAfter), subject, publicKey)
        val signer = JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(signerKey.private)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
    }

    private fun leafFor(publicKey: PublicKey, notBefore: Long, notAfter: Long, clientId: String = "dev-1") =
        sign(X500Name("CN=PinVault Client: $clientId"), publicKey, notBefore, notAfter)

    private fun storeLeaf(notBefore: Long, notAfter: Long) {
        val leaf = leafFor(key.publicKey(), notBefore, notAfter)
        store.saveChain(label, listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(caCert)))
    }

    /** A fake backend that issues over whatever key the CSR carries. */
    private inner class FakeApi(
        private val onRenew: (clientId: String, csr: PKCS10CertificationRequest, recoveryUrl: String?) -> ClientCertRenewalResponse
    ) : CertificateConfigApi {
        val calls = mutableListOf<String?>()
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int) = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) = EnrollmentResult(ByteArray(0))
        override suspend fun renewClientCert(clientId: String, csrDer: ByteArray, recoveryUrl: String?): ClientCertRenewalResponse {
            calls.add(recoveryUrl)
            return onRenew(clientId, PKCS10CertificationRequest(csrDer), recoveryUrl)
        }
    }

    private fun issuing(ttlDays: Long = 90): FakeApi = FakeApi { _, csr, _ ->
        val pub = org.bouncycastle.jce.provider.BouncyCastleProvider().let {
            java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(csr.subjectPublicKeyInfo.encoded))
        }
        val leaf = leafFor(pub, now - 3600_000, now + ttlDays * DAY)
        ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(caCert)))
    }

    private fun renewer(api: CertificateConfigApi, block: ConfigApiBlock = block()) =
        ClientCertRenewer(block, store, { key }, { api }, { reloads++ }, { now })

    // ── decide ──────────────────────────────────────────────────────────

    @Test
    fun `decide — fresh, past threshold, expired`() {
        val r = renewer(issuing())
        val fresh = leafFor(key.publicKey(), now - DAY, now + 89 * DAY)
        assertEquals(ClientCertRenewer.Decision.None, r.decide(fresh, now, 1.0 / 3))

        val near = leafFor(key.publicKey(), now - 61 * DAY, now + 29 * DAY)     // 29/90 < 1/3
        assertEquals(ClientCertRenewer.Decision.Renew, r.decide(near, now, 1.0 / 3))
        assertEquals(ClientCertRenewer.Decision.None, r.decide(near, now, 0.25))  // 0.32 > 0.25

        val expired = leafFor(key.publicKey(), now - 100 * DAY, now - 1)
        assertEquals(ClientCertRenewer.Decision.Recover, r.decide(expired, now, 1.0 / 3))
    }

    // ── renewIfNeeded ───────────────────────────────────────────────────

    @Test
    fun `nothing stored, P12 stored, or renewal disabled → NotApplicable`() = runTest {
        assertEquals(ClientCertRenewalResult.NotApplicable, renewer(issuing()).renewIfNeeded())

        store.save(label, byteArrayOf(1, 2, 3))
        assertEquals(ClientCertRenewalResult.NotApplicable, renewer(issuing()).renewIfNeeded())

        storeLeaf(now - 80 * DAY, now + 10 * DAY)
        val api = issuing()
        assertEquals(ClientCertRenewalResult.NotApplicable, renewer(api, block(enabled = false)).renewIfNeeded())
        assertTrue(api.calls.isEmpty())
        // force still works with renewal disabled
        assertTrue(renewer(api, block(enabled = false)).renewIfNeeded(force = true) is ClientCertRenewalResult.Renewed)
    }

    @Test
    fun `fresh certificate → NotNeeded without a request`() = runTest {
        storeLeaf(now - DAY, now + 89 * DAY)
        val api = issuing()
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.NotNeeded
        assertEquals((now + 89 * DAY).toDouble(), result.notAfterEpochMs.toDouble(), 1000.0)
        assertTrue(api.calls.isEmpty())
        assertEquals(0, reloads)
    }

    @Test
    fun `near expiry → renewed over mTLS, chain replaced, clients reloaded`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val api = issuing()
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Renewed

        assertEquals(ClientCertRenewalVia.MTLS, result.via)
        assertEquals(listOf<String?>(null), api.calls)
        assertEquals(1, reloads)
        val stored = Pkcs10Csr.parsePemChain(store.loadChain(label)!!)
        assertEquals(result.notAfterEpochMs, stored[0].notAfter.time)
        assertEquals((now + 90 * DAY).toDouble(), stored[0].notAfter.time.toDouble(), 1000.0)
        assertEquals("dev-1", ClientCertRenewer.clientIdOf(stored[0]))
    }

    @Test
    fun `expired → straight to the recovery URL`() = runTest {
        storeLeaf(now - 100 * DAY, now - 1)
        val api = issuing()
        val result = renewer(api, block(renewalUrl = "https://recover.test/")).renewIfNeeded() as ClientCertRenewalResult.Renewed

        assertEquals(ClientCertRenewalVia.RECOVERY, result.via)
        assertEquals(listOf<String?>("https://recover.test/"), api.calls)
    }

    @Test
    fun `recovery URL defaults to the block URL`() = runTest {
        storeLeaf(now - 100 * DAY, now - 1)
        val api = issuing()
        renewer(api).renewIfNeeded()
        assertEquals(listOf<String?>("https://config.test/"), api.calls)
    }

    @Test
    fun `handshake refused on mTLS → retried over recovery once`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val good = issuing()
        val api = FakeApi { clientId, csr, url ->
            if (url == null) throw SSLHandshakeException("Handshake failed")
            kotlinx.coroutines.runBlocking { good.renewClientCert(clientId, csr.encoded, url) }
        }
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Renewed
        assertEquals(ClientCertRenewalVia.RECOVERY, result.via)
        assertEquals(listOf<String?>(null, "https://config.test/"), api.calls)
    }

    @Test
    fun `a pin failure is not a client-cert refusal`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val api = FakeApi { _, _, _ ->
            throw SSLHandshakeException("pin").apply { initCause(java.security.cert.CertificateException("Pin mismatch")) }
        }
        val result = renewer(api).renewIfNeeded()
        assertTrue(result is ClientCertRenewalResult.Failed)
        assertEquals(listOf<String?>(null), api.calls)
        assertFalse(ClientCertRenewer.isClientCertRefusal(java.io.IOException("x")))
        assertTrue(ClientCertRenewer.isClientCertRefusal(SSLHandshakeException("refused")))
    }

    @Test
    fun `reenroll_required is surfaced and the stored chain is kept`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val api = FakeApi { _, _, _ -> ClientCertRenewalResponse.ReenrollRequired("revoked") }
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.ReenrollRequired
        assertEquals("revoked", result.reason)
        assertEquals(before, store.loadChain(label))
        assertEquals(0, reloads)
    }

    @Test
    fun `an issued chain over another key is refused`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val api = FakeApi { _, _, _ ->
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leafFor(other.public, now, now + 90 * DAY)), Pkcs10Csr.toPem(caCert)))
        }
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(result.reason, result.reason.contains("device's key"))
        assertEquals(before, store.loadChain(label))
    }

    @Test
    fun `an expired issued chain and a chain that does not verify are refused`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val expired = FakeApi { _, _, _ ->
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 2 * DAY, now - DAY)), Pkcs10Csr.toPem(caCert)))
        }
        assertTrue(renewer(expired).renewIfNeeded() is ClientCertRenewalResult.Failed)

        val rogueCa = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val rogue = FakeApi { _, _, _ ->
            val leaf = sign(X500Name("CN=PinVault Client: dev-1"), key.publicKey(), now, now + 90 * DAY, signerKey = rogueCa)
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(caCert)))
        }
        assertTrue(renewer(rogue).renewIfNeeded() is ClientCertRenewalResult.Failed)
        assertEquals(0, reloads)
    }

    @Test
    fun `a chain from another CA is refused even when it ships its own CA`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val rogueCa = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val rogueName = X500Name("CN=Rogue CA")
        val rogueCaCert = sign(rogueName, rogueCa.public, now - DAY, now + 3650 * DAY, issuer = rogueName, signerKey = rogueCa)
        val api = FakeApi { _, _, _ ->
            val leaf = sign(X500Name("CN=PinVault Client: dev-1"), key.publicKey(), now, now + 90 * DAY, issuer = rogueName, signerKey = rogueCa)
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(rogueCaCert)))
        }
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(result.reason, result.reason.contains("not from the CA"))
        assertEquals(before, store.loadChain(label))
        assertEquals(0, reloads)
    }

    @Test
    fun `backend without renewal → NotApplicable`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val api = FakeApi { _, _, _ -> ClientCertRenewalResponse.Unsupported }
        assertEquals(ClientCertRenewalResult.NotApplicable, renewer(api).renewIfNeeded())
    }

    @Test
    fun `chain without its key → NotApplicable`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        key.clear()
        assertEquals(ClientCertRenewalResult.NotApplicable, renewer(issuing()).renewIfNeeded())
        assertNull(null)
    }

    private companion object {
        const val DAY = 24 * 3600_000L
    }
}
