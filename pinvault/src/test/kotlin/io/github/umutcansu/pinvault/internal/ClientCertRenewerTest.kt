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

    private fun block(
        threshold: Double = 1.0 / 3, renewalUrl: String? = null, enabled: Boolean = true,
        caPins: List<String> = emptyList(), maxLifetimeDays: Int = ConfigApiBlock.DEFAULT_MAX_CLIENT_CERT_LIFETIME_DAYS
    ) =
        ConfigApiBlock(
            id = "blk", configUrl = "https://config.test/", bootstrapPins = emptyList(), clientCertLabel = label,
            clientCertRenewalThreshold = threshold, renewalUrl = renewalUrl, clientCertRenewalEnabled = enabled,
            clientCaPins = caPins, maxClientCertLifetimeDays = maxLifetimeDays
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

    /** Leaves the renewer reported as refused over mTLS (see onRefusedOverMtls). */
    private val refusedOverMtls = mutableListOf<X509Certificate>()

    private fun renewer(api: CertificateConfigApi, block: ConfigApiBlock = block()) =
        ClientCertRenewer(block, store, { key }, { api }, { reloads++ }, { now }, onRefusedOverMtls = { refusedOverMtls += it })

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
        // TLS 1.3: the server's alert arrives after the handshake, on the first read.
        assertTrue(ClientCertRenewer.isClientCertRefusal(javax.net.ssl.SSLProtocolException("Read error: SSLV3_ALERT_BAD_CERTIFICATE")))
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
    fun `only a refusal over mTLS speaks about the identity, never one from the recovery door`() = runTest {
        // Over the block's own mTLS connection: the identity was presented.
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val refuse = FakeApi { _, _, _ -> ClientCertRenewalResponse.ReenrollRequired("revoked") }
        assertTrue(renewer(refuse).renewIfNeeded() is ClientCertRenewalResult.ReenrollRequired)
        assertEquals(1, refusedOverMtls.size)
        assertEquals("the leaf that was to be presented", "dev-1", ClientCertRenewer.clientIdOf(refusedOverMtls.single()))

        // Expired: straight to the recovery door (TLS, no client certificate).
        refusedOverMtls.clear()
        storeLeaf(now - 100 * DAY, now - 1)
        assertTrue(renewer(refuse, block(renewalUrl = "https://recover.test/")).renewIfNeeded() is ClientCertRenewalResult.ReenrollRequired)
        assertTrue("reported, but nothing about this identity was refused", refusedOverMtls.isEmpty())

        // The mTLS handshake refused, the recovery door answers reenroll_required.
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val viaDoor = FakeApi { _, _, url ->
            if (url == null) throw SSLHandshakeException("Handshake failed")
            ClientCertRenewalResponse.ReenrollRequired("revoked")
        }
        assertTrue(renewer(viaDoor).renewIfNeeded() is ClientCertRenewalResult.ReenrollRequired)
        assertTrue(refusedOverMtls.isEmpty())
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

    // ── TLS 1.3: the server's verdict arrives after the handshake ───────

    @Test
    fun `a TLS 1_3 alert on the first read falls through to the recovery URL once`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val good = issuing()
        val api = FakeApi { clientId, csr, url ->
            // What Conscrypt throws when the server rejects the client certificate under TLS 1.3.
            if (url == null) throw javax.net.ssl.SSLProtocolException("Read error: ssl=0x7b: Failure in SSL library, usually a protocol error (TLSV1_ALERT_CERTIFICATE_REQUIRED)")
            kotlinx.coroutines.runBlocking { good.renewClientCert(clientId, csr.encoded, url) }
        }
        val result = renewer(api, block(renewalUrl = "https://recover.test/")).renewIfNeeded() as ClientCertRenewalResult.Renewed
        assertEquals(ClientCertRenewalVia.RECOVERY, result.via)
        assertEquals(listOf<String?>(null, "https://recover.test/"), api.calls)
    }

    @Test
    fun `what counts as the server refusing the client certificate`() {
        assertTrue(ClientCertRenewer.isClientCertRefusal(javax.net.ssl.SSLProtocolException("SSLV3_ALERT_BAD_CERTIFICATE")))
        assertTrue(ClientCertRenewer.isClientCertRefusal(javax.net.ssl.SSLPeerUnverifiedException("peer not authenticated")))
        // Our own pin check failing is not: another client certificate would not fix it.
        val pinFailure = javax.net.ssl.SSLProtocolException("wrapped").apply {
            initCause(RuntimeException("x", java.security.cert.CertificateException("Pin mismatch")))
        }
        assertFalse(ClientCertRenewer.isClientCertRefusal(pinFailure))
        // Other TLS and network failures are plain failures: no second request.
        assertFalse(ClientCertRenewer.isClientCertRefusal(javax.net.ssl.SSLException("Connection reset")))
        assertFalse(ClientCertRenewer.isClientCertRefusal(java.net.SocketTimeoutException("timeout")))
    }

    @Test
    fun `a protocol error on the recovery URL is a failure, not a loop`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val api = FakeApi { _, _, _ -> throw javax.net.ssl.SSLProtocolException("alert") }
        assertTrue(renewer(api).renewIfNeeded() is ClientCertRenewalResult.Failed)
        assertEquals("the mTLS attempt, one recovery attempt, nothing more", 2, api.calls.size)
    }

    // ── A chain must come with its CA ───────────────────────────────────

    private fun pinOf(cert: X509Certificate) = Pkcs10Csr.spkiSha256Base64(cert.publicKey)

    private fun rogueCa(name: String = "CN=PinVault Client CA"): Pair<KeyPair, X509Certificate> {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return pair to sign(X500Name(name), pair.public, now - DAY, now + 3650 * DAY, issuer = X500Name(name), signerKey = pair)
    }

    private fun refused(block: () -> Unit): String = try {
        block()
        throw AssertionError("the chain should have been refused")
    } catch (e: SecurityException) {
        e.message.orEmpty()
    }

    @Test
    fun `a chain of one is refused at enrollment and at renewal`() = runTest {
        val leaf = Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 3600_000, now + 90 * DAY))
        assertTrue(refused { ClientCertRenewer.acceptIssuedChain(listOf(leaf), key) }.contains("CA certificate that signed it"))

        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val api = FakeApi { _, _, _ -> ClientCertRenewalResponse.Issued(listOf(leaf)) }
        val result = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(result.reason, result.reason.contains("CA certificate that signed it"))
        assertEquals(before, store.loadChain(label))
    }

    @Test
    fun `a stored chain of one cannot be renewed without pins, and can with them`() = runTest {
        // What an earlier version accepted: the leaf alone.
        store.saveChain(label, listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 61 * DAY, now + 29 * DAY))))
        val api = issuing()

        val unpinned = renewer(api).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(unpinned.reason, unpinned.reason.contains("clientCaPins"))
        assertTrue("no request: there is nothing to hold the answer to", api.calls.isEmpty())

        assertTrue(renewer(api, block(caPins = listOf(pinOf(caCert)))).renewIfNeeded() is ClientCertRenewalResult.Renewed)
        assertEquals(2, store.loadChain(label)!!.size)
    }

    // ── clientCaPins ────────────────────────────────────────────────────

    @Test
    fun `with pins the chain must be signed by a pinned CA of the chain`() {
        val pins = listOf(pinOf(caCert))
        val good = listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 3600_000, now + 90 * DAY)), Pkcs10Csr.toPem(caCert))
        assertEquals(2, ClientCertRenewer.acceptIssuedChain(good, key, caPins = pins).size)

        // A CA of the attacker's own, with the real CA's name: well-formed, valid, over the device's key.
        val (rogueKey, rogueCert) = rogueCa()
        val rogueLeaf = sign(X500Name("CN=PinVault Client: dev-1"), key.publicKey(), now - 3600_000, now + 90 * DAY, signerKey = rogueKey)
        val rogue = listOf(Pkcs10Csr.toPem(rogueLeaf), Pkcs10Csr.toPem(rogueCert))
        assertEquals("without pins a first enrollment takes it", 2, ClientCertRenewer.acceptIssuedChain(rogue, key).size)
        assertTrue(refused { ClientCertRenewer.acceptIssuedChain(rogue, key, caPins = pins) }.contains("pinned client CA"))

        // The pinned CA merely attached to a chain it did not sign is not enough.
        val padded = rogue + Pkcs10Csr.toPem(caCert)
        assertTrue(refused { ClientCertRenewer.acceptIssuedChain(padded, key, caPins = pins) }.contains("pinned client CA"))
    }

    @Test
    fun `with pins a renewal from a holder of the listener key with its own CA is refused`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val (rogueKey, rogueCert) = rogueCa("CN=Rogue CA")
        val api = FakeApi { _, _, _ ->
            val leaf = sign(X500Name("CN=PinVault Client: dev-1"), key.publicKey(), now, now + 90 * DAY, issuer = X500Name("CN=Rogue CA"), signerKey = rogueKey)
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(rogueCert)))
        }
        val result = renewer(api, block(caPins = listOf(pinOf(caCert)))).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(result.reason, result.reason.contains("pinned client CA"))
        assertEquals(before, store.loadChain(label))
        assertEquals(0, reloads)
    }

    @Test
    fun `with pins the client CA can be replaced by another pinned one`() = runTest {
        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val (nextKey, nextCert) = rogueCa("CN=PinVault Client CA 2")
        val api = FakeApi { _, _, _ ->
            val leaf = sign(X500Name("CN=PinVault Client: dev-1"), key.publicKey(), now - 3600_000, now + 90 * DAY, issuer = X500Name("CN=PinVault Client CA 2"), signerKey = nextKey)
            ClientCertRenewalResponse.Issued(listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(nextCert)))
        }
        // Without pins the previous issuer rules: a new CA is refused.
        assertTrue(renewer(api).renewIfNeeded() is ClientCertRenewalResult.Failed)
        // Both CAs pinned: the rotation goes through.
        val pinned = block(caPins = listOf(pinOf(caCert), pinOf(nextCert)))
        assertTrue(renewer(api, pinned).renewIfNeeded() is ClientCertRenewalResult.Renewed)
    }

    @Test
    fun `clientCaPins takes host-pin syntax and refuses anything that is not a SHA-256 hash`() {
        val pin = pinOf(caCert)
        val built = io.github.umutcansu.pinvault.model.PinVaultConfig.Builder()
            .configApi("api", "https://config.test/") {
                bootstrapPins(listOf(io.github.umutcansu.pinvault.model.HostPin("config.test", listOf(pin, pin))))
                allowUnsigned()
                clientCaPins("sha256/$pin", " $pin ")
            }.build().configApis.getValue("api")
        assertEquals(listOf(pin), built.clientCaPins)
        assertEquals(825, built.maxClientCertLifetimeDays)
        assertFalse(built.allowServerGeneratedKey)

        for (bad in listOf("", "not-a-pin", "AAAA", pin.dropLast(4))) {
            try {
                ConfigApiBlock.Builder("api", "https://config.test/").clientCaPins(bad)
                throw AssertionError("'$bad' should have been refused")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    // ── maxClientCertLifetimeDays ───────────────────────────────────────

    @Test
    fun `a certificate valid for decades is refused, at enrollment and at renewal`() = runTest {
        val fiftyYears = listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 3600_000, now + 50 * 365 * DAY)), Pkcs10Csr.toPem(caCert))
        assertTrue(refused { ClientCertRenewer.acceptIssuedChain(fiftyYears, key) }.contains("825 days"))
        // The default cap leaves room for the day issuers backdate notBefore by.
        val atTheCap = listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - DAY, now + 825 * DAY)), Pkcs10Csr.toPem(caCert))
        assertEquals(2, ClientCertRenewer.acceptIssuedChain(atTheCap, key).size)
        // A block may set its own.
        val ninety = listOf(Pkcs10Csr.toPem(leafFor(key.publicKey(), now - 3600_000, now + 90 * DAY)), Pkcs10Csr.toPem(caCert))
        assertTrue(refused { ClientCertRenewer.acceptIssuedChain(ninety, key, maxLifetimeDays = 30) }.contains("30 days"))

        storeLeaf(now - 61 * DAY, now + 29 * DAY)
        val before = store.loadChain(label)
        val result = renewer(issuing(ttlDays = 50 * 365)).renewIfNeeded() as ClientCertRenewalResult.Failed
        assertTrue(result.reason, result.reason.contains("825 days"))
        assertEquals(before, store.loadChain(label))
    }

    @Test
    fun `a stored certificate that outlives the cap is renewed at the next check`() = runTest {
        // Stored before the cap existed: by its own dates renewal would not come due for decades.
        val r = renewer(issuing())
        val longLived = leafFor(key.publicKey(), now - DAY, now + 50 * 365 * DAY)
        assertEquals(ClientCertRenewer.Decision.Renew, r.decide(longLived, now, 1.0 / 3))

        store.saveChain(label, listOf(Pkcs10Csr.toPem(longLived), Pkcs10Csr.toPem(caCert)))
        val result = r.renewIfNeeded() as ClientCertRenewalResult.Renewed
        assertEquals((now + 90 * DAY).toDouble(), result.notAfterEpochMs.toDouble(), 1000.0)
    }

    private companion object {
        const val DAY = 24 * 3600_000L
    }
}
