package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentRefusal
import io.github.umutcansu.pinvault.model.EnrollmentRefusedException
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.IntegrityTokenProvider
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.SecurePreferences
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The app's integrity token goes along with the enrollment request, bound to
 * that request's CSR and device id; a provider that gives nothing (or fails)
 * leaves the request as it was; a custom API that predates the token still
 * gets its call.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnrollmentIntegrityTest {

    private val label = "default"
    private val deviceUid = "a1b2c3d4e5f60718"
    private lateinit var store: ClientCertSecureStore
    private lateinit var key: ClientIdentityKeyProvider

    private data class Call(val csr: ByteArray, val integrityToken: String?, val arity: Int)

    private val calls = mutableListOf<Call>()
    private val chain = EnrollmentResult(ByteArray(0), null, null, listOf("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))

    /** Takes the token: the method PinVault 2.3 calls. */
    private val api = object : CertificateConfigApi {
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int) = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) = chain

        override suspend fun enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
            csrDer: ByteArray, requestId: String?, attestationChain: List<String>
        ): EnrollmentResult {
            calls += Call(csrDer, null, 7)
            return chain
        }

        override suspend fun enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
            csrDer: ByteArray, requestId: String?, attestationChain: List<String>, integrityToken: String?
        ): EnrollmentResult {
            calls += Call(csrDer, integrityToken, 8)
            return chain
        }
    }

    /** Written before the token existed: only the seven-argument method. */
    private val olderApi = object : CertificateConfigApi {
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int) = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) = chain

        override suspend fun enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
            csrDer: ByteArray, requestId: String?, attestationChain: List<String>
        ): EnrollmentResult {
            calls += Call(csrDer, null, 7)
            return chain
        }
    }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences("enroll-int-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, "enroll-int-test", "ns", SoftwarePrefsCipher()))
        key = ClientIdentityKeyProvider.software("enroll-int-test-${System.nanoTime()}")
    }

    @After
    fun tearDown() {
        key.clear()
    }

    private suspend fun send(
        integrity: IntegrityTokenProvider?,
        through: CertificateConfigApi = api,
        deviceId: String? = null,
        uid: String? = deviceUid
    ): EnrollmentResult = EnrollmentRequests.send(
        through, store, key, label, "tok", deviceId, "Pixel", uid, integrity = integrity
    ) {
        key.ensureKeyPair(null)
        Pkcs10Csr.encode("device", key.publicKey(), key::sign)
    }

    @Test
    fun `the token is asked for with the request hash of this CSR and sent along`() = runTest {
        val asked = mutableListOf<String>()
        send(IntegrityTokenProvider { hash -> asked += hash; "verdict-for-$hash" })

        assertEquals(1, calls.size)
        val call = calls.single()
        assertEquals(8, call.arity)
        val expected = IntegrityRequestHash.of(deviceUid, call.csr)
        assertEquals(listOf(expected), asked)
        assertEquals("verdict-for-$expected", call.integrityToken)
    }

    @Test
    fun `without a deviceUid the hash is bound to the deviceId`() = runTest {
        val asked = mutableListOf<String>()
        send(IntegrityTokenProvider { hash -> asked += hash; "t" }, deviceId = "android-id-1", uid = null)
        assertEquals(IntegrityRequestHash.of("android-id-1", calls.single().csr), asked.single())
    }

    @Test
    fun `no provider - the request is sent as before`() = runTest {
        send(integrity = null)
        assertEquals(7, calls.single().arity)
    }

    @Test
    fun `a provider that gives nothing or fails - the request goes without a token`() = runTest {
        send(IntegrityTokenProvider { null })
        send(IntegrityTokenProvider { "   " })
        send(IntegrityTokenProvider { throw IllegalStateException("Play services missing") })
        assertEquals(listOf(7, 7, 7), calls.map { it.arity })
    }

    @Test
    fun `an API written before the token still gets its call`() = runTest {
        send(IntegrityTokenProvider { "t" }, through = olderApi)
        assertEquals(7, calls.single().arity)
        assertNull(calls.single().integrityToken)
    }

    @Test
    fun `an integrity refusal is ATTESTATION_FAILED and does not make a new key`() = runTest {
        val refusing = object : CertificateConfigApi by api {
            override suspend fun enrollWithCsr(
                token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
                csrDer: ByteArray, requestId: String?, attestationChain: List<String>, integrityToken: String?
            ): EnrollmentResult {
                calls += Call(csrDer, integrityToken, 8)
                throw EnrollmentRefusedException(403, "integrity_invalid", "device_integrity")
            }
        }
        try {
            send(IntegrityTokenProvider { "t" }, through = refusing)
            fail("expected a refusal")
        } catch (e: EnrollmentRefusedException) {
            assertEquals(EnrollmentRefusal.ATTESTATION_FAILED, e.refusal)
        }
        // One request: a new key would get the same verdict.
        assertEquals(1, calls.size)
        assertEquals(EnrollmentRefusal.ATTESTATION_FAILED, EnrollmentRefusedException(403, "integrity_required").refusal)
    }
}
