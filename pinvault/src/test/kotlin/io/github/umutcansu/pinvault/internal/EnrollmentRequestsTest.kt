package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentPendingException
import io.github.umutcansu.pinvault.model.EnrollmentRefusal
import io.github.umutcansu.pinvault.model.EnrollmentRefusedException
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.SecurePreferences
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A device told to wait for approval: the request id is remembered and sent
 * back with a CSR from the same key; a request that is over is forgotten
 * together with its key.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnrollmentRequestsTest {

    private val label = "default"
    private lateinit var store: ClientCertSecureStore
    private lateinit var key: ClientIdentityKeyProvider

    /** What one enrollment call carried. */
    private data class Call(val token: String?, val requestId: String?, val spki: String)

    private val calls = mutableListOf<Call>()
    private val answers = ArrayDeque<() -> EnrollmentResult>()

    private val chain = EnrollmentResult(ByteArray(0), null, null, listOf("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))

    private val api = object : CertificateConfigApi {
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int) = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?): EnrollmentResult =
            error("P12 enrollment was not expected")

        override suspend fun enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?, csrDer: ByteArray, requestId: String?
        ): EnrollmentResult {
            calls += Call(token, requestId, key.spkiSha256())
            return answers.removeFirst()()
        }
    }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences("enroll-req-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, "enroll-req-test", "ns", SoftwarePrefsCipher()))
        key = ClientIdentityKeyProvider.software("enroll-req-test-${System.nanoTime()}")
    }

    @After
    fun tearDown() = key.clear()

    private suspend fun send(token: String?, deviceId: String? = null): EnrollmentResult =
        EnrollmentRequests.send(api, store, key, label, token, deviceId, "Pixel", "uid-1") {
            key.ensureKeyPair()
            Pkcs10Csr.encode("device", key.publicKey(), key::sign)
        }

    private suspend fun expectRefusal(token: String?, error: String): EnrollmentRefusedException =
        try {
            send(token)
            fail("expected a refusal ($error)")
            throw AssertionError()
        } catch (e: EnrollmentRefusedException) {
            assertEquals(error, e.serverError)
            e
        }

    @Test
    fun `a wait is remembered and the next attempt asks by its request id with the same key`() = runTest {
        answers += { throw EnrollmentPendingException("r1", "field-x", retryAfterSeconds = 15) }
        answers += { chain }

        try {
            send("K7QM2-XRT9V-4NWDP-J6E8B-HC3MA")
            fail("expected to wait")
        } catch (e: EnrollmentPendingException) {
            assertEquals("r1", e.requestId)
        }
        val pending = store.loadPendingRequest(label)
        assertEquals("r1", pending?.requestId)
        assertEquals("field-x", pending?.clientId)
        assertTrue(key.exists())

        assertEquals(chain, send(null))
        assertEquals(Call("K7QM2-XRT9V-4NWDP-J6E8B-HC3MA", null, calls[0].spki), calls[0])
        assertEquals("r1", calls[1].requestId)
        assertNull(calls[1].token)
        assertEquals("the same key asks again", calls[0].spki, calls[1].spki)

        // Storing the credential forgets the wait.
        store.saveChain(label, chain.certificateChainPem!!)
        assertNull(store.loadPendingRequest(label))
    }

    @Test
    fun `a wait comes back with the code of this device's key`() = runTest {
        answers += { throw EnrollmentPendingException("r1", "device-x") }
        try {
            send(null, deviceId = "android-1")
            fail("expected to wait")
        } catch (e: EnrollmentPendingException) {
            assertEquals(VerificationCode.of(key.publicKey()), e.verificationCode)
        }
    }

    @Test
    fun `a code in the answer gives way to the one from this device's key`() = runTest {
        answers += { throw EnrollmentPendingException("r1", "device-x", verificationCode = "0000-0000") }
        try {
            send(null, deviceId = "android-1")
            fail("expected to wait")
        } catch (e: EnrollmentPendingException) {
            assertEquals(VerificationCode.of(key.publicKey()), e.verificationCode)
        }
    }

    @Test
    fun `a lapsed code-less request is forgotten with its key and the device asks again at once`() = runTest {
        store.savePendingRequest(label, "r1", "device-x")
        answers += { throw EnrollmentRefusedException(410, "enrollment_request_expired") }
        answers += { throw EnrollmentPendingException("r2", "device-y") }

        try {
            send(null, deviceId = "android-1")
            fail("expected to wait again")
        } catch (e: EnrollmentPendingException) {
            assertEquals("r2", e.requestId)
        }
        assertEquals(2, calls.size)
        assertEquals("r1", calls[0].requestId)
        assertNull(calls[1].requestId)
        assertNotEquals("a new key for the new request", calls[0].spki, calls[1].spki)
        assertEquals("r2", store.loadPendingRequest(label)?.requestId)
    }

    @Test
    fun `a lapsed request with no way to ask again just ends`() = runTest {
        key.ensureKeyPair()
        store.savePendingRequest(label, "r1", null)
        answers += { throw EnrollmentRefusedException(410, "enrollment_request_expired") }

        assertEquals(EnrollmentRefusal.EXPIRED, expectRefusal(null, "enrollment_request_expired").refusal)
        assertEquals(1, calls.size)
        assertNull(store.loadPendingRequest(label))
        assertFalse(key.exists())
    }

    @Test
    fun `a rejected request is forgotten together with its key`() = runTest {
        key.ensureKeyPair()
        store.savePendingRequest(label, "r1", "field-x")
        answers += { throw EnrollmentRefusedException(403, "enrollment_rejected") }

        assertEquals(EnrollmentRefusal.REJECTED, expectRefusal(null, "enrollment_rejected").refusal)
        assertNull(store.loadPendingRequest(label))
        assertFalse("the next attempt is a new request over a new key", key.exists())
    }

    @Test
    fun `a request the server no longer knows starts over at once when a code is at hand`() = runTest {
        store.savePendingRequest(label, "r1", "field-x")
        answers += { throw EnrollmentRefusedException(404, "enrollment_request_not_found") }
        answers += { throw EnrollmentPendingException("r2", "field-y") }

        try {
            send("CODE")
            fail("expected to wait again")
        } catch (e: EnrollmentPendingException) {
            assertEquals("r2", e.requestId)
        }
        assertEquals(2, calls.size)
        assertEquals("r1", calls[0].requestId)
        assertNull(calls[1].requestId)
        assertEquals("CODE", calls[1].token)
        assertNotEquals("a new key for the new request", calls[0].spki, calls[1].spki)
        assertEquals("r2", store.loadPendingRequest(label)?.requestId)
    }

    @Test
    fun `without a code a request the server no longer knows is simply over`() = runTest {
        store.savePendingRequest(label, "r1", null)
        answers += { throw EnrollmentRefusedException(404, "enrollment_request_not_found") }

        expectRefusal(null, "enrollment_request_not_found")
        assertEquals(1, calls.size)
        assertNull(store.loadPendingRequest(label))
    }

    @Test
    fun `other refusals keep the request and the key`() = runTest {
        store.savePendingRequest(label, "r1", "field-x")
        answers += { throw EnrollmentRefusedException(409, "device_already_enrolled") }

        expectRefusal(null, "device_already_enrolled")
        assertEquals("r1", store.loadPendingRequest(label)?.requestId)
        assertTrue(key.exists())
    }

    @Test
    fun `a refused token enrollment keeps the key`() = runTest {
        answers += { throw EnrollmentRefusedException(401, "Gecersiz token") }
        expectRefusal("used-token", "Gecersiz token")
        assertTrue(key.exists())
        assertNull(store.loadPendingRequest(label))
    }
}
