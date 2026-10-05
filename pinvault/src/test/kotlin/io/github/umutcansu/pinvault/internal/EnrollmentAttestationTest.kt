package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.keystore.SoftwareClientIdentityKeyProvider
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest

/**
 * The enrollment request carries the device key's attestation, and a key the
 * server made is taken only by a block that asked for it.
 *
 * The software key stands in for the Keystore: it remembers the challenge it
 * was generated with, and `SoftwareClientIdentityKeyProvider.attestation`
 * plays the device's attestation key (null = a device that cannot attest).
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnrollmentAttestationTest {

    private val label = "default"
    private val deviceUid = "a1b2c3d4e5f60718"
    private lateinit var store: ClientCertSecureStore
    private lateinit var key: ClientIdentityKeyProvider

    private data class Call(val requestId: String?, val spki: String, val attestation: List<String>)

    private val calls = mutableListOf<Call>()
    private var p12Calls = 0
    private val answers = ArrayDeque<() -> EnrollmentResult?>()

    private val chain = EnrollmentResult(ByteArray(0), null, null, listOf("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))
    private val p12 = EnrollmentResult(byteArrayOf(1, 2, 3), "hash", "one-off")

    private val api = object : CertificateConfigApi {
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int) = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?): EnrollmentResult {
            p12Calls++
            return p12
        }

        override suspend fun enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
            csrDer: ByteArray, requestId: String?, attestationChain: List<String>
        ): EnrollmentResult? {
            calls += Call(requestId, key.spkiSha256(), attestationChain)
            return answers.removeFirst()()
        }
    }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences("enroll-att-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, "enroll-att-test", "ns", SoftwarePrefsCipher()))
        key = ClientIdentityKeyProvider.software("enroll-att-test-${System.nanoTime()}")
        // This "device" attests: the chain is the challenge itself, then a root.
        SoftwareClientIdentityKeyProvider.attestation = { challenge -> listOf(challenge, "root".toByteArray()) }
    }

    @After
    fun tearDown() {
        key.clear()
        SoftwareClientIdentityKeyProvider.attestation = null
    }

    private val challenge = ClientIdentityKeyProvider.attestationChallenge(deviceUid)

    private fun b64(bytes: ByteArray) = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

    private suspend fun send(
        token: String? = "tok",
        allowServerGeneratedKey: Boolean = false,
        buildCsr: () -> ByteArray? = {
            key.ensureKeyPair(challenge)
            Pkcs10Csr.encode("device", key.publicKey(), key::sign)
        }
    ): EnrollmentResult = EnrollmentRequests.send(
        api, store, key, label, token, null, "Pixel", deviceUid, allowServerGeneratedKey = allowServerGeneratedKey, buildCsr = buildCsr
    )

    // ── The challenge ───────────────────────────────────────────────────

    @Test
    fun `the challenge is SHA-256 of the prefix and the device id the request carries`() {
        val expected = MessageDigest.getInstance("SHA-256").digest("pinvault-identity-key:v1:$deviceUid".toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected, challenge)
        assertEquals(32, challenge.size)
        // Another device id, another challenge; and not the user-auth key's.
        assertFalse(challenge.contentEquals(ClientIdentityKeyProvider.attestationChallenge("another-device")))
        assertFalse(challenge.contentEquals(io.github.umutcansu.pinvault.keystore.UserAuthKeys.attestationChallenge(deviceUid)))
    }

    // ── The chain goes along ────────────────────────────────────────────

    @Test
    fun `the request carries the chain of the key it is signed with, leaf first`() = runTest {
        answers += { chain }
        assertEquals(chain, send())
        assertEquals(listOf(b64(challenge), b64("root".toByteArray())), calls.single().attestation)
    }

    @Test
    fun `a device that cannot attest sends no chain`() = runTest {
        SoftwareClientIdentityKeyProvider.attestation = null
        answers += { chain }
        send()
        assertTrue(calls.single().attestation.isEmpty())
    }

    @Test
    fun `asking again for a waiting request uses the same key and the same chain`() = runTest {
        answers += { throw EnrollmentPendingException("r1", "field-x") }
        answers += { chain }
        try {
            send("K7QM2-XRT9V-4NWDP-J6E8B-HC3MA")
            fail("expected to wait")
        } catch (_: EnrollmentPendingException) {
        }
        assertEquals(chain, send(token = null))
        assertEquals("r1", calls[1].requestId)
        assertEquals(calls[0].spki, calls[1].spki)
        assertEquals(calls[0].attestation, calls[1].attestation)
    }

    // ── A key from before attestation ───────────────────────────────────

    @Test
    fun `a refused key without a chain is replaced once and the request sent again`() = runTest {
        key.ensureKeyPair()                           // made by an earlier version: no challenge, no chain
        val oldKey = key.spkiSha256()
        answers += { throw EnrollmentRefusedException(403, "attestation_required") }
        answers += { chain }

        assertEquals(chain, send())

        assertEquals(2, calls.size)
        assertTrue(calls[0].attestation.isEmpty())
        assertEquals(oldKey, calls[0].spki)
        assertNotEquals("a new key", oldKey, calls[1].spki)
        assertEquals("with its chain", listOf(b64(challenge), b64("root".toByteArray())), calls[1].attestation)
    }

    @Test
    fun `a device that still cannot attest is not asked twice`() = runTest {
        SoftwareClientIdentityKeyProvider.attestation = null
        answers += { throw EnrollmentRefusedException(403, "attestation_required") }
        try {
            send()
            fail("expected a refusal")
        } catch (e: EnrollmentRefusedException) {
            assertEquals(EnrollmentRefusal.ATTESTATION_FAILED, e.refusal)
        }
        assertEquals("one request, no second one with the same empty chain", 1, calls.size)
    }

    @Test
    fun `a refused chain is not retried`() = runTest {
        answers += { throw EnrollmentRefusedException(403, "attestation_invalid", "not_hardware_backed") }
        try {
            send()
            fail("expected a refusal")
        } catch (e: EnrollmentRefusedException) {
            assertEquals("not_hardware_backed", e.serverMessage)
        }
        assertEquals(1, calls.size)
        assertTrue("the key stays: it was attested, the server just does not accept it", key.exists())
    }

    @Test
    fun `a waiting request keeps its key even when refused for attestation`() = runTest {
        key.ensureKeyPair()
        val spki = key.spkiSha256()
        store.savePendingRequest(label, "r1", "field-x")
        answers += { throw EnrollmentRefusedException(403, "attestation_required") }
        try {
            send(token = null)
            fail("expected a refusal")
        } catch (_: EnrollmentRefusedException) {
        }
        assertEquals(1, calls.size)
        assertEquals("the request is tied to this key", spki, key.spkiSha256())
    }

    // ── A key the server made ───────────────────────────────────────────

    @Test
    fun `a P12 answer to a CSR is refused unless the block allows a server-made key`() = runTest {
        answers += { p12 }
        try {
            send()
            fail("a P12 answer must not be accepted")
        } catch (e: ServerGeneratedKeyRefusedException) {
            assertTrue(e.message, e.message!!.contains("allowServerGeneratedKey"))
        }

        answers += { p12 }
        assertEquals(p12, send(allowServerGeneratedKey = true))
    }

    @Test
    fun `without a CSR nothing is sent unless the block allows a server-made key`() = runTest {
        try {
            send(buildCsr = { null })
            fail("P12 enrollment must not be tried")
        } catch (e: ServerGeneratedKeyRefusedException) {
            assertTrue(e.message, e.message!!.contains("allowServerGeneratedKey"))
        }
        assertEquals(0, p12Calls)
        assertTrue(calls.isEmpty())

        assertEquals(p12, send(allowServerGeneratedKey = true, buildCsr = { null }))
        assertEquals(1, p12Calls)
    }

    @Test
    fun `a backend that takes no CSR is used only with the opt-in`() = runTest {
        answers += { null }
        try {
            send()
            fail("enroll() must not be called")
        } catch (_: ServerGeneratedKeyRefusedException) {
        }
        assertEquals(0, p12Calls)

        answers += { null }
        assertEquals(p12, send(allowServerGeneratedKey = true))
        assertEquals(1, p12Calls)
    }
}
