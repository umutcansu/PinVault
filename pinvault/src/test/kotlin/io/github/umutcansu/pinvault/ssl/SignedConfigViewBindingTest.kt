package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.SignedConfigSource
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigViewMismatchException
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.NoConfigAvailableException
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * M6: a signed config is bound to the request it answers (`view` inside the
 * payload; SERVER_IMPLEMENTATION_GUIDE.md §3, `view`). Whoever can answer as the Config
 * API without the signing key holds genuine, fresh, signed narrow views — of
 * another request, another device — and must not be able to make them stick.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SignedConfigViewBindingTest {

    private val gson = com.google.gson.GsonBuilder().disableHtmlEscaping().create()
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L

    private val pin1 = TestCertUtil.generateSelfSigned(cn = "a").sha256Pin
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "b").sha256Pin

    private val key: KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun KeyPair.pub(): String = Base64.getEncoder().encodeToString(public.encoded)
    private fun KeyPair.id(): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(public.encoded))
    private fun KeyPair.sign(payload: String): String = Signature.getInstance("SHA256withECDSA").run {
        initSign(private); update(payload.toByteArray(Charsets.UTF_8)); Base64.getEncoder().encodeToString(sign())
    }

    /** A custom backend (SignedConfigSource): the check is on the payload, not on the transport. */
    private class Api : CertificateConfigApi, SignedConfigSource {
        var next: SignedConfigResponse? = null
        var offline = false
        val requests = mutableListOf<Pair<List<String>?, String?>>()

        override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse {
            requests += null to null
            if (offline) throw java.io.IOException("offline")
            return next!!
        }

        override suspend fun fetchScopedSignedConfig(currentVersion: Int, hosts: List<String>?, deviceId: String?): SignedConfigResponse {
            requests += hosts to deviceId
            if (offline) throw java.io.IOException("offline")
            return next!!
        }

        override suspend fun fetchConfig(currentVersion: Int): CertificateConfig = error("signed block")
        override suspend fun healthCheck() = true
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) =
            EnrollmentResult(ByteArray(0), null)
    }

    private lateinit var store: CertificateConfigStore
    private lateinit var api: Api
    private lateinit var provider: HttpClientProvider

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val prefs = context.getSharedPreferences("view_binding_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        store = CertificateConfigStore.createForTest(prefs).also { it.clock = { now } }
        api = Api()
        provider = HttpClientProvider(DynamicSSLManager())
    }

    private fun updater(wantPinsFor: List<String> = emptyList(), deviceId: String? = "dev-1") = SSLCertificateUpdater(
        context = io.mockk.mockk(relaxed = true),
        configApi = api,
        configStore = store,
        httpClientProvider = provider,
        maxRetryCount = 1,
        wantPinsFor = wantPinsFor,
        deviceIdProvider = { deviceId },
        clock = { now },
        verifier = SignedConfigVerifier(SignatureTrust("default", listOf(key.pub()), 1, emptyList(), 1, null), null) { now }
    )

    /** A payload as the server writes it: `view` last, absent for the full config. */
    private fun payload(issuedAt: Long, hosts: List<String>, version: Int = 1, view: Map<String, Any>? = null): String {
        val body = linkedMapOf<String, Any>(
            "version" to version,
            "pins" to hosts.map { mapOf("hostname" to it, "sha256" to listOf(pin1, pin2), "version" to version) },
            "forceUpdate" to false,
            "issuedAt" to issuedAt,
            "expiresAt" to issuedAt + hour,
            "configApiId" to "default-tls"
        )
        if (view != null) body["view"] = view
        return gson.toJson(body)
    }

    private fun signed(payload: String) = SignedConfigResponse(payload, key.sign(payload), key.id(), null, null)

    private fun view(vararg hosts: String, deviceId: String? = "dev-1"): Map<String, Any> =
        linkedMapOf<String, Any>("hosts" to hosts.toList()).also { m -> deviceId?.let { m["deviceId"] = it } }

    private suspend fun serve(payload: String, with: SSLCertificateUpdater): UpdateResult {
        api.next = signed(payload)
        api.offline = false
        return with.updateNow()
    }

    private fun storedHosts() = store.load()?.pins?.map { it.hostname }?.toSet()
    private fun activeHosts() = provider.currentConfig?.pins?.map { it.hostname }?.toSet()

    private fun assertRefused(result: UpdateResult) {
        val failed = result as? UpdateResult.Failed ?: throw AssertionError("expected a refusal, got $result")
        assertTrue("typed refusal, got ${failed.exception}", failed.exception is ConfigViewMismatchException)
        assertTrue(failed.reason, failed.reason.contains("Signed config rejected"))
    }

    // ── The attack: a full-config device handed a genuine narrow view ──

    @Test
    fun `a full-config block refuses a newer genuine narrowed envelope - stored config and pins unchanged`() = runTest {
        val full = updater()
        assertEquals(UpdateResult.Updated(1), serve(payload(now - 10, listOf("a.test", "b.test")), full))
        val envelopeBefore = store.loadEnvelope()!!.payload

        // Newer, genuinely signed, fresh — but the answer to someone else's `?hosts=a.test`.
        val narrow = payload(now, listOf("a.test"), version = 2, view = view("a.test"))
        assertRefused(serve(narrow, full))

        assertEquals(setOf("a.test", "b.test"), storedHosts())
        assertEquals(setOf("a.test", "b.test"), activeHosts())
        assertEquals(envelopeBefore, store.loadEnvelope()!!.payload)
        assertEquals(now - 10, store.getCurrentIssuedAt())
        // The full request was made: no hosts, no device id.
        assertEquals(null to null, api.requests.last())
    }

    @Test
    fun `a narrowed view with the very same pins is refused too, never AlreadyCurrent`() = runTest {
        val full = updater()
        serve(payload(now - 10, listOf("a.test", "b.test")), full)
        assertRefused(serve(payload(now, listOf("a.test", "b.test"), view = view("a.test", "b.test")), full))
        // Only a device-id view, no host list: still narrowed by an ACL.
        assertRefused(serve(payload(now + 1, listOf("a.test", "b.test"), view = mapOf("deviceId" to "dev-1")), full))
    }

    @Test
    fun `a full-config block refuses a narrowed view on its very first fetch`() = runTest {
        assertRefused(serve(payload(now, listOf("a.test"), view = view("a.test")), updater()))
        assertNull(store.load())
        assertNull(provider.currentConfig)
    }

    // ── A scoped block ──────────────────────────────────────────────────

    @Test
    fun `a scoped block accepts its own view, whatever the spelling of its wantPinsFor`() = runTest {
        val scoped = updater(wantPinsFor = listOf("B.test", "a.test", "b.test "))
        val result = serve(payload(now, listOf("a.test", "b.test"), view = view("a.test", "b.test")), scoped)
        assertEquals(UpdateResult.Updated(1), result)
        assertEquals(listOf("B.test", "a.test", "b.test ") to "dev-1", api.requests.last())
    }

    @Test
    fun `a scoped block refuses another set's view and another device's view`() = runTest {
        val scoped = updater(wantPinsFor = listOf("a.test", "b.test"))
        serve(payload(now - 100, listOf("a.test", "b.test"), view = view("a.test", "b.test")), scoped)

        assertRefused(serve(payload(now - 90, listOf("a.test"), view = view("a.test")), scoped))
        assertRefused(serve(payload(now - 80, listOf("a.test"), view = view("a.test", "b.test", deviceId = "dev-2")), scoped))
        assertRefused(serve(payload(now - 70, listOf("a.test"), view = view("a.test", "b.test", deviceId = null)), scoped))
        // Not canonical (order) = not what this server writes for this request.
        assertRefused(serve(payload(now - 60, listOf("a.test"), view = view("b.test", "a.test")), scoped))
        // A narrowing this client does not understand.
        assertRefused(serve(payload(now - 50, listOf("a.test"), view = view("a.test", "b.test") + ("aclVersion" to 3)), scoped))
        assertRefused(serve(payload(now - 40, listOf("a.test"), view = mapOf("hosts" to "a.test,b.test", "deviceId" to "dev-1")), scoped))

        assertEquals(setOf("a.test", "b.test"), storedHosts())
        assertEquals(setOf("a.test", "b.test"), activeHosts())
    }

    @Test
    fun `a scoped block without a device id refuses a view that names one`() = runTest {
        val scoped = updater(wantPinsFor = listOf("a.test"), deviceId = null)
        assertRefused(serve(payload(now, listOf("a.test"), view = view("a.test", deviceId = "dev-1")), scoped))
        assertEquals(UpdateResult.Updated(1), serve(payload(now + 1, listOf("a.test"), view = view("a.test", deviceId = null)), scoped))
    }

    @Test
    fun `a scoped block accepts a payload without view - a full view, or a server before 2_9_0`() = runTest {
        val scoped = updater(wantPinsFor = listOf("a.test"))
        assertEquals(UpdateResult.Updated(1), serve(payload(now, listOf("a.test", "b.test")), scoped))
        assertEquals(setOf("a.test", "b.test"), storedHosts())
    }

    // ── The stored envelope, re-verified at every load ──────────────────

    @Test
    fun `wantPinsFor grown in an app update - the stored view is discarded and fetched again`() = runTest {
        serve(payload(now - 10, listOf("a.test"), view = view("a.test")), updater(wantPinsFor = listOf("a.test")))

        // Same list, offline: the stored view still answers the request, the app starts.
        provider = HttpClientProvider(DynamicSSLManager())
        api.offline = true
        assertEquals(InitResult.Ready(1), updater(wantPinsFor = listOf("a.test")).initializeAndUpdate())

        // New release asks for one more host, online: discarded, fetched again, Ready.
        provider = HttpClientProvider(DynamicSSLManager())
        api.next = signed(payload(now, listOf("a.test", "b.test"), view = view("a.test", "b.test")))
        api.offline = false
        assertEquals(InitResult.Ready(1), updater(wantPinsFor = listOf("a.test", "b.test")).initializeAndUpdate())
        assertEquals(setOf("a.test", "b.test"), storedHosts())
        assertEquals(setOf("a.test", "b.test"), activeHosts())
    }

    @Test
    fun `wantPinsFor changed and offline - no usable config, the watermarks stay`() = runTest {
        serve(payload(now - 10, listOf("a.test"), view = view("a.test")), updater(wantPinsFor = listOf("a.test")))

        provider = HttpClientProvider(DynamicSSLManager())
        api.offline = true
        val result = updater(wantPinsFor = listOf("a.test", "b.test")).initializeAndUpdate()
        val failed = result as? InitResult.Failed ?: throw AssertionError("expected Failed, got $result")
        assertTrue(failed.exception is NoConfigAvailableException)
        assertTrue(failed.reason, failed.reason.contains("another host set or device"))
        assertNull(provider.currentConfig)
        // A genuine config once accepted: its issuedAt stays as the replay watermark.
        assertEquals(now - 10, store.getCurrentIssuedAt())
    }

    @Test
    fun `a stored narrowed view is discarded by a block that now asks for the full config`() = runTest {
        serve(payload(now - 10, listOf("a.test"), view = view("a.test")), updater(wantPinsFor = listOf("a.test")))
        provider = HttpClientProvider(DynamicSSLManager())
        api.next = signed(payload(now, listOf("a.test", "b.test")))
        assertEquals(InitResult.Ready(1), updater().initializeAndUpdate())
        assertEquals(setOf("a.test", "b.test"), storedHosts())
    }

    @Test
    fun `a stored full config still starts a block that became scoped`() = runTest {
        serve(payload(now - 10, listOf("a.test", "b.test")), updater())
        provider = HttpClientProvider(DynamicSSLManager())
        api.offline = true
        assertEquals(InitResult.Ready(1), updater(wantPinsFor = listOf("a.test")).initializeAndUpdate())
    }

    // ── The config inside an attestation answer ─────────────────────────

    @Test
    fun `applySigned - a full block refuses a narrowed embedded config, a scoped one takes its own`() = runTest {
        val full = updater()
        assertTrue((full.applySigned(signed(payload(now, listOf("a.test"), view = view("a.test")))) as UpdateResult.Failed)
            .exception is ConfigViewMismatchException)
        assertNull(store.load())

        val scoped = updater(wantPinsFor = listOf("a.test"), deviceId = null)
        // The attestation request named "unknown-device" (no usable ANDROID_ID): the view answers that.
        val embedded = signed(payload(now, listOf("a.test"), view = view("a.test", deviceId = "unknown-device")))
        assertEquals(UpdateResult.Updated(1), scoped.applySigned(embedded, requestDeviceId = "unknown-device"))
        // Another device's embedded view is refused.
        val other = signed(payload(now + 1, listOf("a.test"), version = 2, view = view("a.test", deviceId = "dev-9")))
        assertTrue((scoped.applySigned(other, requestDeviceId = "unknown-device") as UpdateResult.Failed).exception is ConfigViewMismatchException)

        // And the stored attestation view starts the app offline (the attestation form of "no id").
        provider = HttpClientProvider(DynamicSSLManager())
        api.offline = true
        assertEquals(InitResult.Ready(1), updater(wantPinsFor = listOf("a.test"), deviceId = null).initializeAndUpdate())
    }
}
