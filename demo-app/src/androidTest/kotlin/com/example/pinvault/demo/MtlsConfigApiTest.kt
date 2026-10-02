package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * mTLS Config API (port 8092) Espresso UI testleri.
 *
 * MtlsToTlsActivity üzerinden:
 *   - Enrollment olmadan → "Enrollment required"
 *   - Token enrollment → init → "Ready"
 *   - btnTest → TLS host bağlantısı → 200
 *   - Enrollment persistence, unenroll, re-enroll
 *
 * Enrollment helper metotları programmatik (Management API token üretimi).
 * Activity UI ile doğrulama.
 */
@RunWith(AndroidJUnit4::class)
class MtlsConfigApiTest {

    @get:org.junit.Rule
    val qaScreenshots = QaScreenshotRule()

    private var scenario: ActivityScenario<MtlsToTlsActivity>? = null

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        try { PinVault.unenroll(context) } catch (_: Exception) {}
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        // Activity kapanmadan ÖNCE son durum screenshot'ı — sonra close.
        qaScreenshots.capture("final")
        try { scenario?.close() } catch (_: Exception) {}
        try { PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    /**
     * Activity "Ready ✓" olana kadar bekler (en çok [timeoutMs]). Sabit
     * uyku yerine: mTLS init, host client cert P12'sini cihazda yeniden
     * şifrelediği için Android 7 emülatöründe ~16 sn sürüyor, Pixel'de ~3 sn.
     * Süre dolarsa sessizce döner; ardından gelen assertion hatayı raporlar.
     */
    private fun awaitReady(timeoutMs: Long = 45000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            var text = ""
            scenario?.onActivity { text = it.findViewById<android.widget.TextView>(R.id.tvStatus).text.toString() }
            if (text.contains("✓") || text.contains("✗")) return
            Thread.sleep(1000)
        }
    }

    private fun clickTest() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    /**
     * Management API'den enrollment token üretir.
     */
    private fun generateEnrollmentToken(): String = generateEnrollmentTokenFor(newClientId())

    private fun newClientId() = "test-${System.currentTimeMillis()}"

    private fun generateEnrollmentTokenFor(clientId: String): String {
        releaseThisDevice()
        return mintToken(clientId)
    }

    /** A token for [clientId], leaving this device's other identities as they are. */
    private fun mintToken(clientId: String): String {
        val resp = TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-tokens/generate")
                .post("""{"clientId":"$clientId"}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Token üretme başarılı olmalı: ${resp.code}", resp.isSuccessful)
        val body = resp.body?.string() ?: ""
        return Regex(""""token":"([^"]+)"""").find(body)?.groupValues?.get(1)
            ?: throw AssertionError("Token parse edilemedi: $body")
    }

    /**
     * Sunucu bir cihazı aynı anda tek bir etkin kimlikle kaydeder: her test
     * yeni bir client id'yle kayıt olduğu için, önceki testlerin bu cihazdan
     * (ANDROID_ID) açtığı ve hâlâ etkin olan kimlikleri iptal eder — yöneticinin
     * yeniden kayıttan önce yaptığı gibi.
     */
    private fun releaseThisDevice() {
        @Suppress("HardwareIds")
        val deviceUid = android.provider.Settings.Secure.getString(
            context.contentResolver, android.provider.Settings.Secure.ANDROID_ID
        ) ?: return
        val resp = TestConfig.adminClient.newCall(
            Request.Builder().url("${TestConfig.MANAGEMENT_URL}/api/v1/client-certs").build()
        ).execute()
        val arr = org.json.JSONArray(resp.body?.string() ?: "[]")
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("deviceUid") == deviceUid && !o.optBoolean("revoked")) revokeOnServer(o.getString("id"))
        }
    }

    /**
     * Test kancası (ALLOW_TEST_HOOKS=true): bu client id'ye verilecek bir
     * sonraki sertifika [ttlSeconds] saniye yaşar.
     */
    private fun setTestTtl(clientId: String, ttlSeconds: Int) {
        val resp = TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/test-hooks/client-cert-ttl")
                .post("""{"clientId":"$clientId","ttlSeconds":$ttlSeconds}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Test kancası açık olmalı (ALLOW_TEST_HOOKS=true): ${resp.code}", resp.isSuccessful)
        resp.close()
    }

    /** Sunucudaki kayıt: {notAfter, renewCount, keyType, revoked}. */
    private fun serverRecord(clientId: String): org.json.JSONObject? {
        val resp = TestConfig.adminClient.newCall(
            Request.Builder().url("${TestConfig.MANAGEMENT_URL}/api/v1/client-certs").build()
        ).execute()
        val arr = org.json.JSONArray(resp.body?.string() ?: "[]")
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("id") == clientId) return o
        }
        return null
    }

    /** "Kayıt Ol" → the dialog's token field → "Kayıt Ol". */
    private fun submitEnrollToken(token: String) {
        onView(withId(R.id.btnEnroll)).perform(click())
        onView(isAssignableFrom(android.widget.EditText::class.java))
            .inRoot(androidx.test.espresso.matcher.RootMatchers.isDialog())
            .perform(androidx.test.espresso.action.ViewActions.replaceText(token),
                androidx.test.espresso.action.ViewActions.closeSoftKeyboard())
        onView(withId(android.R.id.button1)).perform(click())
    }

    /** Waits until a line (the result line by default) shows [expected] (at most [timeoutMs]); the assertion after it reports a miss. */
    private fun awaitResult(expected: String, timeoutMs: Long = 30000, viewId: Int = R.id.tvResult) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            var text = ""
            scenario?.onActivity { text = it.findViewById<android.widget.TextView>(viewId).text.toString() }
            if (text.contains(expected)) return
            Thread.sleep(500)
        }
    }

    private fun revokeOnServer(clientId: String) {
        TestConfig.adminClient.newCall(
            Request.Builder().url("${TestConfig.MANAGEMENT_URL}/api/v1/client-certs/$clientId").delete().build()
        ).execute().close()
    }

    /**
     * TLS Config API üzerinden enrollment yapar (programmatik).
     * MtlsToTlsActivity UI'ı kullanmadan — hızlı enrollment helper.
     */
    private fun enrollProgrammatically(clientId: String = newClientId()) {
        // TLS init for enrollment
        val latch = CountDownLatch(1)
        val config = PinVaultConfig.Builder()
            .configApi("default", TestConfig.TLS_CONFIG_URL) {
                bootstrapPins(bootstrapPins)
                configEndpoint("api/v1/certificate-config?signed=false")
                allowUnsigned()
            }
            .maxRetryCount(1)
            .build()
        PinVault.init(context, config) { latch.countDown() }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))

        val token = generateEnrollmentTokenFor(clientId)
        val enrolled = runBlocking { PinVault.enroll(context, token) }
        assertTrue("Enrollment başarılı olmalı", enrolled)
        assertTrue("Enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()
        PinVault.reset()
        Thread.sleep(500)
    }

    // ─── SDK: mTLS config API ile ilk açılış ────────────

    /**
     * Ekran yok, yalnızca SDK. Tek bir mTLS config API (8092):
     *  - sertifikasız init ağa çıkmadan, hemen "kayıt gerekli" döner;
     *  - enroll(context, config, token) init'ten önce çalışır (8091'e);
     *  - ardından tek init 8092'ye mTLS ile bağlanır ve Ready olur.
     */
    @Test
    fun sdk_mtlsConfig_enroll_before_init_then_single_init() {
        val config = PinVaultConfig.Builder()
            .configApi("main", TestConfig.MTLS_CONFIG_URL) {
                bootstrapPins(bootstrapPins)
                configEndpoint("api/v1/certificate-config?signed=false")
                allowUnsigned()
                enrollmentUrl(TestConfig.TLS_CONFIG_URL)
                renewalUrl(TestConfig.RECOVERY_URL)
            }
            .build()

        assertFalse(PinVault.isEnrolled(context, config))

        val started = System.currentTimeMillis()
        val first = runBlocking { PinVault.init(context, config) }
        val elapsed = System.currentTimeMillis() - started
        assertTrue("Sertifikasız init başarısız olmalı: $first", first is InitResult.Failed)
        assertTrue("Hata 'kayıt gerekli' olmalı: $first",
            (first as InitResult.Failed).exception is io.github.umutcansu.pinvault.model.ClientCertificateRequiredException)
        assertTrue("Ağa çıkmadan hemen dönmeli, ${elapsed}ms sürdü", elapsed < 3000)

        val clientId = newClientId()
        assertTrue("init'ten önce kayıt", runBlocking { PinVault.enroll(context, config, generateEnrollmentTokenFor(clientId)) })
        assertTrue(PinVault.isEnrolled(context, config))
        assertEquals("csr", serverRecord(clientId)?.optString("keyType"))

        val second = runBlocking { PinVault.init(context, config) }
        assertTrue("Kayıttan sonra tek init mTLS ile hazır olmalı: $second", second is InitResult.Ready)
        assertTrue(PinVault.hostPinVersions().isNotEmpty())
    }

    // ─── İlk kayıt: arayüzdeki "Kayıt Ol" düğmesi ───────

    /**
     * Kullanıcının yaptığı gibi: sertifikasız cihaz mTLS ekranını açar,
     * "Kayıt Ol" diyaloğuna token'ı yazar. Kayıt enrollmentUrl'e (8091, düz
     * TLS) gider — 8092 sertifikasız cihazı el sıkışmada reddettiği için.
     */
    @Test
    fun mtlsConfig_enroll_button_enrolls_over_tls() {
        val clientId = newClientId()
        val token = generateEnrollmentTokenFor(clientId)

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(3000)
        onView(withId(R.id.tvEnrollStatus)).check(matches(withText(containsString("✗"))))

        submitEnrollToken(token)
        qaScreenshots.capture("enroll-submitted")

        val deadline = System.currentTimeMillis() + 40000
        while (!PinVault.isEnrolled(context) && System.currentTimeMillis() < deadline) Thread.sleep(1000)
        assertTrue("Arayüzden kayıt tamamlanmalı", PinVault.isEnrolled(context))
        assertEquals("csr", serverRecord(clientId)?.optString("keyType"))

        awaitReady()
        qaScreenshots.capture("after-ui-enroll")
        onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvEnrollStatus)).check(matches(withText(containsString("✓"))))
    }

    /**
     * Sunucu bu cihazı hâlâ başka bir kimlikle etkin biliyorsa (telefondaki
     * kayıt silinmiş olsa da) yeni kimliğin token'ı reddedilir. Ekran nedenini
     * söyler ("token geçersiz" değil) ve token harcanmaz: eski kimlik iptal
     * edilince aynı token'la kayıt olur.
     */
    @Test
    fun mtlsConfig_enroll_refusal_says_why() {
        val first = newClientId()
        enrollProgrammatically(first)
        PinVault.unenroll(context) // yalnızca telefondaki kayıt; sunucuda `first` etkin
        val second = "test-second-${System.currentTimeMillis()}"
        val token = mintToken(second)

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(3000)
        submitEnrollToken(token)
        val why = context.getString(R.string.enrollment_device_already_enrolled)
        awaitResult(why)
        qaScreenshots.capture("refused-device-already-enrolled")
        onView(withId(R.id.tvResult)).check(matches(withText(containsString(why))))
        assertFalse(PinVault.isEnrolled(context))

        revokeOnServer(first)
        submitEnrollToken(token)
        val deadline = System.currentTimeMillis() + 40000
        while (!PinVault.isEnrolled(context) && System.currentTimeMillis() < deadline) Thread.sleep(1000)
        qaScreenshots.capture("enrolled-after-revoke")
        assertTrue("Eski kimlik iptal edilince aynı token'la kayıt olmalı", PinVault.isEnrolled(context))
        assertEquals("csr", serverRecord(second)?.optString("keyType"))
    }

    // ─── Kayıt kodu: tek kod, çok cihaz; her cihaz onaylanır ───

    /** Yönetim API'sinden bir kayıt politikası: (politika id, kod). */
    private fun createPolicy(name: String, maxDevices: Int, approval: Boolean): Pair<String, String> {
        val resp = TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-policies")
                .post("""{"name":"$name","maxDevices":$maxDevices,"validDays":1,"requireApproval":$approval}"""
                    .toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        val body = resp.body?.string() ?: ""
        assertTrue("Politika oluşturulmalı: ${resp.code} $body", resp.isSuccessful)
        val json = org.json.JSONObject(body)
        return json.getJSONObject("policy").getString("id") to json.getString("code")
    }

    /** [policyName] ile onay bekleyen isteğe panelin düğmesi gibi karar verir; verilecek client id'yi döner. */
    private fun decidePendingOf(policyName: String, decision: String): String {
        val list = TestConfig.adminClient.newCall(
            Request.Builder().url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-requests?status=pending").build()
        ).execute().use { org.json.JSONArray(it.body?.string() ?: "[]") }
        val request = (0 until list.length()).map { list.getJSONObject(it) }
            .firstOrNull { it.optString("policyName") == policyName }
            ?: throw AssertionError("$policyName için onay bekleyen istek yok: $list")
        TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-requests/${request.getString("id")}/$decision")
                .post(ByteArray(0).toRequestBody(null))
                .build()
        ).execute().use { assertTrue("$decision başarılı olmalı: ${it.code} ${it.body?.string()}", it.isSuccessful) }
        return request.getString("clientId")
    }

    private fun stopPolicy(policyId: String) {
        TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-policies/$policyId/stop")
                .post(ByteArray(0).toRequestBody(null))
                .build()
        ).execute().close()
    }

    /**
     * Onaylı politika: cihaz kodu girer, "onay bekleniyor" der; yönetici
     * onaylayınca uygulama kendiliğinden kaydı tamamlar ve mTLS config API ile
     * hazır olur. Kod telefonda küçük harfle yazılsa da olur.
     */
    @Test
    fun mtlsConfig_enrollment_code_waits_for_approval_then_completes() {
        releaseThisDevice()
        val name = "espresso-${System.currentTimeMillis()}"
        val (policyId, code) = createPolicy(name, maxDevices = 2, approval = true)
        try {
            scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
            Thread.sleep(3000)
            submitEnrollToken(code.lowercase())

            val waiting = context.getString(R.string.enrollment_pending_status, "")
            awaitResult(waiting, viewId = R.id.tvEnrollStatus)
            qaScreenshots.capture("waiting-for-approval")
            onView(withId(R.id.tvEnrollStatus)).check(matches(withText(containsString(waiting))))
            assertFalse(PinVault.isEnrolled(context))
            assertTrue(PinVault.isEnrollmentPending(context))

            val clientId = decidePendingOf(name, "approve")
            val deadline = System.currentTimeMillis() + 40000
            while (!PinVault.isEnrolled(context) && System.currentTimeMillis() < deadline) Thread.sleep(1000)
            assertTrue("Onaydan sonra kayıt kendiliğinden tamamlanmalı", PinVault.isEnrolled(context))
            assertTrue(clientId, clientId.startsWith("$name-"))
            assertEquals("csr", serverRecord(clientId)?.optString("keyType"))

            awaitReady()
            qaScreenshots.capture("approved-and-ready")
            onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))
            onView(withId(R.id.tvEnrollStatus)).check(matches(withText(containsString("✓"))))
            assertFalse(PinVault.isEnrollmentPending(context))
        } finally {
            stopPolicy(policyId)
        }
    }

    /** Yönetici reddederse ekran bunu söyler; cihaz beklemeyi bırakır, kodla yeniden başvurabilir. */
    @Test
    fun mtlsConfig_enrollment_code_rejected_says_so() {
        releaseThisDevice()
        val name = "espresso-rej-${System.currentTimeMillis()}"
        val (policyId, code) = createPolicy(name, maxDevices = 2, approval = true)
        try {
            scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
            Thread.sleep(3000)
            submitEnrollToken(code)
            awaitResult(context.getString(R.string.enrollment_pending_status, ""), viewId = R.id.tvEnrollStatus)

            decidePendingOf(name, "reject")
            val rejected = context.getString(R.string.enrollment_rejected)
            awaitResult(rejected)
            qaScreenshots.capture("rejected")
            onView(withId(R.id.tvResult)).check(matches(withText(containsString(rejected))))
            assertFalse(PinVault.isEnrolled(context))
            assertFalse("Reddedilen istek unutulur", PinVault.isEnrollmentPending(context))
            onView(withId(R.id.btnEnroll)).check(matches(isEnabled()))
        } finally {
            stopPolicy(policyId)
        }
    }

    // ─── Kodsuz başvuru: token ya da kod yok, yalnızca onay ───

    private fun setOpenApplications(enabled: Boolean) {
        TestConfig.adminClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-open")
                .put("""{"enabled":$enabled}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute().use { assertTrue("Kodsuz başvuru anahtarı: ${it.code}", it.isSuccessful) }
    }

    /**
     * Kodsuz başvuru (MAC filtresi gibi): cihaz hiçbir şey girmeden başvurur ve
     * ekranında bir doğrulama kodu gösterir; panelde aynı kod isteğin yanında
     * görünür. Yönetici onaylayınca uygulama kendiliğinden kayıt olur.
     */
    @Test
    fun mtlsConfig_codeless_application_waits_for_approval() {
        releaseThisDevice()
        setOpenApplications(true)
        try {
            scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
            Thread.sleep(3000)
            onView(withId(R.id.btnEnroll)).perform(click())
            onView(withId(android.R.id.button3)).perform(click())   // "Kodsuz başvur"

            awaitResult(context.getString(R.string.enrollment_pending_status, ""), viewId = R.id.tvEnrollStatus)
            val code = PinVault.enrollmentVerificationCode(context)
            assertNotNull("Cihazın doğrulama kodu olmalı", code)
            onView(withId(R.id.tvEnrollStatus)).check(matches(withText(context.getString(R.string.enrollment_pending_status, code))))
            qaScreenshots.capture("codeless-waiting")

            // Panelde aynı kod: yönetici doğru cihazı onaylar.
            val list = TestConfig.adminClient.newCall(
                Request.Builder().url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-requests?status=pending").build()
            ).execute().use { org.json.JSONArray(it.body?.string() ?: "[]") }
            val request = (0 until list.length()).map { list.getJSONObject(it) }
                .firstOrNull { it.optString("verificationCode") == code }
                ?: throw AssertionError("Panelde $code kodlu istek yok: $list")
            assertTrue(request.optBoolean("openApplication"))
            TestConfig.adminClient.newCall(
                Request.Builder()
                    .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-requests/${request.getString("id")}/approve")
                    .post(ByteArray(0).toRequestBody(null))
                    .build()
            ).execute().use { assertTrue("Onay: ${it.code}", it.isSuccessful) }

            val clientId = request.getString("clientId")
            val deadline = System.currentTimeMillis() + 40000
            while (!PinVault.isEnrolled(context) && System.currentTimeMillis() < deadline) Thread.sleep(1000)
            assertTrue("Onaydan sonra kayıt kendiliğinden tamamlanmalı", PinVault.isEnrolled(context))
            assertTrue(clientId, clientId.startsWith("device-"))
            assertEquals("csr", serverRecord(clientId)?.optString("keyType"))
            awaitReady()
            qaScreenshots.capture("codeless-approved")
            onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))
        } finally {
            setOpenApplications(false)
        }
    }

    // ─── CSR: sertifika yenileme ───────────────────────

    /**
     * Kısa ömürlü sertifika: kalan ömür eşiğin altında olduğu için init
     * sırasında, hâlâ geçerliyken, mTLS üzerinden kendiliğinden yenilenir.
     * (Ömür = 300 s + 1 saat geriye alınmış notBefore; 300/3900 < 1/3.)
     */
    @Test
    fun mtlsConfig_renews_when_cert_near_expiry() {
        val clientId = newClientId()
        setTestTtl(clientId, 300)
        enrollProgrammatically(clientId)
        val before = PinVault.enrolledClientNotAfter(context)!!
        assertEquals("csr", serverRecord(clientId)?.optString("keyType"))

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        qaScreenshots.capture("after-auto-renew")

        onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvCertExpiry)).check(matches(isDisplayed()))
        val after = PinVault.enrolledClientNotAfter(context)!!
        assertTrue("Sertifika yenilenmiş olmalı: $before → $after", after > before)
        assertEquals(1, serverRecord(clientId)?.optInt("renewCount"))
    }

    /**
     * Süresi dolmuş sertifika: mTLS kapısı kapalı, kütüphane CSR'ı 8091'deki
     * kurtarma adresine götürür ve cihaz yeniden mTLS kullanabilir.
     */
    @Test
    fun mtlsConfig_recovers_after_cert_expired() {
        val clientId = newClientId()
        setTestTtl(clientId, 30)
        enrollProgrammatically(clientId)
        val before = PinVault.enrolledClientNotAfter(context)!!
        Thread.sleep(35000)
        assertTrue("Sertifika dolmuş olmalı", before < System.currentTimeMillis())

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        qaScreenshots.capture("after-recovery")

        val after = PinVault.enrolledClientNotAfter(context)!!
        assertTrue("Kurtarma adresi yeni sertifika vermeli: $before → $after", after > System.currentTimeMillis())
        assertEquals(1, serverRecord(clientId)?.optInt("renewCount"))
        onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))
    }

    /** İptal edilmiş kimlik yenilenemez; "Yenile" düğmesi yeniden kayıt gerektiğini söyler. */
    @Test
    fun mtlsConfig_revoked_cert_reports_reenroll_required() {
        val clientId = newClientId()
        enrollProgrammatically(clientId)

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))

        revokeOnServer(clientId)
        TestConfig.waitForMtlsRestart()
        val result = runBlocking { PinVault.renewClientCertIfNeeded(force = true) }
        assertTrue("İptal sonrası yeniden kayıt istenmeli: $result",
            result is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.ReenrollRequired)
        assertEquals(0, serverRecord(clientId)?.optInt("renewCount"))

        onView(withId(R.id.btnRenew)).perform(click())
        Thread.sleep(8000)
        qaScreenshots.capture("renew-refused")
        // Cihaz diline bağımsız: kaynak metnin sabit kısmı ("… (%1$s)" öncesi).
        val expected = context.getString(R.string.log_renew_reenroll, "").substringBefore(" (")
        onView(withId(R.id.tvResult)).check(matches(withText(containsString(expected))))
    }

    /**
     * İptal edilen cihaz bunu yenileme vaktini (90 günün 60.'sı) beklemeden,
     * bir sonraki açılışında öğrenir: config isteği 403 reenroll_required alır
     * ve PinVault yeniden kayıt olayını bir kez yayınlar.
     */
    @Test
    fun mtlsConfig_revoked_device_hears_it_at_next_start() {
        val clientId = newClientId()
        enrollProgrammatically(clientId)

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        onView(withId(R.id.tvStatus)).check(matches(withText(containsString("✓"))))

        revokeOnServer(clientId)
        TestConfig.waitForMtlsRestart()
        scenario?.close()
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        Thread.sleep(3000)
        qaScreenshots.capture("revoked-at-start")

        val expected = context.getString(R.string.log_renew_reenroll, "").substringBefore(" (")
        onView(withId(R.id.logContainer)).check(matches(hasDescendant(withText(containsString(expected)))))
        // Yenileme isteği gönderilmedi: haber config isteğinden geldi.
        assertEquals(0, serverRecord(clientId)?.optInt("renewCount"))
    }

    // ─── mTLS — enrollment olmadan → reddedilir ─────────

    @Test
    fun mtlsConfig_without_enrollment_fails() {
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // MtlsToTlsActivity requiresEnrollment=true → enrollment olmadan ready olmaz
        onView(withId(R.id.tvStatus))
            .check(matches(not(withText(containsString("✓")))))
        onView(withId(R.id.enrollmentCard))
            .check(matches(isDisplayed()))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✗"))))
    }

    // ─── mTLS — enrollment sonrası init succeeds ────────

    @Test
    fun mtlsConfig_after_enrollment_init_succeeds() {
        // 1) ÖNCE: enrollment yokken activity açılır → "✗ Not Enrolled" + "Enrollment required"
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(8000)
        qaScreenshots.capture("before-enroll")
        scenario?.close()
        scenario = null

        // 2) Enrollment: Management API'den token alınıp PinVault.enroll ile P12 yüklenir
        //    (UI ENROLL butonu dialog açtığından dialog Espresso'da token type etmek karmaşık;
        //     aynı code path programmatik olarak tetiklenir — mimari kanıt değişmez).
        enrollProgrammatically()

        // 3) SONRA: Activity tekrar açılır → Client ID görünür + STATUS Ready (v2)
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ─── mTLS → TLS Host → 200 ─────────────────────────

    @Test
    fun mtlsConfig_to_tlsHost_returns_200() {
        enrollProgrammatically()

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        clickTest()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }

    // ─── mTLS — enrollment reinit sonrası korunuyor ─────

    @Test
    fun mtlsConfig_enrollment_persists_after_reinit() {
        enrollProgrammatically()

        // İlk launch
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Kapat
        scenario!!.close()
        PinVault.reset()
        Thread.sleep(500)

        // Tekrar launch — enrollment persist etmiş olmalı
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ─── Unenroll → mTLS reddeder ──────────────────────

    @Test
    fun mtlsConfig_unenroll_then_init_fails() {
        enrollProgrammatically()
        assertTrue(PinVault.isEnrolled(context))

        // 1) Activity aç → "Enrolled + Ready" — "ÖNCE" görseli
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)
        qaScreenshots.capture("before-unenroll")

        // 2) UNENROLL butonuna Espresso ile gerçek tıklama — kullanıcı akışını simüle eder.
        //    Buton tıklanmadan hemen önceki kareyi ayrı bir kanıt olarak yakala.
        qaScreenshots.capture("button-click")
        onView(withId(R.id.btnUnenroll)).perform(click())
        Thread.sleep(2000) // UI refresh

        // 3) Artık "Not Enrolled" olmalı — local cert silindi
        assertFalse(PinVault.isEnrolled(context))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✗"))))
    }

    // ─── Re-enrollment çalışır ──────────────────────────

    @Test
    fun mtlsConfig_reenroll_after_unenroll_works() {
        // İlk enrollment
        enrollProgrammatically()

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Unenroll
        scenario!!.close()
        PinVault.unenroll(context)
        PinVault.reset()
        Thread.sleep(500)

        assertFalse(PinVault.isEnrolled(context))

        // Re-enrollment
        enrollProgrammatically()
        Thread.sleep(2000) // allow re-enrollment to settle on physical devices

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        awaitReady()

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }
}
