package com.example.pinvault.demo

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Espresso tests for the V2 `VaultSecurityDemoActivity` — exercises the
 * multi-Config-API + per-file policy + end-to-end encryption flows on a
 * real device against the real demo-server.
 *
 * **Preconditions**
 *  - demo-server running on :8090/:8091 with V2 migration applied
 *  - Device has network access to the server (Mi 9T: 192.168.1.80)
 *
 * **Device-side state shaping**
 * The activity reads tokens from SharedPreferences("vault_security_demo").
 * Each test uploads files and seeds prefs via [seedToken] before launching
 * the activity, so init (which triggers `registerDevicePublicKey`) happens
 * with the right server state in place.
 */
@RunWith(AndroidJUnit4::class)
class VaultSecurityEspressoTest {

    private lateinit var scenario: ActivityScenario<VaultSecurityDemoActivity>

    private val vaultApi = TestConfig.VAULT_API_URL
    private val deviceSuffix = android.os.Build.MODEL.replace(" ", "-").lowercase()
    private val keyPublic = "demo-public-v2-$deviceSuffix"
    private val keyToken  = "demo-token-v2-$deviceSuffix"
    private val keyE2E    = "demo-e2e-v2-$deviceSuffix"

    @Before
    fun setUp() {
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
        // Remove any stale tokens from previous runs
        prefs().edit().clear().apply()
        // Remove files so each test starts clean
        deleteVault(keyPublic)
        deleteVault(keyToken)
        deleteVault(keyE2E)
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        try { scenario.close() } catch (_: Exception) {}
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
        deleteVault(keyPublic)
        deleteVault(keyToken)
        deleteVault(keyE2E)
    }

    // ── Helpers ──────────────────────────────────────────

    private fun prefs() = InstrumentationRegistry.getInstrumentation().targetContext
        .getSharedPreferences("vault_security_demo", Context.MODE_PRIVATE)

    /**
     * Admin API key — demo-server's default when launched with API_KEY=testkey.
     * Management endpoints (vault PUT + POST tokens + DELETE tokens) require this.
     */
    private val adminApiKey = TestConfig.ADMIN_API_KEY

    private fun uploadWithPolicy(key: String, content: ByteArray, policy: String, encryption: String = "plain") {
        val url = "$vaultApi/$key?policy=$policy&encryption=$encryption"
        TestConfig.plainClient.newCall(
            Request.Builder().url(url)
                .header("X-API-Key", adminApiKey)
                .put(content.toRequestBody("application/octet-stream".toMediaType())).build()
        ).execute().use { r -> assertTrue("upload failed: ${r.code}", r.isSuccessful) }
    }

    private fun deleteVault(key: String) {
        try {
            TestConfig.plainClient.newCall(
                Request.Builder().url("$vaultApi/$key")
                    .header("X-API-Key", adminApiKey)
                    .delete().build()
            ).execute().close()
        } catch (_: Exception) { /* ignore */ }
    }

    private fun issueToken(key: String, deviceId: String): String {
        val url = "$vaultApi/$key/tokens"
        val body = """{"deviceId":"$deviceId"}""".toRequestBody("application/json".toMediaType())
        val resp = TestConfig.plainClient.newCall(
            Request.Builder().url(url)
                .header("X-API-Key", adminApiKey)
                .post(body).build()
        ).execute()
        val text = resp.body?.string() ?: ""
        resp.close()
        val match = Regex("\"token\"\\s*:\\s*\"([^\"]+)\"").find(text)
        return match?.groupValues?.get(1) ?: error("could not parse token from $text")
    }

    private fun seedToken(token: String) {
        prefs().edit()
            .putString("token_$keyToken", token)
            .putString("token_$keyE2E", token)
            .commit()
    }

    private fun launchAndWaitInit() {
        scenario = ActivityScenario.launch(VaultSecurityDemoActivity::class.java)
        // Give init time to register public key + fetch pins
        Thread.sleep(12000)
    }

    private fun currentDeviceId(): String {
        // The library uses ANDROID_ID — mirror that lookup here.
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        return android.provider.Settings.Secure.getString(
            ctx.contentResolver, android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown-device"
    }

    // ── Tests ────────────────────────────────────────────

    @Test
    fun T01_init_shows_ready_and_registers_public_key() {
        uploadWithPolicy(keyPublic, "{}".toByteArray(), "public")
        launchAndWaitInit()

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("Ready"))))
    }

    @Test
    fun T02_public_file_fetch_no_token_needed() {
        uploadWithPolicy(keyPublic,
            """{"feature":"dark_mode","enabled":true}""".toByteArray(), "public")
        launchAndWaitInit()

        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString(keyPublic))))
        // Public file should say Updated or Current, not FAIL
        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("[PUBLIC]"))))
    }

    @Test
    fun T03_token_file_without_token_fails() {
        uploadWithPolicy(keyToken, "secret".toByteArray(), "token")
        // Intentionally no seedToken() — prefs empty

        launchAndWaitInit()
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("FAIL"))))
    }

    @Test
    fun T04_token_file_with_valid_token_succeeds() {
        uploadWithPolicy(keyToken, "token-gated-payload".toByteArray(), "token")
        val token = issueToken(keyToken, currentDeviceId())
        seedToken(token)

        launchAndWaitInit()
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("[TOKEN]"))))
        // Must not contain FAIL for keyToken line
        scenario.onActivity {
            val text = it.findViewById<android.widget.TextView>(R.id.tvResult).text.toString()
            val tokenLine = text.lines().firstOrNull { l -> l.contains(keyToken) } ?: ""
            assertFalse("token line must not be FAIL: $tokenLine",
                tokenLine.contains("FAIL"))
        }
    }

    @Test
    fun T05_token_from_wrong_device_rejected() {
        uploadWithPolicy(keyToken, "secret".toByteArray(), "token")
        // Token for a DIFFERENT device id than this one
        val token = issueToken(keyToken, "some-other-phone")
        seedToken(token)

        launchAndWaitInit()
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("FAIL"))))
    }

    @Test
    fun T06_e2e_encrypted_file_decrypts_locally() {
        // E2E file needs token policy + encryption=end_to_end
        uploadWithPolicy(keyE2E,
            """{"secret":"top-secret-e2e","version":1}""".toByteArray(),
            policy = "token", encryption = "end_to_end")
        val token = issueToken(keyE2E, currentDeviceId())
        seedToken(token)

        launchAndWaitInit()
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(10000)

        // Successful decryption shows Updated + bytes count
        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("[TOKEN+E2E]"))))
        scenario.onActivity {
            val text = it.findViewById<android.widget.TextView>(R.id.tvResult).text.toString()
            val e2eLine = text.lines().firstOrNull { l -> l.contains(keyE2E) } ?: ""
            assertFalse("e2e line must not be FAIL: $e2eLine", e2eLine.contains("FAIL"))
        }
    }

    @Test
    fun T07_all_three_policies_mixed_result() {
        uploadWithPolicy(keyPublic, "p".toByteArray(), "public")
        uploadWithPolicy(keyToken, "t".toByteArray(), "token")
        uploadWithPolicy(keyE2E, "e".toByteArray(), "token", "end_to_end")
        val tokenPlaintext = issueToken(keyToken, currentDeviceId())
        val e2ePlaintext = issueToken(keyE2E, currentDeviceId())
        prefs().edit()
            .putString("token_$keyToken", tokenPlaintext)
            .putString("token_$keyE2E", e2ePlaintext)
            .commit()

        launchAndWaitInit()
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(12000)

        scenario.onActivity {
            val text = it.findViewById<android.widget.TextView>(R.id.tvResult).text.toString()
            // Each of the three keys must appear in the result output
            assertTrue("public missing: $text", text.contains(keyPublic))
            assertTrue("token missing: $text",  text.contains(keyToken))
            assertTrue("e2e missing: $text",    text.contains(keyE2E))
            // None should be FAIL in this happy-path scenario
            assertFalse("unexpected FAIL: $text", text.contains("FAIL"))
        }
    }

    @Test
    fun T08_token_revocation_causes_next_fetch_to_fail() {
        uploadWithPolicy(keyToken, "payload".toByteArray(), "token")
        val token = issueToken(keyToken, currentDeviceId())
        seedToken(token)

        launchAndWaitInit()

        // 1st fetch — succeeds with token
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)
        scenario.onActivity {
            val text = it.findViewById<android.widget.TextView>(R.id.tvResult).text.toString()
            val line = text.lines().firstOrNull { l -> l.contains(keyToken) } ?: ""
            assertFalse("1st fetch should succeed: $line", line.contains("FAIL"))
        }

        // Admin revokes all tokens for this file by re-issuing (any existing
        // row is replaced — old plaintext hash is discarded).
        issueToken(keyToken, currentDeviceId())   // replaces; old token in prefs invalid

        // 2nd fetch — prefs still carry the OLD plaintext → 401
        onView(withId(R.id.btnTest)).perform(androidx.test.espresso.action.ViewActions.click())
        Thread.sleep(8000)
        scenario.onActivity {
            val text = it.findViewById<android.widget.TextView>(R.id.tvResult).text.toString()
            val line = text.lines().firstOrNull { l -> l.contains(keyToken) } ?: ""
            assertTrue("2nd fetch must fail after token rotation: $line",
                line.contains("FAIL"))
        }
    }
}
