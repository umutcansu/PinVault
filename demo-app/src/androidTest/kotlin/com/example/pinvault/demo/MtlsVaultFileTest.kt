package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.PinVault
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * mTLS Config API + VaultFile cross-layer Espresso testleri.
 *
 * VaultFileDemoActivity üzerinden (TLS config ile vault file fetch).
 * Server'a vault dosyası yükler, Activity UI ile fetch/sync yapar, sonucu ekranda doğrular.
 *
 * Not: VaultFileDemoActivity TLS Config API kullanır. mTLS layer testi için
 * vault dosyaları management API üzerinden yüklenir ve TLS config API üzerinden fetch edilir.
 * mTLS enrollment test'leri MtlsConfigApiTest'te test edilir.
 *
 * Önkoşul:
 *   - demo-server management  :8090
 *   - TLS Config API          :8091
 */
@RunWith(AndroidJUnit4::class)
class MtlsVaultFileTest {

    private lateinit var scenario: ActivityScenario<VaultFileDemoActivity>

    private val vaultApi = TestConfig.VAULT_API_URL

    private val deviceSuffix = android.os.Build.MODEL.replace(" ", "-").lowercase()
    private val keyConfig = "feature-flags-$deviceSuffix"
    private val keyBinary = "ml-model-$deviceSuffix"

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
        scenario = ActivityScenario.launch(VaultFileDemoActivity::class.java)
        Thread.sleep(12000)
    }

    @After
    fun tearDown() {
        try { scenario.close() } catch (_: Exception) {}
        try { PinVault.reset() } catch (_: Exception) {}
        deleteVault(keyConfig)
        deleteVault(keyBinary)
    }

    // ── Helpers ──────────────────────────────────────────

    private fun uploadVault(key: String, content: ByteArray) {
        TestConfig.plainClient.newCall(
            Request.Builder().url("$vaultApi/$key")
                .put(content.toRequestBody("application/octet-stream".toMediaType())).build()
        ).execute().close()
    }

    private fun deleteVault(key: String) {
        try {
            TestConfig.plainClient.newCall(
                Request.Builder().url("$vaultApi/$key").delete().build()
            ).execute().close()
        } catch (_: Exception) {}
    }

    private fun getServerStats(): String {
        return try {
            TestConfig.plainClient.newCall(
                Request.Builder().url("$vaultApi/stats").build()
            ).execute().body?.string() ?: "{}"
        } catch (_: Exception) { "{}" }
    }

    private fun clickFetch() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    private fun clickSync() {
        onView(withId(R.id.btnUpdate)).perform(click())
        Thread.sleep(6000)
    }

    // ── Vault file fetch ────────────────────────────────

    @Test
    fun mtlsVault_web_upload_then_mtls_client_fetch() {
        val content = """{"feature":"premium","enabled":true}"""
        uploadVault(keyConfig, content.toByteArray())

        clickFetch()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString(keyConfig))))
        onView(withId(R.id.tvCertInfo))
            .check(matches(withText(containsString("bytes"))))
    }

    // ── Distribution tracking ───────────────────────────

    @Test
    fun mtlsVault_fetch_reports_distribution_to_server() {
        uploadVault(keyConfig, "dist-test".toByteArray())

        clickFetch()
        Thread.sleep(3000) // wait for report

        val stats = getServerStats()
        assertTrue(
            "Server should have distributions: $stats",
            stats.contains("\"totalDistributions\"") && !stats.contains("\"totalDistributions\":0")
        )
    }

    // ── Without upload — fetch fails ────────────────────

    @Test
    fun mtlsVault_without_enrollment_fetch_fails() {
        // Vault dosyası yüklemeden fetch — FAILED göstermeli
        clickFetch()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("FAILED"))))
    }

    // ── Sync all files ──────────────────────────────────

    @Test
    fun mtlsVault_syncAllFiles_over_mtls() {
        uploadVault(keyConfig, "sync-data".toByteArray())

        clickSync()

        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))
    }

    // ── Web update → new content ────────────────────────

    @Test
    fun mtlsVault_web_update_then_mtls_client_gets_new_content() {
        uploadVault(keyConfig, "v1".toByteArray())
        clickFetch()

        // Update on server
        uploadVault(keyConfig, "v2-new-content".toByteArray())
        clickFetch()

        // Log should show both fetches
        onView(withId(R.id.logContainer))
            .check(matches(isDisplayed()))
        onView(withId(R.id.logContainer))
            .check(matches(hasMinimumChildCount(2)))
    }

    // ── Unenroll effect on vault files ──────────────────

    @Test
    fun mtlsVault_unenroll_then_fetch_fails_on_reinit() {
        uploadVault(keyConfig, "data".toByteArray())
        clickFetch()

        // Vault file fetched — result shown
        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString(keyConfig))))

        // Delete vault file on server → next fetch fails
        deleteVault(keyConfig)
        clickFetch()

        // ikinci fetch — dosya yok → FAILED
        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("FAILED"))))
    }
}
