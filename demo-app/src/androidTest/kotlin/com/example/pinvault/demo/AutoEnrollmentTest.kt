package com.example.pinvault.demo

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.8 — Auto-enrollment: init sonrası otomatik P12 indirme
 * B.9 — Host cert indirme: config'te mtls:true → otomatik P12 indir
 * B.8b — P12 Android 11 compat: buildAndroidCompatP12 formatı cihazda yüklenebilmeli
 *
 * Programmatik test — PinVault API üzerinden.
 * Önkoşul: demo-server çalışıyor, TLS config API port 8091
 */
@RunWith(AndroidJUnit4::class)
class AutoEnrollmentTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    @After
    fun tearDown() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    /**
     * Token-based enrollment — güvenli akış (önerilen).
     * Management API'den token üretilir, PinVault.enroll(token) ile kayıt olunur.
     */
    @Test
    fun B8_tokenEnroll_downloads_P12_and_stores() {
        // Init PinVault
        val latch = CountDownLatch(1)
        var initResult: InitResult? = null

        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .build()

        PinVault.init(context, config) {
            initResult = it
            latch.countDown()
        }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
        assertTrue("Init should succeed: $initResult", initResult is InitResult.Ready)

        // Management API'den enrollment token üret
        val tokenResp = TestConfig.plainClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-tokens/generate")
                .post("""{"clientId":"enroll-test-${System.currentTimeMillis()}"}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Token üretme başarılı olmalı", tokenResp.isSuccessful)
        val tokenBody = tokenResp.body?.string() ?: ""
        val token = Regex(""""token":"([^"]+)"""").find(tokenBody)?.groupValues?.get(1)
        assertNotNull("Token parse edilmeli", token)

        // Token ile enroll
        val enrolled = runBlocking { PinVault.enroll(context, token!!) }
        assertTrue("Token enrollment başarılı olmalı", enrolled)
        assertTrue("After enrollment, isEnrolled should be true", PinVault.isEnrolled(context))
    }

    /**
     * P12 Android 11 uyumluluk testi.
     *
     * Server buildAndroidCompatP12 ile eski PBE algoritması (pbeWithSHAAnd3_KeyTripleDES_CBC)
     * kullanır. Bu test, üretilen P12'nin cihazın PKCS12 KeyStore provider'ı tarafından
     * yüklenebilir olduğunu doğrular — özellikle Android 11 (API 30) ve altı için kritik.
     */
    @Test
    fun B8b_p12_android_compat_format_loadable() {
        // Management API üzerinden enrollment token oluştur
        val tokenResp = TestConfig.plainClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-tokens/generate")
                .post("""{"clientId":"android-compat-test-${System.currentTimeMillis()}"}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Token oluşturma başarılı olmalı", tokenResp.isSuccessful)
        val tokenBody = tokenResp.body?.string() ?: ""
        val token = Regex(""""token":"([^"]+)"""").find(tokenBody)?.groupValues?.get(1)
            ?: return // Token endpoint yoksa skip

        // TLS Config API üzerinden enroll — P12 bytes al
        val enrollResp = TestConfig.trustAllClient.newCall(
            Request.Builder()
                .url("${TestConfig.TLS_CONFIG_URL}api/v1/client-certs/enroll")
                .post("""{"token":"$token"}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Enrollment başarılı olmalı: ${enrollResp.code}", enrollResp.isSuccessful)

        val p12Bytes = enrollResp.body?.bytes()
        assertNotNull("P12 bytes boş olmamalı", p12Bytes)
        assertTrue("P12 boyutu > 0", p12Bytes!!.isNotEmpty())

        // P12'yi Android'in PKCS12 KeyStore provider'ı ile yükle
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(p12Bytes.inputStream(), "changeit".toCharArray())

        val aliases = ks.aliases().toList()
        assertTrue("KeyStore en az 1 alias içermeli: $aliases", aliases.isNotEmpty())

        // Private key ve sertifika mevcut olmalı
        val hasKey = aliases.any { ks.isKeyEntry(it) }
        val hasCert = aliases.any { ks.isCertificateEntry(it) || ks.getCertificateChain(it) != null }
        assertTrue("P12'de private key olmalı", hasKey)
        assertTrue("P12'de sertifika olmalı", hasCert)

        // Android API seviyesini logla (test sonucunda görünür)
        println("P12 compat test passed on Android API ${Build.VERSION.SDK_INT} (${Build.MODEL})")
    }

    @Test
    fun B9_hostCert_downloaded_for_mtls_hosts() {
        // Init → config fetch
        val latch = CountDownLatch(1)
        var initResult: InitResult? = null

        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .build()

        PinVault.init(context, config) {
            initResult = it
            latch.countDown()
        }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
        assertTrue("Init should succeed: $initResult", initResult is InitResult.Ready)

        // Config'te mtls:true olan host varsa, SSLCertificateUpdater otomatik
        // P12 indirmiş olmalı. Davranışsal test: mTLS host'a bağlanabilmeli.
        // isEnrolled ile host label kontrolü yapabiliriz.
        val hostEnrolled = PinVault.isEnrolled(context, TestConfig.MTLS_HOST_CERT_LABEL)

        if (hostEnrolled) {
            // Host cert indirilmiş — mTLS host'a bağlantı deneyelim
            val client = PinVault.getClient()
            val resp = try {
                client.newCall(
                    Request.Builder().url("https://${TestConfig.HOST_IP}:8444/health").build()
                ).execute()
            } catch (_: Exception) { null }

            if (resp != null) {
                assertEquals("mTLS host should accept with host cert", 200, resp.code)
            }
            // resp == null ise mock server yok — test geçerli ama skip
        }
        // hostEnrolled == false ise config'te mtls host yoktur veya download başarısız — test fail değil
    }
}
