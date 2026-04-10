package io.github.umutcansu.pinvault

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * A.5 — PinVault.autoEnroll: isEnrolled doğrulaması
 * A.6 — PinVault.unenroll: cert silme sonrası isEnrolled false
 *
 * Instrumented test — EncryptedSharedPreferences requires AndroidKeyStore.
 */
@RunWith(AndroidJUnit4::class)
class PinVaultEnrollTest {

    private lateinit var context: Context
    private lateinit var certStore: ClientCertSecureStore

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        certStore = ClientCertSecureStore(context)
        certStore.clearAll()
        try { PinVault.reset() } catch (_: Exception) {}
    }

    private fun generateTestP12(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        // Minimal self-signed cert using platform APIs
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        // Can't create X509Certificate without BouncyCastle in androidTest
        // So we store a minimal P12 with just a key
        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, "changeit".toCharArray())
        return baos.toByteArray()
    }

    @Test
    fun isEnrolled_false_when_no_cert() {
        assertFalse(PinVault.isEnrolled(context))
    }

    @Test
    fun isEnrolled_true_after_manual_cert_store() {
        // Store any bytes to simulate enrollment
        certStore.save(byteArrayOf(1, 2, 3, 4, 5))
        assertTrue(PinVault.isEnrolled(context))
    }

    @Test
    fun isEnrolled_with_custom_label() {
        assertFalse(PinVault.isEnrolled(context, "my_host"))
        certStore.save("my_host", byteArrayOf(10, 20))
        assertTrue(PinVault.isEnrolled(context, "my_host"))
        assertFalse(PinVault.isEnrolled(context)) // default label still empty
    }

    @Test
    fun unenroll_removes_default_cert() {
        certStore.save(byteArrayOf(1, 2, 3))
        assertTrue(PinVault.isEnrolled(context))

        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))
    }

    @Test
    fun unenroll_with_label_removes_only_that_label() {
        certStore.save(byteArrayOf(1))
        certStore.save("host_x", byteArrayOf(2))

        assertTrue(PinVault.isEnrolled(context))
        assertTrue(PinVault.isEnrolled(context, "host_x"))

        PinVault.unenroll(context, "host_x")

        assertTrue(PinVault.isEnrolled(context))      // default untouched
        assertFalse(PinVault.isEnrolled(context, "host_x")) // removed
    }

    @Test
    fun double_unenroll_is_safe() {
        PinVault.unenroll(context)
        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))
    }
}
