package io.github.umutcansu.pinvault

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * `allowUnsigned()` and `allowUnpinnedConfigApi()` are test relaxations: a
 * release build (the app is not debuggable) refuses a block that has one,
 * before anything is set up or sent, unless the block also called
 * `allowRelaxationsInRelease()`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ReleaseRelaxationsTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val pins = listOf(HostPin("api.example.com", listOf("A".repeat(43) + "=", "E".repeat(43) + "=")))
    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhV/GUJAv4A77uf8C9XygQ225QOYWLF0Wck49+yXjV/9OE7uE8sVdhjxmNuXXgklz6bYA4oKIdkvQqNZaXM90WQ=="
    private val debuggable = PinVault.isDebuggableApp

    @Before fun releaseBuild() { PinVault.isDebuggableApp = { false } }
    @After fun restore() { PinVault.isDebuggableApp = debuggable }

    private fun config(block: ConfigApiBlock.Builder.() -> Unit) = PinVaultConfig.Builder()
        .configApi("api", "https://api.example.com/", block)
        .build()

    @Test
    fun `a signed and pinned block is not affected`() {
        assertNull(PinVault.releaseRefusal(context, config { bootstrapPins(pins); signaturePublicKey(key) }))
    }

    @Test
    fun `allowUnsigned and allowUnpinnedConfigApi are refused in a release build, naming the block`() {
        val unsigned = PinVault.releaseRefusal(context, config { bootstrapPins(pins); allowUnsigned() })!!
        assertTrue(unsigned.message, unsigned.message!!.contains("'api': allowUnsigned()"))
        val both = PinVault.releaseRefusal(context, config { allowUnpinnedConfigApi(); allowUnsigned() })!!
        assertTrue(both.message, both.message!!.contains("'api': allowUnsigned() and allowUnpinnedConfigApi()"))
        assertTrue(both.message!!.contains("allowRelaxationsInRelease()"))
    }

    @Test
    fun `allowRelaxationsInRelease keeps them deliberately`() {
        assertNull(PinVault.releaseRefusal(context, config { allowUnpinnedConfigApi(); allowUnsigned(); allowRelaxationsInRelease() }))
    }

    @Test
    fun `a debug build takes them as before`() {
        PinVault.isDebuggableApp = { true }
        assertNull(PinVault.releaseRefusal(context, config { allowUnpinnedConfigApi(); allowUnsigned() }))
    }

    @Test
    fun `init fails before anything is set up`() = runTest {
        val result = PinVault.init(context, config { bootstrapPins(pins); allowUnsigned() })
        assertTrue(result.toString(), result is InitResult.Failed)
        val failed = result as InitResult.Failed
        assertTrue(failed.exception is IllegalStateException)
        assertTrue(failed.reason, failed.reason.startsWith("Release build refused: Config API 'api': allowUnsigned()"))
    }

    @Test
    fun `enrollment before init fails the same way`() = runTest {
        val result = PinVault.enrollForResult(context, config { allowUnpinnedConfigApi(); signaturePublicKey(key) }, "token")
        assertTrue(result.toString(), result is ClientCertEnrollmentResult.Failed)
        assertEquals(
            "Release build refused: Config API 'api': allowUnpinnedConfigApi() — test relaxations. Remove them for release, " +
                "or call allowRelaxationsInRelease() on the block to keep them deliberately.",
            (result as ClientCertEnrollmentResult.Failed).message
        )
    }
}
