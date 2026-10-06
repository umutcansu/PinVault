package io.github.umutcansu.pinvault

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.GuardedOperation
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UntrustedEnvironmentException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The app's environment guard is asked before each guarded operation, and a
 * "no" — or a guard that throws — refuses it before anything is sent.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnvironmentGuardTest {

    private val pins = listOf(
        HostPin("api.example.com", listOf("A".repeat(43) + "=", "E".repeat(43) + "="))
    )

    private fun config(guard: ((GuardedOperation) -> Boolean)?) = PinVaultConfig.Builder()
        .configApi("api", "https://api.example.com/") { bootstrapPins(pins); allowUnsigned() }
        .apply { guard?.let { g -> environmentGuard { g(it) } } }
        .build()

    @Test
    fun `no guard - nothing is refused`() {
        GuardedOperation.values().forEach { assertNull(PinVault.environmentRefusal(config(null), it)) }
    }

    @Test
    fun `the guard is asked with the operation and its no refuses only that one`() {
        val asked = mutableListOf<GuardedOperation>()
        val cfg = config { op -> asked += op; op == GuardedOperation.INIT }
        assertNull(PinVault.environmentRefusal(cfg, GuardedOperation.INIT))
        val refused = PinVault.environmentRefusal(cfg, GuardedOperation.ENROLL)!!
        assertEquals(GuardedOperation.ENROLL, refused.operation)
        assertEquals(listOf(GuardedOperation.INIT, GuardedOperation.ENROLL), asked)
    }

    @Test
    fun `a guard that throws refuses`() {
        val refused = PinVault.environmentRefusal(config { throw IllegalStateException("detector crashed") }, GuardedOperation.FETCH_FILE)!!
        assertEquals(GuardedOperation.FETCH_FILE, refused.operation)
        assertTrue(refused.cause is IllegalStateException)
    }

    @Test
    fun `init is refused before anything is set up`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val result = PinVault.init(context, config { false })
        assertTrue(result is InitResult.Failed)
        assertTrue((result as InitResult.Failed).exception is UntrustedEnvironmentException)
    }

    @Test
    fun `enrollment before init is refused and nothing is sent`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val result = PinVault.enrollForResult(context, config { it != GuardedOperation.ENROLL }, "token")
        assertTrue(result is ClientCertEnrollmentResult.Failed)
        val cause = (result as ClientCertEnrollmentResult.Failed).cause
        assertTrue(cause is UntrustedEnvironmentException)
        assertEquals(GuardedOperation.ENROLL, (cause as UntrustedEnvironmentException).operation)
    }
}
