package io.github.umutcansu.pinvault

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.keystore.KeystoreOptions
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A second `init` is skipped, and so is its config: the running setup's
 * config and Keystore options are not changed by a call that sets nothing up.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SecondInitKeystoreOptionsTest {

    private val initialized = PinVault::class.java.getDeclaredField("initialized").apply { isAccessible = true }
    private val runningConfig = PinVault::class.java.getDeclaredField("pinManagerConfig").apply { isAccessible = true }

    @After
    fun tearDown() {
        initialized.setBoolean(PinVault, false)
        runningConfig.set(PinVault, null)
        KeystoreOptions.unlockedDeviceRequired = false
        KeystoreOptions.unlockedDeviceFallbackAllowed = false
        KeystoreOptions.hardwareBackedRequired = false
    }

    @Test
    fun `a skipped init leaves the Keystore options and the running config as they are`() = runTest {
        val running = PinVaultConfig.static(HostPin("api.example.com", listOf("A".repeat(43) + "=", "E".repeat(43) + "=")))
        runningConfig.set(PinVault, running)
        initialized.setBoolean(PinVault, true)
        val strict = PinVaultConfig.Builder()
            .configApi("api", "https://api.example.com/") {
                bootstrapPins(listOf(HostPin("api.example.com", listOf("A".repeat(43) + "=", "E".repeat(43) + "="))))
                allowUnsigned()
            }
            .requireUnlockedDevice()
            .requireHardwareBackedKeys()
            .build()

        // The running setup is faked: only the flag is set, so the answer's
        // version lookup may fail here; what the call changed is the point.
        runCatching { PinVault.init(ApplicationProvider.getApplicationContext<Context>(), strict) }

        assertFalse(KeystoreOptions.unlockedDeviceRequired)
        assertFalse(KeystoreOptions.hardwareBackedRequired)
        assertSame(running, runningConfig.get(PinVault))
    }
}
