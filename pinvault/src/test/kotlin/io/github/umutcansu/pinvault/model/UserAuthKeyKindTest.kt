package io.github.umutcansu.pinvault.model

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import io.github.umutcansu.pinvault.internal.UserAuthPrompt
import io.github.umutcansu.pinvault.keystore.KeystoreUserAuthKeys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The API-level decisions behind the user-auth key: which kind a device
 * gets, and what the prompt may offer for it. Each case runs with
 * Robolectric at the Android version it is about, so `Build.VERSION.SDK_INT`
 * is the real thing the library reads.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class UserAuthKeyKindTest {

    @Test
    @Config(sdk = [24])
    fun `Android 7 gets a fingerprint-only key with a fingerprint, else a time-bound one, and the prompt pairs strong with the screen lock`() {
        assertEquals(24, Build.VERSION.SDK_INT)
        assertEquals(UserAuthKeyKind.PER_USE_BIOMETRIC, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = true))
        assertEquals(UserAuthKeyKind.TIME_BOUND, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = false))
        assertEquals("STRONG | DEVICE_CREDENTIAL is supported below API 28: no weak biometric",
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND))
        assertEquals(BIOMETRIC_STRONG, UserAuthPrompt.authenticators(UserAuthKeyKind.PER_USE_BIOMETRIC))
    }

    @Test
    @Config(sdk = [27])
    fun `Android 8_1 decides like Android 7`() {
        assertEquals(UserAuthKeyKind.TIME_BOUND, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = false))
        assertEquals(UserAuthKeyKind.PER_USE_BIOMETRIC, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = true))
        assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND))
    }

    @Test
    @Config(sdk = [28])
    fun `Android 9 gets the same kinds, but the time-bound prompt must list weak biometrics`() {
        assertEquals(UserAuthKeyKind.PER_USE_BIOMETRIC, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = true))
        assertEquals(UserAuthKeyKind.TIME_BOUND, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = false))
        assertEquals("androidx.biometric: STRONG | DEVICE_CREDENTIAL is unsupported on API 28-29",
            BIOMETRIC_WEAK or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND))
        assertEquals("the CryptoObject key takes a strong biometric only",
            BIOMETRIC_STRONG, UserAuthPrompt.authenticators(UserAuthKeyKind.PER_USE_BIOMETRIC))
    }

    @Test
    @Config(sdk = [29])
    fun `Android 10 decides like Android 9`() {
        assertEquals(UserAuthKeyKind.TIME_BOUND, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = false))
        assertEquals(BIOMETRIC_WEAK or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND))
    }

    @Test
    @Config(sdk = [30])
    fun `from Android 11 every key is per-use, fingerprint or not`() {
        assertEquals(UserAuthKeyKind.PER_USE, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = true))
        assertEquals(UserAuthKeyKind.PER_USE, UserAuthKeyKind.expected(Build.VERSION.SDK_INT, strongBiometricEnrolled = false))
        assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.PER_USE))
        assertEquals("a time-bound key carried over from Android 10 by an upgrade",
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND))
    }

    @Test
    @Config(sdk = [34])
    fun `the kinds say what they are`() {
        assertTrue(UserAuthKeyKind.PER_USE.perUse)
        assertTrue(UserAuthKeyKind.PER_USE_BIOMETRIC.perUse)
        assertFalse(UserAuthKeyKind.TIME_BOUND.perUse)
        assertEquals(0, UserAuthKeyKind.PER_USE.windowSeconds)
        assertEquals(0, UserAuthKeyKind.PER_USE_BIOMETRIC.windowSeconds)
        assertEquals("the documented window", 5, UserAuthKeyKind.TIME_BOUND.windowSeconds)
        assertEquals("the Keystore is asked for exactly that window",
            UserAuthKeyKind.TIME_BOUND.windowSeconds, KeystoreUserAuthKeys.LEGACY_WINDOW_SECONDS)
        assertTrue("the reference server accepts windows up to 10 s", UserAuthKeyKind.TIME_BOUND.windowSeconds <= 10)
    }
}
