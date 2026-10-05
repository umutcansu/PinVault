package io.github.umutcansu.pinvault.keystore

import android.os.Build
import timber.log.Timber

/**
 * Process-wide options for the Android Keystore keys the library generates.
 * Set from the app's `PinVaultConfig` whenever the library is handed one
 * (`init`, and the calls that take a config before `init`), because the keys
 * are made in places that never see a config: the encrypted stores open on
 * first use, the identity key at enrollment.
 */
internal object KeystoreOptions {

    /**
     * `PinVaultConfig.Builder.requireUnlockedDevice()`: new keys are usable
     * only while the device is unlocked (Android 9+).
     */
    @Volatile
    var unlockedDeviceRequired: Boolean = false

    /** True when a key generated now should carry `setUnlockedDeviceRequired(true)`. */
    fun wantsUnlockedDevice(): Boolean = unlockedDeviceRequired && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

    /**
     * Runs [generate] asking for an unlocked-device key when the option is on,
     * and once more without the flag when the Keystore refuses it: a ROM that
     * cannot make such a key must not leave the app without any key.
     * [cleanUp] removes whatever a failed attempt left behind.
     */
    inline fun <T> generating(what: String, cleanUp: () -> Unit = {}, generate: (unlockedDeviceRequired: Boolean) -> T): T {
        if (!wantsUnlockedDevice()) return generate(false)
        return try {
            generate(true)
        } catch (e: Exception) {
            Timber.w(e, "%s: the Keystore refused an unlocked-device key — generating it without that requirement", what)
            cleanUp()
            generate(false)
        }
    }
}
