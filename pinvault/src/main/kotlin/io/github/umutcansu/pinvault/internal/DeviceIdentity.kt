package io.github.umutcansu.pinvault.internal

import android.content.Context
import android.provider.Settings

/**
 * Single source of truth for the device identifier PinVault presents to a
 * Config API.
 *
 * The same value is used in three places and they MUST agree, otherwise the
 * server-side ACL keyed on it silently fails to match:
 *  - `X-Device-Id` on scoped config fetches ([io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater])
 *  - `X-Device-Id` on vault file downloads ([VaultFileRouter])
 *  - `deviceUid` sent during enrollment ([io.github.umutcansu.pinvault.PinVault])
 *
 * SECURITY NOTE (M-02): ANDROID_ID is a soft identifier — per app-signing-key
 * and per user, spoofable on a rooted device. It identifies a device well
 * enough for ACL scoping and distribution tracking, but it is not a
 * hardware-attested identity and must not be treated as an authentication
 * factor on its own.
 */
internal object DeviceIdentity {

    /**
     * Reads `Settings.Secure.ANDROID_ID`, or null when it is unavailable
     * (Robolectric without a shadow, restricted profile, SecurityException).
     */
    fun androidId(context: Context): String? = try {
        @Suppress("HardwareIds")
        Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ANDROID_ID
        )
    } catch (_: Exception) {
        null
    }
}
