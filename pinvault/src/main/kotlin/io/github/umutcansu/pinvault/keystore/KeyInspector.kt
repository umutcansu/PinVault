package io.github.umutcansu.pinvault.keystore

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import io.github.umutcansu.pinvault.model.KeySecurityLevel
import timber.log.Timber
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Asks the Android Keystore where a key lives ([KeyInfo]). Android 12+
 * reports the security level directly; before that only "inside secure
 * hardware" (TEE or StrongBox, undistinguished) or not. Any failure to ask
 * is [KeySecurityLevel.UNKNOWN] — never a guess at hardware.
 */
internal object KeyInspector {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /** What a key's [KeyInfo] says about it. */
    class Properties(
        val level: KeySecurityLevel
    )

    /** [Properties] of an Android Keystore private or secret key. */
    fun inspect(key: Key): Properties = try {
        val info = keyInfo(key)
        if (info == null) Properties(KeySecurityLevel.UNKNOWN) else Properties(levelOf(info))
    } catch (e: Exception) {
        Timber.w(e, "Could not read the Keystore's description of a %s key", key.algorithm)
        Properties(KeySecurityLevel.UNKNOWN)
    }

    /** Shorthand for [inspect] when only the level matters. */
    fun securityLevel(key: Key): KeySecurityLevel = inspect(key).level

    private fun keyInfo(key: Key): KeyInfo? = when (key) {
        is PrivateKey -> KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        is SecretKey -> SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java) as? KeyInfo
        else -> null
    }

    private fun levelOf(info: KeyInfo): KeySecurityLevel {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                // UNKNOWN_SECURE: "secure hardware, which kind is not known".
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                else -> KeySecurityLevel.UNKNOWN
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) KeySecurityLevel.TRUSTED_ENVIRONMENT else KeySecurityLevel.SOFTWARE
    }
}
