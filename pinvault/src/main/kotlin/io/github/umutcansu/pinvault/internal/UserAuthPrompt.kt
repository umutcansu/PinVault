package io.github.umutcansu.pinvault.internal

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.github.umutcansu.pinvault.keystore.UserAuthKeyKind
import io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt
import io.github.umutcansu.pinvault.store.AuthOutcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import javax.crypto.Cipher
import kotlin.coroutines.resume

/** The system unlock prompt, matched to the kind of the user-auth key. */
internal object UserAuthPrompt {

    suspend fun authenticate(
        activity: FragmentActivity,
        texts: VaultFileUnlockPrompt,
        kind: UserAuthKeyKind,
        cipher: Cipher?
    ): AuthOutcome =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (cont.isActive) cont.resume(AuthOutcome.Succeeded(result.cryptoObject?.cipher))
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (cont.isActive) cont.resume(outcomeOf(errorCode, errString))
                        }
                        // onAuthenticationFailed: one wrong finger; the prompt stays up.
                    })
                val authenticators = authenticators(kind)
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(texts.title)
                    .setSubtitle(texts.subtitle)
                    .setDescription(texts.description)
                    .setAllowedAuthenticators(authenticators)
                    .apply {
                        // A prompt without the screen-lock option needs its own
                        // way out; with it, the system forbids one.
                        if (authenticators and DEVICE_CREDENTIAL == 0) setNegativeButtonText(texts.negativeButtonText)
                    }
                    .build()
                if (cipher != null) prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
                else prompt.authenticate(info)
                cont.invokeOnCancellation { activity.runOnUiThread { prompt.cancelAuthentication() } }
            }
        }

    /**
     * - Per-use key on Android 11+: a strong biometric or the screen lock,
     *   bound to the operation by a CryptoObject.
     * - Per-use fingerprint key (made on Android 7–10): a strong biometric
     *   only; the Keystore takes nothing else for it.
     * - Time-bound key: anything that passes the screen lock opens its
     *   window. Before Android 11 androidx.biometric cannot pair the screen
     *   lock with a strong-only biometric, so weak is listed there; a face
     *   unlock passes the prompt but does not open the key, which then fails
     *   to unwrap and reports Failed.
     */
    internal fun authenticators(kind: UserAuthKeyKind, sdk: Int = Build.VERSION.SDK_INT): Int = when (kind) {
        UserAuthKeyKind.PER_USE -> BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        UserAuthKeyKind.PER_USE_BIOMETRIC -> BIOMETRIC_STRONG
        UserAuthKeyKind.TIME_BOUND ->
            if (sdk >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL
            else BIOMETRIC_WEAK or DEVICE_CREDENTIAL
    }

    internal fun outcomeOf(errorCode: Int, errString: CharSequence): AuthOutcome = when (errorCode) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED -> AuthOutcome.Cancelled
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> AuthOutcome.NoScreenLock
        else -> AuthOutcome.Error("Unlock prompt error $errorCode: $errString")
    }
}
