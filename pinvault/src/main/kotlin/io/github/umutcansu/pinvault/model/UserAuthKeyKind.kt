package io.github.umutcansu.pinvault.model

import android.os.Build

/**
 * How the device's user-auth key — the key behind [UserAuth] vault files —
 * is opened. Fixed when the key is made and read back from the key itself,
 * so a key made on Android 10 keeps its kind after an upgrade to 11; read
 * it with `PinVault.userAuthKeyKind()`, or ask [expected] what a device
 * would get before any key exists.
 *
 * What the platform allows, by Android version:
 *
 * | Android | Kind | Opened by |
 * |---|---|---|
 * | 11+ (API 30+) | [PER_USE] | every use: strong biometric **or** screen lock, bound to the operation (`CryptoObject`) |
 * | 7–10 with a strong fingerprint when the key is made | [PER_USE_BIOMETRIC] | every use: that fingerprint, bound to the operation (`CryptoObject`); the screen lock does not open it |
 * | 7–10 without one | [TIME_BOUND] | the screen lock (or a fingerprint), for [windowSeconds] seconds after it is passed — in the prompt or by unlocking the phone |
 *
 * Before Android 11 the Keystore cannot bind the screen lock to a single
 * operation (`setUserAuthenticationValidityDurationSeconds(-1)` takes a
 * fingerprint only), so a per-use key there is a fingerprint-only key, and
 * a phone without one gets a time-bound key. The window is the shortest
 * that still works: the Keystore checks it when the cipher is initialised,
 * which the library does right after the prompt returns.
 */
enum class UserAuthKeyKind(
    /** True when every use of the key asks the user; false for a time-bound key. */
    val perUse: Boolean,
    /** Seconds the key stays usable after the screen lock is passed; 0 for a per-use key. */
    val windowSeconds: Int
) {
    /**
     * Android 11+: every use asks; a strong biometric or the screen lock.
     * Authorised by `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`, the key is bound
     * to the device credential (the Keystore ties it to the screen lock's
     * secure id, not to the enrolled biometrics): only removing the screen
     * lock retires it. Enrolling a new fingerprint or face does NOT — that
     * invalidates biometric-only keys, which this is not.
     */
    PER_USE(perUse = true, windowSeconds = 0),

    /**
     * Android 7–10 with a strong fingerprint at key generation: every use
     * asks, fingerprint only. This is the one biometric-only kind, bound to
     * the enrolled fingerprints: a new fingerprint, removing all fingerprints
     * or removing the screen lock retires the key.
     */
    PER_USE_BIOMETRIC(perUse = true, windowSeconds = 0),

    /**
     * Android 7–10 without one: opens for [TIME_BOUND_WINDOW_SECONDS]
     * seconds after the screen lock is passed, in the prompt or by unlocking
     * the phone. Only removing the screen lock retires it; a new fingerprint
     * does not. The weakest kind: the reference server can refuse it
     * (`USER_AUTH_REQUIRE_PER_USE=true`).
     */
    TIME_BOUND(perUse = false, windowSeconds = 5);

    companion object {
        /**
         * The window of a [TIME_BOUND] key, in seconds (the literal on the
         * entry; an enum entry cannot read its companion). The Keystore
         * checks it when the decrypt cipher is initialised, which the
         * library does on the thread hop right after the prompt's callback —
         * well under a second — so 5 s covers a slow Keystore while keeping
         * the key shut most of the time (it was 10 s until 2.3.0). 0 is not
         * a window the Keystore honours before Android 11, and -1 means
         * fingerprint-only.
         */
        const val TIME_BOUND_WINDOW_SECONDS = 5

        /**
         * The kind a key made now on a device running [sdkInt] would get:
         * [PER_USE] from Android 11, else [PER_USE_BIOMETRIC] when
         * [strongBiometricEnrolled] (a fingerprint the Keystore counts as
         * strong is enrolled right now), else [TIME_BOUND].
         */
        @JvmStatic
        fun expected(sdkInt: Int, strongBiometricEnrolled: Boolean): UserAuthKeyKind = when {
            sdkInt >= Build.VERSION_CODES.R -> PER_USE
            strongBiometricEnrolled -> PER_USE_BIOMETRIC
            else -> TIME_BOUND
        }
    }
}
