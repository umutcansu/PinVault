package io.github.umutcansu.pinvault.model

/**
 * The operations an [EnvironmentGuard] is asked about.
 */
enum class GuardedOperation {
    /** `PinVault.init` (every overload). Refused: [InitResult.Failed]. */
    INIT,

    /**
     * `enroll`, `enrollForResult`, `autoEnroll`, `autoEnrollForResult` and
     * `checkPendingEnrollment` (with or without a config), and the pick-up of
     * a pending enrollment at init and on periodic updates. Refused:
     * [ClientCertEnrollmentResult.Failed]; nothing is sent, no token is spent.
     */
    ENROLL,

    /**
     * `fetchFile`, `syncAllFiles` and the periodic sync of vault files.
     * Refused: [VaultFileResult.Failed]; nothing is downloaded.
     */
    FETCH_FILE,

    /**
     * `unlockFile`. Refused: [VaultFileUnlockResult.Failed]; no prompt is
     * shown and the content never reaches the app's memory.
     */
    UNLOCK_FILE,

    /**
     * `loadFile`: reading a stored copy, which needs no network. Refused:
     * `loadFile` returns null and the copy is not decrypted; it stays stored.
     * Added in 2.4.0: an exhaustive `when` over this enum needs a branch for it.
     */
    LOAD_FILE
}

/**
 * The app's own answer to "may PinVault do this here, now?".
 *
 * PinVault detects nothing about the device itself: no root, hooking,
 * debugger or emulator checks. Those belong to a tool made for them (a RASP
 * or app-shielding product, RootBeer, Play Integrity), which keeps its
 * detection up to date. This is where its verdict goes: PinVault asks before
 * each [GuardedOperation] and refuses the operation when the answer is
 * `false`, so the check cannot be forgotten on one code path, and it runs
 * just before the operation, not only at app start (a hooking tool can be
 * attached after the app has started).
 *
 * ```kotlin
 * PinVaultConfig.Builder()
 *     .environmentGuard { operation ->
 *         when (operation) {
 *             GuardedOperation.INIT -> true              // pinned traffic keeps working
 *             else -> !shield.isCompromised()            // no enrollment or files on a compromised device
 *         }
 *     }
 * ```
 *
 * [allows] runs on the thread that called the PinVault method (the main
 * thread for the callback overloads, a background one for `syncAllFiles`
 * and the periodic work): keep it quick, cache an expensive verdict. A
 * guard that throws counts as a refusal (fail closed).
 *
 * A check inside the app can be switched off by whoever controls the
 * device. Treat the guard as a speed bump, and let the server decide what
 * matters: [IntegrityTokenProvider] sends a verdict the server checks.
 */
fun interface EnvironmentGuard {
    /** True when [operation] may run on this device now. */
    fun allows(operation: GuardedOperation): Boolean
}

/**
 * An operation was refused because the app's [EnvironmentGuard] said no
 * (or threw: [cause]). Carried as the exception of the failed result.
 */
class UntrustedEnvironmentException @JvmOverloads constructor(
    val operation: GuardedOperation,
    message: String = "The app's environment guard refused $operation on this device",
    cause: Throwable? = null
) : SecurityException(message, cause)
