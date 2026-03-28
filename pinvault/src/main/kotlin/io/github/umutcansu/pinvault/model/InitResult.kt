package io.github.umutcansu.pinvault.model

/**
 * Result of [PinVault.init].
 */
sealed class InitResult {
    /** Pinning is ready — safe to proceed with network calls. */
    data class Ready(val version: Int) : InitResult()

    /**
     * Initialization failed — do NOT proceed with network calls.
     *
     * Happens when:
     * - No stored config + backend unreachable
     * - forceUpdate=true + backend unreachable (even if stored config exists)
     */
    data class Failed(val reason: String, val exception: Exception? = null) : InitResult()
}
