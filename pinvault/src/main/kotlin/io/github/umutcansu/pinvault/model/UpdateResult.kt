package io.github.umutcansu.pinvault.model

/**
 * Result of a certificate config update operation.
 */
sealed class UpdateResult {
    /** Config updated successfully to the given version. */
    data class Updated(val newVersion: Int) : UpdateResult()

    /** Config is already up to date. */
    data object AlreadyCurrent : UpdateResult()

    /** Update failed. */
    data class Failed(val reason: String, val exception: Exception? = null) : UpdateResult()
}
