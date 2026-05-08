package io.github.umutcansu.pinvault.api

/**
 * Single-method callback PinVault invokes for every [PinVaultConnectionEvent].
 *
 * Declared as a Kotlin `fun interface` (SAM), so callers in both Kotlin and
 * Java can supply a lambda — Java callers do **not** need to return
 * `kotlin.Unit.INSTANCE` like they do for the multi-Config-API DSL block.
 *
 * The library invokes [onEvent] **off the TLS handshake thread** (the
 * implementation hands events to a background dispatcher), so listeners
 * may safely perform short blocking work — but should still avoid
 * long-running operations like synchronous HTTP. Throwables raised by
 * [onEvent] are logged via Timber and swallowed; a misbehaving listener
 * can never break the underlying connection.
 */
fun interface PinVaultConnectionListener {
    /** Called for every emitted [PinVaultConnectionEvent]. Use a `when` to dispatch on subtype. */
    fun onEvent(event: PinVaultConnectionEvent)
}
