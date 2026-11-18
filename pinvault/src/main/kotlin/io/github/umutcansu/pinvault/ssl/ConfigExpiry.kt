package io.github.umutcansu.pinvault.ssl

/**
 * The moment a config stops being usable: its `expiresAt` plus the
 * `expiredConfigGrace`. Every expiry check goes through [deadline], which
 * saturates: an app asking for a huge grace (`Long.MAX_VALUE` ms) must get
 * "never", not a sum that wraps negative and calls every config expired.
 * A `PinVaultConfig` can be built without the builder, so the value is not
 * trusted to be small.
 */
internal object ConfigExpiry {

    fun deadline(expiresAt: Long, graceMs: Long): Long {
        val sum = expiresAt + graceMs
        // Overflow iff both operands have the same sign and the sum does not.
        if (((expiresAt xor sum) and (graceMs xor sum)) < 0L) {
            return if (graceMs > 0L) Long.MAX_VALUE else Long.MIN_VALUE
        }
        return sum
    }
}
