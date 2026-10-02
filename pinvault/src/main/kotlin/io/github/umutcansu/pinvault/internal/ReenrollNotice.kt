package io.github.umutcansu.pinvault.internal

/**
 * One "re-enroll" notice per client identity.
 *
 * A revoked device hears `reenroll_required` on every request until it
 * re-enrolls, and a refused renewal says it once more; the app wants to be
 * told once. A new identity (after re-enrollment) can be reported again.
 */
internal class ReenrollNotice {

    private var notifiedFor: String? = null

    /** True the first time it is called for [identity], false after that. */
    @Synchronized
    fun claim(identity: String): Boolean {
        if (identity == notifiedFor) return false
        notifiedFor = identity
        return true
    }
}
