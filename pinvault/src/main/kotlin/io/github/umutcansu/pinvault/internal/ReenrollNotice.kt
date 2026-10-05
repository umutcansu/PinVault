package io.github.umutcansu.pinvault.internal

import java.security.cert.X509Certificate

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

/**
 * Decides when a `reenroll_required` answer is about THIS device's identity,
 * which is the only time something on the device (its vault files, with
 * `wipeVaultFilesOnRevocation()`) is deleted because of it.
 *
 * The answer is a plain `403` with a JSON body. On a connection that
 * presented the client certificate loaded now, it is the server refusing
 * that certificate. On any other connection — a TLS-only block, a request
 * made before enrollment, a listener that asks for no certificate — the
 * server was not looking at an identity at all, and whatever made it answer
 * that way must not be able to wipe a device: the app is told, nothing more.
 *
 * @param currentIdentity the leaf the block's SSL manager presents now, or null
 */
internal class IdentityRevocation(private val currentIdentity: () -> X509Certificate?) {

    private val notice = ReenrollNotice()

    /** True when [presented] — what a connection showed the server — is the identity loaded now. */
    fun presentedCurrent(presented: X509Certificate?): Boolean {
        val current = currentIdentity() ?: return false
        return presented != null && presented.encoded.contentEquals(current.encoded)
    }

    /** True the first time the identity loaded now is found revoked; false when none is loaded. */
    fun claim(): Boolean {
        val leaf = currentIdentity() ?: return false
        return notice.claim("${leaf.issuerX500Principal.name}#${leaf.serialNumber}")
    }

    /** A refusal that arrived on a connection showing [presented]: true when the device's files should go now. */
    fun refusedOnConnection(presented: X509Certificate?): Boolean = presentedCurrent(presented) && claim()
}
