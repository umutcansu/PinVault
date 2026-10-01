package io.github.umutcansu.pinvault.model

/** Which door a renewal went through. */
enum class ClientCertRenewalVia {
    /** The certificate was still valid: renewed over the block's own (mTLS) connection. */
    MTLS,

    /**
     * The certificate had expired or was refused: renewed over the recovery
     * URL, which asks for no client certificate and authenticates the CSR
     * signature against the device key the server registered at enrollment.
     */
    RECOVERY
}

/**
 * Outcome of [io.github.umutcansu.pinvault.PinVault.renewClientCertIfNeeded]
 * and of the renewal check the library runs at init and on every periodic
 * update.
 */
sealed class ClientCertRenewalResult {
    /** A new certificate is stored and presented from now on. */
    data class Renewed(val notAfterEpochMs: Long, val via: ClientCertRenewalVia) : ClientCertRenewalResult()

    /** The current certificate still has enough lifetime left. */
    data class NotNeeded(val notAfterEpochMs: Long) : ClientCertRenewalResult()

    /**
     * The server will not renew this identity. The stored certificate is
     * left in place; the host app should re-enroll (with a new token, a user
     * login, or whatever its enrollment policy asks for).
     */
    data class ReenrollRequired(val reason: String) : ClientCertRenewalResult()

    /** Renewal was attempted and failed (network, server error, bad response). Retried next time. */
    data class Failed(val reason: String, val exception: Throwable? = null) : ClientCertRenewalResult()

    /**
     * Nothing to renew: not enrolled, enrolled with a server-generated P12
     * (no device key to sign with), static-pin mode, renewal disabled, or a
     * custom backend without renewal support.
     */
    object NotApplicable : ClientCertRenewalResult() {
        override fun toString() = "NotApplicable"
    }
}
