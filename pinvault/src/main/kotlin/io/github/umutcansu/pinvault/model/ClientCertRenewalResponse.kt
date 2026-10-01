package io.github.umutcansu.pinvault.model

/**
 * What a backend answers to a client-certificate renewal request
 * ([io.github.umutcansu.pinvault.api.CertificateConfigApi.renewClientCert]).
 */
sealed class ClientCertRenewalResponse {
    /** A new certificate was issued over the device's key: PEM chain, leaf first. */
    data class Issued(val certificateChainPem: List<String>) : ClientCertRenewalResponse()

    /**
     * The server refuses to renew this identity — revoked, unknown, or its
     * key no longer matches — and the device must enroll again from scratch.
     */
    data class ReenrollRequired(val reason: String) : ClientCertRenewalResponse()

    /** The backend has no renewal endpoint (custom backends, older servers). */
    object Unsupported : ClientCertRenewalResponse() {
        override fun toString() = "Unsupported"
    }
}
