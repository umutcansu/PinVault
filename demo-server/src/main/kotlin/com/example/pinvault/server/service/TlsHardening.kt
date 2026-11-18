package com.example.pinvault.server.service

/**
 * JSSE settings for every TLS listener of this process (Config APIs, the
 * recovery door, mock hosts, the management HTTPS port). They are read once,
 * when the TLS classes load, so [apply] runs first thing in `main`.
 *
 * testssl 2026-11-18 on a Config API and the recovery door:
 * - client-initiated renegotiation was accepted (TLS 1.2): a client could make
 *   the server redo the expensive half of a handshake over and over on one
 *   connection. Refused now; TLS 1.3 has no renegotiation at all.
 * - the handshake offered SHA-1 and SHA-224 signature schemes. Every key this
 *   server or the library makes signs with SHA-256 or better, so only those
 *   are offered (Android 7, the library's oldest platform, supports all of them).
 *
 * A value the operator set already (`JAVA_TOOL_OPTIONS=-D…`) is kept.
 */
object TlsHardening {

    /** The signature schemes offered in a handshake: SHA-256 and better, no SHA-1 / SHA-224. */
    const val SIGNATURE_SCHEMES =
        "ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,ecdsa_secp521r1_sha512," +
            "ed25519,ed448," +
            "rsa_pss_rsae_sha256,rsa_pss_rsae_sha384,rsa_pss_rsae_sha512," +
            "rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512," +
            "rsa_pkcs1_sha256,rsa_pkcs1_sha384,rsa_pkcs1_sha512"

    fun apply(properties: java.util.Properties = System.getProperties()) {
        properties.putIfAbsent("jdk.tls.rejectClientInitiatedRenegotiation", "true")
        properties.putIfAbsent("jdk.tls.server.SignatureSchemes", SIGNATURE_SCHEMES)
    }
}
