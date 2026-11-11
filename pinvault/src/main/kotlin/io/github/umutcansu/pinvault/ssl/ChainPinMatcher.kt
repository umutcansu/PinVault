package io.github.umutcansu.pinvault.ssl

import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

/**
 * Pin matching up the served certificate chain.
 *
 * The leaf's key is checked first, as always. A pin may also name an issuer —
 * an intermediate or root CA certificate — so a host keeps working when its
 * leaf is renewed with a new key by the same CA.
 *
 * The library does no CA validation (self-signed certificates are fine), so an
 * issuer pin only counts when the leaf really chains to that issuer: the path
 * from the leaf up to the pinned certificate is validated with the pinned
 * certificate as the sole trust anchor (signatures, validity, CA constraints).
 * Without that check an attacker could append the genuine intermediate to a
 * forged leaf and pass.
 *
 * PKIX takes a trust anchor as given: it checks neither that the anchor is a
 * CA nor what the leaf may be used for. Both are checked here, because the pin
 * is all that vouches for the anchor: the pinned certificate must be a CA
 * (`basicConstraints`), or any leaf whose key is pinned could issue for the
 * host; and the leaf must be usable as a TLS server certificate, or a client
 * certificate from the same CA would do.
 */
internal object ChainPinMatcher {

    /**
     * The pin in [accepted] that [chain] satisfies, or null. [spkiPin] hashes a
     * certificate's public key the way pins are written.
     */
    fun match(
        chain: Array<X509Certificate>,
        accepted: Set<String>,
        spkiPin: (X509Certificate) -> String
    ): String? {
        if (chain.isEmpty()) return null
        spkiPin(chain[0]).let { if (it in accepted) return it }
        for (anchor in 1 until chain.size) {
            val pin = spkiPin(chain[anchor])
            if (pin in accepted && isCa(chain[anchor]) && isServerCertificate(chain[0]) && chainsTo(chain, anchor)) return pin
        }
        return null
    }

    /**
     * True when [leaf] is issued for [hostname]: a `subjectAltName` matches
     * it (a DNS name, with RFC 6125 single-label wildcards, or an IP
     * address literal). Same rules as OkHttp's own verifier, which an app
     * that brings its own builder may have replaced. An empty host name
     * never matches.
     */
    internal fun leafNamesHost(leaf: X509Certificate, hostname: String): Boolean {
        if (hostname.isEmpty()) return false
        return try {
            okhttp3.internal.tls.OkHostnameVerifier.verify(hostname, leaf)
        } catch (e: Exception) {
            false
        }
    }

    /** True when [cert] says it may sign certificates (`basicConstraints` CA). A v1 certificate does not. */
    internal fun isCa(cert: X509Certificate): Boolean = cert.basicConstraints >= 0

    /**
     * True when [leaf] may be used as a TLS server certificate: it has no
     * `extendedKeyUsage`, or one that lists serverAuth or anyExtendedKeyUsage.
     * An extension that does not parse counts as "may not".
     */
    internal fun isServerCertificate(leaf: X509Certificate): Boolean = try {
        val usages = leaf.extendedKeyUsage
        usages == null || SERVER_AUTH in usages || ANY_EXTENDED_KEY_USAGE in usages
    } catch (e: java.security.cert.CertificateParsingException) {
        false
    }

    private const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    private const val ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0"

    /** True when `chain[0]` chains through `chain[1 until anchor]` to `chain[anchor]`. */
    internal fun chainsTo(chain: Array<X509Certificate>, anchor: Int): Boolean = try {
        chain[anchor].checkValidity()
        val path = CertificateFactory.getInstance("X.509").generateCertPath(chain.take(anchor))
        val params = PKIXParameters(setOf(TrustAnchor(chain[anchor], null))).apply {
            // Pins replace revocation here as they replace CA trust; a lookup
            // would also fail offline and for private CAs.
            isRevocationEnabled = false
        }
        CertPathValidator.getInstance("PKIX").validate(path, params)
        true
    } catch (e: GeneralSecurityException) {
        false
    } catch (e: IllegalArgumentException) {
        false
    }
}
