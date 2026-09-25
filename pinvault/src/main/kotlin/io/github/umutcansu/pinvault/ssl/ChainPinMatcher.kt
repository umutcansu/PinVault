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
            if (pin in accepted && chainsTo(chain, anchor)) return pin
        }
        return null
    }

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
