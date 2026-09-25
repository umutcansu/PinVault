package com.example.pinvault.server.service

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * The library's pin rule, for checks the server makes on a device's behalf:
 * a chain satisfies a pin set when the leaf's pin is in it, or when an issuer
 * certificate's pin is and the leaf really chains to that issuer (the path is
 * validated with the pinned certificate as the only trust anchor). Mirrors
 * `ChainPinMatcher` in the library.
 */
object PinChain {

    fun spkiPin(cert: X509Certificate): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    fun satisfies(chain: List<X509Certificate>, pins: Collection<String>): Boolean {
        if (chain.isEmpty()) return false
        if (spkiPin(chain[0]) in pins) return true
        return (1 until chain.size).any { anchor -> spkiPin(chain[anchor]) in pins && chainsTo(chain, anchor) }
    }

    private fun chainsTo(chain: List<X509Certificate>, anchor: Int): Boolean = try {
        chain[anchor].checkValidity()
        val path = CertificateFactory.getInstance("X.509").generateCertPath(chain.take(anchor))
        val params = PKIXParameters(setOf(TrustAnchor(chain[anchor], null))).apply { isRevocationEnabled = false }
        CertPathValidator.getInstance("PKIX").validate(path, params)
        true
    } catch (e: GeneralSecurityException) {
        false
    } catch (e: IllegalArgumentException) {
        false
    }
}
