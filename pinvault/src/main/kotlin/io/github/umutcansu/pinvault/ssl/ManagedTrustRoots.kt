package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.HostnameMismatchException
import io.github.umutcansu.pinvault.model.ManagedTrustRootException
import timber.log.Timber
import java.security.cert.X509Certificate

/**
 * Managed trust roots: for a host that has **no pin entry**, a chain is
 * accepted when the platform's CAs validate it **and** the chain the
 * platform validated contains a certificate whose key is one of the signed
 * config's `trustRoots` (SHA-256 of the SubjectPublicKeyInfo, Base64, the
 * same form as pins) — normally the root the platform anchored on — and the
 * leaf names the host.
 *
 * This is the device trust store with the authority taken away from it:
 * a CA a user or an attacker added to the device is not in `trustRoots`,
 * so it does not count, and a root the operator stops listing stops being
 * trusted on the next config, without an app update. Hosts that have a pin
 * entry are not affected; pins stay the stricter choice.
 */
internal object ManagedTrustRoots {

    /**
     * The root pin of [trustRoots] that [chain] validates to for [hostname],
     * or a [java.security.cert.CertificateException] saying why not:
     * [ManagedTrustRootException] when the platform refuses the chain or no
     * validated certificate matches a listed root, [HostnameMismatchException]
     * when the leaf is not issued for [hostname].
     */
    fun match(
        chain: Array<X509Certificate>,
        authType: String,
        hostname: String,
        trustRoots: Set<String>,
        resolver: TrustAnchorResolver,
        spkiPin: (X509Certificate) -> String
    ): String {
        if (chain.isEmpty()) throw ManagedTrustRootException("No server certificate provided")
        if (trustRoots.isEmpty()) throw ManagedTrustRootException("The config lists no managed trust roots")
        val validated = try {
            resolver.validatedChain(chain, authType, hostname)
        } catch (e: Exception) {
            throw ManagedTrustRootException(
                "Managed trust roots: the platform does not trust the certificate chain for '$hostname': ${e.message}", e
            )
        }
        // The anchor (last) first: that is what the list is meant to name.
        val matched = validated.asReversed().map(spkiPin).firstOrNull { it in trustRoots }
            ?: throw ManagedTrustRootException(
                "Managed trust roots: the chain for '$hostname' validates to a root the config does not list " +
                    "(${trustRoots.size} listed)"
            )
        if (!ChainPinMatcher.leafNamesHost(chain[0], hostname)) {
            throw HostnameMismatchException(
                "Certificate for $hostname chains to a managed trust root but is not issued for $hostname (no matching subjectAltName)"
            )
        }
        Timber.d("Managed trust root matched for %s — sha256/%s...", hostname, matched.take(12))
        return matched
    }
}
