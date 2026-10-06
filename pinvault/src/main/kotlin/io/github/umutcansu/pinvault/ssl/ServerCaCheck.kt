package io.github.umutcansu.pinvault.ssl

import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The second check behind `requireCaTrust`: does a certificate authority the
 * platform trusts vouch for this chain? Throws when it does not.
 */
internal fun interface ServerCaCheck {
    fun check(chain: Array<X509Certificate>, authType: String, host: String)
}

/**
 * [ServerCaCheck] over an [X509TrustManager]. [platform] is the default
 * TrustManagerFactory's — the system CAs, shaped by the app's network
 * security config when it has one (user CAs, debug overrides, its own pins).
 */
internal class TrustManagerCaCheck(private val trustManager: () -> X509TrustManager) : ServerCaCheck {

    override fun check(chain: Array<X509Certificate>, authType: String, host: String) {
        val tm = trustManager()
        // The hostname-aware call: a network security config with per-domain
        // rules refuses the plain two-argument check. Not every trust manager
        // supports it (a JVM's does not), so fall back to the plain check.
        val extensions = runCatching { android.net.http.X509TrustManagerExtensions(tm) }.getOrNull()
        if (extensions != null && host.isNotEmpty()) {
            extensions.checkServerTrusted(chain, authType, host)
        } else {
            tm.checkServerTrusted(chain, authType)
        }
    }

    companion object {
        internal val platformTrustManager: X509TrustManager by lazy {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            factory.trustManagers.filterIsInstance<X509TrustManager>().first()
        }

        fun platform(): TrustManagerCaCheck = TrustManagerCaCheck { platformTrustManager }
    }
}

/**
 * The platform's view of a chain, for managed trust roots: the certificates
 * the platform validated, **ending in the trust anchor it used** when it
 * can say which one that was. Throws when the platform does not trust the
 * chain for [host].
 */
internal fun interface TrustAnchorResolver {
    fun validatedChain(chain: Array<X509Certificate>, authType: String, host: String): List<X509Certificate>
}

/**
 * [TrustAnchorResolver] over an [X509TrustManager]. Android's
 * `X509TrustManagerExtensions.checkServerTrusted` returns the cleaned chain
 * with the anchor appended; a plain trust manager (a JVM's) returns nothing,
 * so the anchor is looked up among its accepted issuers by name and signature.
 */
internal class TrustManagerAnchorResolver(private val trustManager: () -> X509TrustManager) : TrustAnchorResolver {

    override fun validatedChain(chain: Array<X509Certificate>, authType: String, host: String): List<X509Certificate> {
        val tm = trustManager()
        val extensions = runCatching { android.net.http.X509TrustManagerExtensions(tm) }.getOrNull()
        if (extensions != null && host.isNotEmpty()) {
            val validated = extensions.checkServerTrusted(chain, authType, host)
            if (!validated.isNullOrEmpty()) return validated
        } else {
            tm.checkServerTrusted(chain, authType)
        }
        // No anchor in the answer: find the issuer of the last certificate
        // among the trust manager's own anchors and check that it signed it.
        val last = chain.last()
        val anchor = tm.acceptedIssuers.firstOrNull { issuer ->
            issuer.subjectX500Principal == last.issuerX500Principal &&
                runCatching { last.verify(issuer.publicKey) }.isSuccess
        }
        return if (anchor == null || isSelfSigned(last)) chain.toList() else chain.toList() + anchor
    }

    private fun isSelfSigned(cert: X509Certificate): Boolean =
        cert.subjectX500Principal == cert.issuerX500Principal && runCatching { cert.verify(cert.publicKey) }.isSuccess

    companion object {
        fun platform(): TrustManagerAnchorResolver = TrustManagerAnchorResolver { TrustManagerCaCheck.platformTrustManager }
    }
}
