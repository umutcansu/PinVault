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
        private val platformTrustManager: X509TrustManager by lazy {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            factory.trustManagers.filterIsInstance<X509TrustManager>().first()
        }

        fun platform(): TrustManagerCaCheck = TrustManagerCaCheck { platformTrustManager }
    }
}
