package io.github.umutcansu.pinvault.ssl

import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager

/**
 * A client-side KeyManager for one fixed identity: a private key that stays
 * in the Android Keystore plus the certificate chain issued over it.
 *
 * [javax.net.ssl.KeyManagerFactory] wants a KeyStore it can read the key
 * material out of, which a Keystore-resident key does not allow — so this
 * is the KeyChain pattern instead: hand Conscrypt the opaque [PrivateKey]
 * and let the hardware sign the handshake.
 *
 * The alias is offered unconditionally. The server's CertificateRequest
 * lists the key types and issuer names it accepts, but there is only ever
 * one identity here, and letting the server reject it beats second-guessing
 * how a given Conscrypt build spells "EC".
 */
internal class FixedClientKeyManager(
    private val alias: String,
    private val privateKey: PrivateKey,
    private val chain: Array<X509Certificate>
) : X509ExtendedKeyManager() {

    init {
        require(chain.isNotEmpty()) { "Certificate chain must not be empty" }
    }

    /** The leaf this identity presents. */
    val certificate: X509Certificate get() = chain[0]

    override fun chooseClientAlias(keyTypes: Array<String>?, issuers: Array<Principal>?, socket: Socket?): String = alias

    override fun chooseEngineClientAlias(keyTypes: Array<String>?, issuers: Array<Principal>?, engine: SSLEngine?): String = alias

    override fun getClientAliases(keyType: String?, issuers: Array<Principal>?): Array<String> = arrayOf(alias)

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias == this.alias) chain.copyOf() else null

    override fun getPrivateKey(alias: String?): PrivateKey? =
        if (alias == this.alias) privateKey else null

    // Server-side (unused in a client)
    override fun chooseServerAlias(keyType: String?, issuers: Array<Principal>?, socket: Socket?): String? = null
    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<Principal>?, engine: SSLEngine?): String? = null
    override fun getServerAliases(keyType: String?, issuers: Array<Principal>?): Array<String>? = null
}
