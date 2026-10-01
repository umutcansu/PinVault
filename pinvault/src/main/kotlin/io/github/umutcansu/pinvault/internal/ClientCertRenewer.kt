package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.ClientCertRenewalResponse
import io.github.umutcansu.pinvault.model.ClientCertRenewalResult
import io.github.umutcansu.pinvault.model.ClientCertRenewalVia
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import timber.log.Timber
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Keeps a CSR-enrolled client certificate alive.
 *
 * The decision is taken from the stored leaf's own dates, without touching
 * the network. While the certificate is valid and past the renewal
 * threshold, the CSR goes over the block's own connection (mTLS: the current
 * certificate authenticates it). Once it has expired — or the server refuses
 * the handshake — the same CSR goes to the block's recovery URL, which asks
 * for no client certificate; there the server authenticates the CSR
 * signature against the device key it registered at enrollment.
 *
 * An expired certificate is never presented to anything and never accepted
 * from anything: an issued chain is checked for validity, for being over
 * this device's key, and for chaining to its issuer before it is stored.
 */
internal class ClientCertRenewer(
    private val block: ConfigApiBlock,
    private val certStore: ClientCertSecureStore,
    private val identityKeyFactory: (label: String) -> ClientIdentityKeyProvider,
    private val api: () -> CertificateConfigApi,
    /** Installs the stored credentials into the SSL manager and rebuilds the clients. */
    private val reload: () -> Unit,
    private val clock: () -> Long = System::currentTimeMillis
) {

    sealed class Decision {
        object None : Decision()
        object Renew : Decision()
        object Recover : Decision()
    }

    /**
     * `Recover` once [nowMs] is past `notAfter`; `Renew` when the remaining
     * lifetime is below [threshold] of the whole lifetime; else `None`.
     */
    fun decide(leaf: X509Certificate, nowMs: Long, threshold: Double): Decision {
        val notAfter = leaf.notAfter.time
        val notBefore = leaf.notBefore.time
        if (nowMs > notAfter) return Decision.Recover
        val lifetime = (notAfter - notBefore).coerceAtLeast(1L)
        val remaining = notAfter - nowMs
        return if (remaining.toDouble() / lifetime < threshold) Decision.Renew else Decision.None
    }

    /**
     * @param force renew even when the threshold has not been reached.
     */
    suspend fun renewIfNeeded(force: Boolean = false): ClientCertRenewalResult {
        if (!block.clientCertRenewalEnabled && !force) return ClientCertRenewalResult.NotApplicable
        val label = block.clientCertLabel
        val pemChain = certStore.loadChain(label) ?: return ClientCertRenewalResult.NotApplicable
        val key = identityKeyFactory(label)
        if (!key.exists()) {
            Timber.w("Client cert renewal [%s]: certificate stored but its Keystore key is gone", block.id)
            return ClientCertRenewalResult.NotApplicable
        }

        val stored = try {
            Pkcs10Csr.parsePemChain(pemChain)
        } catch (e: Exception) {
            return ClientCertRenewalResult.Failed("Stored certificate chain is unreadable: ${e.message}", e)
        }
        val leaf = stored.first()
        // The CA that issued the current certificate. A renewal must come from
        // the same CA: whoever answers on the renewal door — even a party that
        // got hold of the door's TLS key — cannot swap in a chain of its own.
        val currentIssuer = stored.getOrNull(1)

        val decision = decide(leaf, clock(), block.clientCertRenewalThreshold)
        if (decision == Decision.None && !force) {
            return ClientCertRenewalResult.NotNeeded(leaf.notAfter.time)
        }

        val clientId = clientIdOf(leaf)
        val via = if (decision == Decision.Recover) ClientCertRenewalVia.RECOVERY else ClientCertRenewalVia.MTLS
        Timber.i("Client cert renewal [%s]: %s via %s (notAfter=%s)", block.id, clientId, via, leaf.notAfter)

        return try {
            val csr = Pkcs10Csr.encode(clientId, key.publicKey(), key::sign)
            val (response, usedVia) = request(clientId, csr, via)
            when (response) {
                is ClientCertRenewalResponse.Issued -> {
                    val certs = acceptIssuedChain(response.certificateChainPem, key, currentIssuer)
                    certStore.saveChain(label, response.certificateChainPem)
                    reload()
                    Timber.i("Client cert renewed [%s] via %s — valid until %s", block.id, usedVia, certs[0].notAfter)
                    ClientCertRenewalResult.Renewed(certs[0].notAfter.time, usedVia)
                }
                is ClientCertRenewalResponse.ReenrollRequired -> {
                    Timber.w("Client cert renewal [%s] refused: %s — re-enrollment required", block.id, response.reason)
                    ClientCertRenewalResult.ReenrollRequired(response.reason)
                }
                ClientCertRenewalResponse.Unsupported -> {
                    Timber.w("Client cert renewal [%s]: backend has no renewal endpoint", block.id)
                    ClientCertRenewalResult.NotApplicable
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.e(e, "Client cert renewal [%s] failed", block.id)
            ClientCertRenewalResult.Failed(e.message ?: e.javaClass.simpleName, e)
        }
    }

    /**
     * Sends the CSR through [via]. A handshake the server refuses on the mTLS
     * path (its client-certificate check, not our pin check) falls through to
     * the recovery path once — that is what the recovery door is for.
     */
    private suspend fun request(
        clientId: String,
        csr: ByteArray,
        via: ClientCertRenewalVia
    ): Pair<ClientCertRenewalResponse, ClientCertRenewalVia> {
        if (via == ClientCertRenewalVia.MTLS) {
            try {
                return api().renewClientCert(clientId, csr, null) to via
            } catch (e: Exception) {
                if (!isClientCertRefusal(e)) throw e
                Timber.w(e, "Client cert renewal [%s]: handshake refused, trying the recovery URL", block.id)
            }
        }
        return api().renewClientCert(clientId, csr, block.renewalUrl ?: block.configUrl) to ClientCertRenewalVia.RECOVERY
    }

    companion object {
        internal const val CLIENT_CN_PREFIX = "PinVault Client: "

        /** The enrolled client id: the leaf's CN without the server's prefix. */
        fun clientIdOf(leaf: X509Certificate): String {
            val cn = leaf.subjectX500Principal.name.substringAfter("CN=", "").substringBefore(",")
            return cn.removePrefix(CLIENT_CN_PREFIX).trim().ifEmpty { cn }
        }

        /**
         * A TLS failure the server caused by rejecting our client certificate,
         * as opposed to one our own pin check caused (a [CertificateException]
         * somewhere in the cause chain — the pinned trust manager throws that,
         * and refetching a client cert cannot fix it).
         */
        fun isClientCertRefusal(e: Throwable): Boolean {
            if (e !is SSLHandshakeException && e !is SSLPeerUnverifiedException) return false
            var cause: Throwable? = e
            val seen = HashSet<Throwable>()
            while (cause != null && seen.add(cause)) {
                if (cause is CertificateException) return false
                cause = cause.cause
            }
            return true
        }

        /**
         * Checks a chain the server issued before it is trusted: parses, the
         * leaf is currently valid, it is over [key]'s public key, and it was
         * signed by the next certificate in the chain when one is given.
         *
         * With [expectedIssuer] (a renewal: the CA of the certificate being
         * replaced) the leaf must also verify against that CA's key — the
         * issuer certificate sent along with the answer is not trusted on its
         * own word.
         */
        fun acceptIssuedChain(
            pemChain: List<String>,
            key: ClientIdentityKeyProvider,
            expectedIssuer: X509Certificate? = null
        ): List<X509Certificate> {
            val certs = Pkcs10Csr.parsePemChain(pemChain)
            require(certs.isNotEmpty()) { "Issued chain is empty" }
            val leaf = certs[0]
            leaf.checkValidity()
            if (!leaf.publicKey.encoded.contentEquals(key.publicKey().encoded)) {
                throw SecurityException("Issued certificate is not over this device's key")
            }
            if (leaf.subjectX500Principal.name.isBlank()) throw SecurityException("Issued certificate has no subject")
            if (certs.size > 1) {
                val issuer = certs[1]
                if (leaf.issuerX500Principal != issuer.subjectX500Principal) {
                    throw SecurityException("Issued certificate does not chain to the issuer sent with it")
                }
                leaf.verify(issuer.publicKey)
            }
            if (expectedIssuer != null) {
                try {
                    leaf.verify(expectedIssuer.publicKey)
                } catch (e: Exception) {
                    throw SecurityException("Renewed certificate is not from the CA that issued the current one", e)
                }
            }
            return certs
        }
    }
}
