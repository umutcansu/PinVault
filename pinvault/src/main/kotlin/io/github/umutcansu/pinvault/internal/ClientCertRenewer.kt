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
import javax.net.ssl.SSLProtocolException

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
 * from anything. An issued chain is stored only when it is the leaf plus the
 * CA certificate that signed it, the leaf is valid now, over this device's
 * key, not longer-lived than the block allows, and from the right CA: one
 * the block pins (`clientCaPins`), or — without pins — the CA of the
 * certificate being replaced. Whoever answers on the renewal door cannot
 * hand the device a certificate of their own making.
 */
internal class ClientCertRenewer(
    private val block: ConfigApiBlock,
    private val certStore: ClientCertSecureStore,
    private val identityKeyFactory: (label: String) -> ClientIdentityKeyProvider,
    private val api: () -> CertificateConfigApi,
    /** Installs the stored credentials into the SSL manager and rebuilds the clients. */
    private val reload: () -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
    /**
     * Told when the server refused the renewal as `reenroll_required` on the
     * block's own (mTLS) connection, with the leaf that connection was to
     * present. Only that answer is about the device's identity; the same
     * answer on the recovery door (TLS, no client certificate) is from a
     * listener that saw no identity, so it is reported and nothing more.
     */
    private val onRefusedOverMtls: (leaf: X509Certificate) -> Unit = { }
) {

    sealed class Decision {
        object None : Decision()
        object Renew : Decision()
        object Recover : Decision()
    }

    /**
     * `Recover` once [nowMs] is past `notAfter`; `Renew` when the remaining
     * lifetime is below [threshold] of the whole lifetime, or when the
     * certificate lives longer than the block accepts (one stored before the
     * cap existed: without this its renewal would never come due); else
     * `None`.
     */
    fun decide(leaf: X509Certificate, nowMs: Long, threshold: Double): Decision {
        val notAfter = leaf.notAfter.time
        val notBefore = leaf.notBefore.time
        if (nowMs > notAfter) return Decision.Recover
        val lifetime = (notAfter - notBefore).coerceAtLeast(1L)
        if (lifetime > maxLifetimeMs(block.maxClientCertLifetimeDays) + LIFETIME_SLACK_MS) return Decision.Renew
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
        // The CA that issued the current certificate. Without pinned client
        // CAs a renewal must come from the same CA: whoever answers on the
        // renewal door — even a party that got hold of the door's TLS key —
        // cannot swap in a chain of its own.
        val currentIssuer = stored.getOrNull(1)

        val decision = decide(leaf, clock(), block.clientCertRenewalThreshold)
        if (decision == Decision.None && !force) {
            return ClientCertRenewalResult.NotNeeded(leaf.notAfter.time)
        }

        if (currentIssuer == null && block.clientCaPins.isEmpty()) {
            // A chain of one, stored by an earlier version: there is no CA to
            // hold the answer to, and an answer nobody can check is not stored.
            Timber.e("Client cert renewal [%s]: the stored chain has no CA certificate and the block pins none", block.id)
            return ClientCertRenewalResult.Failed(
                "The stored client certificate has no CA certificate with it, so a renewed one cannot be checked. " +
                    "Pin the client CA with clientCaPins(...) or enroll again."
            )
        }

        val clientId = clientIdOf(leaf)
        val via = if (decision == Decision.Recover) ClientCertRenewalVia.RECOVERY else ClientCertRenewalVia.MTLS
        // The client id is the certificate's CN and names the device: not logged.
        Timber.i("Client cert renewal [%s] via %s (notAfter=%s)", block.id, via, leaf.notAfter)

        return try {
            val csr = Pkcs10Csr.encode(clientId, key.publicKey(), key::sign)
            val (response, usedVia) = request(clientId, csr, via)
            when (response) {
                is ClientCertRenewalResponse.Issued -> {
                    val certs = acceptIssuedChain(
                        response.certificateChainPem, key, currentIssuer, block.clientCaPins, block.maxClientCertLifetimeDays
                    )
                    certStore.saveChain(label, response.certificateChainPem)
                    reload()
                    Timber.i("Client cert renewed [%s] via %s — valid until %s", block.id, usedVia, certs[0].notAfter)
                    ClientCertRenewalResult.Renewed(certs[0].notAfter.time, usedVia)
                }
                is ClientCertRenewalResponse.ReenrollRequired -> {
                    Timber.w("Client cert renewal [%s] refused via %s: %s — re-enrollment required", block.id, usedVia, response.reason)
                    if (usedVia == ClientCertRenewalVia.MTLS) runCatching { onRefusedOverMtls(leaf) }
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
         *
         * With TLS 1.3 (which the library no longer caps away) the server's
         * verdict on the client certificate arrives after the client's side
         * of the handshake is done: the alert surfaces on the first read, on
         * Android as an [SSLProtocolException]. That counts as well.
         *
         * An [SSLProtocolException] can also be some other protocol fault.
         * Counting it here is safe: all that follows is one more attempt, at
         * the recovery URL — pinned like every other connection of the block,
         * presenting no certificate — and the chain that comes back is held
         * to the same rules ([acceptIssuedChain]) whichever way it came.
         */
        fun isClientCertRefusal(e: Throwable): Boolean {
            if (e !is SSLHandshakeException && e !is SSLPeerUnverifiedException && e !is SSLProtocolException) return false
            var cause: Throwable? = e
            val seen = HashSet<Throwable>()
            while (cause != null && seen.add(cause)) {
                if (cause is CertificateException) return false
                cause = cause.cause
            }
            return true
        }

        /**
         * Checks a chain the server issued before it is stored. Always:
         *  - at least two certificates — the leaf and the CA certificate that
         *    signed it. A leaf on its own leaves a later renewal nothing to
         *    be held to, so it is refused;
         *  - the leaf is valid now, over [key]'s public key, has a subject,
         *    and names and verifies against the next certificate;
         *  - the leaf's lifetime, and what is left of it from now, is at most
         *    [maxLifetimeDays]: a certificate valid for decades never comes
         *    up for renewal, so the server never gets to refuse it.
         *
         * Then who signed it:
         *  - with [caPins] (the block's `clientCaPins`): a certificate of the
         *    chain whose SubjectPublicKeyInfo matches a pin must verify the
         *    leaf's signature. This holds for enrollment and for renewal;
         *  - without pins, with [expectedIssuer] (a renewal: the CA of the
         *    certificate being replaced): the leaf must verify against that
         *    CA's key — the CA certificate sent along with the answer is not
         *    trusted on its own word;
         *  - without either (a first enrollment, no pins): the chain is taken
         *    as the pinned enrollment listener sent it.
         */
        fun acceptIssuedChain(
            pemChain: List<String>,
            key: ClientIdentityKeyProvider,
            expectedIssuer: X509Certificate? = null,
            caPins: List<String> = emptyList(),
            maxLifetimeDays: Int = ConfigApiBlock.DEFAULT_MAX_CLIENT_CERT_LIFETIME_DAYS,
            nowMs: Long = System.currentTimeMillis()
        ): List<X509Certificate> {
            val certs = Pkcs10Csr.parsePemChain(pemChain)
            if (certs.size < 2) {
                throw SecurityException(
                    "Issued chain has ${certs.size} certificate(s): the leaf must come with the CA certificate that signed it"
                )
            }
            val leaf = certs[0]
            leaf.checkValidity()
            if (!leaf.publicKey.encoded.contentEquals(key.publicKey().encoded)) {
                throw SecurityException("Issued certificate is not over this device's key")
            }
            if (leaf.subjectX500Principal.name.isBlank()) throw SecurityException("Issued certificate has no subject")

            val maxMs = maxLifetimeMs(maxLifetimeDays) + LIFETIME_SLACK_MS
            if (leaf.notAfter.time - leaf.notBefore.time > maxMs || leaf.notAfter.time - nowMs > maxMs) {
                throw SecurityException(
                    "Issued certificate is valid for longer than $maxLifetimeDays days (maxClientCertLifetimeDays); refused"
                )
            }

            val issuer = certs[1]
            if (leaf.issuerX500Principal != issuer.subjectX500Principal) {
                throw SecurityException("Issued certificate does not chain to the issuer sent with it")
            }
            leaf.verify(issuer.publicKey)

            if (caPins.isNotEmpty()) {
                val signedByPinned = certs.drop(1).any { ca ->
                    Pkcs10Csr.spkiSha256Base64(ca.publicKey) in caPins && runCatching { leaf.verify(ca.publicKey) }.isSuccess
                }
                if (!signedByPinned) {
                    throw SecurityException("Issued certificate is not signed by a pinned client CA (clientCaPins)")
                }
            } else if (expectedIssuer != null) {
                try {
                    leaf.verify(expectedIssuer.publicKey)
                } catch (e: Exception) {
                    throw SecurityException("Renewed certificate is not from the CA that issued the current one", e)
                }
            }
            return certs
        }

        internal fun maxLifetimeMs(days: Int): Long = days.toLong() * 24 * 60 * 60 * 1000

        /** Issuers backdate `notBefore` a little against clock skew; that is not "longer than allowed". */
        internal const val LIFETIME_SLACK_MS = 24L * 60 * 60 * 1000
    }
}
