package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.EnrollmentPendingException
import io.github.umutcansu.pinvault.model.EnrollmentRefusedException
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import timber.log.Timber

/**
 * One enrollment request, and what it means for a device that was told to
 * wait for an administrator's approval:
 *
 * - a 202 ([EnrollmentPendingException]) is remembered per label, so the next
 *   attempt — the app's, init's or the periodic update's — asks again by the
 *   request id with a CSR from the same key;
 * - a request that is over (turned away, unknown to the server, made with
 *   another key) is forgotten together with its key, so the next attempt is a
 *   new request an administrator can let in.
 */
internal object EnrollmentRequests {

    /** Server errors after which a remembered request is of no use any more. */
    private val OVER = setOf(
        "enrollment_rejected", "enrollment_request_not_found", "enrollment_request_mismatch", "enrollment_request_expired"
    )

    /** Over for the key itself even when nothing was remembered: the same key would get the same answer. */
    private val OVER_FOR_THIS_KEY = setOf("enrollment_rejected", "enrollment_request_expired")

    /** Over, but the device may ask again at once when it can (a code, or code-less applications). */
    private val ASK_AGAIN = setOf("enrollment_request_not_found", "enrollment_request_expired")

    /** Server errors that say the device key's attestation was missing or refused. */
    private val ATTESTATION = setOf("attestation_required", "attestation_invalid")

    /**
     * @param buildCsr makes the key if needed — with its attestation
     *   challenge — and a CSR over it; null when the key store cannot (only
     *   with [allowServerGeneratedKey]: the server then makes the key)
     * @param allowServerGeneratedKey the block's `allowServerGeneratedKey()`.
     *   Without it a request without a CSR is never sent, and a PKCS12
     *   answer to a CSR is refused ([ServerGeneratedKeyRefusedException]).
     */
    suspend fun send(
        api: CertificateConfigApi,
        certStore: ClientCertSecureStore,
        key: ClientIdentityKeyProvider,
        certLabel: String,
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        allowServerGeneratedKey: Boolean = false,
        retried: Boolean = false,
        attestationRefusal: EnrollmentRefusedException? = null,
        buildCsr: () -> ByteArray?
    ): EnrollmentResult {
        val pending = certStore.loadPendingRequest(certLabel)
        val csr = buildCsr()
        // Leaf first, as the Keystore returns it; empty when the key carries
        // no attestation (older servers ignore the field).
        val attestation = if (csr != null) attestationOf(key) else emptyList()
        // Second round after an attestation refusal: a new key that still
        // cannot be attested gets the same answer — do not ask twice.
        if (attestationRefusal != null && attestation.isEmpty()) throw attestationRefusal
        try {
            val answer = csr?.let {
                enrollWithCsr(api, token, deviceId, deviceAlias, deviceUid, it, pending?.requestId, attestation)
            } ?: run {
                if (!allowServerGeneratedKey) {
                    throw ServerGeneratedKeyRefusedException(
                        "The backend takes no certificate signing request, and this Config API block does not accept a " +
                            "key the server generates. Nothing was requested. Call allowServerGeneratedKey() on the " +
                            "block only if such a key is acceptable."
                    )
                }
                api.enroll(token, deviceId, deviceAlias, deviceUid)
            }
            if (answer.certificateChainPem == null && !allowServerGeneratedKey) {
                throw ServerGeneratedKeyRefusedException(
                    "The server answered the certificate request with a key of its own making (a PKCS12) instead of a " +
                        "certificate over this device's key. It was not stored. The server must issue over the CSR; call " +
                        "allowServerGeneratedKey() on the Config API block only if a server-made key is acceptable. " +
                        "A one-time token was spent by this answer."
                )
            }
            return answer
        } catch (e: EnrollmentPendingException) {
            certStore.savePendingRequest(certLabel, e.requestId, e.clientId)
            // The code the device shows comes from its own key, never from the answer.
            val code = runCatching { VerificationCode.of(key.publicKey()) }.getOrNull()
            if (code != null && code != e.verificationCode) {
                throw EnrollmentPendingException(e.requestId, e.clientId, e.serverMessage, e.retryAfterSeconds, code)
            }
            throw e
        } catch (e: EnrollmentRefusedException) {
            // A key made before the library asked for attestation (or made when
            // no device id was known) has no chain. The refusal spends nothing,
            // so: one new key, with a challenge, and one more request. Never for
            // a request that waits for approval — it is tied to the key it has.
            if (e.serverError in ATTESTATION && csr != null && attestation.isEmpty() && pending == null && attestationRefusal == null) {
                Timber.i("Enrollment refused (%s) and the device key carries no attestation — making a new key once", e.serverError)
                if (!mayDeleteKey(certStore, certLabel)) throw e
                runCatching { key.clear() }.onFailure { Timber.w(it, "Could not delete the identity key") }
                return send(
                    api, certStore, key, certLabel, token, deviceId, deviceAlias, deviceUid,
                    allowServerGeneratedKey, retried, attestationRefusal = e, buildCsr = buildCsr
                )
            }
            val over = e.serverError in OVER && (pending != null || e.serverError in OVER_FOR_THIS_KEY)
            if (!over) throw e
            Timber.i("Enrollment request over (%s) — the next attempt starts a new one", e.serverError)
            certStore.clearPendingRequest(certLabel)
            if (mayDeleteKey(certStore, certLabel)) runCatching { key.clear() }.onFailure { Timber.w(it, "Could not delete the identity key") }
            // Unknown to the server (reset, purged) or lapsed, while the device can ask
            // afresh — with a code, or without one (code-less applications): ask now.
            if (e.serverError in ASK_AGAIN && (token != null || deviceId != null) && !retried) {
                return send(
                    api, certStore, key, certLabel, token, deviceId, deviceAlias, deviceUid,
                    allowServerGeneratedKey, retried = true, attestationRefusal = attestationRefusal, buildCsr = buildCsr
                )
            }
            throw e
        }
    }

    /**
     * False when a certificate chain is stored under [certLabel] — the key
     * is that enrollment's, and an answer to another request must not take
     * it away — or when that cannot be told right now (pass a strict store,
     * [ClientCertSecureStore.openStrict]: a non-strict one reads an
     * unreadable chain as none). Only then may a refused request delete it.
     */
    fun mayDeleteKey(certStore: ClientCertSecureStore, certLabel: String): Boolean = try {
        if (certStore.hasChain(certLabel)) {
            Timber.w("Enrollment [%s]: a certificate chain is stored over this key — the key is kept", certLabel)
            false
        } else {
            true
        }
    } catch (e: Exception) {
        Timber.w(e, "Enrollment [%s]: the credential store cannot be read right now — the key is kept", certLabel)
        false
    }

    /** The key's attestation chain as the request carries it: Base64 DER, leaf first; empty when there is none. */
    private fun attestationOf(key: ClientIdentityKeyProvider): List<String> = try {
        key.attestationChain().map { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
    } catch (e: Exception) {
        Timber.w(e, "Could not read the identity key's attestation chain; enrolling without")
        emptyList()
    } catch (e: LinkageError) {
        // A key provider compiled against an earlier PinVault has no such method.
        emptyList()
    }

    /**
     * A custom [CertificateConfigApi] compiled against PinVault 2.1.x has no
     * `enrollWithCsr` that takes the attestation chain; calling it ends in a
     * linkage error, and the six-argument method is called instead.
     */
    private suspend fun enrollWithCsr(
        api: CertificateConfigApi,
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csr: ByteArray,
        requestId: String?,
        attestation: List<String>
    ): EnrollmentResult? = try {
        api.enrollWithCsr(token, deviceId, deviceAlias, deviceUid, csr, requestId, attestation)
    } catch (e: AbstractMethodError) {
        api.enrollWithCsr(token, deviceId, deviceAlias, deviceUid, csr, requestId)
    } catch (e: NoSuchMethodError) {
        api.enrollWithCsr(token, deviceId, deviceAlias, deviceUid, csr, requestId)
    }
}

/**
 * The enrollment would have ended with a private key the server generated,
 * and the block did not ask for that (`allowServerGeneratedKey()`). Reported
 * to the app as `ClientCertEnrollmentResult.Failed` with this message.
 */
internal class ServerGeneratedKeyRefusedException(message: String) : Exception(message)
