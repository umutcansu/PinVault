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

    /**
     * @param buildCsr makes the key if needed and a CSR over it; null when the
     *   key store cannot (the server then makes the key: P12 enrollment)
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
        retried: Boolean = false,
        buildCsr: () -> ByteArray?
    ): EnrollmentResult {
        val pending = certStore.loadPendingRequest(certLabel)
        val csr = buildCsr()
        try {
            return csr?.let { api.enrollWithCsr(token, deviceId, deviceAlias, deviceUid, it, pending?.requestId) }
                ?: api.enroll(token, deviceId, deviceAlias, deviceUid)
        } catch (e: EnrollmentPendingException) {
            certStore.savePendingRequest(certLabel, e.requestId, e.clientId)
            // The code the device shows comes from its own key, never from the answer.
            val code = runCatching { VerificationCode.of(key.publicKey()) }.getOrNull()
            if (code != null && code != e.verificationCode) {
                throw EnrollmentPendingException(e.requestId, e.clientId, e.serverMessage, e.retryAfterSeconds, code)
            }
            throw e
        } catch (e: EnrollmentRefusedException) {
            val over = e.serverError in OVER && (pending != null || e.serverError in OVER_FOR_THIS_KEY)
            if (!over) throw e
            Timber.i("Enrollment request over (%s) [%s] — the next attempt starts a new one", e.serverError, certLabel)
            certStore.clearPendingRequest(certLabel)
            runCatching { key.clear() }.onFailure { Timber.w(it, "Could not delete the identity key [%s]", certLabel) }
            // Unknown to the server (reset, purged) or lapsed, while the device can ask
            // afresh — with a code, or without one (code-less applications): ask now.
            if (e.serverError in ASK_AGAIN && (token != null || deviceId != null) && !retried) {
                return send(api, certStore, key, certLabel, token, deviceId, deviceAlias, deviceUid, retried = true, buildCsr = buildCsr)
            }
            throw e
        }
    }
}
