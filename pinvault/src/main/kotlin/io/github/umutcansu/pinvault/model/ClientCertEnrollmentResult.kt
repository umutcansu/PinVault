package io.github.umutcansu.pinvault.model

/**
 * What an enrollment came to, from `PinVault.enrollForResult` and
 * `autoEnrollForResult`. The `Boolean` `enroll` / `autoEnroll` return `true`
 * exactly for [Enrolled]; these say why when they return `false`, so an app
 * can tell its user what to do instead of "enrollment failed".
 */
sealed class ClientCertEnrollmentResult {

    /** A certificate was issued and stored, or one was already stored ([alreadyEnrolled]). */
    data class Enrolled(val alreadyEnrolled: Boolean = false) : ClientCertEnrollmentResult()

    /**
     * The server answered and refused. [reason] says what to do next;
     * [serverError] and [message] are the server's own words, for logs.
     */
    data class Refused(
        val reason: EnrollmentRefusal,
        val httpStatus: Int,
        val serverError: String? = null,
        val message: String? = null
    ) : ClientCertEnrollmentResult()

    /**
     * The server took the request but an administrator has to approve this
     * device first: it enrolled with a code whose policy asks for approval.
     * The device keeps its key and the [requestId]; `PinVault.checkPendingEnrollment`
     * asks again (init and the periodic update do too), and the certificate
     * is stored once the device is let in. [clientId] is the identity it will
     * get; [retryAfterSeconds] how long the server asks it to wait between tries.
     */
    data class Pending(
        val requestId: String,
        val clientId: String? = null,
        val message: String? = null,
        val retryAfterSeconds: Int? = null,
        /**
         * Code from this device's key (`4F7K-2QXM-9D3T-H6WP`, 16 characters): show it, the
         * administrator sees the same next to the request and compares.
         */
        val verificationCode: String? = null
    ) : ClientCertEnrollmentResult()

    /**
     * No usable answer: the server could not be reached, its certificate did
     * not match the pins, the device's key store failed, or what came back did
     * not check out.
     */
    data class Failed(val message: String, val cause: Throwable? = null) : ClientCertEnrollmentResult()
}

/** Why a server refused an enrollment. */
enum class EnrollmentRefusal {
    /** The token is unknown, already used or expired (401). Ask for a new one. */
    INVALID_TOKEN,

    /** The server enrolls only with a token, so a token-less `autoEnroll` was refused. */
    TOKEN_REQUIRED,

    /**
     * This device is enrolled under another client id (409
     * `device_already_enrolled`), or this client id is already enrolled over
     * another key (409 `identity_already_enrolled`). Once an administrator
     * revokes that one (and, for the same id, forgets it), the same token
     * works: a refused enrollment does not spend it.
     */
    DEVICE_ALREADY_ENROLLED,

    /** The client id the token is for was revoked (403 `revoked`). A token for a new id is needed. */
    REVOKED,

    /**
     * An administrator turned this device away (403 `enrollment_rejected`). The
     * device forgets the request and its key; asking again starts a new request.
     */
    REJECTED,

    /** The enrollment code has no device left (403 `enrollment_limit_reached`). Ask for a new code. */
    LIMIT_REACHED,

    /**
     * Nobody decided on the request in time (410 `enrollment_request_expired`).
     * The device forgot it and its key; asking again starts a new request.
     */
    EXPIRED,

    /**
     * The server asks for an Android key attestation of the device key and
     * got none (403 `attestation_required`: this device's Keystore could not
     * attest the key) or refused the one it got (403 `attestation_invalid`;
     * [ClientCertEnrollmentResult.Refused.message] carries the server's
     * reason — an emulator, an unlocked bootloader, another app). Nothing
     * the user can retry; the token is not spent.
     *
     * Also the server's answer to an integrity verdict
     * (`integrityTokenProvider`): `integrity_required` when the request
     * carried no integrity token, `integrity_invalid` when the verdict was
     * refused (a rooted device, an app not installed from Play, a token for
     * another request). [ClientCertEnrollmentResult.Refused.serverError]
     * tells the two kinds apart. An integrity refusal can be transient (the
     * token service was unreachable): trying again later may work.
     */
    ATTESTATION_FAILED,

    /**
     * The server issues certificates only over a certificate signing request
     * (`csr_required`) and this request carried none: the device could not
     * make its own key and the block allowed asking for a server-made one
     * (`allowServerGeneratedKey()`), which the server does not hand out.
     */
    CSR_REQUIRED,

    /** Anything else the server refused; see [ClientCertEnrollmentResult.Refused.serverError]. */
    OTHER
}

/**
 * Thrown by a [io.github.umutcansu.pinvault.api.CertificateConfigApi] when
 * the server refuses an enrollment (an HTTP 4xx answer). A custom backend
 * throws it too, so PinVault can report the reason to the app
 * ([ClientCertEnrollmentResult.Refused]); any other exception is reported as
 * [ClientCertEnrollmentResult.Failed].
 *
 * @param serverError the `error` field of the server's JSON answer, if any
 * @param serverMessage its `message` field, if any — for an attestation
 *   refusal the server's `reason`
 */
class EnrollmentRefusedException(
    val httpStatus: Int,
    val serverError: String? = null,
    val serverMessage: String? = null
) : Exception("Enrollment refused — HTTP $httpStatus" + (serverError?.let { " $it" } ?: "")) {

    /** What the refusal means for the app. */
    val refusal: EnrollmentRefusal
        get() = when {
            httpStatus == 401 -> EnrollmentRefusal.INVALID_TOKEN
            serverError == "device_already_enrolled" || serverError == "identity_already_enrolled" ->
                EnrollmentRefusal.DEVICE_ALREADY_ENROLLED
            serverError == "revoked" -> EnrollmentRefusal.REVOKED
            serverError == "enrollment_rejected" -> EnrollmentRefusal.REJECTED
            serverError == "enrollment_limit_reached" -> EnrollmentRefusal.LIMIT_REACHED
            serverError == "enrollment_request_expired" -> EnrollmentRefusal.EXPIRED
            // The server issues this enrollment only over a CSR.
            serverError == "csr_required" -> EnrollmentRefusal.CSR_REQUIRED
            serverError == "attestation_required" || serverError == "attestation_invalid" ||
                serverError == "integrity_required" || serverError == "integrity_invalid" ->
                EnrollmentRefusal.ATTESTATION_FAILED
            // The reference server answers a token-less enrollment in token mode
            // with 403 and a sentence in `error` ("Token required for enrollment…").
            httpStatus == 403 && serverError?.startsWith("Token required") == true -> EnrollmentRefusal.TOKEN_REQUIRED
            else -> EnrollmentRefusal.OTHER
        }
}

/**
 * Thrown by a [io.github.umutcansu.pinvault.api.CertificateConfigApi] when the
 * server takes an enrollment but an administrator has to approve the device
 * first (the reference server answers HTTP 202 with a `requestId`). PinVault
 * remembers [requestId] and reports [ClientCertEnrollmentResult.Pending]; the
 * next attempt sends it back with a CSR from the same key to ask whether the
 * device was let in. A custom backend with an approval step throws it too.
 *
 * @param clientId the identity the device will get, if the server said
 * @param serverMessage the server's `message`, if any
 * @param retryAfterSeconds the server's `Retry-After`, if any
 */
class EnrollmentPendingException(
    val requestId: String,
    val clientId: String? = null,
    val serverMessage: String? = null,
    val retryAfterSeconds: Int? = null,
    /** Set by PinVault from the device's own key, whatever a backend put here. */
    val verificationCode: String? = null
) : Exception("Enrollment waits for approval — request $requestId")
