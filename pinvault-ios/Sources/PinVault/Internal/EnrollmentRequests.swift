import Foundation

/// One enrollment request, and what it means for a device that was told to
/// wait for an administrator's approval (Kotlin `EnrollmentRequests`):
///
/// - a 202 (``PinVaultError/enrollmentPending(requestId:clientId:serverMessage:retryAfterSeconds:verificationCode:)``)
///   is remembered per label, so the next attempt — the app's, start's or the
///   periodic update's — asks again by the request id with a CSR from the same key;
/// - a request that is over (turned away, unknown to the server, made with
///   another key) is forgotten together with its key, so the next attempt is
///   a new request an administrator can let in.
enum EnrollmentRequests {

    /// Server errors after which a remembered request is of no use any more.
    private static let over: Set<String> = [
        "enrollment_rejected", "enrollment_request_not_found", "enrollment_request_mismatch", "enrollment_request_expired",
    ]

    /// Over for the key itself even when nothing was remembered: the same key would get the same answer.
    private static let overForThisKey: Set<String> = ["enrollment_rejected", "enrollment_request_expired"]

    /// Over, but the device may ask again at once when it can (a code, or code-less applications).
    private static let askAgain: Set<String> = ["enrollment_request_not_found", "enrollment_request_expired"]

    /// Server errors that say the device key's attestation was missing or refused.
    private static let attestation: Set<String> = ["attestation_required", "attestation_invalid"]

    private static let log = PinVaultLog.tag("EnrollmentRequests")

    /// - Parameters:
    ///   - certStore: a strict store (``ClientCertSecureStore/openStrict(environment:)``):
    ///     what is read here decides whether a key may go.
    ///   - buildCsr: makes the key if needed and a CSR over it; nil when the key
    ///     store cannot (only with `allowServerGeneratedKey`: the server then makes the key).
    ///   - allowServerGeneratedKey: the block's `allowServerGeneratedKey()`.
    ///     Without it a request without a CSR is never sent, and a PKCS12
    ///     answer to a CSR is refused (``ServerGeneratedKeyRefusedError``).
    ///   - integrity: the app's `integrityTokenProvider`: asked for a token bound
    ///     to this request's CSR and device id (``IntegrityRequestHash``), sent
    ///     along when it gives one.
    ///   - appAttestation: makes the App Attest attestation of a new request
    ///     (``EnrollmentAppAttestation``); not asked when a pending request
    ///     asks again by its id.
    /// - Throws: the server's refusal or wait (``PinVaultError``), transport
    ///   failures, ``ServerGeneratedKeyRefusedError``.
    static func send(
        api: any CertificateConfigApi,
        certStore: ClientCertSecureStore,
        key: any ClientIdentityKeyProvider,
        certLabel: String,
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        allowServerGeneratedKey: Bool = false,
        retried: Bool = false,
        attestationRefusal: PinVaultError? = nil,
        integrity: (any IntegrityTokenProvider)? = nil,
        appAttestation: EnrollmentAppAttestation.Source? = nil,
        buildCsr: () throws -> Data?
    ) async throws -> EnrollmentResult {
        let pending = try certStore.loadPendingRequest(certLabel)
        let csr = try buildCsr()
        // Leaf first; empty when the key carries no attestation (iOS keys never
        // do; the API client then omits the field).
        let chain = csr != nil ? attestationOf(key) : []
        let requestHash = csr.map { IntegrityRequestHash.of(deviceId: deviceUid ?? deviceId, csrDer: $0) }
        // iOS: App Attest speaks for the request instead — on a new request
        // only; one waiting for approval was attested when it was made.
        var appAttest: String?
        if let requestHash, pending == nil, let appAttestation {
            appAttest = await appAttestationOf(appAttestation, requestHash: requestHash)
        }
        let attested = !chain.isEmpty || appAttest != nil
        // Second round after an attestation refusal: a new key that still
        // cannot be attested gets the same answer — do not ask twice.
        if let attestationRefusal, !attested { throw attestationRefusal }
        var integrityToken: String?
        if let csr, let integrity {
            integrityToken = await integrityTokenOf(integrity, deviceId: deviceUid ?? deviceId, csr: csr)
        }
        do {
            let answer: EnrollmentResult
            if let csr, let issued = try await enrollWithCsr(
                api, token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid, csr: csr,
                requestId: pending?.requestId, attestation: chain, integrityToken: integrityToken, appAttestation: appAttest
            ) {
                answer = issued
            } else {
                guard allowServerGeneratedKey else {
                    throw ServerGeneratedKeyRefusedError(
                        "The backend takes no certificate signing request, and this Config API block does not accept a " +
                            "key the server generates. Nothing was requested. Call allowServerGeneratedKey() on the " +
                            "block only if such a key is acceptable."
                    )
                }
                answer = try await api.enroll(token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid)
            }
            if answer.certificateChainPem == nil && !allowServerGeneratedKey {
                throw ServerGeneratedKeyRefusedError(
                    "The server answered the certificate request with a key of its own making (a PKCS12) instead of a " +
                        "certificate over this device's key. It was not stored. The server must issue over the CSR; call " +
                        "allowServerGeneratedKey() on the Config API block only if a server-made key is acceptable. " +
                        "A one-time token was spent by this answer."
                )
            }
            return answer
        } catch let PinVaultError.enrollmentPending(requestId, clientId, serverMessage, retryAfterSeconds, verificationCode) {
            try certStore.savePendingRequest(certLabel, requestId: requestId, clientId: clientId)
            // The code the device shows comes from its own key, never from the answer.
            let code = try? VerificationCode.of(publicKey: key.publicKey())
            throw PinVaultError.enrollmentPending(
                requestId: requestId, clientId: clientId, serverMessage: serverMessage,
                retryAfterSeconds: retryAfterSeconds, verificationCode: code ?? verificationCode
            )
        } catch let refusal as PinVaultError {
            guard case .enrollmentRefused(_, let serverError?, _) = refusal else { throw refusal }
            // A request that went without attestation (a key made when the
            // server did not ask for it; on iOS, App Attest gave nothing). The
            // refusal spends nothing, so: one new key, a fresh attestation and
            // one more request. Never for a request that waits for approval —
            // it is tied to the key it has — nor for one whose attestation was
            // refused (a new one would be refused the same way).
            if attestation.contains(serverError), csr != nil, !attested, pending == nil, attestationRefusal == nil {
                log.i("Enrollment refused (\(serverError)) and the device key carries no attestation — making a new key once")
                if !mayDeleteKey(certStore: certStore, certLabel: certLabel) { throw refusal }
                clearKey(key)
                return try await send(
                    api: api, certStore: certStore, key: key, certLabel: certLabel, token: token, deviceId: deviceId,
                    deviceAlias: deviceAlias, deviceUid: deviceUid, allowServerGeneratedKey: allowServerGeneratedKey,
                    retried: retried, attestationRefusal: refusal, integrity: integrity, appAttestation: appAttestation,
                    buildCsr: buildCsr
                )
            }
            let isOver = over.contains(serverError) && (pending != nil || overForThisKey.contains(serverError))
            if !isOver { throw refusal }
            log.i("Enrollment request over (\(serverError)) — the next attempt starts a new one")
            try certStore.clearPendingRequest(certLabel)
            if mayDeleteKey(certStore: certStore, certLabel: certLabel) { clearKey(key) }
            // Unknown to the server (reset, purged) or lapsed, while the device can ask
            // afresh — with a code, or without one (code-less applications): ask now.
            if askAgain.contains(serverError), token != nil || deviceId != nil, !retried {
                return try await send(
                    api: api, certStore: certStore, key: key, certLabel: certLabel, token: token, deviceId: deviceId,
                    deviceAlias: deviceAlias, deviceUid: deviceUid, allowServerGeneratedKey: allowServerGeneratedKey,
                    retried: true, attestationRefusal: attestationRefusal, integrity: integrity, appAttestation: appAttestation,
                    buildCsr: buildCsr
                )
            }
            throw refusal
        }
    }

    /// False when a certificate chain is stored under `certLabel` — the key is
    /// that enrollment's, and an answer to another request must not take it
    /// away — or when that cannot be told right now (pass a strict store: a
    /// non-strict one reads an unreadable chain as none). Only then may a
    /// refused request delete it.
    static func mayDeleteKey(certStore: ClientCertSecureStore, certLabel: String) -> Bool {
        do {
            if try certStore.hasChain(certLabel) {
                log.w("Enrollment [\(certLabel)]: a certificate chain is stored over this key — the key is kept")
                return false
            }
            return true
        } catch {
            log.w("Enrollment [\(certLabel)]: the credential store cannot be read right now — the key is kept", error)
            return false
        }
    }

    private static func clearKey(_ key: any ClientIdentityKeyProvider) {
        do {
            try key.clear()
        } catch {
            log.w("Could not delete the identity key", error)
        }
    }

    /// The key's attestation chain as the request carries it: Base64 DER, leaf first; empty when there is none.
    private static func attestationOf(_ key: any ClientIdentityKeyProvider) -> [String] {
        key.attestationChain().map(Base64.encode)
    }

    /// The app's integrity token for this request, or nil: none given, or the
    /// provider failed (logged; the request goes without, and a server that
    /// requires one refuses without spending the enrollment token).
    private static func integrityTokenOf(_ provider: any IntegrityTokenProvider, deviceId: String?, csr: Data) async -> String? {
        do {
            let token = try await provider.token(requestHash: IntegrityRequestHash.of(deviceId: deviceId, csrDer: csr))
            guard let token, !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                log.w("Integrity token provider gave no token; enrolling without")
                return nil
            }
            return token
        } catch {
            log.w("Integrity token provider failed; enrolling without", error)
            return nil
        }
    }

    /// The App Attest attestation of a new request, or nil: none given, or
    /// App Attest gave nothing (simulator, unsupported, a failure); the
    /// request then goes without, and a server that enforces attestation refuses it.
    private static func appAttestationOf(_ source: EnrollmentAppAttestation.Source, requestHash: String) async -> String? {
        let attestation = await source(EnrollmentAppAttestation.clientDataHash(requestHash: requestHash))
        guard let attestation, !attestation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            log.w("App Attest gave no attestation for this enrollment request; enrolling without")
            return nil
        }
        return attestation
    }

    /// With an App Attest attestation, the call that carries it (an API that
    /// cannot carry it gets the call without); with an `integrityToken`, the
    /// eight-argument `enrollWithCsr` (a custom API that does not implement it
    /// gets the token dropped by the protocol default); else the seven-argument call.
    private static func enrollWithCsr(
        _ api: any CertificateConfigApi,
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csr: Data,
        requestId: String?,
        attestation: [String],
        integrityToken: String?,
        appAttestation: String?
    ) async throws -> EnrollmentResult? {
        if let appAttestation {
            if let attestedApi = api as? any AppAttestedEnrollmentApi {
                return try await attestedApi.enrollWithCsr(
                    token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid, csrDer: csr,
                    requestId: requestId, attestationChain: attestation, integrityToken: integrityToken,
                    appAttestation: appAttestation
                )
            }
            log.w("The Config API takes no App Attest attestation; enrolling without")
        }
        if let integrityToken {
            return try await api.enrollWithCsr(
                token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid, csrDer: csr,
                requestId: requestId, attestationChain: attestation, integrityToken: integrityToken
            )
        }
        return try await api.enrollWithCsr(
            token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid, csrDer: csr,
            requestId: requestId, attestationChain: attestation
        )
    }
}

/// The enrollment would have ended with a private key the server generated,
/// and the block did not ask for that (`allowServerGeneratedKey()`). Reported
/// to the app as ``ClientCertEnrollmentResult/failed(message:cause:)`` with this message.
struct ServerGeneratedKeyRefusedError: Error, CustomStringConvertible, LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var description: String { "ServerGeneratedKeyRefusedException: \(message)" }
    var errorDescription: String? { message }
}
