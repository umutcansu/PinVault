import Foundation

/// The device-side attestation endpoints of a Config API (`ATTESTATION.md`
/// §2), relative to the block's `configUrl`. Reached only through the
/// library's own client (`DefaultCertificateConfigApi`, over the pinned
/// bootstrap session): a block whose ``CertificateConfigApi`` does not adopt
/// this protocol — a custom one — reports ``AttestationResult/unsupported``,
/// as Kotlin's `api as? DefaultCertificateConfigApi` does.
protocol AttestationApi: Sendable {

    /// `GET <configUrl>api/v1/attest/challenge`: the answer body as it came
    /// (`{"nonce", "expiresIn", "serverTime"}`). Throws ``AttestationHttpError``
    /// for any non-2xx answer (use ``AttestationHttpError/of(httpStatus:body:)``).
    func attestChallenge() async throws -> Data

    /// `POST <configUrl>api/v1/attest` with `body` (JSON, `application/json`),
    /// returning the server's verdict body as it came. Throws
    /// ``AttestationHttpError`` for any non-2xx answer, with the server's
    /// `error` (`nonce_expired`, `signature_invalid`, `device_revoked`,
    /// `key_mismatch`, `attestation_required`, …).
    func attest(body: Data) async throws -> Data
}

/// Device-side attestation endpoints, relative to the block's `configUrl`.
enum AttestationEndpoints {
    static let challenge = "api/v1/attest/challenge"
    static let attest = "api/v1/attest"
}

/// The server refused an attestation call (Kotlin `AttestationHttpException`).
/// `serverError` is its `error`, `serverMessage` its `message` or `reason`;
/// both nil when the body was not JSON.
struct AttestationHttpError: Error, Equatable, CustomStringConvertible {
    let httpStatus: Int
    let serverError: String?
    let serverMessage: String?

    /// `Attestation refused — HTTP 403 key_mismatch: another key is registered…`
    var message: String {
        "Attestation refused — HTTP \(httpStatus)"
            + (serverError.map { " \($0)" } ?? "")
            + (serverMessage.map { ": \($0)" } ?? "")
    }

    var description: String { message }

    static func of(httpStatus: Int, body: Data) -> AttestationHttpError {
        let json = LenientJSON.object(body)
        return AttestationHttpError(
            httpStatus: httpStatus,
            serverError: json.flatMap { LenientJSON.nonBlankString($0, "error") },
            serverMessage: json.flatMap { LenientJSON.nonBlankString($0, "message") ?? LenientJSON.nonBlankString($0, "reason") }
        )
    }
}
