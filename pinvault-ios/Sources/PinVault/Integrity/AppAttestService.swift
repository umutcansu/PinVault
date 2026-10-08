import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// The calls of `DCAppAttestService` the App Attest providers make, as a
/// protocol so tests can run the whole token flow with a fake service.
protocol AppAttestService: Sendable {
    /// `DCAppAttestService.isSupported`: false on the simulator and on devices without a Secure Enclave.
    var isSupported: Bool { get }
    /// A new App Attest key; returns its key id (Base64 SHA-256 of the public key).
    func generateKey() async throws -> String
    /// The attestation object (CBOR) for the key, bound to `clientDataHash`. Asks Apple's servers.
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    /// An assertion (CBOR) by the key over `clientDataHash`. Local, no network.
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// What can go wrong in a ``AppAttestService`` call (`DCError`).
enum AppAttestServiceError: Error, Equatable, CustomStringConvertible {
    /// The device or the app cannot use App Attest (`DCError.featureUnsupported`).
    case featureUnsupported
    case invalidInput
    /// The key is gone or unusable (`DCError.invalidKey`): make a new one.
    case invalidKey
    /// Apple's server could not be reached (`DCError.serverUnavailable`): try again later with the same key.
    case serverUnavailable
    case failed(String)

    var description: String {
        switch self {
        case .featureUnsupported: return "App Attest is not supported here (featureUnsupported)"
        case .invalidInput: return "App Attest refused the input (invalidInput)"
        case .invalidKey: return "The App Attest key is invalid (invalidKey)"
        case .serverUnavailable: return "Apple's App Attest server is unavailable (serverUnavailable)"
        case .failed(let message): return "App Attest failed: \(message)"
        }
    }
}

/// The `DCAppAttestService.shared` behind ``AppAttestService``.
struct DeviceCheckAppAttestService: AppAttestService {

    var isSupported: Bool {
        #if canImport(DeviceCheck) && !os(watchOS)
        return DCAppAttestService.shared.isSupported
        #else
        return false
        #endif
    }

    func generateKey() async throws -> String {
        #if canImport(DeviceCheck) && !os(watchOS)
        return try await Self.call { done in DCAppAttestService.shared.generateKey { keyId, error in done(keyId, error) } }
        #else
        throw AppAttestServiceError.featureUnsupported
        #endif
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        #if canImport(DeviceCheck) && !os(watchOS)
        return try await Self.call { done in
            DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) { object, error in done(object, error) }
        }
        #else
        throw AppAttestServiceError.featureUnsupported
        #endif
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        #if canImport(DeviceCheck) && !os(watchOS)
        return try await Self.call { done in
            DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) { object, error in done(object, error) }
        }
        #else
        throw AppAttestServiceError.featureUnsupported
        #endif
    }

    /// A completion-handler call as `async`, with `DCError` mapped.
    private static func call<Value: Sendable>(
        _ start: (@escaping @Sendable (Value?, (any Error)?) -> Void) -> Void
    ) async throws -> Value {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Value, any Error>) in
            start { value, error in
                if let value, error == nil {
                    continuation.resume(returning: value)
                } else {
                    continuation.resume(throwing: map(error))
                }
            }
        }
    }

    static func map(_ error: (any Error)?) -> AppAttestServiceError {
        guard let error else { return .failed("no result") }
        #if canImport(DeviceCheck) && !os(watchOS)
        if let dcError = error as? DCError {
            switch dcError.code {
            case .featureUnsupported: return .featureUnsupported
            case .invalidInput: return .invalidInput
            case .invalidKey: return .invalidKey
            case .serverUnavailable: return .serverUnavailable
            default: return .failed(dcError.localizedDescription)
            }
        }
        #endif
        return .failed(String(describing: error))
    }
}

/// The App Attest token of `PORTING.md` §6, the string that travels as the
/// report's `verdictProvider.token` and as the enrollment `integrityToken`:
/// `{"provider":"app-attest","keyId":"…","attestation"|"assertion":"<Base64 CBOR>"}`.
enum AppAttestToken {
    /// `verdictProvider.name` and the token's `provider`.
    static let provider = "app-attest"

    static func attestation(keyId: String, object: Data) -> String {
        IntegrityJSON.object([
            .init("provider", .string(provider)),
            .init("keyId", .string(keyId)),
            .init("attestation", .string(Base64.encode(object))),
        ]).serialized
    }

    static func assertion(keyId: String, object: Data) -> String {
        IntegrityJSON.object([
            .init("provider", .string(provider)),
            .init("keyId", .string(keyId)),
            .init("assertion", .string(Base64.encode(object))),
        ]).serialized
    }

    /// An attestation round's client data hash: SHA-256 of `pinvault-app-attest:v1:<nonce>:<deviceId>` (UTF-8).
    static func roundClientDataHash(nonce: String, deviceId: String) -> Data {
        Hashing.sha256("pinvault-app-attest:v1:\(nonce):\(deviceId)")
    }

    /// A v2 round's client data hash: SHA-256 of `pinvault-app-attest:v2:<canonical>` (UTF-8),
    /// where `canonical` is the string the identity key signs
    /// (`pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>`). It binds the
    /// assertion to the report's content as well as the round; the token then
    /// travels beside the report, not inside it (`ATTESTATION.md` §12).
    static func roundClientDataHashV2(canonical: String) -> Data {
        Hashing.sha256("pinvault-app-attest:v2:\(canonical)")
    }

    /// An enrollment's client data hash: SHA-256 of the 43-character integrity request hash (UTF-8).
    static func enrollmentClientDataHash(requestHash: String) -> Data {
        Hashing.sha256(requestHash)
    }
}
