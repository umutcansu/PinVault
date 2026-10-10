// Native results → plain dictionaries for Dart (the Swift twin of ResultMapper.kt;
// same keys). `type` is the Kotlin sealed subclass in lowerCamel, enum values are
// the Kotlin constant names (= Swift raw values). Every free-text field passes
// through VaultTokenStore.redact; vault content appears only in `unlocked`
// (after the native prompt) and in `loadFile`, never in a download result or an event.
import Foundation
import PinVault

public final class ResultMapper {
    public static let utf8 = "utf8"
    public static let base64 = "base64"

    private let tokens: VaultTokenStore

    public init(tokens: VaultTokenStore) { self.tokens = tokens }

    private func text(_ s: String?) -> Any { tokens.redact(s) ?? NSNull() }
    private func opt(_ v: Any?) -> Any { v ?? NSNull() }

    public static func checkEncoding(_ encoding: String) throws -> String {
        guard encoding == utf8 || encoding == base64 else { throw BridgeInputError("encoding: must be 'utf8' or 'base64'") }
        return encoding
    }

    public static func encode(_ data: Data, _ encoding: String) -> String {
        encoding == base64 ? data.base64EncodedString() : String(decoding: data, as: UTF8.self)
    }

    /// The Kotlin exception class name and message (`PinVaultError.exceptionName`).
    public func exception(_ error: (any Error)?) -> Any {
        guard let error else { return NSNull() }
        if let e = error as? PinVaultError {
            return ["name": e.exceptionName, "message": text(e.message)]
        }
        if let e = error as? BridgeInputError {
            return ["name": "IllegalArgumentException", "message": text(e.message)]
        }
        let ns = error as NSError
        let name = ns.domain == NSURLErrorDomain ? "URLError(\(ns.code))" : String(describing: type(of: error))
        return ["name": name, "message": text(ns.localizedDescription)]
    }

    public func initResult(_ r: InitResult) -> [String: Any] {
        switch r {
        case .ready(let version): return ["type": "ready", "version": version]
        case .failed(let reason, let e): return ["type": "failed", "reason": text(reason), "exception": exception(e)]
        }
    }

    public func update(_ r: UpdateResult) -> [String: Any] {
        switch r {
        case .updated(let v): return ["type": "updated", "newVersion": v]
        case .alreadyCurrent: return ["type": "alreadyCurrent"]
        case .failed(let reason, let e): return ["type": "failed", "reason": text(reason), "exception": exception(e)]
        }
    }

    public func enrollment(_ r: ClientCertEnrollmentResult) -> [String: Any] {
        switch r {
        case .enrolled(let already, let level):
            return ["type": "enrolled", "alreadyEnrolled": already, "keySecurityLevel": opt(level?.rawValue)]
        case .refused(let reason, let status, let serverError, let message):
            return [
                "type": "refused", "reason": reason.rawValue, "httpStatus": status,
                "serverError": text(serverError), "message": text(message),
            ]
        case .pending(let requestId, let clientId, let message, let retryAfter, let code):
            return [
                "type": "pending", "requestId": requestId, "clientId": opt(clientId), "message": text(message),
                "retryAfterSeconds": opt(retryAfter), "verificationCode": opt(code),
            ]
        case .failed(let message, let cause):
            return ["type": "failed", "message": text(message), "cause": exception(cause)]
        }
    }

    public func vaultFile(_ r: VaultFileResult) -> [String: Any] {
        switch r {
        // No bytes: the content is read with loadFile / unlockFile, on purpose.
        case .updated(let key, let version, _): return ["type": "updated", "key": key, "version": version]
        case .alreadyCurrent(let key, let version): return ["type": "alreadyCurrent", "key": key, "version": version]
        case .failed(let key, let reason, let e, let code):
            return ["type": "failed", "key": key, "reason": text(reason), "code": code, "exception": exception(e)]
        }
    }

    public func unlock(_ r: VaultFileUnlockResult, encoding: String) -> [String: Any] {
        switch r {
        case .unlocked(let key, let version, let bytes):
            return ["type": "unlocked", "key": key, "version": version, "content": Self.encode(bytes, encoding), "encoding": encoding]
        case .notFound(let key): return ["type": "notFound", "key": key]
        case .cancelled(let key): return ["type": "cancelled", "key": key]
        case .invalidated(let key): return ["type": "invalidated", "key": key]
        case .stale(let key): return ["type": "stale", "key": key]
        case .failed(let key, let reason, let e):
            return ["type": "failed", "key": key, "reason": text(reason), "exception": exception(e)]
        }
    }

    public func attestation(_ s: AttestationStatus) -> [String: Any] {
        [
            "configApiId": s.configApiId,
            "result": s.result.rawValue,
            "arc": opt(s.arc),
            "rejectionReasons": s.rejectionReasons,
            "warnings": s.warnings,
            "tokenExpiresAt": opt(s.tokenExpiresAt),
            "lastAttestedAt": opt(s.lastAttestedAt),
            "nextAttestAt": opt(s.nextAttestAt),
            "clockSkewMs": opt(s.clockSkewMs),
            "lastError": text(s.lastError),
            "policyVersion": opt(s.policyVersion),
        ]
    }

    public func attestationToken(_ r: AttestationTokenResult) -> [String: Any] {
        switch r {
        case .token(let value, let expiresAt): return ["type": "token", "value": value, "expiresAt": expiresAt]
        case .rejected(let status): return ["type": "rejected", "status": attestation(status)]
        case .failed(let message): return ["type": "failed", "message": text(message)]
        case .unsupported: return ["type": "unsupported"]
        }
    }

    public func signing(_ s: SigningStatus) -> [String: Any] {
        [
            "configApiId": s.configApiId,
            "trustedKeyIds": s.trustedKeyIds,
            "requiredSignatures": s.requiredSignatures,
            "keySetVersion": s.keySetVersion,
            "recoveryKeyIds": s.recoveryKeyIds,
            "lastConfigSignedBy": s.lastConfigSignedBy,
        ]
    }

    /// Connection telemetry. The library puts no token in events; free text is redacted anyway.
    public func event(_ e: PinVaultConnectionEvent) -> [String: Any] {
        switch e {
        case let .connection(hostname, success, pinVersion, manufacturer, model, actualPin, expectedPins):
            return [
                "type": "connection", "hostname": hostname, "success": success, "pinVersion": pinVersion,
                "deviceManufacturer": manufacturer, "deviceModel": model, "actualPin": actualPin, "expectedPins": expectedPins,
            ]
        case let .configUpdate(status, newVersion, manufacturer, model, failureReason):
            return [
                "type": "configUpdate", "status": status.rawValue, "newVersion": newVersion,
                "deviceManufacturer": manufacturer, "deviceModel": model, "failureReason": text(failureReason),
            ]
        case let .clientCertRenewal(status, notAfter, via, configApiId, manufacturer, model, failureReason):
            return [
                "type": "clientCertRenewal", "status": status.rawValue, "notAfterEpochMs": notAfter, "via": opt(via?.rawValue),
                "configApiId": configApiId, "deviceManufacturer": manufacturer, "deviceModel": model,
                "failureReason": text(failureReason),
            ]
        case let .attestation(configApiId, status, arc, reasons, warnings, tokenExpiresAt, manufacturer, model, failureReason):
            return [
                "type": "attestation", "configApiId": configApiId, "status": status.rawValue, "arc": opt(arc),
                "rejectionReasons": reasons, "warnings": warnings, "tokenExpiresAt": opt(tokenExpiresAt),
                "deviceManufacturer": manufacturer, "deviceModel": model, "failureReason": text(failureReason),
            ]
        }
    }
}
