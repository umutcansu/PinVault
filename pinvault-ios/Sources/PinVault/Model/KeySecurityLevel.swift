import Foundation

/// Where a key the library generated actually lives, as the platform reports
/// it after the fact — not what was asked for.
///
/// Reported on ``ClientCertEnrollmentResult/enrolled(alreadyEnrolled:keySecurityLevel:)``,
/// in the enrollment request (`keySecurityLevel`) and in the attestation
/// report, and enforced by ``PinVaultConfig/Builder/requireHardwareBackedKeys()``.
/// The raw value is the Kotlin constant name; ``wireName`` is what goes on the wire.
public enum KeySecurityLevel: String, Sendable, Equatable, Hashable, CaseIterable {
    /// A dedicated secure element (Android StrongBox).
    case strongbox = "STRONGBOX"
    /// The trusted execution environment of the main processor (Android TEE).
    case trustedEnvironment = "TRUSTED_ENVIRONMENT"
    /// The key is held by software only; a jailbroken / rooted device can copy it.
    case software = "SOFTWARE"
    /// The platform did not say. Treated like ``software`` where hardware is required.
    case unknown = "UNKNOWN"
    /// iOS: the Secure Enclave.
    case secureEnclave = "SECURE_ENCLAVE"

    /// The value on the wire and in logs.
    public var wireName: String {
        switch self {
        case .strongbox: return "strongbox"
        case .trustedEnvironment: return "tee"
        case .software: return "software"
        case .unknown: return "unknown"
        case .secureEnclave: return "secure_enclave"
        }
    }

    /// True for ``strongbox``, ``trustedEnvironment`` and ``secureEnclave``.
    public var hardwareBacked: Bool {
        self == .strongbox || self == .trustedEnvironment || self == .secureEnclave
    }

    /// The level named by `name` (case-insensitive, trimmed), or ``unknown``.
    public static func fromWireName(_ name: String?) -> KeySecurityLevel {
        guard let wanted = name?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() else { return .unknown }
        return allCases.first { $0.wireName == wanted } ?? .unknown
    }
}
