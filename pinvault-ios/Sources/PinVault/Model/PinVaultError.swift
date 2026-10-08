import Foundation

/// Every failure the library reports: one case per Kotlin exception class of
/// `model/SSLPinningException.kt` (and the other public exception classes),
/// with the same message texts, plus the JVM families the Kotlin code throws
/// (`IllegalArgumentException`, `IllegalStateException`, `SecurityException`,
/// `IOException`, `SSLHandshakeException`, …).
///
/// ``exceptionName`` gives the Kotlin/Java simple class name and ``message``
/// the message, so an app can show the same text as on Android
/// (`e.getClass().getSimpleName() + "\n" + e.getMessage()`).
public enum PinVaultError: Error, Sendable {

    // MARK: SSLPinningException and its subclasses

    /// `SSLPinningException`: base pinning failure.
    case sslPinning(message: String, cause: (any Error)? = nil)
    /// `BackendUnreachableException`: the Config API's health endpoint is unreachable or unhealthy.
    case backendUnreachable(message: String = "Backend is unreachable or unhealthy", cause: (any Error)? = nil)
    /// `InvalidPinFormatException`: a pin config that is not well-formed.
    case invalidPinFormat(message: String = "Pin hash format is invalid", cause: (any Error)? = nil)
    /// `PinMismatchException`: the pins were applied but do not match the server certificate.
    case pinMismatch(message: String = "Pin hashes do not match server certificate", cause: (any Error)? = nil)
    /// `ForceUpdateFailedException`: `forceUpdate` is set and the backend is unreachable.
    case forceUpdateFailed(message: String = "Force update required but backend is unreachable", cause: (any Error)? = nil)
    /// `NoConfigAvailableException`: nothing stored and the backend is unreachable.
    case noConfigAvailable(message: String = "No stored config and backend is unreachable", cause: (any Error)? = nil)
    /// `ConfigExpiredException`: the stored config is past `expiresAt` (Unix ms) plus the grace.
    /// `message` nil = the Kotlin default text.
    case configExpired(expiresAt: Int64, message: String? = nil, cause: (any Error)? = nil)
    /// `ClientCertificateRequiredException`: the Config API needs a client certificate; enroll before start.
    case clientCertificateRequired(
        message: String = "Client certificate required — enroll before init (PinVault.enroll(context, config, token))",
        cause: (any Error)? = nil
    )
    /// `HardwareBackedKeyRequiredException`: `requireHardwareBackedKeys()` and the key was made in software.
    case hardwareBackedKeyRequired(keyKind: String, level: KeySecurityLevel, cause: (any Error)? = nil)
    /// `StoreUnreadableException`: the encrypted storage cannot be read right now (not "nothing stored").
    case storeUnreadable(message: String, cause: (any Error)? = nil)

    // MARK: CertificateException subclasses (thrown by the pinning trust check)

    /// `CaTrustException`: pins matched, the platform CAs do not trust the chain (`requireCaTrust`).
    case caTrust(message: String, cause: (any Error)? = nil)
    /// `CertificateValidityException`: the leaf is expired or not yet valid.
    case certificateValidity(message: String, cause: (any Error)? = nil)
    /// `HostnameMismatchException`: an issuer pin matched but the leaf does not name the host.
    case hostnameMismatch(message: String, cause: (any Error)? = nil)
    /// `ManagedTrustRootException`: managed trust roots refused a host without a pin entry.
    case managedTrustRoot(message: String, cause: (any Error)? = nil)
    /// `UnpinnedHostException`: the config has no entry for the host.
    case unpinnedHost(message: String, cause: (any Error)? = nil)
    /// `java.security.cert.CertificateException`: any other certificate failure.
    case certificate(message: String, cause: (any Error)? = nil)

    // MARK: Enrollment

    /// `EnrollmentRefusedException`: the server refused an enrollment (HTTP 4xx).
    case enrollmentRefused(httpStatus: Int, serverError: String? = nil, serverMessage: String? = nil)
    /// `EnrollmentPendingException`: the server took the request; an administrator approves first.
    case enrollmentPending(
        requestId: String,
        clientId: String? = nil,
        serverMessage: String? = nil,
        retryAfterSeconds: Int? = nil,
        verificationCode: String? = nil
    )

    // MARK: Guard and vault files

    /// `UntrustedEnvironmentException`: the app's ``EnvironmentGuard`` said no (or threw: `cause`).
    /// `message` nil = the Kotlin default text.
    case untrustedEnvironment(operation: GuardedOperation, message: String? = nil, cause: (any Error)? = nil)
    /// `ScreenLockRequiredException`: a `userAuth` file needs a screen lock (device passcode) the device has not got.
    case screenLockRequired(key: String, message: String? = nil)

    // MARK: Platform families

    /// `IllegalArgumentException` from a builder's `require(...)`: the configuration is invalid.
    case invalidConfiguration(String)
    /// `IllegalArgumentException` outside the builders (malformed input).
    case illegalArgument(String)
    /// `IllegalStateException` (`check(...)`, "not initialized", …).
    case illegalState(String)
    /// `SecurityException`: a security check refused something.
    case security(message: String, cause: (any Error)? = nil)
    /// `GeneralSecurityException` (`AEADBadTagException`, key failures): a cryptographic operation failed.
    case crypto(message: String, cause: (any Error)? = nil)
    /// `IOException`: network or file I/O failed.
    case io(message: String, cause: (any Error)? = nil)
    /// `SSLHandshakeException`: the TLS handshake failed; `cause` is the trust check's error.
    case sslHandshake(message: String, cause: (any Error)? = nil)
    /// `SSLPeerUnverifiedException`: the connection's certificate failed the per-request check.
    case sslPeerUnverified(message: String)

    // MARK: Accessors

    /// The message, exactly as the Kotlin exception's.
    public var message: String {
        switch self {
        case .sslPinning(let message, _), .backendUnreachable(let message, _), .invalidPinFormat(let message, _),
             .pinMismatch(let message, _), .forceUpdateFailed(let message, _), .noConfigAvailable(let message, _),
             .clientCertificateRequired(let message, _), .storeUnreadable(let message, _),
             .caTrust(let message, _), .certificateValidity(let message, _), .hostnameMismatch(let message, _),
             .managedTrustRoot(let message, _), .unpinnedHost(let message, _), .certificate(let message, _),
             .security(let message, _), .crypto(let message, _), .io(let message, _), .sslHandshake(let message, _):
            return message
        case .configExpired(let expiresAt, let message, _):
            return message ?? "Stored pin config expired at \(expiresAt) (Unix ms) and no fresh config could be fetched"
        case .hardwareBackedKeyRequired(let keyKind, let level, _):
            // The Kotlin text names the Android Keystore, StrongBox and the TEE.
            return "\(keyKind): the Keychain made the key at security level '\(level.wireName)', " +
                "and requireHardwareBackedKeys() accepts the Secure Enclave only"
        case .enrollmentRefused(let httpStatus, let serverError, _):
            return "Enrollment refused — HTTP \(httpStatus)" + (serverError.map { " \($0)" } ?? "")
        case .enrollmentPending(let requestId, _, _, _, _):
            return "Enrollment waits for approval — request \(requestId)"
        case .untrustedEnvironment(let operation, let message, _):
            return message ?? "The app's environment guard refused \(operation.rawValue) on this device"
        case .screenLockRequired(let key, let message):
            return message
                ?? "Vault file '\(key)' needs a screen lock (userAuth = REQUIRED); the device has none, so it was not stored"
        case .invalidConfiguration(let message), .illegalArgument(let message), .illegalState(let message),
             .sslPeerUnverified(let message):
            return message
        }
    }

    /// The underlying error, if any.
    public var cause: (any Error)? {
        switch self {
        case .sslPinning(_, let cause), .backendUnreachable(_, let cause), .invalidPinFormat(_, let cause),
             .pinMismatch(_, let cause), .forceUpdateFailed(_, let cause), .noConfigAvailable(_, let cause),
             .clientCertificateRequired(_, let cause), .storeUnreadable(_, let cause),
             .caTrust(_, let cause), .certificateValidity(_, let cause), .hostnameMismatch(_, let cause),
             .managedTrustRoot(_, let cause), .unpinnedHost(_, let cause), .certificate(_, let cause),
             .security(_, let cause), .crypto(_, let cause), .io(_, let cause), .sslHandshake(_, let cause),
             .configExpired(_, _, let cause), .hardwareBackedKeyRequired(_, _, let cause),
             .untrustedEnvironment(_, _, let cause):
            return cause
        case .enrollmentRefused, .enrollmentPending, .screenLockRequired, .invalidConfiguration,
             .illegalArgument, .illegalState, .sslPeerUnverified:
            return nil
        }
    }

    /// The Kotlin/Java simple class name of the exception this case stands for.
    public var exceptionName: String {
        switch self {
        case .sslPinning: return "SSLPinningException"
        case .backendUnreachable: return "BackendUnreachableException"
        case .invalidPinFormat: return "InvalidPinFormatException"
        case .pinMismatch: return "PinMismatchException"
        case .forceUpdateFailed: return "ForceUpdateFailedException"
        case .noConfigAvailable: return "NoConfigAvailableException"
        case .configExpired: return "ConfigExpiredException"
        case .clientCertificateRequired: return "ClientCertificateRequiredException"
        case .hardwareBackedKeyRequired: return "HardwareBackedKeyRequiredException"
        case .storeUnreadable: return "StoreUnreadableException"
        case .caTrust: return "CaTrustException"
        case .certificateValidity: return "CertificateValidityException"
        case .hostnameMismatch: return "HostnameMismatchException"
        case .managedTrustRoot: return "ManagedTrustRootException"
        case .unpinnedHost: return "UnpinnedHostException"
        case .certificate: return "CertificateException"
        case .enrollmentRefused: return "EnrollmentRefusedException"
        case .enrollmentPending: return "EnrollmentPendingException"
        case .untrustedEnvironment: return "UntrustedEnvironmentException"
        case .screenLockRequired: return "ScreenLockRequiredException"
        case .invalidConfiguration, .illegalArgument: return "IllegalArgumentException"
        case .illegalState: return "IllegalStateException"
        case .security: return "SecurityException"
        case .crypto: return "GeneralSecurityException"
        case .io: return "IOException"
        case .sslHandshake: return "SSLHandshakeException"
        case .sslPeerUnverified: return "SSLPeerUnverifiedException"
        }
    }

    /// True for the `SSLPinningException` subclasses (`catch (e: SSLPinningException)`).
    public var isSSLPinningException: Bool {
        switch self {
        case .sslPinning, .backendUnreachable, .invalidPinFormat, .pinMismatch, .forceUpdateFailed,
             .noConfigAvailable, .configExpired, .clientCertificateRequired, .hardwareBackedKeyRequired,
             .storeUnreadable:
            return true
        default:
            return false
        }
    }

    /// True for the `CertificateException` subclasses, which the pin-recovery
    /// logic tells apart from a pin mismatch.
    public var isCertificateException: Bool {
        switch self {
        case .caTrust, .certificateValidity, .hostnameMismatch, .managedTrustRoot, .unpinnedHost, .certificate:
            return true
        default:
            return false
        }
    }

    /// For ``enrollmentRefused(httpStatus:serverError:serverMessage:)``: what the
    /// refusal means for the app (`EnrollmentRefusedException.refusal`); nil for other cases.
    public var refusal: EnrollmentRefusal? {
        guard case .enrollmentRefused(let httpStatus, let serverError, _) = self else { return nil }
        return EnrollmentRefusal.from(httpStatus: httpStatus, serverError: serverError)
    }
}

extension PinVaultError: LocalizedError {
    public var errorDescription: String? { message }
}

extension PinVaultError: CustomStringConvertible {
    /// `ExceptionName: message`, like a JVM exception's `toString()`.
    public var description: String { "\(exceptionName): \(message)" }
}
