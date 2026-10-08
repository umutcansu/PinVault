import Foundation

// What the vault layer needs to know about the errors of the API client
// (L2's `DefaultCertificateConfigApi` port). The router recognises them by
// these protocols, so the client's own error types only have to adopt them
// (or throw the concrete types below).

/// A vault download the server refused (Kotlin `VaultFetchHttpException`): the
/// router reacts to `412 {"error":"user_auth_key_required"}` and reports
/// `http_<status>`.
protocol VaultFetchHTTPFailure: Error {
    var httpStatus: Int { get }
    /// The start of the response body (the Kotlin client keeps 200 bytes), if any.
    var responseBody: String? { get }
}

/// The server refused the device's user-auth key (Kotlin
/// `UserAuthKeyRefusedException`): reported as `user_auth_key_rejected`.
protocol VaultKeyRefusalFailure: Error {}

/// The response body was longer than the library reads (Kotlin
/// `ResponseTooLargeException`): reported as `response_too_large`.
protocol VaultResponseTooLargeFailure: Error {}

/// The concrete refused download: message `Vault fetch failed: HTTP <code> — <body>`.
struct VaultFetchHTTPError: VaultFetchHTTPFailure, LocalizedError, CustomStringConvertible {
    let httpStatus: Int
    let responseBody: String?

    init(httpStatus: Int, responseBody: String?) {
        self.httpStatus = httpStatus
        self.responseBody = responseBody
    }

    var errorDescription: String? { "Vault fetch failed: HTTP \(httpStatus) — \(responseBody ?? "null")" }
    var description: String { errorDescription ?? "" }
}

/// The Kotlin `e.message` / exception class of an error, for results and logs.
enum VaultErrorText {

    static func message(_ error: any Error) -> String {
        if let error = error as? PinVaultError { return error.message }
        if let error = error as? UserAuthKeyError { return error.message }
        if let error = error as? LocalizedError, let text = error.errorDescription { return text }
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain || nsError.domain == NSOSStatusErrorDomain || nsError.domain == NSCocoaErrorDomain {
            return nsError.localizedDescription
        }
        return String(describing: error)
    }

    /// A request that did not complete (Kotlin `IOException`).
    static func isNetwork(_ error: any Error) -> Bool {
        if error is URLError { return true }
        if let error = error as? PinVaultError {
            switch error {
            case .io, .sslHandshake, .sslPeerUnverified: return true
            default: return false
            }
        }
        return (error as NSError).domain == NSURLErrorDomain
    }
}
