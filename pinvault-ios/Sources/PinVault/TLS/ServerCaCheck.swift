import Foundation
import Security

/// The second check behind `requireCaTrust`: does a certificate authority the
/// platform trusts vouch for this chain, for `host`? Throws when it does not.
protocol ServerCaCheck: Sendable {
    func check(_ chain: [X509Certificate], host: String, at date: Date) throws
}

/// The platform's view of a chain, for managed trust roots: the certificates
/// the platform validated, **ending in the trust anchor it used**. Throws when
/// the platform does not trust the chain for `host`.
protocol TrustAnchorResolver: Sendable {
    func validatedChain(_ chain: [X509Certificate], host: String, at date: Date) throws -> [X509Certificate]
}

/// ``ServerCaCheck`` and ``TrustAnchorResolver`` over `SecTrust` with the SSL
/// server policy for the (logical) host name — which also checks the name
/// against the leaf — at the library clock. ``platform`` uses the system's
/// anchors (and, on a device, those the user or an MDM profile installed and
/// trusted); tests pass their own `anchors`, which then are the only ones.
struct SecTrustCaCheck: ServerCaCheck, TrustAnchorResolver {

    /// DER of the only anchors to trust; nil = the system's.
    let anchors: [Data]?

    static let platform = SecTrustCaCheck(anchors: nil)

    init(anchors: [Data]?) {
        self.anchors = anchors
    }

    func check(_ chain: [X509Certificate], host: String, at date: Date) throws {
        _ = try evaluate(chain, host: host, at: date)
    }

    func validatedChain(_ chain: [X509Certificate], host: String, at date: Date) throws -> [X509Certificate] {
        let built = try evaluate(chain, host: host, at: date)
        return try built.map { try X509Certificate(certificate: $0) }
    }

    /// The chain `SecTrust` validated (anchor last), or the reason it did not.
    private func evaluate(_ chain: [X509Certificate], host: String, at date: Date) throws -> [SecCertificate] {
        guard !chain.isEmpty else { throw PinVaultError.certificate(message: "No server certificate provided") }
        let certificates = chain.compactMap { $0.secCertificate() }
        guard certificates.count == chain.count else {
            throw PinVaultError.certificate(message: "A certificate of the chain cannot be read")
        }
        let policy = SecPolicyCreateSSL(true, host.isEmpty ? nil : host as CFString)
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            throw PinVaultError.certificate(message: "SecTrustCreateWithCertificates failed (\(status))")
        }
        if let anchors {
            let anchorCerts = anchors.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
            SecTrustSetAnchorCertificates(trust, anchorCerts as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            SecTrustSetNetworkFetchAllowed(trust, false)
        }
        SecTrustSetVerifyDate(trust, date as CFDate)
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            let reason = error.map { CFErrorCopyDescription($0) as String? ?? "\($0)" } ?? "not trusted"
            throw PinVaultError.certificate(message: reason)
        }
        return (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? certificates
    }
}

/// A ``ServerCaCheck`` from a closure (tests).
struct ClosureCaCheck: ServerCaCheck {
    let body: @Sendable ([X509Certificate], String) throws -> Void

    func check(_ chain: [X509Certificate], host: String, at date: Date) throws {
        try body(chain, host)
    }
}

/// A ``TrustAnchorResolver`` from a closure (tests).
struct ClosureAnchorResolver: TrustAnchorResolver {
    let body: @Sendable ([X509Certificate], String) throws -> [X509Certificate]

    func validatedChain(_ chain: [X509Certificate], host: String, at date: Date) throws -> [X509Certificate] {
        try body(chain, host)
    }
}
