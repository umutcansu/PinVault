import Foundation

/// Result of a client certificate enrollment request
/// (``CertificateConfigApi/enroll(token:deviceId:deviceAlias:deviceUid:)`` and the `enrollWithCsr` family).
///
/// Either a PKCS12 bundle the server generated (``p12Bytes``), or — for a CSR
/// enrollment over the device's own key — the issued PEM chain
/// (``certificateChainPem``), in which case ``p12Bytes`` is empty.
public struct EnrollmentResult: Sendable, Equatable, Hashable {
    /// PKCS12 bytes. Empty for a CSR enrollment.
    public var p12Bytes: Data
    /// SHA-256 of the P12 (Base64), for integrity verification (`X-P12-SHA256`).
    public var p12Hash: String?
    /// The password the P12 is wrapped with when the server sent one (`X-P12-Password`);
    /// nil = the block's `clientKeyPassword`.
    public var p12Password: String?
    /// CSR enrollment: the issued chain as PEM, leaf first. Nil for a P12 response.
    public var certificateChainPem: [String]?

    public init(p12Bytes: Data, p12Hash: String? = nil, p12Password: String? = nil, certificateChainPem: [String]? = nil) {
        self.p12Bytes = p12Bytes
        self.p12Hash = p12Hash
        self.p12Password = p12Password
        self.certificateChainPem = certificateChainPem
    }

    /// True when the server answered a CSR enrollment with a certificate chain.
    public var isCertificateChain: Bool { certificateChainPem != nil }
}

extension EnrollmentResult: CustomStringConvertible, CustomDebugStringConvertible {
    /// The password is a secret: never in logs.
    public var description: String {
        "EnrollmentResult(p12Bytes=\(p12Bytes.count) bytes, p12Hash=\(p12Hash ?? "null"), " +
            "p12Password=\(p12Password == nil ? "null" : "***"), chain=\(certificateChainPem.map { String($0.count) } ?? "null"))"
    }

    public var debugDescription: String { description }
}
