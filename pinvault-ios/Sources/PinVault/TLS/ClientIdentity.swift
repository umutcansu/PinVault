import Foundation
import Security

/// One fixed client identity for mTLS: a `SecIdentity` (whose private key may
/// stay in the Secure Enclave or the Keychain) plus the certificate chain the
/// server issued over its key — the counterpart of Kotlin's
/// `FixedClientKeyManager` (and of a KeyManager over a PKCS12).
///
/// It is offered whatever the server's CertificateRequest lists: there is only
/// ever one identity here, and letting the server reject it beats
/// second-guessing. WHICH hosts get to see the identity at all is not decided
/// here: ``DynamicSSLManager`` hands it out only to the block's own listeners
/// and to hosts the config marks as mTLS.
///
/// L3 builds these for CSR-enrolled keys (`init(identity:chain:)`); P12
/// credentials go through ``fromPKCS12(_:password:)``.
final class ClientIdentity: @unchecked Sendable {

    let identity: SecIdentity
    /// Leaf first, then the issuing CAs (what the handshake sends).
    let chain: [SecCertificate]
    /// The leaf, parsed; nil when Security hands back bytes the parser refuses.
    let leaf: X509Certificate?

    /// - Throws: ``PinVaultError/illegalArgument(_:)`` for an empty chain
    ///   (`require(chain.isNotEmpty())`).
    init(identity: SecIdentity, chain: [SecCertificate]) throws {
        guard let first = chain.first else { throw PinVaultError.illegalArgument("Certificate chain must not be empty") }
        self.identity = identity
        self.chain = chain
        self.leaf = try? X509Certificate(certificate: first)
    }

    /// The credential answering a client-certificate challenge: the identity
    /// and the intermediates (the leaf is the identity's own certificate).
    func credential() -> URLCredential {
        // nil, not [], without intermediates: CFNetwork reads element 0 of a
        // non-nil array and an empty one crashes the process (a self-signed identity).
        let intermediates = Array(chain.dropFirst())
        return URLCredential(identity: identity, certificates: intermediates.isEmpty ? nil : intermediates, persistence: .forSession)
    }

    /// The identity inside a PKCS12, held in process memory only (never in
    /// the Keychain; `kSecImportToMemoryOnly` on macOS 15+ / iOS 18+, the iOS default before).
    /// - Throws: ``PinVaultError/crypto(message:cause:)`` when the bytes or the password are wrong.
    static func fromPKCS12(_ p12: Data, password: String) throws -> ClientIdentity {
        var options: [String: Any] = [kSecImportExportPassphrase as String: password]
        if #available(macOS 15.0, iOS 18.0, *) {
            options[kSecImportToMemoryOnly as String] = true
        }
        var items: CFArray?
        let status = SecPKCS12Import(p12 as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess else {
            let reason = status == errSecAuthFailed ? "wrong password or damaged data" : "status \(status)"
            throw PinVaultError.crypto(message: "PKCS12 cannot be read: \(reason)")
        }
        guard let entry = (items as? [[String: Any]])?.first(where: { $0[kSecImportItemIdentity as String] != nil }),
              let identityValue = entry[kSecImportItemIdentity as String] else {
            throw PinVaultError.crypto(message: "PKCS12 holds no private key entry")
        }
        // A CF type: the cast always succeeds once the value is there.
        let identity = identityValue as! SecIdentity
        var leaf: SecCertificate?
        SecIdentityCopyCertificate(identity, &leaf)
        let bundled = (entry[kSecImportItemCertChain as String] as? [SecCertificate]) ?? []
        var chain: [SecCertificate] = []
        if let leaf { chain.append(leaf) }
        for certificate in bundled where !chain.contains(where: { CFEqual($0, certificate) }) {
            chain.append(certificate)
        }
        return try ClientIdentity(identity: identity, chain: chain)
    }
}
