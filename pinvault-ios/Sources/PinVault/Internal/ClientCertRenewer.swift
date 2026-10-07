import Foundation

/// Keeps a CSR-enrolled client certificate alive (Kotlin `ClientCertRenewer`).
///
/// The decision is taken from the stored leaf's own dates, without touching
/// the network. While the certificate is valid and past the renewal
/// threshold, the CSR goes over the block's own connection (mTLS: the current
/// certificate authenticates it). Once it has expired — or the server refuses
/// the handshake — the same CSR goes to the block's recovery URL, which asks
/// for no client certificate; there the server authenticates the CSR
/// signature against the device key it registered at enrollment.
///
/// An expired certificate is never presented to anything and never accepted
/// from anything. An issued chain is stored only when it is the leaf plus the
/// CA certificate that signed it, the leaf is valid now, over this device's
/// key, not longer-lived than the block allows, and from the right CA: one
/// the block pins (`clientCaPins`), or — without pins — the CA of the
/// certificate being replaced. Whoever answers on the renewal door cannot
/// hand the device a certificate of their own making.
final class ClientCertRenewer: Sendable {

    enum Decision: Sendable, Equatable { case none, renew, recover }

    static let clientCnPrefix = "PinVault Client: "
    /// Issuers backdate `notBefore` a little against clock skew; that is not "longer than allowed".
    static let lifetimeSlackMs: Int64 = 24 * 60 * 60 * 1000

    private let block: ConfigApiBlock
    private let certStore: ClientCertSecureStore
    private let identityKeys: @Sendable (String) -> any ClientIdentityKeyProvider
    private let api: @Sendable () -> any CertificateConfigApi
    private let reload: @Sendable () -> Void
    private let clock: @Sendable () -> Int64
    private let onRefusedOverMtls: @Sendable (X509Certificate) -> Void
    private static let log = PinVaultLog.tag("ClientCertRenewer")

    /// - Parameters:
    ///   - identityKeys: the identity key behind the certificate stored under a label.
    ///   - api: the block's Config API.
    ///   - reload: installs the stored credentials into the SSL manager and rebuilds the sessions.
    ///   - clock: epoch ms (the library's wall clock: E2E builds shift it).
    ///   - onRefusedOverMtls: told when the server refused the renewal as
    ///     `reenroll_required` on the block's own (mTLS) connection, with the
    ///     leaf that connection was to present. Only that answer is about the
    ///     device's identity; the same answer on the recovery door (TLS, no
    ///     client certificate) is reported and nothing more.
    init(
        block: ConfigApiBlock,
        certStore: ClientCertSecureStore,
        identityKeys: @escaping @Sendable (String) -> any ClientIdentityKeyProvider,
        api: @escaping @Sendable () -> any CertificateConfigApi,
        reload: @escaping @Sendable () -> Void,
        clock: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis,
        onRefusedOverMtls: @escaping @Sendable (X509Certificate) -> Void = { _ in }
    ) {
        self.block = block
        self.certStore = certStore
        self.identityKeys = identityKeys
        self.api = api
        self.reload = reload
        self.clock = clock
        self.onRefusedOverMtls = onRefusedOverMtls
    }

    /// ``Decision/recover`` once `nowMs` is past `notAfter`; ``Decision/renew``
    /// when the remaining lifetime is below `threshold` of the whole lifetime,
    /// or when the certificate lives longer than the block accepts (one stored
    /// before the cap existed: without this its renewal would never come due);
    /// else ``Decision/none``.
    func decide(_ leaf: X509Certificate, nowMs: Int64, threshold: Double) -> Decision {
        let notAfter = Self.millis(leaf.notAfter)
        let notBefore = Self.millis(leaf.notBefore)
        if nowMs > notAfter { return .recover }
        let lifetime = max(notAfter - notBefore, 1)
        if lifetime > Self.maxLifetimeMs(block.maxClientCertLifetimeDays) + Self.lifetimeSlackMs { return .renew }
        let remaining = notAfter - nowMs
        return Double(remaining) / Double(lifetime) < threshold ? .renew : .none
    }

    /// - Parameter force: renew even when the threshold has not been reached.
    func renewIfNeeded(force: Bool = false) async -> ClientCertRenewalResult {
        if !block.clientCertRenewalEnabled && !force { return .notApplicable }
        let label = block.clientCertLabel
        guard let pemChain = (try? certStore.loadChain(label)) ?? nil else { return .notApplicable }
        let key = identityKeys(label)
        if !key.exists() {
            Self.log.w("Client cert renewal [\(block.id)]: certificate stored but its Keychain key is gone")
            return .notApplicable
        }

        let stored: [X509Certificate]
        do {
            stored = try Pkcs10Csr.parsePemChain(pemChain)
            guard !stored.isEmpty else { throw PinVaultError.illegalArgument("Empty certificate chain") }
        } catch {
            return .failed(reason: "Stored certificate chain is unreadable: \(Self.message(error))", exception: error)
        }
        let leaf = stored[0]
        // The CA that issued the current certificate. Without pinned client
        // CAs a renewal must come from the same CA: whoever answers on the
        // renewal door cannot swap in a chain of its own.
        let currentIssuer = stored.count > 1 ? stored[1] : nil

        let decision = decide(leaf, nowMs: clock(), threshold: block.clientCertRenewalThreshold)
        if decision == .none && !force {
            return .notNeeded(notAfterEpochMs: Self.millis(leaf.notAfter))
        }

        if currentIssuer == nil && block.clientCaPins.isEmpty {
            // A chain of one, stored by an earlier version: there is no CA to
            // hold the answer to, and an answer nobody can check is not stored.
            Self.log.e("Client cert renewal [\(block.id)]: the stored chain has no CA certificate and the block pins none")
            return .failed(
                reason: "The stored client certificate has no CA certificate with it, so a renewed one cannot be checked. " +
                    "Pin the client CA with clientCaPins(...) or enroll again."
            )
        }

        let clientId = Self.clientIdOf(leaf)
        let via: ClientCertRenewalVia = decision == .recover ? .recovery : .mtls
        // The client id is the certificate's CN and names the device: not logged.
        Self.log.i("Client cert renewal [\(block.id)] via \(via.rawValue) (notAfter=\(leaf.notAfter))")

        do {
            let csr = try Pkcs10Csr.encode(commonName: clientId, key: key)
            let (response, usedVia) = try await request(clientId: clientId, csr: csr, via: via)
            switch response {
            case .issued(let chain):
                let certs = try Self.acceptIssuedChain(
                    chain, key: key, expectedIssuer: currentIssuer, caPins: block.clientCaPins,
                    maxLifetimeDays: block.maxClientCertLifetimeDays, nowMs: clock()
                )
                try certStore.saveChain(label, pemChain: chain)
                reload()
                Self.log.i("Client cert renewed [\(block.id)] via \(usedVia.rawValue) — valid until \(certs[0].notAfter)")
                return .renewed(notAfterEpochMs: Self.millis(certs[0].notAfter), via: usedVia)
            case .reenrollRequired(let reason):
                Self.log.w("Client cert renewal [\(block.id)] refused via \(usedVia.rawValue): \(reason) — re-enrollment required")
                if usedVia == .mtls { onRefusedOverMtls(leaf) }
                return .reenrollRequired(reason: reason)
            case .unsupported:
                Self.log.w("Client cert renewal [\(block.id)]: backend has no renewal endpoint")
                return .notApplicable
            }
        } catch is CancellationError {
            return .failed(reason: "CancellationError", exception: CancellationError())
        } catch {
            Self.log.e("Client cert renewal [\(block.id)] failed", error)
            return .failed(reason: Self.message(error), exception: error)
        }
    }

    /// Sends the CSR through `via`. A handshake the server refuses on the mTLS
    /// path (its client-certificate check, not our pin check) falls through to
    /// the recovery path once — that is what the recovery door is for.
    private func request(clientId: String, csr: Data, via: ClientCertRenewalVia) async throws -> (ClientCertRenewalResponse, ClientCertRenewalVia) {
        if via == .mtls {
            do {
                return (try await api().renewClientCert(clientId: clientId, csrDer: csr, recoveryUrl: nil), via)
            } catch {
                if !Self.isClientCertRefusal(error) { throw error }
                Self.log.w("Client cert renewal [\(block.id)]: handshake refused, trying the recovery URL", error)
            }
        }
        let response = try await api().renewClientCert(clientId: clientId, csrDer: csr, recoveryUrl: block.renewalUrl ?? block.configUrl)
        return (response, .recovery)
    }

    // MARK: Helpers

    /// The enrolled client id: the leaf's CN without the server's prefix.
    static func clientIdOf(_ leaf: X509Certificate) -> String {
        let cn = leaf.subject.commonName ?? ""
        let trimmed = (cn.hasPrefix(clientCnPrefix) ? String(cn.dropFirst(clientCnPrefix.count)) : cn)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? cn : trimmed
    }

    /// A TLS failure the server caused by rejecting our client certificate,
    /// as opposed to one our own trust check caused (a certificate error
    /// somewhere in the cause chain — the pinning check throws those, and
    /// refetching a client certificate cannot fix it).
    ///
    /// With TLS 1.3 the server's verdict on the client certificate arrives
    /// after the client's side of the handshake is done; URLSession reports
    /// it as a failed secure connection. That counts as well. Counting another
    /// TLS fault here is safe: all that follows is one more attempt, at the
    /// recovery URL — pinned like every other connection of the block,
    /// presenting no certificate — and the chain that comes back is held to
    /// the same rules (``acceptIssuedChain(_:key:expectedIssuer:caPins:maxLifetimeDays:nowMs:)``).
    static func isClientCertRefusal(_ error: any Error) -> Bool {
        if let urlError = error as? URLError { return isTLSRefusal(urlError) }
        guard let error = error as? PinVaultError else { return false }
        switch error {
        case .sslHandshake, .sslPeerUnverified:
            break
        default:
            return false
        }
        var cause = error.cause
        var depth = 0
        while let current = cause, depth < 16 {
            if let pinVault = current as? PinVaultError {
                if pinVault.isCertificateException || pinVault.isSSLPinningException { return false }
                cause = pinVault.cause
            } else {
                cause = (current as NSError).userInfo[NSUnderlyingErrorKey] as? any Error
            }
            depth += 1
        }
        return true
    }

    private static func isTLSRefusal(_ error: URLError) -> Bool {
        switch error.code {
        case .secureConnectionFailed, .clientCertificateRejected, .clientCertificateRequired: return true
        default: return false
        }
    }

    /// Checks a chain the server issued before it is stored. Always:
    ///  - at least two certificates — the leaf and the CA certificate that
    ///    signed it. A leaf on its own leaves a later renewal nothing to be held to;
    ///  - the leaf is valid now, over `key`'s public key, has a subject, and
    ///    names and verifies against the next certificate;
    ///  - the leaf's lifetime, and what is left of it from now, is at most
    ///    `maxLifetimeDays`: a certificate valid for decades never comes up for
    ///    renewal, so the server never gets to refuse it.
    ///
    /// Then who signed it:
    ///  - with `caPins` (the block's `clientCaPins`): a certificate of the
    ///    chain whose SubjectPublicKeyInfo matches a pin must verify the leaf's
    ///    signature (enrollment and renewal);
    ///  - without pins, with `expectedIssuer` (a renewal: the CA of the
    ///    certificate being replaced): the leaf must verify against that CA's
    ///    key — the CA certificate sent along is not trusted on its own word;
    ///  - without either (a first enrollment, no pins): the chain is taken as
    ///    the pinned enrollment listener sent it.
    static func acceptIssuedChain(
        _ pemChain: [String],
        key: any ClientIdentityKeyProvider,
        expectedIssuer: X509Certificate? = nil,
        caPins: [String] = [],
        maxLifetimeDays: Int = ConfigApiBlock.defaultMaxClientCertLifetimeDays,
        nowMs: Int64 = LibraryClock.wallMillis()
    ) throws -> [X509Certificate] {
        let certs = try Pkcs10Csr.parsePemChain(pemChain)
        if certs.count < 2 {
            throw PinVaultError.security(
                message: "Issued chain has \(certs.count) certificate(s): the leaf must come with the CA certificate that signed it"
            )
        }
        let leaf = certs[0]
        try checkValidity(leaf, nowMs: nowMs)
        if leaf.subjectPublicKeyInfo != (try SPKI.der(for: key.publicKey())) {
            throw PinVaultError.security(message: "Issued certificate is not over this device's key")
        }
        if leaf.subject.rfc2253.trimmingCharacters(in: .whitespaces).isEmpty {
            throw PinVaultError.security(message: "Issued certificate has no subject")
        }

        let maxMs = maxLifetimeMs(maxLifetimeDays) + lifetimeSlackMs
        if millis(leaf.notAfter) - millis(leaf.notBefore) > maxMs || millis(leaf.notAfter) - nowMs > maxMs {
            throw PinVaultError.security(
                message: "Issued certificate is valid for longer than \(maxLifetimeDays) days (maxClientCertLifetimeDays); refused"
            )
        }

        let issuer = certs[1]
        if leaf.issuer.der != issuer.subject.der {
            throw PinVaultError.security(message: "Issued certificate does not chain to the issuer sent with it")
        }
        try CertificateSignature.verify(leaf, issuerSPKI: issuer.subjectPublicKeyInfo)

        if !caPins.isEmpty {
            let signedByPinned = certs.dropFirst().contains { ca in
                caPins.contains(ca.spkiPin) && CertificateSignature.isSigned(leaf, by: ca.subjectPublicKeyInfo)
            }
            if !signedByPinned {
                throw PinVaultError.security(message: "Issued certificate is not signed by a pinned client CA (clientCaPins)")
            }
        } else if let expectedIssuer {
            do {
                try CertificateSignature.verify(leaf, issuerSPKI: expectedIssuer.subjectPublicKeyInfo)
            } catch {
                throw PinVaultError.security(message: "Renewed certificate is not from the CA that issued the current one", cause: error)
            }
        }
        return certs
    }

    static func maxLifetimeMs(_ days: Int) -> Int64 { Int64(days) * 24 * 60 * 60 * 1000 }

    static func millis(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded()) }

    /// `X509Certificate.checkValidity()`, at `nowMs`.
    private static func checkValidity(_ certificate: X509Certificate, nowMs: Int64) throws {
        if nowMs > millis(certificate.notAfter) {
            throw PinVaultError.certificate(message: "certificate expired on \(certificate.notAfter)")
        }
        if nowMs < millis(certificate.notBefore) {
            throw PinVaultError.certificate(message: "certificate not valid till \(certificate.notBefore)")
        }
    }

    /// The text a failure reports: a ``PinVaultError``'s message, any other error's description.
    static func message(_ error: any Error) -> String {
        if let error = error as? PinVaultError { return error.message }
        if let error = error as? ServerGeneratedKeyRefusedError { return error.message }
        if let error = error as? LocalizedError, let description = error.errorDescription { return description }
        return String(describing: error)
    }
}
