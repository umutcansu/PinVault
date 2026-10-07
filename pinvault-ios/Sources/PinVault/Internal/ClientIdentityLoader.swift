import Foundation
import Security

/// Installs a Config API block's stored client credentials into its SSL
/// manager (Kotlin `ConfigApiClient.loadClientIdentity` and its helpers): the
/// enrolled credential under the block's `clientCertLabel` — a certificate
/// chain over the device's Secure Enclave / Keychain key, or a server-made key
/// (`allowServerGeneratedKey()`) — and, only when nothing is enrolled, the P12
/// bundled with the app (`clientKeystore(...)`, the bootstrap identity for an
/// mTLS Config API).
///
/// A key that came in a P12 is presented from the Keychain, where it was
/// imported; only where the platform refuses the import is the P12 itself loaded.
///
/// `ConfigApiClient` (L2) makes one per block and calls ``load()`` when it is
/// built and again after enroll, renew and unenroll.
final class ClientIdentityLoader: Sendable {

    /// What ``loadEnrolledChain(certStore:label:key:present:)`` came to.
    enum EnrolledChain: Sendable, Equatable {
        /// Presented now.
        case loaded
        /// Kept, but cannot be read right now: present no identity until the next load.
        case unavailable
        /// Can never be presented again (does not parse, key gone, certificate
        /// not over the key): cleared, re-enrollment needed.
        case dropped
    }

    private let block: ConfigApiBlock
    private let certStore: ClientCertSecureStore
    private let sslManager: DynamicSSLManager
    private let identityKeys: @Sendable (String) -> any ClientIdentityKeyProvider
    private let importedKeys: any ImportedClientKeys
    private let importedIdentities: ImportedIdentities
    private static let log = PinVaultLog.tag("ConfigApiClient")
    private static let bundledLabelPrefix = "bundled_"
    /// Keychain alias → key fingerprint of the bundled keystore imported under it in this process.
    private static let bundledImports = Locked<[String: String]>([:])

    init(
        block: ConfigApiBlock,
        certStore: ClientCertSecureStore,
        sslManager: DynamicSSLManager,
        identityKeys: @escaping @Sendable (String) -> any ClientIdentityKeyProvider = ClientIdentityKeys.secureEnclave,
        importedKeys: any ImportedClientKeys = ImportedKeys.keychain()
    ) {
        self.block = block
        self.certStore = certStore
        self.sslManager = sslManager
        self.identityKeys = identityKeys
        self.importedKeys = importedKeys
        self.importedIdentities = ImportedIdentities(certStore: certStore, keys: importedKeys)
    }

    /// Re-reads the stored credentials into the SSL manager. Rebuilding the
    /// sessions that present them is the caller's (`reloadClientIdentity`).
    func load() {
        let label = block.clientCertLabel
        switch (try? certStore.mode(label)) ?? .none {
        case .chain:
            loadEnrolledChain(label)
        case .imported, .p12:
            let imported = importedIdentities.loadOrMigrate(label: label, password: block.clientKeyPassword)
            let p12 = imported == nil ? ((try? certStore.load(label)) ?? nil) : nil
            if let imported {
                sslManager.loadClientKey(imported)
            } else if let p12 {
                loadKeystore(p12, what: "stored client PKCS12")
            } else {
                loadBundledKeystore()
            }
        case .none:
            loadBundledKeystore()
        }
    }

    /// A chain issued over the device's identity key. The enrollment is given
    /// up (chain cleared, re-enrollment needed) only when it can never be
    /// presented again: the chain does not parse, or its key is gone or is
    /// not the key the certificate names. A Keychain that merely fails right
    /// now says nothing about either: everything is kept and no identity is
    /// presented until the next load.
    private func loadEnrolledChain(_ label: String) {
        let manager = sslManager
        let outcome = Self.loadEnrolledChain(certStore: certStore, label: label, key: identityKeys(label)) { key, chain in
            manager.loadClientKey(try EnrolledIdentity.clientIdentity(key: key, label: label, chain: chain))
        }
        switch outcome {
        case .loaded: break
        case .unavailable: sslManager.clearClientKeystore(includeHostCerts: false)
        case .dropped: loadBundledKeystore()
        }
    }

    /// The decision behind the instance's chain loading, apart from the SSL manager (unit tests).
    static func loadEnrolledChain(
        certStore: ClientCertSecureStore,
        label: String,
        key: any ClientIdentityKeyProvider,
        present: (any ClientIdentityKeyProvider, [X509Certificate]) throws -> Void
    ) -> EnrolledChain {
        let pems: [String]?
        do {
            pems = try certStore.loadChain(label)
        } catch {
            return unavailable(label, error)
        }
        // The entry is there (mode is chain) but did not read: a Keychain
        // failure of the non-strict store, not a missing enrollment.
        guard let pems else { return unavailable(label, nil) }
        let chain: [X509Certificate]
        do {
            chain = try Pkcs10Csr.parsePemChain(pems)
            guard !chain.isEmpty else { throw PinVaultError.illegalArgument("Empty certificate chain") }
        } catch {
            return drop(certStore, label, "does not parse", error)
        }
        // The chain outlived its key (a restored backup, a reset Keychain):
        // it cannot be presented, so start over.
        if !key.exists() { return drop(certStore, label, "has no Keychain key", nil) }
        do {
            try present(key, chain)
            return .loaded
        } catch {
            let gone = error is EnrolledIdentity.NotOverKey || !key.exists()
            return gone ? drop(certStore, label, "has a missing or different Keychain key", error) : unavailable(label, error)
        }
    }

    private static func drop(_ certStore: ClientCertSecureStore, _ label: String, _ why: String, _ error: (any Error)?) -> EnrolledChain {
        log.e("Client cert [\(label)] \(why) — dropping it, re-enrollment needed", error)
        try? certStore.clear(label)
        return .dropped
    }

    private static func unavailable(_ label: String, _ error: (any Error)?) -> EnrolledChain {
        log.e("Client cert [\(label)] cannot be read right now (Keychain) — kept; no client certificate is presented until it can be", error)
        return .unavailable
    }

    /// The keystore bundled with the app, presented from the Keychain: its key
    /// is imported once per process (under an alias of its own, never under
    /// the enrollment label — it is not an enrollment), so the SSL manager
    /// holds a Keychain identity instead of the P12's in-memory one.
    private func loadBundledKeystore() {
        guard let bundled = block.clientKeystoreBytes else {
            sslManager.clearClientKeystore(includeHostCerts: false)
            return
        }
        let alias = ImportedKeys.aliasFor(Self.bundledLabelPrefix + block.id)
        do {
            let parsed = try ImportedIdentities.readP12(bundled, password: block.clientKeyPassword)
            let leaf = parsed.chain[0]
            let fingerprint = try X509Certificate(certificate: leaf).spkiPin
            let known = Self.bundledImports.withLock { $0[alias] }
            let present = known == fingerprint ? try importedKeys.identity(alias: alias, leaf: leaf) : nil
            if present == nil {
                try importedKeys.importIdentity(alias: alias, identity: parsed.identity, chain: parsed.chain)
                Self.bundledImports.withLock { $0[alias] = fingerprint }
            }
            guard let imported = try importedKeys.identity(alias: alias, leaf: leaf) else {
                throw PinVaultError.illegalState("imported key cannot be read back")
            }
            sslManager.loadClientKey(try ClientIdentity(identity: imported, chain: parsed.chain))
        } catch {
            Self.log.w(
                "ConfigApiClient[\(block.id)]: the bundled client keystore could not be imported into the Keychain — loading it as a PKCS12",
                error
            )
            loadKeystore(bundled, what: "bundled client keystore")
        }
    }

    private func loadKeystore(_ p12: Data, what: String) {
        do {
            try sslManager.loadClientKeystore(p12, password: block.clientKeyPassword)
        } catch {
            Self.log.e("ConfigApiClient[\(block.id)]: the \(what) cannot be loaded", error)
            sslManager.clearClientKeystore(includeHostCerts: false)
        }
    }
}

/// The TLS identity of a certificate chain issued over the device's own key
/// (Secure Enclave or Keychain): the Keychain pairs the stored leaf with the
/// key (``KeychainIdentities``).
enum EnrolledIdentity {

    /// The certificate does not name the identity key: it can never be presented.
    struct NotOverKey: Error, CustomStringConvertible {
        var description: String { "The client certificate is not over the identity key" }
    }

    /// The identity for `chain` (leaf first) over `key`, the identity key of `label`.
    static func clientIdentity(key: any ClientIdentityKeyProvider, label: String, chain: [X509Certificate]) throws -> ClientIdentity {
        guard let leaf = chain.first else { throw PinVaultError.illegalArgument("Certificate chain must not be empty") }
        guard try SPKI.der(for: key.publicKey()) == leaf.subjectPublicKeyInfo else { throw NotOverKey() }
        let certificates = try chain.map { certificate -> SecCertificate in
            guard let secCertificate = certificate.secCertificate() else {
                throw PinVaultError.certificate(message: "Security refuses a certificate of the chain")
            }
            return secCertificate
        }
        guard let identity = try KeychainIdentities.identity(alias: ClientIdentityKeys.aliasFor(label), leaf: certificates[0]) else {
            throw PinVaultError.crypto(message: "The Keychain does not pair the client certificate with its key")
        }
        return try ClientIdentity(identity: identity, chain: certificates)
    }
}
