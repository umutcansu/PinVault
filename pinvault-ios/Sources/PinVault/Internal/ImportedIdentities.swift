import Foundation
import Security

/// Client credentials that arrived as a PKCS12 bundle, kept the safe way
/// (Kotlin `ImportedIdentities`): the private key in the Keychain
/// (``ImportedClientKeys``), the certificate chain in
/// ``ClientCertSecureStore``, and no P12 bytes.
///
/// Used for every P12 the library accepts: a host's client certificate, an
/// enrollment the server made the key for (`allowServerGeneratedKey()`), the
/// keystore bundled with the app. `SecPKCS12Import` opens the bundle in
/// memory; only the key and its leaf go into the Keychain.
final class ImportedIdentities: Sendable {

    private let certStore: ClientCertSecureStore
    private let keys: any ImportedClientKeys
    private static let log = PinVaultLog.tag("ImportedIdentities")

    init(certStore: ClientCertSecureStore, keys: any ImportedClientKeys) {
        self.certStore = certStore
        self.keys = keys
    }

    /// Imports the key of `p12` for `label` and stores its chain in place of
    /// whatever `label` held (a stored P12 included). Returns nil when the
    /// platform refuses the key: nothing was changed then, and the caller
    /// keeps using the P12 form for this credential.
    ///
    /// - Throws: when `p12` itself is unusable (wrong password, no key entry),
    ///   or the chain cannot be stored.
    func `import`(label: String, p12: Data, password: String) throws -> ClientIdentity? {
        let parsed = try Self.readP12(p12, password: password)
        let alias = ImportedKeys.aliasFor(label)
        let algorithm = Self.algorithm(parsed.identity)
        let imported: SecIdentity
        do {
            try keys.importIdentity(alias: alias, identity: parsed.identity, chain: parsed.chain)
            guard let readBack = try keys.identity(alias: alias, leaf: parsed.chain[0]) else {
                throw PinVaultError.illegalState("imported key cannot be read back")
            }
            imported = readBack
        } catch {
            Self.log.w("The Keychain refused to import a client key (\(algorithm)) — it stays in its PKCS12 form", error)
            keys.delete(alias: alias)
            return nil
        }
        try certStore.saveImported(label, pemChain: parsed.chain.map { Pkcs10Csr.toPem(der: SecCertificateCopyData($0) as Data) })
        Self.log.i("Client key imported into the Keychain (\(algorithm), this device only); PKCS12 bytes dropped")
        return try ClientIdentity(identity: imported, chain: parsed.chain)
    }

    /// The imported credential stored under `label`; nil when there is none
    /// or the Keychain cannot be read right now (nothing is dropped then). A
    /// chain whose Keychain key is gone (a restored backup, a reset Keychain)
    /// cannot be presented: it is dropped.
    func load(label: String) -> ClientIdentity? {
        guard let pems = (try? certStore.loadImported(label)) ?? nil else { return nil }
        let chain: [SecCertificate]
        do {
            chain = try Pkcs10Csr.parsePemChain(pems).map { certificate in
                guard let secCertificate = certificate.secCertificate() else {
                    throw PinVaultError.certificate(message: "Security refuses a certificate of the chain")
                }
                return secCertificate
            }
            guard !chain.isEmpty else { throw PinVaultError.illegalArgument("Empty certificate chain") }
        } catch {
            Self.log.e("An imported client certificate chain is unreadable — dropping it", error)
            forget(label: label)
            return nil
        }
        let identity: SecIdentity?
        do {
            identity = try keys.identity(alias: ImportedKeys.aliasFor(label), leaf: chain[0])
        } catch {
            // The Keychain failed; the key may be fine. Keep the chain and
            // present nothing for now.
            Self.log.w("An imported client key cannot be read right now — certificate kept, not presented", error)
            return nil
        }
        guard let identity else {
            Self.log.w("An imported client certificate has no Keychain key — dropping it")
            try? certStore.clear(label)
            return nil
        }
        return try? ClientIdentity(identity: identity, chain: chain)
    }

    /// The credential stored under `label` in the imported form, moving a P12
    /// stored there into the Keychain first. Nil when `label` holds no
    /// imported credential and its P12 (if any) could not be moved; the caller
    /// then loads the P12 as before.
    func loadOrMigrate(label: String, password: String) -> ClientIdentity? {
        if let loaded = load(label: label) { return loaded }
        guard let p12 = (try? certStore.load(label)) ?? nil else { return nil }
        do {
            return try self.import(label: label, p12: p12, password: password)
        } catch {
            Self.log.w("A stored PKCS12 could not be read for import — left as it is", error)
            return nil
        }
    }

    /// Deletes the credential under `label` in every form, and its imported key.
    func forget(label: String) {
        try? certStore.clear(label)
        keys.delete(alias: ImportedKeys.aliasFor(label))
    }

    /// The first identity of `p12` and its certificate chain, opened in memory.
    static func readP12(_ p12: Data, password: String) throws -> (identity: SecIdentity, chain: [SecCertificate]) {
        let identity = try ClientIdentity.fromPKCS12(p12, password: password)
        return (identity.identity, identity.chain)
    }

    private static func algorithm(_ identity: SecIdentity) -> String {
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else { return "unknown" }
        return KeyInspector.algorithm(key)
    }
}
