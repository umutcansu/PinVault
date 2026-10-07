import Foundation

extension ConfigApiClient.Collaborators {

    /// What every block of a started ``PinVault`` gets (Kotlin `ConfigApiClient`'s
    /// own members): the enrolled identity and the bundled keystore
    /// (``ClientIdentityLoader``), host client certificates kept as Keychain
    /// keys (``ImportedIdentities``), certificate renewal (``ClientCertRenewer``),
    /// and the revocation hooks — the block's vault files on a refused
    /// identity (`wipeVaultFilesOnRevocation()`), the app's renewal event on
    /// `reenroll_required`. Attestation is attached by the façade once every
    /// block exists (``ConfigApiClient/attach(attestation:)``).
    static func standard(block: ConfigApiBlock, vault: PinVault) -> ConfigApiClient.Collaborators {
        let storage = vault.enrollmentStorage
        let log = PinVaultLog.tag("ConfigApiClient")
        return ConfigApiClient.Collaborators(
            enrolledIdentity: { block, sslManager in
                let certStore: ClientCertSecureStore
                do {
                    certStore = try storage.openStore()
                } catch {
                    log.e("ConfigApiClient[\(block.id)]: the client credential store cannot be opened — no client certificate presented", error)
                    return .unavailable
                }
                ClientIdentityLoader(
                    block: block, certStore: certStore, sslManager: sslManager,
                    identityKeys: storage.identityKeys, importedKeys: storage.importedKeys
                ).load()
                return .loaded
            },
            hostCertStore: (try? storage.openStore()).map { ImportedHostCertificates(certStore: $0, keys: storage.importedKeys) },
            renewer: { client in
                guard let certStore = try? storage.openStore() else { return NoRenewal() }
                return ClientCertRenewer(
                    block: client.block,
                    certStore: certStore,
                    identityKeys: storage.identityKeys,
                    api: { [unowned client] in client.api },
                    reload: { [unowned client] in client.reloadClientIdentity() },
                    // A refusal of the renewal over mTLS wipes when that connection
                    // presented the identity loaded now; one on the recovery door never does.
                    onRefusedOverMtls: { [unowned client] leaf in client.identityRefused(presented: leaf) }
                )
            },
            onIdentityRevoked: { [weak vault] configApiId in vault?.wipeOnRevocation(configApiId) },
            onReenrollRequired: { [weak vault] configApiId, reason in
                vault?.dispatchRenewalEvent(configApiId, .reenrollRequired(reason: reason))
            }
        )
    }
}

extension ClientCertRenewer: ClientCertRenewing {}

/// A block whose credential store cannot be opened renews nothing.
private struct NoRenewal: ClientCertRenewing {
    func renewIfNeeded(force: Bool) async -> ClientCertRenewalResult { .notApplicable }
}

/// The client certificates of `mtls` pin entries (`host_<hostname>`): the
/// key in the Keychain and the chain in ``ClientCertSecureStore``
/// (``ImportedIdentities``); the P12 itself only where the Keychain refuses it.
struct ImportedHostCertificates: HostClientCertStore {
    let certStore: ClientCertSecureStore
    let keys: any ImportedClientKeys

    private var identities: ImportedIdentities { ImportedIdentities(certStore: certStore, keys: keys) }

    func exists(_ label: String) -> Bool { (try? certStore.exists(label)) ?? false }

    func load(_ label: String) -> Data? { (try? certStore.load(label)) ?? nil }

    func save(_ label: String, _ p12: Data) {
        do {
            try certStore.save(label, p12: p12)
        } catch {
            PinVaultLog.tag("SSLCertificateUpdater").w("Host client cert [\(label)] could not be stored", error)
        }
    }

    func loadImportedIdentity(_ label: String, password: String) -> ClientIdentity? {
        identities.loadOrMigrate(label: label, password: password)
    }

    func importIdentity(_ label: String, p12: Data, password: String) throws -> ClientIdentity? {
        try identities.import(label: label, p12: p12, password: password)
    }

    func deleteImportedKey(_ label: String) {
        keys.delete(alias: ImportedKeys.aliasFor(label))
    }
}
