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
                // Built at the first renewal check, not here: a credential store
                // that cannot be opened at start (the Keychain before the first
                // unlock) is asked again at the next check instead of turning
                // renewal off for the client's lifetime. The strict store, so a
                // certificate that cannot be read is a failure, not "none stored".
                DeferredRenewal(blockId: client.block.id) { [unowned client] in
                    ClientCertRenewer(
                        block: client.block,
                        certStore: try storage.openStrictStore(),
                        identityKeys: storage.identityKeys,
                        api: { [unowned client] in client.api },
                        reload: { [unowned client] in client.reloadClientIdentity() },
                        // A refusal of the renewal over mTLS wipes when that connection
                        // presented the identity loaded now; one on the recovery door never does.
                        onRefusedOverMtls: { [unowned client] leaf in client.identityRefused(presented: leaf) }
                    )
                }
            },
            onIdentityRevoked: { [weak vault] configApiId in vault?.wipeOnRevocation(configApiId) },
            onReenrollRequired: { [weak vault] configApiId, reason in
                vault?.dispatchRenewalEvent(configApiId, .reenrollRequired(reason: reason))
            }
        )
    }
}

extension ClientCertRenewer: ClientCertRenewing {}

/// A block's renewer, built when it is first needed. While `make` throws —
/// the credential store cannot be opened — every check answers
/// ``ClientCertRenewalResult/failed(reason:exception:)`` and the next one
/// tries again; once it worked the renewer is kept.
final class DeferredRenewal: ClientCertRenewing {
    private let blockId: String
    private let make: @Sendable () throws -> any ClientCertRenewing
    private let built = Locked<(any ClientCertRenewing)?>(nil)
    private static let log = PinVaultLog.tag("ClientCertRenewer")

    init(blockId: String, _ make: @escaping @Sendable () throws -> any ClientCertRenewing) {
        self.blockId = blockId
        self.make = make
    }

    func renewIfNeeded(force: Bool) async -> ClientCertRenewalResult {
        let renewer: any ClientCertRenewing
        do {
            renewer = try built.withLock { built in
                if let built { return built }
                let made = try make()
                built = made
                return made
            }
        } catch {
            Self.log.e("Client cert renewal [\(blockId)]: the client credential store cannot be opened", error)
            return .failed(
                reason: "The client credential store cannot be opened: \(ClientCertRenewer.message(error))", exception: error
            )
        }
        return await renewer.renewIfNeeded(force: force)
    }
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
