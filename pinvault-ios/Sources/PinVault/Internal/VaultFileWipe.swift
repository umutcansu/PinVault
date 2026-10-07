import Foundation

/// Deletes the stored vault files of one or more Config APIs (Kotlin
/// `VaultFileWipe`): when a revoked device hears `reenroll_required`
/// (`wipeVaultFilesOnRevocation()`), or on `unenroll(…, wipeVaultFiles: true)`.
enum VaultFileWipe {
    private static let log = PinVaultLog.tag("VaultFileWipe")

    /// The Config APIs that use the client certificate stored under `label` for
    /// mTLS — what `unenroll(…, wipeVaultFiles: true)` wipes. Every block has a
    /// `clientCertLabel`, so the label alone would also catch TLS-only blocks; a
    /// block counts only when it also shows it talks mTLS: it names an
    /// `enrollmentUrl` or a `renewalUrl`, bundles a `clientKeystore`, or carries
    /// a `token_mtls` vault file.
    static func mtlsBlocksUsing(_ label: String, blocks: [ConfigApiBlock], files: [VaultFileConfig]) -> Set<String> {
        Set(blocks.filter { block in
            block.clientCertLabel == label && (
                block.enrollmentUrl != nil ||
                    block.renewalUrl != nil ||
                    block.clientKeystoreBytes != nil ||
                    files.contains { $0.configApiId == block.id && $0.accessPolicy == .tokenMtls }
            )
        }.map(\.id))
    }

    /// Clears every file in `files` bound to `configApiIds`, copies locked with
    /// `userAuth` included. The user-auth key belongs to the device, not to one
    /// Config API, so it is deleted only when no locked file is left anywhere;
    /// `onUserAuthKeyDeleted` then runs (the router forgets where it registered
    /// the old key). Never throws; returns how many files it cleared.
    @discardableResult
    static func wipe(
        _ configApiIds: Set<String>,
        files: [VaultFileConfig],
        storageFor: (String) -> any VaultStorageProvider,
        userAuthKeys: (any UserAuthKeys)?,
        onUserAuthKeyDeleted: () -> Void = {}
    ) -> Int {
        let wiped = files.filter { configApiIds.contains($0.configApiId) }
        for file in wiped {
            do {
                try storageFor(file.key).clear(key: file.key)
            } catch {
                log.w("Could not wipe vault file [\(file.key)]", error)
            }
        }
        if let userAuthKeys, wiped.contains(where: { $0.userAuth != .none }) {
            let lockedLeft = files.contains { file in
                file.userAuth != .none && ((try? storageFor(file.key).exists(key: file.key)) ?? true)
            }
            if !lockedLeft {
                userAuthKeys.delete()
                onUserAuthKeyDeleted()
            }
        }
        log.w("Vault files of [\(configApiIds.sorted().joined(separator: ", "))] wiped (\(wiped.count) files)")
        return wiped.count
    }
}
