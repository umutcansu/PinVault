package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import timber.log.Timber

/**
 * Deletes the stored vault files of one or more Config APIs: when a revoked
 * device hears `reenroll_required` (`wipeVaultFilesOnRevocation()`), or on
 * `unenroll(…, wipeVaultFiles = true)`.
 */
internal object VaultFileWipe {

    /**
     * The Config APIs that use the client certificate stored under [label]
     * for mTLS — what `unenroll(…, wipeVaultFiles = true)` wipes. Every block
     * has a `clientCertLabel` (the default one unless set), so the label alone
     * would also catch TLS-only blocks; a block counts only when it also shows
     * it talks mTLS: it names an `enrollmentUrl` (its own URL is an mTLS
     * listener) or a `renewalUrl`, bundles a `clientKeystore`, or carries a
     * `token_mtls` vault file.
     */
    fun mtlsBlocksUsing(
        label: String,
        blocks: Collection<io.github.umutcansu.pinvault.model.ConfigApiBlock>,
        files: Collection<VaultFileConfig>
    ): Set<String> = blocks.filter { block ->
        block.clientCertLabel == label && (
            block.enrollmentUrl != null ||
                block.renewalUrl != null ||
                block.clientKeystoreBytes != null ||
                files.any {
                    it.configApiId == block.id &&
                        it.accessPolicy == io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.TOKEN_MTLS
                }
            )
    }.map { it.id }.toSet()

    /**
     * Clears every file in [files] bound to [configApiIds], copies locked
     * with `userAuth` included. The user-auth key belongs to the device, not
     * to one Config API, so it is deleted only when no locked file is left
     * anywhere; [onUserAuthKeyDeleted] then runs (the router forgets where it
     * registered the old key). Never throws; returns how many files it cleared.
     */
    fun wipe(
        configApiIds: Set<String>,
        files: Collection<VaultFileConfig>,
        storageFor: (String) -> VaultStorageProvider,
        userAuthKeys: UserAuthKeys?,
        onUserAuthKeyDeleted: () -> Unit = {}
    ): Int {
        val wiped = files.filter { it.configApiId in configApiIds }
        for (file in wiped) {
            try {
                storageFor(file.key).clear(file.key)
            } catch (e: Exception) {
                Timber.w(e, "Could not wipe vault file [%s]", file.key)
            }
        }
        if (userAuthKeys != null && wiped.any { it.userAuth != UserAuth.NONE }) {
            val lockedLeft = files.any {
                it.userAuth != UserAuth.NONE && runCatching { storageFor(it.key).exists(it.key) }.getOrDefault(true)
            }
            if (!lockedLeft) {
                userAuthKeys.delete()
                onUserAuthKeyDeleted()
            }
        }
        Timber.w("Vault files of %s wiped (%d files)", configApiIds, wiped.size)
        return wiped.size
    }
}
