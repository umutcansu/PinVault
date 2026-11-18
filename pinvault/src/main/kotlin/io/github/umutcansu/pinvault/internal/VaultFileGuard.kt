package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileStatus
import io.github.umutcansu.pinvault.ssl.TrustedClock
import io.github.umutcansu.pinvault.store.StoredSignatures
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
import io.github.umutcansu.pinvault.store.VaultFileMeta
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import timber.log.Timber

/**
 * How a block checks a stored copy: which signature scheme it expects
 * ([scheme], 1 or 2) and the check itself — null when the copy passes,
 * otherwise why it does not.
 */
internal class StoredVerifier(
    val scheme: Int,
    /**
     * Why nothing can be checked right now, or null: the block's signing-key
     * set is not on record (`SignatureTrust.missingKeySet`), so the only keys
     * at hand are ones that set may have revoked. A copy is then neither
     * handed out nor deleted — it may be perfectly good.
     */
    val unavailable: () -> String? = { null },
    val verify: (plaintext: ByteArray, version: Int, signatures: List<SignatureEntry>) -> String?
)

/**
 * Stands between the app and a stored vault file. A file used to be checked
 * when it was downloaded and then trusted for as long as it sat on the
 * device; this is what is checked every time it is read:
 *
 *  - **Signature.** A file of a signing Config API is stored with the
 *    signatures it came with ([VaultFileMeta]) and verified again on every
 *    `loadFile` / `unlockFile`, with the keys trusted now. A copy that fails
 *    — rewritten, swapped for another file's, relabelled with another
 *    version, or signed by a key that has since been revoked — is deleted. A
 *    copy with no signature on record (stored by an earlier version) is not
 *    handed out and is downloaded again by the next fetch. Files of unsigned
 *    blocks are not checked, as before.
 *  - **Offline lifetime** (`maxOfflineAge`). The time the server last
 *    confirmed the copy is recorded; once that is longer ago than the file
 *    allows — by the trusted clock, which a device clock set back does not
 *    fool — the copy is not handed out, and deleted with `wipeWhenStale()`.
 *    A confirmation time ahead of the trusted clock counts as "not
 *    confirmed": not handed out, never deleted on that ground alone.
 *  - **Version floor.** The highest version of a file that ever passed its
 *    signature check is kept apart from the copy and outlives it: after
 *    `clearFile`, a deletion here, a revocation wipe or `unenroll`, the next
 *    download must be that version or a newer one ([versionFloor]), and a
 *    stored copy below it is not handed out when it is read (an older copy
 *    put back on its own with its own signature record). Files of unsigned
 *    blocks have no floor — nothing vouches for their version.
 *
 * A Keystore that cannot be read right now is none of these: nothing is
 * handed out and nothing is deleted. The same goes while the block's
 * signing-key set is not on record ([StoredVerifier.unavailable]): the keys
 * left to check with may be revoked ones.
 *
 * What it cannot do: stop someone with root from putting the whole of the
 * app's storage back to an earlier state (an older, validly signed file with
 * its older signature, and the floor of that time). Nothing kept on the
 * device can. The offline lifetime bounds how long such a copy stays usable,
 * and the next fetch replaces it.
 */
internal class VaultFileGuard(
    private val meta: VaultFileMeta,
    /** The trusted clock of a Config API, by id. */
    private val now: (configApiId: String) -> Long,
    /** `PinVaultConfig.vaultFileMaxOfflineAgeMs`; 0 = no limit. */
    private val defaultMaxOfflineAgeMs: Long = 0L,
    /** Told when a stored copy was deleted here, and why. */
    private val onRemoved: (key: String, reason: String) -> Unit = { _, _ -> }
) {

    /** What a read came to: the content, or why there is none. */
    sealed class Read {
        class Content(val bytes: ByteArray) : Read()
        class Refused(val status: VaultFileStatus, val reason: String) : Read()
        /** Nothing stored, or a sealed copy `loadFile` does not open. */
        object Absent : Read()
    }

    // ── What the router records ──────────────────────────────────────────

    /** A download was verified and stored as [version]. [signatures] null: an unsigned block, or a copy that carries its own. */
    fun stored(file: VaultFileConfig, version: Int, signatures: StoredSignatures?) = quietly(file.key) {
        meta.saveSignatures(file.key, signatures)
        recordConfirmation(file)
        meta.setProblem(file.key, null)
        // The version the signatures name: the store's own count (a backend
        // without version headers) is not something a signature vouches for.
        if (signatures != null) meta.raiseVersionFloor(file.configApiId, file.key, signatures.version)
    }

    /**
     * The highest version of [file] this device accepted with a verified
     * signature, 0 when none: what a download must reach even when no copy
     * is stored any more. Kept through [forget], [integrityFailed] and every
     * deletion here.
     *
     * @throws StoreUnreadableException when it cannot be read right now —
     *   which is not "no floor"
     */
    fun versionFloor(file: VaultFileConfig): Int = meta.versionFloor(file.configApiId, file.key)

    /**
     * `unlockFile` opened a server-sealed (`user_auth`) copy and its
     * signature passed: only now is its version one a signature vouches for.
     * Null when it may be handed out; the floor is then raised to [version].
     *
     * First, though, the floor as it stood before this unlock: a copy below
     * it is one a newer verified version superseded, put back on its own
     * (its envelope still verifies — nothing in it names the floor). It is
     * deleted the way a failed check deletes, and the floor is kept.
     */
    fun verifiedAtUnlock(file: VaultFileConfig, storage: VaultStorageProvider, version: Int): Read.Refused? {
        val floor = try {
            meta.versionFloor(file.configApiId, file.key)
        } catch (e: StoreUnreadableException) {
            return unavailable(file.key, e)
        }
        belowFloorProblem(version, floor)?.let { problem ->
            return remove(file, storage, VaultFileStatus.INTEGRITY_FAILED,
                "Vault file '${file.key}' failed its check when unlocked: $problem. The stored copy was deleted; fetch it again.")
        }
        quietly(file.key) { meta.raiseVersionFloor(file.configApiId, file.key, version) }
        return null
    }

    /**
     * Why a copy signed as [version] may not be handed out under [floor], or
     * null. A copy without a version (0: a backend that sends none) is not
     * judged, as at download.
     */
    private fun belowFloorProblem(version: Int, floor: Int): String? =
        if (version in 1 until floor) {
            "it is signed as v$version, but this device has already verified v$floor of it (an older copy put back)"
        } else null

    /** Forgets every version floor (`PinVault.resetAndWipeStoredState`, tests only). */
    fun wipeVersionFloors() = quietly("*") { meta.wipeVersionFloors() }

    /** The server confirmed the stored copy (304, or the same content again). */
    fun confirmed(file: VaultFileConfig) = quietly(file.key) {
        recordConfirmation(file)
    }

    /**
     * A `user_auth` download went to the pending slot (see
     * [UserAuthVaultStorage.saveSealedByServer]): nothing in it has been
     * checked, so the copy on record keeps its signatures and its
     * confirmation. Only the time the server served the new copy is written
     * down, apart, for [promoted].
     */
    fun pendingStored(file: VaultFileConfig) = quietly(file.key) {
        meta.setConfirmedAt(pendingRecord(file.key), now(file.configApiId))
    }

    /**
     * `unlockFile` opened the pending copy and its signature passed: it is
     * the stored copy now, as [version]. Its confirmation is the time the
     * server served it, not the time the user opened it — the offline
     * lifetime counts from the server's last word, and a device may have
     * been offline between the two.
     */
    fun promoted(file: VaultFileConfig, version: Int) = quietly(file.key) {
        val served = meta.confirmedAt(pendingRecord(file.key))
        meta.clear(pendingRecord(file.key))
        meta.saveSignatures(file.key, null)
        meta.setConfirmedAt(file.key, if (served > 0L) served else now(file.configApiId))
        meta.setProblem(file.key, null)
        Timber.d("Vault file [%s] v%d verified at unlock; it is the stored copy now", file.key, version)
    }

    /**
     * Where the serving time of a pending `user_auth` copy is kept: a record
     * of its own next to the file's, under the slot's name, so the copy on
     * record is not touched. (The storage keeps the copy itself under the
     * same suffix.)
     */
    private fun pendingRecord(key: String) = "$key$PENDING_SUFFIX"

    /**
     * The confirmation time is the trusted clock's reading, never more, and
     * it replaces whatever was on record — a time that lay ahead included.
     */
    private fun recordConfirmation(file: VaultFileConfig) {
        meta.setConfirmedAt(file.key, now(file.configApiId))
    }

    /**
     * True when the stored copy of a signed file has no usable signature on
     * record, so the fetch must download the file whatever version the
     * device holds (the server would otherwise answer "not modified").
     */
    fun needsSignature(file: VaultFileConfig, verifier: StoredVerifier?): Boolean {
        if (verifier == null || carriesOwnSignatures(file)) return false
        return try {
            meta.signatures(file.key)?.scheme != verifier.scheme
        } catch (_: StoreUnreadableException) {
            false
        }
    }

    /** The app cleared the file, or it was wiped. Its version floor stays. */
    fun forget(key: String) = quietly(key) {
        meta.clear(key)
        meta.clear(pendingRecord(key))
        meta.setProblem(key, null)
    }

    // ── What a read checks ───────────────────────────────────────────────

    /** `loadFile`: the content when the copy may be handed out. */
    fun load(file: VaultFileConfig, storage: VaultStorageProvider, verifier: StoredVerifier?): Read = try {
        when {
            !storage.exists(file.key) -> Read.Absent
            isStale(file) -> stale(file, storage)
            else -> {
                val bytes = storage.load(file.key)
                when {
                    bytes != null -> check(file, storage, bytes, storage.getVersion(file.key), verifier)
                    // The store itself found the copy bad (it did not decrypt
                    // for this file and version) and dropped it.
                    !storage.exists(file.key) -> {
                        val reason = "Vault file '${file.key}' did not open for this file and version. The stored copy was deleted; fetch it again."
                        integrityFailed(file, reason)
                        Read.Refused(VaultFileStatus.INTEGRITY_FAILED, reason)
                    }
                    else -> Read.Absent
                }
            }
        }
    } catch (e: StoreUnreadableException) {
        unavailable(file.key, e)
    }

    /**
     * `unlockFile`, before the prompt: null to go ahead, otherwise why not.
     * With [verifier]: also when the copy cannot be checked right now — a
     * server-sealed copy is verified inside the unlock, where a failed check
     * deletes it.
     */
    fun beforeUnlock(file: VaultFileConfig, storage: VaultStorageProvider, verifier: StoredVerifier? = null): Read.Refused? = try {
        when {
            !storage.exists(file.key) -> null
            // A newer copy the server served within the lifetime is waiting to
            // be opened: the prompt goes ahead for it. What the unlock hands
            // out is checked again afterwards ([staleAfterUnlock]), so a
            // waiting copy that fails its check does not let the old one out.
            isStale(file) && freshness(file, pendingRecord(file.key)) != Freshness.FRESH -> stale(file, storage)
            else -> verifier?.unavailable?.invoke()?.let { uncheckable(file.key, it) }
        }
    } catch (e: StoreUnreadableException) {
        unavailable(file.key, e)
    }

    /**
     * `unlockFile`, after a copy opened: null when it may be handed out. A
     * waiting copy that passed its check is the stored copy by now, confirmed
     * as of the time the server served it ([promoted]); a copy that is still
     * past its lifetime here is the old one, opened because the waiting copy
     * was missing or failed.
     */
    fun staleAfterUnlock(file: VaultFileConfig, storage: VaultStorageProvider): Read.Refused? = try {
        if (isStale(file)) stale(file, storage) else null
    } catch (e: StoreUnreadableException) {
        unavailable(file.key, e)
    }

    /**
     * Checks content that was just read (or unsealed) against the signatures
     * stored with it. A copy that fails is deleted.
     */
    fun check(file: VaultFileConfig, storage: VaultStorageProvider, bytes: ByteArray, version: Int, verifier: StoredVerifier?): Read {
        if (verifier == null || carriesOwnSignatures(file)) return Read.Content(bytes)
        val signatures = try {
            // Before anything is judged: without the block's signing-key set
            // a "failed" check would delete a copy that may be good.
            verifier.unavailable()?.let { return uncheckable(file.key, it) }
            meta.signatures(file.key)
        } catch (e: StoreUnreadableException) {
            return unavailable(file.key, e)
        }
        if (signatures == null || signatures.scheme != verifier.scheme) {
            val reason = "Vault file '${file.key}' has no signature on record for this Config API (it was stored by an " +
                "earlier version, or before serverScope was set); it is not handed out until it has been fetched again"
            Timber.w(reason)
            return Read.Refused(VaultFileStatus.NEEDS_FETCH, reason)
        }
        // The version the signature names. (A backend that sends no version
        // header has its files signed and recorded as v0 while the store
        // counts them itself; only then may the two differ.)
        val signedVersion = signatures.version
        // The floor lives in an entry of its own: an older copy put back with
        // its own signature record (entries are bound to their names, not to
        // each other) still verifies, but sits below it.
        val floor = try {
            meta.versionFloor(file.configApiId, file.key)
        } catch (e: StoreUnreadableException) {
            return unavailable(file.key, e)
        }
        val problem = when {
            signedVersion > 0 && signedVersion != version -> "it is stored as v$version but was signed as v$signedVersion"
            signatures.entries.isEmpty() -> "it carries no signature but a verifying key is configured"
            else -> verifier.verify(bytes, signedVersion, signatures.entries) ?: belowFloorProblem(signedVersion, floor)
        } ?: return Read.Content(bytes)

        return remove(file, storage, VaultFileStatus.INTEGRITY_FAILED,
            "Vault file '${file.key}' failed its check when read: $problem. The stored copy was deleted; fetch it again.")
    }

    /** A copy that did not open for this file and version, or failed the check done at unlock: gone already. */
    fun integrityFailed(file: VaultFileConfig, reason: String) = quietly(file.key) {
        meta.clear(file.key)
        meta.clear(pendingRecord(file.key))
        meta.setProblem(file.key, VaultFileStatus.INTEGRITY_FAILED)
        onRemoved(file.key, reason)
    }

    fun status(file: VaultFileConfig, storage: VaultStorageProvider, verifier: StoredVerifier?): VaultFileStatus = try {
        // Read first: an unreadable Keystore must show as that, not as "nothing stored".
        val problem = meta.problem(file.key)
        when {
            !storage.exists(file.key) -> problem ?: VaultFileStatus.NOT_STORED
            isStale(file) -> VaultFileStatus.STALE
            verifier?.unavailable?.invoke() != null -> VaultFileStatus.STORAGE_UNAVAILABLE
            needsSignature(file, verifier) -> VaultFileStatus.NEEDS_FETCH
            (storage as? UserAuthVaultStorage)?.isLocked(file.key) == true -> VaultFileStatus.LOCKED
            else -> VaultFileStatus.AVAILABLE
        }
    } catch (e: StoreUnreadableException) {
        VaultFileStatus.STORAGE_UNAVAILABLE
    }

    /**
     * Deletes every copy that is past its offline lifetime and asked for
     * `wipeWhenStale()`. Run at init and on the periodic update, so a device
     * that stays offline loses the file even if the app never reads it.
     */
    fun sweep(files: Collection<VaultFileConfig>, storageFor: (String) -> VaultStorageProvider) {
        for (file in files) {
            if (!file.wipeWhenStale) continue
            try {
                val storage = storageFor(file.key)
                if (storage.exists(file.key) && isStale(file)) stale(file, storage)
            } catch (e: StoreUnreadableException) {
                Timber.w("Vault file [%s]: storage unreadable right now — offline lifetime not checked", file.key)
            } catch (e: Exception) {
                Timber.w(e, "Vault file [%s]: could not check its offline lifetime", file.key)
            }
        }
    }

    /** The file's offline lifetime in ms; 0 = no limit. */
    fun maxOfflineAgeMs(file: VaultFileConfig): Long = file.maxOfflineAgeMs ?: defaultMaxOfflineAgeMs

    /** @throws StoreUnreadableException when the confirmation time cannot be read right now */
    fun isStale(file: VaultFileConfig): Boolean = freshness(file) != Freshness.FRESH

    /**
     * [Freshness.STALE] is established from the record alone: past the
     * lifetime, or never confirmed. [Freshness.UNCONFIRMED] is a confirmation
     * time that lies ahead of the trusted clock — written while the clock was
     * ahead (the trusted clock is lowered again by a newer config), or put
     * there by someone with access to the storage. Counted from it the copy
     * would stay "fresh" for as long as it lies ahead, so it is not handed
     * out until the server confirms it again; but a time that cannot be
     * trusted is no proof of staleness either, so it never deletes a copy
     * (`wipeWhenStale`) on its own.
     *
     * @throws StoreUnreadableException when the confirmation time cannot be read right now
     */
    private fun freshness(file: VaultFileConfig, record: String = file.key): Freshness {
        val max = maxOfflineAgeMs(file)
        if (max <= 0L) return Freshness.FRESH
        val confirmedAt = meta.confirmedAt(record)
        // Never on record: stored before a limit was set. Fail closed — and an
        // entry removed from storage must not read as "confirmed just now".
        if (confirmedAt <= 0L) return Freshness.STALE
        val now = now(file.configApiId)
        // The trusted clock may restart up to one persist step behind the
        // time it last handed out (see TrustedClock): not "in the future".
        if (confirmedAt > now + TrustedClock.PERSIST_STEP_MS) return Freshness.UNCONFIRMED
        return if (now - confirmedAt > max) Freshness.STALE else Freshness.FRESH
    }

    private enum class Freshness { FRESH, STALE, UNCONFIRMED }

    private fun stale(file: VaultFileConfig, storage: VaultStorageProvider): Read.Refused {
        if (freshness(file) == Freshness.UNCONFIRMED) {
            val reason = "Vault file '${file.key}': the time its server last confirmed it lies ahead of the trusted " +
                "clock, so its offline lifetime cannot be counted; it is not handed out until it is fetched again"
            Timber.w(reason)
            return Read.Refused(VaultFileStatus.STALE, reason)
        }
        val reason = "Vault file '${file.key}' has not been confirmed by its server within its offline lifetime " +
            "(maxOfflineAge); fetch it again"
        if (!file.wipeWhenStale) {
            Timber.w(reason)
            return Read.Refused(VaultFileStatus.STALE, reason)
        }
        return remove(file, storage, VaultFileStatus.STALE, "$reason. The stored copy was deleted (wipeWhenStale).")
    }

    private fun remove(file: VaultFileConfig, storage: VaultStorageProvider, status: VaultFileStatus, reason: String): Read.Refused {
        Timber.e(reason)
        try {
            storage.clear(file.key)
        } catch (e: Exception) {
            Timber.w(e, "Could not delete vault file [%s]", file.key)
        }
        quietly(file.key) {
            meta.clear(file.key)
            meta.clear(pendingRecord(file.key))
            meta.setProblem(file.key, status)
        }
        runCatching { onRemoved(file.key, reason) }
        return Read.Refused(status, reason)
    }

    /** The copy is there, but the keys to check it with are not: kept, not handed out. */
    private fun uncheckable(key: String, why: String): Read.Refused {
        Timber.w("Vault file [%s] cannot be checked right now — nothing handed out, nothing deleted: %s", key, why)
        return Read.Refused(VaultFileStatus.STORAGE_UNAVAILABLE, "Vault file '$key' cannot be checked right now: $why")
    }

    private fun unavailable(key: String, e: StoreUnreadableException): Read.Refused {
        Timber.w("Vault file [%s]: storage cannot be read right now — nothing handed out, nothing deleted (%s)", key, e.message)
        return Read.Refused(
            VaultFileStatus.STORAGE_UNAVAILABLE,
            "Vault file '$key' cannot be checked right now: the encrypted storage is unreadable (${e.message})"
        )
    }

    /** A server-sealed `user_auth` copy keeps its signatures inside the copy and is checked at unlock. */
    private fun carriesOwnSignatures(file: VaultFileConfig) = file.encryption == VaultFileEncryption.USER_AUTH

    /** Bookkeeping must never fail a fetch or a read. */
    private inline fun quietly(key: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            Timber.w(e, "Vault file [%s]: could not update its record", key)
        }
    }

    companion object {
        /** Suffix of the pending slot's record; the same one [UserAuthVaultStorage] uses for the copy. */
        private const val PENDING_SUFFIX = ".pending"
    }
}
