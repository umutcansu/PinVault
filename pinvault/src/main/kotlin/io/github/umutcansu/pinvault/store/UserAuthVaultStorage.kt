package io.github.umutcansu.pinvault.store

import io.github.umutcansu.pinvault.crypto.VaultFileDecryptor
import io.github.umutcansu.pinvault.keystore.UserAuthKeyKind
import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import io.github.umutcansu.pinvault.model.ScreenLockRequiredException
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import timber.log.Timber
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** What the unlock prompt reported. */
internal sealed class AuthOutcome {
    /** [cipher] is the prompt's authorised cipher (per-use key), null for a time-bound key. */
    class Succeeded(val cipher: Cipher?) : AuthOutcome()
    object Cancelled : AuthOutcome()
    object NoScreenLock : AuthOutcome()
    class Error(val message: String) : AuthOutcome()
}

/**
 * Checks the signature of a `user_auth` file once it is open: null when it
 * passes (or the file's Config API runs unsigned), otherwise why it failed.
 */
internal typealias UnlockVerifier = (plaintext: ByteArray, version: Int, signatures: List<SignatureEntry>) -> String?

/**
 * A [UserAuth] vault file, stored in [inner] (which adds its own Keystore
 * encryption on top) in one of these forms:
 *
 * - **Sealed here** — `PVUA` `0x04` `[key id, 8][wrapped key length, 2][wrapped key][IV, 12][ciphertext]`:
 *   the content under a fresh AES-256-GCM key, that key wrapped with the
 *   device's user-auth RSA key. The GCM tag covers the file name and the
 *   version it is stored as, so a sealed blob cannot be passed off as
 *   another file's, or as another version of this one. (`0x02` is the same
 *   without the version, written by earlier builds: it is read, and written
 *   again as `0x04` the first time it is opened.)
 * - **Sealed by the server** (`encryption = USER_AUTH`) — `PVUA` `0x03`
 *   `[key id, 8][signatures length, 2][signatures][envelope]`: the server's
 *   envelope exactly as downloaded, with its signatures. The content is only
 *   ever decrypted in [unlock], after the prompt, and checked there. The key
 *   id is the key the library had registered with the server when it saved
 *   the copy (the key the server sealed for), not merely the device's
 *   current key.
 *
 * With [serverSealedOnly] (an `encryption = USER_AUTH` file) ONLY the
 * server-sealed kind is accepted: any other blob — open, sealed here, or
 * without the prefix — was not written for this file by the library (root
 * running as the app could plant one), so [load] and [unlock] delete it and
 * never return its content; unlock reports
 * [VaultFileUnlockResult.Invalidated] (fetch again). [load] never returns
 * content for such a file.
 *
 * **The pending slot.** A server-sealed copy can only be checked after the
 * prompt, so a download that arrives while a copy is already stored must
 * not take that copy's place: whoever answers the download (the server, or
 * whoever holds its TLS key) could otherwise destroy a good, verified copy
 * with bytes that are found bad — and deleted — only at the next unlock.
 * [saveSealedByServer] therefore writes a second copy to a slot of its own
 * (`<key>.pending` in [inner]) whenever a copy exists, and leaves the
 * existing one alone. [unlock] opens the pending copy first: when it passes
 * its checks it is written under the file's own name and the slot is
 * emptied; when it fails, it alone is deleted and the copy it was to
 * replace is opened instead (asking for the prompt once more when the
 * passed prompt's cipher was already used: a per-use key authorises one
 * operation). The first copy ever stored goes straight to the file's own
 * name, as there is nothing to protect. [exists], [getVersion], [isLocked]
 * and [load] describe the copy under the file's own name; the pending copy
 * is invisible to the app until it has been opened.
 * - **Open** — `PVUA` `0x00` `[content]`: an [UserAuth.IF_SCREEN_LOCK] copy
 *   saved while the device had no screen lock.
 * - Anything without the `PVUA` prefix is a copy stored before the app turned
 *   the lock on; it is sealed on first read. Any other `PVUA` kind was sealed
 *   with a key this version no longer has (the key per file of earlier
 *   development builds) and is treated as retired.
 *
 * The key id names the key a copy was sealed with. There is one key per
 * device; when Android retires it a new one is made, and copies with the old
 * id can no longer be opened, so they are deleted like a retired key's.
 *
 * Saving needs no prompt. [load] never prompts either: it returns the content
 * of an unsealed copy and null for a sealed one, which only [unlock] opens.
 *
 * Only a retired or missing key, a server copy sealed for another key (a
 * padding failure after a passed prompt) or a copy that is not of the
 * expected kind deletes a copy; only a retired or missing key replaces the
 * key. Any other Keystore error is reported as [VaultFileUnlockResult.Failed]
 * and leaves everything as it was (the copy is at most marked
 * [needsFetch], so the next fetch downloads it whole); so does a cancelled
 * prompt.
 */
internal class UserAuthVaultStorage(
    private val inner: VaultStorageProvider,
    private val keys: UserAuthKeys,
    private val policy: UserAuth,
    /** An `encryption = USER_AUTH` file: only server-sealed copies count (see the class comment). */
    private val serverSealedOnly: Boolean = false
) : VaultStorageProvider {

    init {
        require(policy != UserAuth.NONE) { "UserAuthVaultStorage needs a locking policy" }
    }

    override fun save(key: String, bytes: ByteArray, version: Int) {
        check(!serverSealedOnly) {
            "Vault file '$key' is sealed by the server (encryption = USER_AUTH); only saveSealedByServer stores it"
        }
        inner.save(key, seal(key, bytes, version), version)
        replaced(key)
    }

    /**
     * Stores a `user_auth` download as it came: [envelope] is sealed for the
     * user-auth key the library registered with the server, whose id is
     * [sealedFor] (the device's current key when not given), and is only
     * opened by [unlock].
     *
     * Returns true when the copy went to the pending slot: a copy is already
     * stored and keeps its place until the new one has passed its checks in
     * [unlock] (see the class comment). False: it is the stored copy now.
     */
    fun saveSealedByServer(
        key: String,
        envelope: ByteArray,
        version: Int,
        signatures: List<SignatureEntry>,
        sealedFor: ByteArray? = null
    ): Boolean {
        VaultFileDecryptor.parse(envelope)   // refuse a malformed envelope now, not at unlock
        val keyId = sealedFor ?: UserAuthKeys.keyId(keys.publicKey())
        require(keyId.size == UserAuthKeys.KEY_ID_BYTES) { "key id must be ${UserAuthKeys.KEY_ID_BYTES} bytes" }
        val sigs = encodeSignatures(signatures)
        val blob = ByteBuffer.allocate(HEADER + UserAuthKeys.KEY_ID_BYTES + 2 + sigs.size + envelope.size)
            .put(MAGIC)
            .put(SERVER)
            .put(keyId)
            .putShort(sigs.size.toShort())
            .put(sigs)
            .put(envelope)
            .array()
        if (inner.exists(key)) {
            // Nothing in the new copy has been checked: the one on record
            // stays, with its stamp and its failure counters, until the new
            // one has opened. The whole file did arrive, though, so a copy
            // kept after an inconclusive failure needs no download again.
            inner.save(pendingKey(key), blob, version)
            unwrapFailures.remove(pendingKey(key))
            refetch.remove(key)
            Timber.d("Vault file [%s] v%d stored in the pending slot; it replaces the stored copy once an unlock has verified it", key, version)
            return true
        }
        inner.save(key, blob, version)
        replaced(key)
        return false
    }

    /** The version waiting in the pending slot, or 0 when it is empty. */
    fun pendingVersion(key: String): Int = if (inner.exists(pendingKey(key))) inner.getVersion(pendingKey(key)) else 0

    /** Deletes the pending copy alone; the stored copy stays. */
    fun clearPending(key: String) {
        inner.clear(pendingKey(key))
        unwrapFailures.remove(pendingKey(key))
    }

    /** The id of the key the pending copy was sealed for, or null when the slot is empty. */
    fun pendingSealedKeyId(key: String): ByteArray? = inner.load(pendingKey(key))?.let(::sealedKeyIdOf)

    /** Where a download waits while a copy is stored: the inner store binds it to this name, as it does the copy itself. */
    private fun pendingKey(key: String) = "$key$PENDING_SUFFIX"

    override fun load(key: String): ByteArray? {
        val blob = inner.load(key) ?: return null
        if (serverSealedOnly) {
            // Never content: a server-sealed copy opens only in unlock, and
            // anything else was not written here for this file.
            if (kindOf(blob) != Kind.SERVER) dropForeign(key, Slot.MAIN)
            else Timber.d("Vault file [%s] is locked; PinVault.unlockFile opens it", key)
            return null
        }
        return when (kindOf(blob)) {
            Kind.OPEN -> adopt(key, blob.copyOfRange(HEADER, blob.size))
            Kind.EARLIER -> adopt(key, blob)
            Kind.SEALED, Kind.SERVER, Kind.RETIRED -> {
                Timber.d("Vault file [%s] is locked; PinVault.unlockFile opens it", key)
                null
            }
        }
    }

    override fun getVersion(key: String): Int = inner.getVersion(key)

    override fun exists(key: String): Boolean = inner.exists(key)

    /** Deletes the copy, and a pending one. The key is the device's and stays (see [UserAuthKeys]). */
    override fun clear(key: String) {
        inner.clear(key)
        inner.clear(pendingKey(key))
        replaced(key)
    }

    /**
     * True when an approved unlock of the stored copy failed in a way that
     * says nothing certain about the copy (see [open]): the copy is kept, and
     * the next fetch asks for the whole file instead of "newer than the
     * stored version", so a copy that really is bad gets replaced without
     * being deleted on a guess. Cleared by any save, clear or successful
     * unlock. In memory: a new process simply tries the copy again.
     */
    fun needsFetch(key: String): Boolean = refetch.contains(key)

    /** A new copy (or none) is stored: earlier failures say nothing about it. */
    private fun replaced(key: String) {
        unwrapFailures.remove(key)
        unwrapFailures.remove(pendingKey(key))
        refetch.remove(key)
    }

    /** True when the stored copy is sealed, i.e. only [unlock] opens it. */
    fun isLocked(key: String): Boolean = inner.load(key)?.let(::kindOf)?.let {
        if (serverSealedOnly) it == Kind.SERVER
        else it == Kind.SEALED || it == Kind.SERVER || it == Kind.RETIRED
    } == true

    /**
     * The id of the key the stored copy was sealed for (8 bytes), or null
     * when nothing sealed is stored.
     */
    fun sealedKeyId(key: String): ByteArray? = inner.load(key)?.let(::sealedKeyIdOf)

    private fun sealedKeyIdOf(blob: ByteArray): ByteArray? {
        val kind = kindOf(blob)
        if (kind != Kind.SEALED && kind != Kind.SERVER) return null
        if (blob.size < HEADER + UserAuthKeys.KEY_ID_BYTES) return null
        return blob.copyOfRange(HEADER, HEADER + UserAuthKeys.KEY_ID_BYTES)
    }

    /**
     * Opens the stored copy. [authenticate] shows the prompt for the key's
     * kind; it gets the cipher the prompt must authorise (null for a
     * time-bound key) and runs only for a sealed copy. [verify] checks a
     * server-sealed copy's signature once it is open; a copy that fails is
     * deleted. A [serverSealedOnly] file needs [verify] (fail closed without
     * one: a missing check is a setup error, not a reason to skip it).
     *
     * A key that passed the prompt but cannot unwrap a SERVER-sealed copy
     * (bad OAEP padding: the server sealed it for another key) makes the copy
     * useless: it is deleted, [onSealedForAnotherKey] runs (the router forgets the
     * registration so the key is registered again) and the result is
     * [VaultFileUnlockResult.Invalidated].
     *
     * A copy waiting in the pending slot is opened first. When it passes,
     * it becomes the stored copy and [onPromoted] runs with its version
     * (the guard records the confirmation only then); when it fails for a
     * reason that is the copy's own, it alone is deleted and the stored
     * copy is opened as if the pending one had never been there.
     */
    suspend fun unlock(
        key: String,
        authenticate: suspend (UserAuthKeyKind, Cipher?) -> AuthOutcome,
        onSealedForAnotherKey: () -> Unit = {},
        onPromoted: (version: Int) -> Unit = {},
        // Last on purpose: callers pass the verifier as a trailing lambda.
        verify: UnlockVerifier? = null
    ): VaultFileUnlockResult {
        var stored = inner.load(key)
        val pending = inner.load(pendingKey(key))
        if (stored == null && pending == null) return VaultFileUnlockResult.NotFound(key)
        if (serverSealedOnly) {
            if (stored != null && kindOf(stored) != Kind.SERVER) {
                dropForeign(key, Slot.MAIN)
                // A pending copy the server did seal may still open below.
                if (pending == null) return VaultFileUnlockResult.Invalidated(key)
                stored = null
            }
            if (verify == null) {
                Timber.e("Vault file [%s]: no signature check available (its Config API is not configured) — not opened", key)
                return VaultFileUnlockResult.Failed(
                    key, "Vault file '$key' cannot be checked: its Config API is not configured, so it is not opened"
                )
            }
        }

        // A prompt that passed for the pending copy and can still serve the
        // stored one: a time-bound key, or a per-use cipher that was never
        // used. Null = ask again.
        var passed: AuthOutcome.Succeeded? = null
        var pendingFailure: VaultFileUnlockResult? = null
        if (pending != null) {
            val attempt = openSlot(key, Slot.PENDING, pending, inner.getVersion(pendingKey(key)), authenticate, verify, onSealedForAnotherKey, null)
            val result = attempt.result
            if (result is VaultFileUnlockResult.Unlocked) {
                promote(key, pending, result.version)
                runCatching { onPromoted(result.version) }
                return result
            }
            // Cancelled, a prompt error, a Keystore fault, a retired key:
            // nothing more is tried, nothing else is touched.
            if (!attempt.condemned) return result
            Timber.w("Vault file [%s]: the pending copy did not open and was deleted; opening the copy it was to replace", key)
            pendingFailure = result
            passed = attempt.passed
        }
        val blob = stored ?: return pendingFailure ?: VaultFileUnlockResult.NotFound(key)
        return openSlot(key, Slot.MAIN, blob, inner.getVersion(key), authenticate, verify, onSealedForAnotherKey, passed).result
    }

    /** The two places a copy can be: under the file's own name, and the pending slot. */
    private enum class Slot { MAIN, PENDING }

    /**
     * What opening one slot came to. [condemned]: the copy was found bad and
     * deleted, so the other slot may be tried; [passed]: a passed prompt the
     * next slot may reuse (null when a per-use cipher was already used, or
     * no prompt passed).
     */
    private class Attempt(val result: VaultFileUnlockResult, val condemned: Boolean = false, val passed: AuthOutcome.Succeeded? = null)

    /** One slot, from the stored blob to the content: the checks before the prompt, the prompt, then [open]. */
    private suspend fun openSlot(
        key: String,
        slot: Slot,
        blob: ByteArray,
        version: Int,
        authenticate: suspend (UserAuthKeyKind, Cipher?) -> AuthOutcome,
        verify: UnlockVerifier?,
        onSealedForAnotherKey: () -> Unit,
        passed: AuthOutcome.Succeeded?
    ): Attempt {
        val kindOfBlob = kindOf(blob)
        if (slot == Slot.PENDING && kindOfBlob != Kind.SERVER) {
            // Only saveSealedByServer writes this slot: anything else was planted.
            dropForeign(key, slot)
            return Attempt(VaultFileUnlockResult.Invalidated(key), condemned = true, passed = passed)
        }
        val unsealed = when (kindOfBlob) {
            Kind.OPEN -> blob.copyOfRange(HEADER, blob.size)
            Kind.EARLIER -> blob
            Kind.SEALED, Kind.SERVER -> null
            Kind.RETIRED -> return Attempt(invalidated(key))
        }
        if (unsealed != null) {
            val bytes = adopt(key, unsealed) ?: return Attempt(invalidated(key))
            return Attempt(VaultFileUnlockResult.Unlocked(key, version, bytes))
        }

        val sealed = try { Sealed.parse(blob) } catch (e: Exception) {
            return Attempt(damaged(key, slot, "the stored copy is malformed", e), condemned = true, passed = passed)
        }

        // Which key the copy needs, and whether it is still there. Only a
        // retired or missing key is a reason to give the copy up — and that
        // gives up every copy, not just this slot's.
        val kind = try {
            if (keys.state() != UserAuthKeys.State.USABLE) return Attempt(invalidated(key))
            if (!sealed.keyId.contentEquals(UserAuthKeys.keyId(keys.publicKey()))) {
                Timber.w("Vault file [%s] was sealed with a user-auth key that no longer exists", key)
                // A pending copy for another key says nothing about the
                // stored one, whose stamp is checked on its own turn.
                return if (slot == Slot.PENDING) Attempt(givenUp(key, slot), condemned = true, passed = passed)
                else Attempt(invalidated(key))
            }
            keys.kind()
        } catch (e: Exception) {
            return Attempt(keystoreFailure(key, "Could not read the unlock key", e))
        }

        val outcome = passed ?: run {
            val promptCipher = try {
                keys.cipherForPrompt()
            } catch (e: Exception) {
                return Attempt(keystoreFailure(key, "Could not prepare the unlock", e))
            }
            authenticate(kind, promptCipher)
        }

        return when (outcome) {
            is AuthOutcome.Succeeded -> open(key, slot, version, sealed, outcome, verify, onSealedForAnotherKey)
            AuthOutcome.Cancelled -> Attempt(VaultFileUnlockResult.Cancelled(key))
            AuthOutcome.NoScreenLock -> Attempt(VaultFileUnlockResult.Failed(key, "The device has no screen lock; set one to open this file"))
            is AuthOutcome.Error -> Attempt(VaultFileUnlockResult.Failed(key, outcome.message))
        }
    }

    /** After a passed prompt: the Keystore step, then the software steps. */
    private fun open(
        key: String,
        slot: Slot,
        version: Int,
        sealed: Sealed,
        outcome: AuthOutcome.Succeeded,
        verify: UnlockVerifier?,
        onSealedForAnotherKey: () -> Unit
    ): Attempt {
        val authorised = outcome.cipher
        // A per-use cipher does one operation: once the unwrap has run, the
        // other slot needs a prompt of its own. A time-bound key opens
        // without the cipher for as long as its window lasts.
        var used = false
        val unwrap = { wrapped: ByteArray -> used = true; keys.unwrap(authorised, wrapped) }
        fun reusable(): AuthOutcome.Succeeded? = if (authorised == null || !used) outcome else null
        return when (sealed) {
            is Sealed.Local -> {
                // Never given up here (only a retired key is): the copy's key
                // id was checked against the current key before the prompt,
                // and this device sealed it itself, so a failure now is a
                // Keystore fault or a damaged copy — not "another key". The
                // next fetch downloads the file whole and replaces it.
                val fileKey = try { unwrap(sealed.wrappedKey) } catch (e: Exception) {
                    if (!UserAuthKeys.isRetired(e) && !WrongKeyForCopy.isAuthFailure(e)) refetch.add(key)
                    return Attempt(keystoreFailure(key, "Unlock was approved but the key did not open", e))
                }
                val content = try { sealed.open(key, version, fileKey) } catch (e: Exception) {
                    return Attempt(damaged(key, slot, "the stored copy did not decrypt for this file and version", e), condemned = true, passed = reusable())
                }
                if (!sealed.boundToVersion) {
                    // Sealed by an earlier build, without the version: write it
                    // again in the current form (sealing needs no prompt).
                    try {
                        inner.save(key, Sealed.Local.create(key, version, content, keys.publicKey()), version)
                    } catch (e: Exception) {
                        Timber.w(e, "Vault file [%s]: could not re-seal the copy in the current form", key)
                    }
                }
                replaced(key)
                Attempt(VaultFileUnlockResult.Unlocked(key, version, content))
            }
            is Sealed.Server -> {
                val parts = try { VaultFileDecryptor.parse(sealed.envelope) } catch (e: Exception) {
                    return Attempt(damaged(key, slot, "the stored envelope is malformed", e), condemned = true, passed = reusable())
                }
                val sessionKey = try { unwrap(parts.wrappedKey) } catch (e: Exception) {
                    if (isWrongKeyForCopy(e) || failedAgain(slotKey(key, slot), e)) {
                        return Attempt(sealedForAnotherKey(key, slot, e, onSealedForAnotherKey), condemned = true, passed = reusable())
                    }
                    // Kept: what failed is not known to be the copy. A fresh
                    // download replaces a stored copy if it was (a pending
                    // one is the fresh download already).
                    if (slot == Slot.MAIN && !UserAuthKeys.isRetired(e) && !WrongKeyForCopy.isAuthFailure(e)) refetch.add(key)
                    return Attempt(keystoreFailure(key, "Unlock was approved but the key did not open", e))
                }
                val content = try {
                    VaultFileDecryptor.openContent(parts, SecretKeySpec(sessionKey, "AES")).also { sessionKey.fill(0) }
                } catch (e: Exception) {
                    return Attempt(damaged(key, slot, "the server's envelope did not decrypt", e), condemned = true, passed = reusable())
                }
                verify?.invoke(content, version, sealed.signatures)?.let { problem ->
                    content.fill(0)
                    return Attempt(damaged(key, slot, problem, null), condemned = true, passed = reusable())
                }
                if (slot == Slot.MAIN) replaced(key)
                Attempt(VaultFileUnlockResult.Unlocked(key, version, content))
            }
        }
    }

    /**
     * The pending copy passed: it is written under the file's own name (the
     * inner store binds a blob to its name, so it cannot simply be renamed)
     * and the slot is emptied. The copy it replaces is gone with that save.
     */
    private fun promote(key: String, blob: ByteArray, version: Int) {
        inner.save(key, blob, version)
        inner.clear(pendingKey(key))
        replaced(key)
        Timber.d("Vault file [%s]: the pending copy (v%d) opened and replaced the stored one", key, version)
    }

    /** The inner store's name for a slot's copy; also what the failure counter is kept under. */
    private fun slotKey(key: String, slot: Slot) = if (slot == Slot.PENDING) pendingKey(key) else key

    /** Deletes one slot's copy. The stored copy's deletion takes its failure marks with it. */
    private fun condemn(key: String, slot: Slot) {
        if (slot == Slot.PENDING) {
            clearPending(key)
        } else {
            inner.clear(key)
            unwrapFailures.remove(key)
            refetch.remove(key)
        }
    }

    private fun seal(key: String, bytes: ByteArray, version: Int): ByteArray {
        if (keys.isScreenLockSet()) {
            keys.ensureKey()
            return Sealed.Local.create(key, version, bytes, keys.publicKey())
        }
        if (policy == UserAuth.REQUIRED) throw ScreenLockRequiredException(key)
        Timber.w("Vault file [%s] stored without a lock: the device has no screen lock (IF_SCREEN_LOCK)", key)
        return MAGIC + OPEN + bytes
    }

    /**
     * An unsealed copy's content, sealed in place when the device has a
     * screen lock. Null when the policy does not allow it unsealed.
     */
    private fun adopt(key: String, bytes: ByteArray): ByteArray? {
        if (!keys.isScreenLockSet()) return bytes.takeIf { policy == UserAuth.IF_SCREEN_LOCK }
        try {
            val version = inner.getVersion(key)
            inner.save(key, seal(key, bytes, version), version)
            Timber.d("Vault file [%s] sealed now that the device has a screen lock", key)
        } catch (e: Exception) {
            Timber.w(e, "Could not seal vault file [%s]", key)
        }
        return bytes
    }

    /** The key is gone: no copy of this file will open again, whichever slot it is in. */
    private fun invalidated(key: String): VaultFileUnlockResult {
        Timber.w("Vault file [%s]: the unlock key is gone (the screen lock was removed, or the fingerprints changed on a fingerprint-only key); stored copy deleted", key)
        clear(key)
        return VaultFileUnlockResult.Invalidated(key)
    }

    /** A pending copy stamped with a key the device no longer has: it alone is given up. */
    private fun givenUp(key: String, slot: Slot): VaultFileUnlockResult {
        Timber.w("Vault file [%s]: the %s copy was sealed for a key that is gone; deleted", key, slotName(slot))
        condemn(key, slot)
        return VaultFileUnlockResult.Invalidated(key)
    }

    /** A blob a [serverSealedOnly] file (or the pending slot) must not hold: deleted unread. */
    private fun dropForeign(key: String, slot: Slot) {
        Timber.e("Vault file [%s]: the %s copy is not one the server sealed; deleted unread — fetch it again", key, slotName(slot))
        condemn(key, slot)
    }

    /**
     * The prompt passed but the key could not unwrap the copy: it was sealed
     * for another key (the server kept an older registration, or the copy was
     * swapped). Nothing about it will ever open; give it up.
     */
    private fun sealedForAnotherKey(key: String, slot: Slot, e: Exception, onSealedForAnotherKey: () -> Unit): VaultFileUnlockResult {
        Timber.w(e, "Vault file [%s]: approved, but the %s copy is not sealed for this key — deleted; fetch it again", key, slotName(slot))
        condemn(key, slot)
        runCatching(onSealedForAnotherKey)
        return VaultFileUnlockResult.Invalidated(key)
    }

    private fun slotName(slot: Slot) = if (slot == Slot.PENDING) "pending" else "stored"

    private fun isWrongKeyForCopy(e: Throwable): Boolean = WrongKeyForCopy.matches(e)

    /**
     * Unwrap failures of a SERVER-sealed copy after a PASSED prompt, per
     * file, in this process. Not every Keystore names a wrong key: the
     * emulator's KeyMint answers a copy sealed for another key with
     * `UNKNOWN_ERROR` (-1000), and nothing more specific. Only that answer is
     * counted ([WrongKeyForCopy.isUnknownKeystoreError]): twice in a row and
     * the copy is given up. Anything else — a busy Keystore, a pruned
     * operation (-28), too many operations (-31), anything about
     * authentication — is never counted, so transient faults cannot delete a
     * good copy. Reset whenever the copy is replaced, cleared or opens.
     */
    private val unwrapFailures = java.util.concurrent.ConcurrentHashMap<String, Int>()

    /** Copies kept after an inconclusive failure that the next fetch downloads whole; see [needsFetch]. */
    private val refetch: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()

    private fun failedAgain(key: String, e: Throwable): Boolean {
        if (!WrongKeyForCopy.isUnknownKeystoreError(e)) return false
        val count = unwrapFailures.merge(key, 1, Int::plus) ?: 1
        if (count < MAX_UNWRAP_FAILURES) return false
        unwrapFailures.remove(key)
        return true
    }

    /** A Keystore error: retired → [invalidated]; anything else keeps the copy and the key. */
    private fun keystoreFailure(key: String, what: String, e: Exception): VaultFileUnlockResult {
        if (UserAuthKeys.isRetired(e)) return invalidated(key)
        Timber.w(e, "Vault file [%s]: %s — copy kept, try again", key, what)
        return VaultFileUnlockResult.Failed(key, "$what: ${e.message}", e)
    }

    /** The copy itself is bad (damaged, wrong signature): delete it — that slot's copy only — the next fetch replaces it. */
    private fun damaged(key: String, slot: Slot, problem: String, e: Exception?): VaultFileUnlockResult {
        Timber.e(e, "Vault file [%s]: %s — %s copy deleted", key, problem, slotName(slot))
        condemn(key, slot)
        return VaultFileUnlockResult.Failed(key, "Vault file '$key' did not open: $problem. The ${slotName(slot)} copy was deleted; fetch it again.", e)
    }

    private enum class Kind { SEALED, SERVER, OPEN, EARLIER, RETIRED }

    private fun kindOf(blob: ByteArray): Kind {
        if (blob.size < HEADER || !blob.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) return Kind.EARLIER
        return when (blob[MAGIC.size]) {
            SEALED, SEALED_V3 -> Kind.SEALED
            SERVER -> Kind.SERVER
            OPEN -> Kind.OPEN
            else -> Kind.RETIRED
        }
    }

    private sealed class Sealed(val keyId: ByteArray) {

        class Local(
            keyId: ByteArray,
            val wrappedKey: ByteArray,
            val iv: ByteArray,
            val ciphertext: ByteArray,
            /** False for a `0x02` copy, whose tag covers the file name only. */
            val boundToVersion: Boolean
        ) : Sealed(keyId) {

            fun open(key: String, version: Int, fileKey: ByteArray): ByteArray {
                // Not Cipher.run { }: inside it `iv` would be Cipher.getIV().
                val cipher = Cipher.getInstance(AES_GCM)
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(fileKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
                fileKey.fill(0)
                cipher.updateAAD(if (boundToVersion) aad(key, version) else legacyAad(key))
                return cipher.doFinal(ciphertext)
            }

            companion object {
                fun create(key: String, version: Int, bytes: ByteArray, publicKey: PublicKey): ByteArray {
                    val random = SecureRandom()
                    val fileKey = ByteArray(32).also(random::nextBytes)
                    val iv = ByteArray(GCM_IV_BYTES).also(random::nextBytes)
                    val ciphertext = Cipher.getInstance(AES_GCM).run {
                        init(Cipher.ENCRYPT_MODE, SecretKeySpec(fileKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
                        updateAAD(aad(key, version))
                        doFinal(bytes)
                    }
                    val wrapped = Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).run {
                        init(Cipher.ENCRYPT_MODE, publicKey, UserAuthKeys.OAEP)
                        doFinal(fileKey)
                    }
                    fileKey.fill(0)
                    return ByteBuffer.allocate(HEADER + UserAuthKeys.KEY_ID_BYTES + 2 + wrapped.size + iv.size + ciphertext.size)
                        .put(MAGIC)
                        .put(SEALED_V3)
                        .put(UserAuthKeys.keyId(publicKey))
                        .putShort(wrapped.size.toShort())
                        .put(wrapped)
                        .put(iv)
                        .put(ciphertext)
                        .array()
                }

                /** File name and version: neither can be swapped under the tag. */
                private fun aad(key: String, version: Int) = "pinvault-user-auth:v3:$key:$version".toByteArray(Charsets.UTF_8)

                private fun legacyAad(key: String) = "pinvault-user-auth:v2:$key".toByteArray(Charsets.UTF_8)
            }
        }

        class Server(keyId: ByteArray, val signatures: List<SignatureEntry>, val envelope: ByteArray) : Sealed(keyId)

        companion object {
            fun parse(blob: ByteArray): Sealed {
                val buffer = ByteBuffer.wrap(blob, HEADER, blob.size - HEADER)
                val keyId = ByteArray(UserAuthKeys.KEY_ID_BYTES).also { buffer.get(it) }
                val length = buffer.short.toInt() and 0xFFFF
                require(buffer.remaining() >= length) { "truncated" }
                val kind = blob[MAGIC.size]
                return if (kind == SEALED || kind == SEALED_V3) {
                    require(buffer.remaining() > length + GCM_IV_BYTES) { "truncated" }
                    val wrapped = ByteArray(length).also { buffer.get(it) }
                    val iv = ByteArray(GCM_IV_BYTES).also { buffer.get(it) }
                    val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }
                    Local(keyId, wrapped, iv, ciphertext, boundToVersion = kind == SEALED_V3)
                } else {
                    val sigs = ByteArray(length).also { buffer.get(it) }
                    val envelope = ByteArray(buffer.remaining()).also { buffer.get(it) }
                    Server(keyId, decodeSignatures(sigs), envelope)
                }
            }
        }
    }

    companion object {
        private val MAGIC = "PVUA".toByteArray(Charsets.US_ASCII)
        /** Approved unlocks of a server copy that may fail with `UNKNOWN_ERROR` in a row before it is given up. */
        private const val MAX_UNWRAP_FAILURES = 2
        private const val OPEN: Byte = 0x00
        // 0x01 was the key-per-file format of earlier development builds.
        private const val SEALED: Byte = 0x02
        private const val SERVER: Byte = 0x03
        /** Sealed here, the tag covering file name AND version. */
        private const val SEALED_V3: Byte = 0x04
        /** The pending slot's name in the inner store: `<key>.pending`. */
        internal const val PENDING_SUFFIX = ".pending"
        private val HEADER = MAGIC.size + 1
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BITS = 128

        /**
         * `keyId:signature` per line, as in the `X-Vault-Signatures` header;
         * Base64 has no `:` and no newline. An entry without a key id is
         * written with an empty one.
         */
        private fun encodeSignatures(entries: List<SignatureEntry>): ByteArray =
            entries.joinToString("\n") { "${it.keyId.orEmpty()}:${it.signature}" }.toByteArray(Charsets.UTF_8)

        private fun decodeSignatures(bytes: ByteArray): List<SignatureEntry> =
            String(bytes, Charsets.UTF_8).split('\n').filter { it.isNotBlank() }.map { line ->
                val keyId = line.substringBefore(':', "")
                SignatureEntry(keyId = keyId.ifEmpty { null }, signature = line.substringAfter(':'))
            }
    }
}

/**
 * Tells "this ciphertext was not made for this key" apart from "the Keystore
 * failed" after a passed prompt. The first makes the stored copy useless
 * (it is deleted and fetched again); the second says nothing about the copy,
 * which must be kept.
 *
 * The Android Keystore reports nearly every failure of a private-key
 * operation as an [javax.crypto.IllegalBlockSizeException] — a busy or
 * crashed Keystore, a locked device, a rate limit, a vendor bug — with the
 * real error as its cause. So the exception type alone proves nothing. It
 * counts as "wrong key" only when
 *  - it is an `IllegalBlockSizeException` or `BadPaddingException` WITHOUT a
 *    cause: what a software RSA implementation throws when OAEP does not
 *    decode, and what Keystore2 was seen to throw for it on API 33; or
 *  - its cause is the Keystore's own exception with the error
 *    `INVALID_ARGUMENT` (-38): what KeyMint answers when the padding does
 *    not decode.
 *
 * Anything with another cause — and anything that speaks of authentication —
 * keeps the copy.
 */
internal object WrongKeyForCopy {

    /** KeyMint / Keymaster `ErrorCode::INVALID_ARGUMENT`. */
    internal const val KM_ERROR_INVALID_ARGUMENT = -38

    /** KeyMint / Keymaster `ErrorCode::UNKNOWN_ERROR`: what the emulator's KeyMint answers a wrong key with. */
    internal const val KM_ERROR_UNKNOWN_ERROR = -1000

    private const val KEYSTORE_EXCEPTION = "android.security.KeyStoreException"

    fun matches(e: Throwable): Boolean {
        if (UserAuthKeys.isRetired(e)) return false
        if (isAuthFailure(e)) return false
        if (e !is javax.crypto.IllegalBlockSizeException && e !is javax.crypto.BadPaddingException) return false
        val cause = e.cause?.takeIf { it !== e } ?: return true
        return isKeystoreInvalidArgument(cause)
    }

    /** True when the failure is about user authentication (a locked key), anywhere in the cause chain. */
    fun isAuthFailure(e: Throwable): Boolean =
        generateSequence(e) { it.cause?.takeIf { cause -> cause !== it } }.take(8).any {
            it is android.security.keystore.UserNotAuthenticatedException ||
                it.message?.contains("authenticat", ignoreCase = true) == true
        }

    /**
     * True when [t] is the Keystore's exception carrying `INVALID_ARGUMENT`.
     * Its error code is read by name (the accessor is not public on every
     * Android version); where that is not allowed, from its message, which
     * names the code (`internal Keystore code: -38`, or `Invalid argument` on
     * older versions).
     */
    internal fun isKeystoreInvalidArgument(t: Throwable): Boolean {
        if (t.javaClass.name != KEYSTORE_EXCEPTION) return false
        val code = keystoreErrorCode(t)
        if (code != null) return code == KM_ERROR_INVALID_ARGUMENT
        val message = t.message ?: return false
        return message.contains("internal Keystore code: $KM_ERROR_INVALID_ARGUMENT") ||
            message.trim().equals("Invalid argument", ignoreCase = true)
    }

    /**
     * True when the unwrap failed with the Keystore's `UNKNOWN_ERROR` (-1000)
     * somewhere in the cause chain, and nothing in it is about a retired key
     * or authentication. The only unnamed failure that is counted towards
     * giving a server copy up (see `UserAuthVaultStorage.failedAgain`).
     */
    fun isUnknownKeystoreError(e: Throwable): Boolean {
        if (UserAuthKeys.isRetired(e) || isAuthFailure(e)) return false
        return generateSequence(e) { it.cause?.takeIf { cause -> cause !== it } }.take(8).any { t ->
            if (t.javaClass.name != KEYSTORE_EXCEPTION) return@any false
            val code = keystoreErrorCode(t)
            if (code != null) code == KM_ERROR_UNKNOWN_ERROR
            else t.message?.contains("internal Keystore code: $KM_ERROR_UNKNOWN_ERROR") == true
        }
    }

    /** The Keystore exception's error code, read by name (not public on every Android version); null where not allowed. */
    private fun keystoreErrorCode(t: Throwable): Int? = try {
        t.javaClass.getMethod("getErrorCode").invoke(t) as? Int
    } catch (_: Exception) {
        null
    }
}
