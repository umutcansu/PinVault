package io.github.umutcansu.pinvault.ssl

import timber.log.Timber

/**
 * The time used to decide whether a pin config has expired.
 *
 * The device's wall clock alone is not enough: set it back and an expired
 * config is valid again. This clock never goes back on its own. It returns
 * the later of the wall clock and the highest time it has seen — a reference
 * that is persisted ([persist]) and, while the process lives, carried forward
 * by the monotonic clock ([elapsed], which a changed wall clock does not
 * touch). So rolling the wall clock back neither revives an expired config
 * nor stops time for one that is still valid.
 *
 * ## The one way back
 * A wall clock that was once set far ahead by mistake would otherwise leave
 * the reference in the future for good, and every config would look expired.
 * [resetTo] lowers the reference, and the updater calls it in one case only:
 * a config was accepted whose `issuedAt` is newer than every config accepted
 * before. For a signed block nobody can make such a config without a signing
 * key, and each config can do it once — after that its `issuedAt` is the
 * watermark. The reference then becomes the later of the wall clock and that
 * `issuedAt`.
 *
 * What this cannot do: tell the real time after a reboot with the wall clock
 * set back. Time then resumes from the last persisted reference (at most
 * [PERSIST_STEP_MS] old), which is still never earlier than what was seen.
 *
 * Only expiry decisions use this clock: of the stored config, and whether a
 * fetched config is already expired — except for a fetched config newer than
 * every config accepted before, which is judged by the wall clock so that it
 * can still correct a reference that ran ahead (see
 * `SignedConfigVerifier.expiryNow`). Whether a fetched `issuedAt` lies ahead
 * of the device is judged by the wall clock, as before.
 *
 * @param load reads the persisted reference (0 = none). May throw when the
 *   store is unreadable; the wall clock is used for that call and the read is
 *   tried again later.
 * @param persist writes the reference. May throw; tried again later.
 */
internal class TrustedClock(
    private val wall: () -> Long = System::currentTimeMillis,
    private val elapsed: () -> Long = { android.os.SystemClock.elapsedRealtime() },
    private val load: () -> Long = { 0L },
    private val persist: (Long) -> Unit = { }
) {
    private val lock = Any()

    /** The highest time seen, and the monotonic clock's reading when it was taken. */
    private var reference = 0L
    private var referenceElapsed = 0L

    private var loaded = false
    private var lastLoadAttemptElapsed = Long.MIN_VALUE
    private var persisted = 0L
    private var nextWriteAttempt = Long.MIN_VALUE

    /** The later of the wall clock and the carried-forward reference. Cheap: writes at most once per [PERSIST_STEP_MS]. */
    fun now(): Long = synchronized(lock) {
        val now = advance()
        if (loaded && now - persisted >= PERSIST_STEP_MS && now >= nextWriteAttempt) write(now)
        now
    }

    /** Persists the current time as the reference right away. Called around config fetches. */
    fun checkpoint() {
        synchronized(lock) {
            val now = advance()
            if (loaded && now > persisted) write(now)
        }
    }

    /**
     * Lowers the reference to the later of the wall clock and [issuedAt] —
     * see the class comment for when. Never raises it.
     */
    fun resetTo(issuedAt: Long) {
        synchronized(lock) {
            val current = advance()
            val target = maxOf(wall(), issuedAt)
            if (!loaded || target >= current) return
            Timber.w(
                "Trusted clock moved back by %d s: a newer config (issuedAt=%d) shows the reference was ahead",
                (current - target) / 1000, issuedAt
            )
            reference = target
            referenceElapsed = elapsed()
            write(target)
        }
    }

    private fun advance(): Long {
        ensureLoaded()
        val wallNow = wall()
        val elapsedNow = elapsed()
        val carried = if (reference > 0L) reference + (elapsedNow - referenceElapsed).coerceAtLeast(0L) else 0L
        val now = maxOf(wallNow, carried)
        reference = now
        referenceElapsed = elapsedNow
        return now
    }

    private fun ensureLoaded() {
        if (loaded) return
        val elapsedNow = elapsed()
        if (lastLoadAttemptElapsed != Long.MIN_VALUE && elapsedNow - lastLoadAttemptElapsed < LOAD_RETRY_MS) return
        lastLoadAttemptElapsed = elapsedNow
        try {
            val stored = load()
            persisted = stored
            if (stored > reference) {
                reference = stored
                referenceElapsed = elapsedNow
            }
            loaded = true
        } catch (e: Exception) {
            Timber.e(e, "Trusted clock: the stored reference is unreadable — using the wall clock until it can be read")
        }
    }

    private fun write(time: Long) {
        try {
            persist(time)
            persisted = time
        } catch (e: Exception) {
            nextWriteAttempt = time + LOAD_RETRY_MS
            Timber.w(e, "Trusted clock: could not persist the reference — trying again later")
        }
    }

    companion object {
        /** The reference on disk is at most this far behind the time seen. */
        internal const val PERSIST_STEP_MS = 5L * 60 * 1000

        /** How long to wait before reading (or writing) an unreadable reference again. */
        private const val LOAD_RETRY_MS = 30_000L
    }
}
