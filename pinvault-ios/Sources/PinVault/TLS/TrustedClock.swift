import Foundation

/// The library's wall clock: the device clock plus the E2E harness's offset
/// (`PinVault.e2eSetClockOffset`, PORTING.md §8 — the counterpart of `date -s`
/// on Android, so 0 outside E2E builds). Certificate validity, `SecTrust`
/// verify dates, the recovery windows and ``TrustedClock``'s wall source read
/// it, so a shifted clock reaches every decision `date -s` reaches on Android.
enum LibraryClock {

    /// Epoch milliseconds.
    static func wallMillis() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) + PinVault.shared.e2eClockOffsetMs
    }

    /// The same instant as a `Date`.
    static func now() -> Date {
        Date(timeIntervalSince1970: Double(wallMillis()) / 1000)
    }

    /// Monotonic milliseconds (`CLOCK_MONOTONIC_RAW`): untouched by a changed
    /// wall clock — the counterpart of `SystemClock.elapsedRealtime()`.
    static func elapsedMillis() -> Int64 {
        Int64(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1_000_000)
    }

    /// Monotonic nanoseconds (`System.nanoTime()`).
    static func monotonicNanos() -> UInt64 {
        clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
    }
}

/// The time used to decide whether a pin config has expired.
///
/// The device's wall clock alone is not enough: set it back and an expired
/// config is valid again. This clock never goes back on its own. It returns
/// the later of the wall clock and the highest time it has seen — a reference
/// that is persisted (`persist`) and, while the process lives, carried forward
/// by the monotonic clock (`elapsed`, which a changed wall clock does not
/// touch). So rolling the wall clock back neither revives an expired config
/// nor stops time for one that is still valid.
///
/// ## The one way back
/// A wall clock that was once set far ahead by mistake would otherwise leave
/// the reference in the future for good, and every config would look expired.
/// ``resetTo(issuedAt:)`` lowers the reference, and the updater calls it in one
/// case only: a config was accepted whose `issuedAt` is newer than every
/// config accepted before. For a signed block nobody can make such a config
/// without a signing key, and each config can do it once — after that its
/// `issuedAt` is the watermark. The reference then becomes the later of the
/// wall clock and that `issuedAt`.
///
/// What this cannot do: tell the real time after a reboot with the wall clock
/// set back. Time then resumes from the last persisted reference (at most
/// ``persistStepMs`` old), which is still never earlier than what was seen.
///
/// Only expiry decisions use this clock (see `SignedConfigVerifier.expiryNow`
/// in the Kotlin code for the one exception).
///
/// - `load` reads the persisted reference (0 = none). May throw when the
///   store is unreadable; the wall clock is used for that call and the read is
///   tried again later.
/// - `persist` writes the reference. May throw; tried again later.
final class TrustedClock: @unchecked Sendable {

    /// The reference on disk is at most this far behind the time seen.
    static let persistStepMs: Int64 = 5 * 60 * 1000

    /// How long to wait before reading (or writing) an unreadable reference again.
    private static let loadRetryMs: Int64 = 30_000

    private let wall: @Sendable () -> Int64
    private let elapsed: @Sendable () -> Int64
    private let load: @Sendable () throws -> Int64
    private let persist: @Sendable (Int64) throws -> Void
    private let log = PinVaultLog.tag("TrustedClock")

    private struct State {
        /// The highest time seen, and the monotonic clock's reading when it was taken.
        var reference: Int64 = 0
        var referenceElapsed: Int64 = 0
        var loaded = false
        var lastLoadAttemptElapsed: Int64?
        var persisted: Int64 = 0
        var nextWriteAttempt = Int64.min
    }

    // A recursive lock: the closures run with it held (Kotlin `synchronized`), and
    // never call back into this clock.
    private let lock = NSRecursiveLock()
    private var state = State()

    init(
        wall: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis,
        elapsed: @escaping @Sendable () -> Int64 = LibraryClock.elapsedMillis,
        load: @escaping @Sendable () throws -> Int64 = { 0 },
        persist: @escaping @Sendable (Int64) throws -> Void = { _ in }
    ) {
        self.wall = wall
        self.elapsed = elapsed
        self.load = load
        self.persist = persist
    }

    /// The later of the wall clock and the carried-forward reference. Cheap:
    /// writes at most once per ``persistStepMs``.
    func now() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        let now = advance()
        if state.loaded, now - state.persisted >= Self.persistStepMs, now >= state.nextWriteAttempt { write(now) }
        return now
    }

    /// Persists the current time as the reference right away. Called around config fetches.
    func checkpoint() {
        lock.lock()
        defer { lock.unlock() }
        let now = advance()
        if state.loaded, now > state.persisted { write(now) }
    }

    /// Lowers the reference to the later of the wall clock and `issuedAt` —
    /// see the type comment for when. Never raises it.
    func resetTo(issuedAt: Int64) {
        lock.lock()
        defer { lock.unlock() }
        let current = advance()
        let target = max(wall(), issuedAt)
        if !state.loaded || target >= current { return }
        log.w(
            "Trusted clock moved back by \((current - target) / 1000) s: a newer config (issuedAt=\(issuedAt)) " +
                "shows the reference was ahead"
        )
        state.reference = target
        state.referenceElapsed = elapsed()
        write(target)
    }

    private func advance() -> Int64 {
        ensureLoaded()
        let wallNow = wall()
        let elapsedNow = elapsed()
        let carried = state.reference > 0 ? state.reference + max(elapsedNow - state.referenceElapsed, 0) : 0
        let now = max(wallNow, carried)
        state.reference = now
        state.referenceElapsed = elapsedNow
        return now
    }

    private func ensureLoaded() {
        if state.loaded { return }
        let elapsedNow = elapsed()
        if let last = state.lastLoadAttemptElapsed, elapsedNow - last < Self.loadRetryMs { return }
        state.lastLoadAttemptElapsed = elapsedNow
        do {
            let stored = try load()
            state.persisted = stored
            if stored > state.reference {
                state.reference = stored
                state.referenceElapsed = elapsedNow
            }
            state.loaded = true
        } catch {
            log.e("Trusted clock: the stored reference is unreadable — using the wall clock until it can be read", error)
        }
    }

    private func write(_ time: Int64) {
        do {
            try persist(time)
            state.persisted = time
        } catch {
            state.nextWriteAttempt = time + Self.loadRetryMs
            log.w("Trusted clock: could not persist the reference — trying again later", error)
        }
    }
}
