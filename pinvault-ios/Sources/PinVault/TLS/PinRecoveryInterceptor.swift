import Foundation

/// Catches pin-mismatch failures, fetches updated pins and retries the request
/// (Kotlin `PinRecoveryInterceptor`).
///
/// 1. The request fails with a pin mismatch;
/// 2. the updater fetches a new config;
/// 3. it brought one → the request is retried; it did not → the original error is thrown.
///
/// ## What counts as a mismatch
/// By error type only: ``PinVaultError/sslPeerUnverified(message:)``, or
/// ``PinVaultError/sslHandshake(message:cause:)`` whose cause is a certificate
/// error (the `CertificateException` family) — never by message text. Three
/// certificate failures are excluded, since no config can repair them: a
/// leaf outside its validity window (``PinVaultError/certificateValidity(message:cause:)``),
/// a chain the platform CAs refuse under `requireCaTrust`
/// (``PinVaultError/caTrust(message:cause:)``), and a leaf that chains to a
/// pinned issuer but is issued for another host (``PinVaultError/hostnameMismatch(message:cause:)``).
/// An EXPIRED config is exactly what a refetch repairs, so it stays recoverable.
///
/// ## Budget
/// A refetch costs the backend a request, and a failing handshake is something
/// anyone on the network can cause. Recovery is bounded three ways:
///   - **Per host** (circuit breaker): after 3 failed recoveries within 5
///     minutes, the host enters a 10-minute cooldown; the original error is
///     then rethrown without consulting the updater. At most 64 hosts are
///     tracked (least recently used first out).
///   - **Across hosts**: at most 6 refetches per 5 minutes, whatever the hosts.
///   - **Unknown hosts**: a host the config has no pin entry for (or that
///     managed trust roots refused) is worth one refetch — the config may have
///     gained the host since — but only one per window for all such hosts together.
///
/// Refetches are serialised (single flight), and requests that fail together
/// share one: the cooldown and the budget are checked inside the gate, and a
/// request that finds a refetch finished since it started takes that
/// refetch's outcome instead of running its own.
final class PinRecoveryInterceptor: PinnedInterceptor, @unchecked Sendable {

    /// How many failed recoveries within ``attemptWindowMs`` trip the breaker.
    static let maxAttemptsPerWindow = 3
    /// Sliding window for counting recovery failures (5 minutes).
    static let attemptWindowMs: Int64 = 5 * 60 * 1000
    /// How long the breaker stays open after tripping (10 minutes).
    static let cooldownMs: Int64 = 10 * 60 * 1000
    /// Refetches allowed per ``attemptWindowMs`` across all hosts.
    static let globalMaxRefetches = 6
    /// Hosts whose recovery state is kept; the least recently used one goes first.
    static let maxTrackedHosts = 64

    private static let log = PinVaultLog.tag("PinRecoveryInterceptor")

    private let updater: @Sendable () async throws -> Bool
    /// Fallback session for the retry, used only when the retry on the caller's
    /// own chain still hits a pin mismatch.
    private let newClientProvider: (@Sendable () -> PinnedSession?)?
    /// Wall clock for the windows and the cooldown (library clock); tests set it.
    private let clock: @Sendable () -> Int64

    /// Per-host recovery state, tracked separately so a misbehaving host cannot
    /// starve recovery for unrelated hosts.
    struct RecoveryState: Equatable, Sendable {
        var firstAttemptMs: Int64 = 0
        var attemptCount = 0
        var cooldownUntilMs: Int64 = 0
    }

    private struct State {
        /// Access-ordered (oldest first) and bounded: host names come from requests.
        var recoveryState: [String: RecoveryState] = [:]
        var order: [String] = []
        /// When the refetches of the current window started, oldest first.
        var refetchTimes: [Int64] = []
        /// When a refetch was last spent on a host without a pin entry.
        var lastUnknownHostRefetchMs: Int64?
        /// The last refetch: when it finished (monotonic ns) and whether it brought a usable config.
        var lastRefetch: (finishedAtNanos: UInt64, updated: Bool)?

        mutating func touch(_ host: String) {
            order.removeAll { $0 == host }
            order.append(host)
        }

        mutating func stateFor(_ host: String) -> RecoveryState {
            if recoveryState[host] == nil {
                recoveryState[host] = RecoveryState()
                order.append(host)
                while order.count > PinRecoveryInterceptor.maxTrackedHosts {
                    recoveryState[order.removeFirst()] = nil
                }
            } else {
                touch(host)
            }
            return recoveryState[host]!
        }
    }

    private let state = Locked(State())
    /// Serialises refetches (the Kotlin `synchronized(lock)` around the updater).
    private let gate = AsyncGate()

    init(
        updater: @escaping @Sendable () async throws -> Bool,
        newClientProvider: (@Sendable () -> PinnedSession?)? = nil,
        clock: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis
    ) {
        self.updater = updater
        self.newClientProvider = newClientProvider
        self.clock = clock
    }

    /// The tracked per-host state (tests).
    var trackedHosts: [String: RecoveryState] {
        state.withLock { $0.recoveryState }
    }

    func intercept(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        // The fallback retry runs on a session that has this interceptor too;
        // one recovery per request, never a nested one.
        if exchange.tags.contains(.recoveryAttempt) { return try await proceed(exchange) }
        let startedAtNanos = LibraryClock.monotonicNanos()
        do {
            return try await proceed(exchange)
        } catch {
            guard Self.isPinMismatch(error) else { throw error }
            let host = exchange.host
            let updated = try await refetch(host: host, startedAtNanos: startedAtNanos, failure: error)
            if !updated {
                recordFailure(host)
                Self.log.e("Auto-recovery failed for \(host) — update unsuccessful")
                throw error
            }
            // A stream body was read by the first attempt: re-sending it would send
            // nothing (OkHttp fails such a retry). The pins are repaired for the next request.
            if exchange.request.httpBodyStream != nil {
                Self.log.w("Pins updated, but the request body to \(host) can be sent once only — not retried")
                throw error
            }
            Self.log.d("Pins updated — retrying request to \(host)")
            do {
                let response = try await retry(exchange, proceed: proceed)
                recordSuccess(host)
                return response
            } catch let retryError {
                recordFailure(host)
                throw retryError
            }
        }
    }

    /// The refetch for a failed request (or the outcome of one that finished
    /// since it started); throws `failure` when recovery must not try.
    private func refetch(host: String, startedAtNanos: UInt64, failure: any Error) async throws -> Bool {
        await gate.lock()
        defer { gate.unlock() }
        // Inside the gate on purpose: of several requests failing together, the
        // first refetches; by the time the others get here the host may be in
        // cooldown or the answer may be in.
        if isInCooldown(host) {
            Self.log.w("Pin recovery in cooldown for \(host) — rethrowing")
            throw failure
        }
        if let last = state.withLock({ $0.lastRefetch }), last.finishedAtNanos > startedAtNanos {
            Self.log.d("Pin failure for \(host) — a config refetch finished since this request started, using its result")
            return last.updated
        }
        // A host the config has no entry for — or that managed trust roots
        // refused — earns the smaller "unknown host" budget.
        if !takeBudget(host, unknownHost: Self.isUnknownHost(failure)) { throw failure }
        Self.log.w("Pin mismatch detected for \(host) — attempting auto-recovery")
        let result: Bool
        do {
            result = try await updater()
        } catch {
            Self.log.e("Auto-recovery for \(host) threw", error)
            result = false
        }
        state.withLock { $0.lastRefetch = (LibraryClock.monotonicNanos(), result) }
        return result
    }

    /// True when one more refetch may be spent now, and then it is counted.
    private func takeBudget(_ host: String, unknownHost: Bool) -> Bool {
        let now = clock()
        return state.withLock { state -> Bool in
            state.refetchTimes.removeAll { now - $0 > Self.attemptWindowMs }
            if unknownHost, let last = state.lastUnknownHostRefetchMs, (0...Self.attemptWindowMs).contains(now - last) {
                Self.log.w("No pin entry for \(host) — a refetch for an unknown host was already spent in this window, rethrowing")
                return false
            }
            if state.refetchTimes.count >= Self.globalMaxRefetches {
                Self.log.w(
                    "Pin recovery budget used up (\(Self.globalMaxRefetches) refetches in \(Self.attemptWindowMs / 60_000) min) — " +
                        "rethrowing for \(host)"
                )
                return false
            }
            if unknownHost { state.lastUnknownHostRefetchMs = now }
            state.refetchTimes.append(now)
            return true
        }
    }

    /// Retries on the CALLER's chain first: its transport re-reads the live
    /// config and rebuilds its sessions after a pin change, and when the
    /// session is one the app configured (`applyTo`) the retry keeps the app's
    /// configuration. A second attempt runs on the library's current session
    /// ([newClientProvider]) only when that still mismatches. If the fallback
    /// fails too, the caller gets the error from its own chain (the fallback's
    /// is logged): the fallback carries none of the app's settings, and its
    /// failure would hide the real diagnosis.
    private func retry(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        do {
            return try await proceed(exchange)
        } catch {
            guard let fallback = newClientProvider?(), Self.isPinMismatch(error) else { throw error }
            Self.log.d("Retry on the caller's client still mismatched — retrying on the refreshed client")
            do {
                return try await fallback.send(exchange.tagged(.recoveryAttempt))
            } catch let fallbackError {
                Self.log.w("Fallback retry on the refreshed client also failed — rethrowing the original pin error", fallbackError)
                throw error
            }
        }
    }

    /// True for a failure a fresh config may repair (see the type comment).
    static func isPinMismatch(_ error: any Error) -> Bool {
        guard let error = error as? PinVaultError else { return false }
        switch error {
        case .sslPeerUnverified:
            return true
        case .sslHandshake(_, let cause):
            guard let cause = cause as? PinVaultError, cause.isCertificateException else { return false }
            switch cause {
            case .certificateValidity, .caTrust, .hostnameMismatch: return false
            default: return true
            }
        default:
            return false
        }
    }

    private static func isUnknownHost(_ error: any Error) -> Bool {
        guard case .sslHandshake(_, let cause)? = error as? PinVaultError, let cause = cause as? PinVaultError else { return false }
        switch cause {
        case .unpinnedHost, .managedTrustRoot: return true
        default: return false
        }
    }

    private func isInCooldown(_ host: String) -> Bool {
        let now = clock()
        return state.withLock { state -> Bool in
            guard let entry = state.recoveryState[host] else { return false }
            state.touch(host)
            return now < entry.cooldownUntilMs
        }
    }

    private func recordFailure(_ host: String) {
        let now = clock()
        state.withLock { state in
            var entry = state.stateFor(host)
            // Reset the window when the previous one has elapsed.
            if now - entry.firstAttemptMs > Self.attemptWindowMs {
                entry.firstAttemptMs = now
                entry.attemptCount = 1
            } else {
                entry.attemptCount += 1
            }
            if entry.attemptCount >= Self.maxAttemptsPerWindow {
                entry.cooldownUntilMs = now + Self.cooldownMs
                Self.log.w("Pin recovery circuit-broken for \(host) until +\(Self.cooldownMs)ms")
            }
            state.recoveryState[host] = entry
        }
    }

    private func recordSuccess(_ host: String) {
        // Intentionally a no-op. Clearing the per-host state on success let a
        // partial MITM keep the breaker open indefinitely by interleaving forged
        // handshakes with legitimate ones: the failure counter only ages out
        // through the window in recordFailure.
        _ = host
    }
}

/// A FIFO mutex for async code (never held across anything but the refetch).
final class AsyncGate: @unchecked Sendable {
    private let mutex = NSLock()
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func lock() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            mutex.lock()
            if held {
                waiters.append(continuation)
                mutex.unlock()
            } else {
                held = true
                mutex.unlock()
                continuation.resume()
            }
        }
    }

    func unlock() {
        mutex.lock()
        if waiters.isEmpty {
            held = false
            mutex.unlock()
        } else {
            let next = waiters.removeFirst()
            mutex.unlock()
            next.resume()
        }
    }
}
