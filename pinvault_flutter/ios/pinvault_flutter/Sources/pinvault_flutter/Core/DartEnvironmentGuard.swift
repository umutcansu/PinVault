// `environmentGuard` answered by a Dart callback. Fail closed: no answer in time,
// an unknown request id — every one of them is a refusal.
//
// PinVault's `EnvironmentGuard.allows(_:)` is synchronous and runs on the
// calling task, i.e. on a thread of Swift's shared cooperative pool. Waiting
// there for Dart would hold that thread for up to the timeout (30 s at most). So
// the plugin asks Dart *before* it calls the library (`withVerdicts`): the wait
// is a suspended continuation, no thread is held, and the library's
// synchronous check answers at once from that verdict. Only an operation the
// library starts on its own (a background refresh picking up a pending
// enrollment, a periodic vault sync) finds no verdict and waits on its own
// thread, bounded by the timeout.
import Foundation
import PinVault

public final class DartEnvironmentGuard: EnvironmentGuard, @unchecked Sendable {
    public static let defaultTimeoutMs: Int64 = 5000
    public static let minTimeoutMs: Int64 = 100
    public static let maxTimeoutMs: Int64 = 30_000

    /// One question to Dart; answered exactly once (by Dart, or `false` at the deadline).
    private final class Pending: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private let deliver: (Bool) -> Void

        init(_ deliver: @escaping (Bool) -> Void) { self.deliver = deliver }

        func finish(_ allowed: Bool) {
            lock.lock()
            let first = !done
            done = true
            lock.unlock()
            if first { deliver(allowed) }
        }
    }

    private let timeoutMs: Int64
    private let ask: (_ requestId: String, _ operation: String) -> Void
    private let lock = NSLock()
    private var pending: [String: Pending] = [:]
    /// Verdicts asked before a plugin call, per operation, while that call runs.
    private var verdicts: [GuardedOperation: [(UUID, Bool)]] = [:]

    public init(timeoutMs: Int64, ask: @escaping (_ requestId: String, _ operation: String) -> Void) {
        self.timeoutMs = timeoutMs
        self.ask = ask
    }

    private func send(_ operation: GuardedOperation, _ deliver: @escaping (Bool) -> Void) {
        let id = UUID().uuidString
        let request = Pending { [weak self] allowed in
            self?.lock.lock()
            self?.pending.removeValue(forKey: id)
            self?.lock.unlock()
            deliver(allowed)
        }
        lock.lock(); pending[id] = request; lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(Int(timeoutMs))) { request.finish(false) }
        ask(id, operation.rawValue)
    }

    /// Dart's verdict on `operation`, waited for without holding a thread.
    public func verdict(_ operation: GuardedOperation) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            send(operation) { continuation.resume(returning: $0) }
        }
    }

    /// Runs `body` (a library call) with Dart's verdicts on `operations` asked
    /// beforehand: the library's synchronous ``allows(_:)`` reads them.
    public func withVerdicts<T>(_ operations: [GuardedOperation], _ body: () async throws -> T) async rethrows -> T {
        var asked: [(GuardedOperation, Bool)] = []
        for operation in operations { asked.append((operation, await verdict(operation))) }
        let token = UUID()
        hold(asked, token)
        defer { release(asked.map(\.0), token) }
        return try await body()
    }

    private func hold(_ asked: [(GuardedOperation, Bool)], _ token: UUID) {
        lock.lock(); defer { lock.unlock() }
        for (operation, allowed) in asked { verdicts[operation, default: []].append((token, allowed)) }
    }

    private func release(_ operations: [GuardedOperation], _ token: UUID) {
        lock.lock(); defer { lock.unlock() }
        for operation in operations { verdicts[operation]?.removeAll { $0.0 == token } }
    }

    public func allows(_ operation: GuardedOperation) throws -> Bool {
        lock.lock()
        let held = verdicts[operation] ?? []
        lock.unlock()
        // Asked before the plugin call that runs now: no waiting. A refusal wins.
        if !held.isEmpty { return held.allSatisfy { $0.1 } }
        // The library asks on its own: wait here, bounded by the timeout.
        let semaphore = DispatchSemaphore(value: 0)
        let result = Locked(false)
        send(operation) { allowed in
            result.set(allowed)
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + .milliseconds(Int(timeoutMs) + 50)) == .success else { return false }
        return result.get()
    }

    /// Dart's verdict; ignored when the request is unknown or already timed out.
    public func answer(_ requestId: String, allowed: Bool) {
        lock.lock()
        let request = pending[requestId]
        lock.unlock()
        request?.finish(allowed)
    }

    public var pendingCount: Int {
        lock.lock(); defer { lock.unlock() }
        return pending.count
    }

    /// A value behind a lock (the answer crosses threads).
    private final class Locked<V>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: V
        init(_ value: V) { self.value = value }
        func set(_ v: V) { lock.lock(); value = v; lock.unlock() }
        func get() -> V { lock.lock(); defer { lock.unlock() }; return value }
    }
}
