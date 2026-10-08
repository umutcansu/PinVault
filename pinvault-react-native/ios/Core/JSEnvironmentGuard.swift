// `environmentGuard` answered by a JS callback. PinVault asks synchronously on
// one of its own tasks; this sends `{requestId, operation}` to JS and waits for
// `answer` up to the timeout. Fail closed: no answer in time, an unknown request
// id — every one of them is a refusal. The answer arrives on the module's method
// queue, never on the waiting thread.
import Foundation
import PinVault

public final class JSEnvironmentGuard: EnvironmentGuard, @unchecked Sendable {
    public static let defaultTimeoutMs: Int64 = 5000
    public static let minTimeoutMs: Int64 = 100
    public static let maxTimeoutMs: Int64 = 30_000

    private final class Pending {
        let semaphore = DispatchSemaphore(value: 0)
        var allowed = false
    }

    private let timeoutMs: Int64
    private let ask: (_ requestId: String, _ operation: String) -> Void
    private let lock = NSLock()
    private var pending: [String: Pending] = [:]

    public init(timeoutMs: Int64, ask: @escaping (_ requestId: String, _ operation: String) -> Void) {
        self.timeoutMs = timeoutMs
        self.ask = ask
    }

    public func allows(_ operation: GuardedOperation) throws -> Bool {
        let id = UUID().uuidString
        let request = Pending()
        lock.lock(); pending[id] = request; lock.unlock()
        defer { lock.lock(); pending.removeValue(forKey: id); lock.unlock() }
        ask(id, operation.rawValue)
        guard request.semaphore.wait(timeout: .now() + .milliseconds(Int(timeoutMs))) == .success else { return false }
        lock.lock(); defer { lock.unlock() }
        return request.allowed
    }

    /// JS's verdict; ignored when the request is unknown or already timed out.
    public func answer(_ requestId: String, allowed: Bool) {
        lock.lock()
        let request = pending[requestId]
        request?.allowed = allowed
        lock.unlock()
        request?.semaphore.signal()
    }

    public var pendingCount: Int {
        lock.lock(); defer { lock.unlock() }
        return pending.count
    }
}
