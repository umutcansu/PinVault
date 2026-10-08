import Foundation

/// A value behind an `NSLock`. Every access goes through ``withLock(_:)``, so
/// the box can be shared across threads and tasks.
///
/// Never `await` inside the closure (it is synchronous by design) and never
/// call back into code that takes the same lock: `NSLock` is not reentrant.
final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) {
        self.value = value
    }

    /// Runs `body` with exclusive access to the value and returns its result.
    @discardableResult
    func withLock<Result>(_ body: (inout Value) throws -> Result) rethrows -> Result {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }

    /// A copy of the current value.
    func get() -> Value {
        withLock { $0 }
    }

    /// Replaces the value.
    func set(_ newValue: Value) {
        withLock { $0 = newValue }
    }
}
