// Vault access tokens (and the enrollment token of a running call), in memory
// only: never written to disk or the Keychain, gone with the process. The
// vault files' `accessToken { … }` providers read from here on every download.
// Every string that goes back to Dart passes through `redact`.
import Foundation

public final class VaultTokenStore: @unchecked Sendable {
    public static let minRedactLength = 6
    public static let maxMessage = 1000

    private let lock = NSLock()
    private var tokens: [String: String] = [:]
    private var transient: [String: Int] = [:]

    public init() {}

    public func put(_ key: String, _ token: String?) {
        lock.lock(); defer { lock.unlock() }
        if let token, !token.isEmpty { tokens[key] = token } else { tokens.removeValue(forKey: key) }
    }

    /// Empty when there is none: the server refuses that as an invalid token.
    public func get(_ key: String) -> String {
        lock.lock(); defer { lock.unlock() }
        return tokens[key] ?? ""
    }

    @discardableResult
    public func clear() -> Int {
        lock.lock(); defer { lock.unlock() }
        let n = tokens.count
        tokens.removeAll()
        return n
    }

    /// A secret that is not stored but must still be redacted while a call runs.
    public func withTransientSecret<T>(_ secret: String, _ body: () async throws -> T) async rethrows -> T {
        addTransient(secret)
        defer { removeTransient(secret) }
        return try await body()
    }

    private func addTransient(_ secret: String) {
        guard secret.count >= Self.minRedactLength else { return }
        lock.lock(); defer { lock.unlock() }
        transient[secret, default: 0] += 1
    }

    private func removeTransient(_ secret: String) {
        lock.lock(); defer { lock.unlock() }
        if let n = transient[secret] {
            if n <= 1 { transient.removeValue(forKey: secret) } else { transient[secret] = n - 1 }
        }
    }

    public func redact(_ text: String?) -> String? {
        guard var out = text else { return nil }
        lock.lock()
        let secrets = Array(tokens.values) + Array(transient.keys)
        lock.unlock()
        for secret in secrets where secret.count >= Self.minRedactLength {
            out = out.replacingOccurrences(of: secret, with: "***")
        }
        return out.count > Self.maxMessage ? String(out.prefix(Self.maxMessage)) + "…" : out
    }
}
