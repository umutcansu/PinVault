import Foundation

// Small result types, grouped: InitResult.kt, UpdateResult.kt,
// ScheduledTaskInfo.kt, SigningStatus.kt, VaultFileStatus.kt.

/// Result of `PinVault.start(config:)`.
public enum InitResult: Sendable {
    /// Pinning is ready: safe to proceed with network calls.
    case ready(version: Int)
    /// Start failed — do NOT proceed with network calls. Happens with nothing
    /// stored and the backend unreachable, or `forceUpdate` and the backend unreachable.
    case failed(reason: String, exception: (any Error)? = nil)

    public var isReady: Bool {
        if case .ready = self { return true }
        return false
    }
}

extension InitResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.ready(a), .ready(b)): return a == b
        case let (.failed(a, e1), .failed(b, e2)): return a == b && errorsEqual(e1, e2)
        default: return false
        }
    }
}

extension InitResult: CustomStringConvertible {
    public var description: String {
        switch self {
        case .ready(let version): return "Ready(version=\(version))"
        case .failed(let reason, let exception):
            return "Failed(reason=\(reason), exception=\(exception.map { String(describing: $0) } ?? "null"))"
        }
    }
}

/// Result of a certificate config update.
public enum UpdateResult: Sendable {
    /// Config updated to `newVersion`.
    case updated(newVersion: Int)
    /// Config is already up to date.
    case alreadyCurrent
    /// Update failed.
    case failed(reason: String, exception: (any Error)? = nil)
}

extension UpdateResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.updated(a), .updated(b)): return a == b
        case (.alreadyCurrent, .alreadyCurrent): return true
        case let (.failed(a, e1), .failed(b, e2)): return a == b && errorsEqual(e1, e2)
        default: return false
        }
    }
}

extension UpdateResult: CustomStringConvertible {
    public var description: String {
        switch self {
        case .updated(let version): return "Updated(newVersion=\(version))"
        case .alreadyCurrent: return "AlreadyCurrent"
        case .failed(let reason, let exception):
            return "Failed(reason=\(reason), exception=\(exception.map { String(describing: $0) } ?? "null"))"
        }
    }
}

/// Status of a scheduled pin update task (`PinVault.scheduledTasks()`).
public struct ScheduledTaskInfo: Sendable, Equatable, Hashable, Codable {
    public enum State: String, Sendable, Equatable, Hashable, CaseIterable, Codable {
        case enqueued = "ENQUEUED"
        case running = "RUNNING"
        case succeeded = "SUCCEEDED"
        case failed = "FAILED"
        case cancelled = "CANCELLED"
        case blocked = "BLOCKED"
        case unknown = "UNKNOWN"
    }

    public var id: String
    public var state: State
    public var runAttemptCount: Int

    public init(id: String, state: State, runAttemptCount: Int) {
        self.id = id
        self.state = state
        self.runAttemptCount = runAttemptCount
    }
}

/// How one Config API block verifies signatures right now (`PinVault.signingStatus`).
/// Key ids are Base64 SHA-256 over each key's SPKI — the TLS pin format.
public struct SigningStatus: Sendable, Equatable, Hashable {
    /// The block.
    public var configApiId: String
    /// Keys a config signature may come from: the compiled-in ones, or those of the latest signing-key set.
    public var trustedKeyIds: [String]
    /// How many distinct trusted keys must sign.
    public var requiredSignatures: Int
    /// Version of the applied signing-key set; 0 = compiled-in keys.
    public var keySetVersion: Int
    /// Offline keys allowed to authorise a new key set; empty when rotation is off.
    public var recoveryKeyIds: [String]
    /// Keys whose signatures verified on the most recent accepted config of this process.
    public var lastConfigSignedBy: [String]

    public init(
        configApiId: String,
        trustedKeyIds: [String],
        requiredSignatures: Int,
        keySetVersion: Int,
        recoveryKeyIds: [String],
        lastConfigSignedBy: [String]
    ) {
        self.configApiId = configApiId
        self.trustedKeyIds = trustedKeyIds
        self.requiredSignatures = requiredSignatures
        self.keySetVersion = keySetVersion
        self.recoveryKeyIds = recoveryKeyIds
        self.lastConfigSignedBy = lastConfigSignedBy
    }
}

/// What `PinVault.fileStatus(_:)` says about the stored copy of a vault file.
public enum VaultFileStatus: String, Sendable, Equatable, Hashable, CaseIterable {
    /// A copy is stored and `loadFile` returns it.
    case available = "AVAILABLE"
    /// A copy is stored, sealed with ``UserAuth``: `unlockFile` opens it, `loadFile` returns nil.
    case locked = "LOCKED"
    /// Nothing is stored.
    case notStored = "NOT_STORED"
    /// Older than the file's `maxOfflineAge`; a successful fetch makes it readable again.
    case stale = "STALE"
    /// A signing block's copy without a stored signature (an earlier library version): fetch again.
    case needsFetch = "NEEDS_FETCH"
    /// The copy failed its check when last read and was deleted. Fetch again.
    case integrityFailed = "INTEGRITY_FAILED"
    /// The encrypted storage cannot be read right now (device locked, Keychain failure). Nothing deleted.
    case storageUnavailable = "STORAGE_UNAVAILABLE"
}
