import Foundation
import XCTest
@testable import PinVault

// Test support of the updater and the façade (L2).

/// A ``CertificateConfigStore`` that records what the updater writes (the
/// Kotlin tests' relaxed mock); the reads are the real store's.
final class SpyConfigStore: UpdaterConfigStore, @unchecked Sendable {
    let base: CertificateConfigStore
    private let lock = NSLock()
    private var _saves: [CertificateConfig] = []
    private var _clearActiveCalls = 0
    private var _wipeAllCalls = 0

    init(base: CertificateConfigStore = CertificateConfigStore(prefs: InMemoryPreferences())) {
        self.base = base
    }

    var saves: [CertificateConfig] { lock.withLock { _saves } }
    var clearActiveCalls: Int { lock.withLock { _clearActiveCalls } }
    var wipeAllCalls: Int { lock.withLock { _wipeAllCalls } }

    func getCurrentVersion() throws -> Int { try base.getCurrentVersion() }
    func getCurrentIssuedAt() throws -> Int64 { try base.getCurrentIssuedAt() }
    func getVersionWatermarks() throws -> [String: Int] { try base.getVersionWatermarks() }

    func save(_ config: CertificateConfig, envelope: StoredEnvelope?) throws {
        lock.withLock { _saves.append(config) }
        try base.save(config, envelope: envelope)
    }

    func load() throws -> CertificateConfig? { try base.load() }
    func loadEnvelope() throws -> StoredEnvelope? { try base.loadEnvelope() }
    func markRolledBack(_ config: CertificateConfig) throws { try base.markRolledBack(config) }
    func isRolledBack(_ config: CertificateConfig) throws -> Bool { try base.isRolledBack(config) }

    func clearActive(keepAsWatermarks: Bool) throws {
        lock.withLock { _clearActiveCalls += 1 }
        try base.clearActive(keepAsWatermarks: keepAsWatermarks)
    }

    func wipeAll() throws {
        lock.withLock { _wipeAllCalls += 1 }
        try base.wipeAll()
    }

    func reconcileMirror(keySetVersion: Int, anchors: String) { base.reconcileMirror(keySetVersion: keySetVersion, anchors: anchors) }
    func resetWatermarks(keySetVersion: Int, anchors: String?) throws { try base.resetWatermarks(keySetVersion: keySetVersion, anchors: anchors) }
    func keySetVersionSeen() throws -> Int? { try base.keySetVersionSeen() }
    func setKeySetVersionSeen(_ version: Int) throws { try base.setKeySetVersionSeen(version) }
    func trustAnchorsSeen() throws -> String? { try base.trustAnchorsSeen() }
    func setTrustAnchorsSeen(_ fingerprint: String) throws { try base.setTrustAnchorsSeen(fingerprint) }
}

/// A host client certificate store in memory (L3 fills the real one).
final class InMemoryHostCertStore: HostClientCertStore, @unchecked Sendable {
    private let entries = Locked<[String: Data]>([:])
    private let loads = Locked<[String]>([])
    private let savedLabels = Locked<[String]>([])

    var stored: [String: Data] { entries.get() }
    var loaded: [String] { loads.get() }
    var saved: [String] { savedLabels.get() }

    func exists(_ label: String) -> Bool { entries.get()[label] != nil }

    func load(_ label: String) -> Data? {
        loads.withLock { $0.append(label) }
        return entries.get()[label]
    }

    func save(_ label: String, _ p12: Data) {
        savedLabels.withLock { $0.append(label) }
        entries.withLock { $0[label] = p12 }
    }

    func put(_ label: String, _ p12: Data) {
        entries.withLock { $0[label] = p12 }
    }
}

/// An updater wait that returns at once (and records how long it was asked to wait).
final class SleepRecorder: @unchecked Sendable {
    private let waits = Locked<[Int64]>([])
    var recorded: [Int64] { waits.get() }
    var sleep: @Sendable (Int64) async -> Void {
        { [waits] ms in waits.withLock { $0.append(ms) } }
    }
}

/// A fresh ``PinVault`` whose stores live in a temporary directory with
/// in-memory keys, and whose start never waits between attempts.
func isolatedPinVault(_ testCase: XCTestCase) throws -> PinVault {
    let vault = PinVault()
    let environment = SecureStoreEnvironment(directory: try temporaryStoreDirectory(testCase))
    vault.storeEnvironment = environment
    vault.enrollmentStorage = .on(environment, identityKeys: { ClientIdentityKeys.software(label: $0) }, importedKeys: InMemoryImportedClientKeys())
    vault.appAttestationSource = nil
    vault.retrySleep = { _ in }
    return vault
}
