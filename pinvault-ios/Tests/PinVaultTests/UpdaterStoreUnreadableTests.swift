import Foundation
import XCTest
@testable import PinVault

/// The two updater cases of StoreUnreadableTest: a Keychain that fails is not
/// an empty store — an update applies nothing, start fails, and both work
/// again once the Keychain does.
final class UpdaterStoreUnreadableTests: XCTestCase {

    private let cipher = FlakyCipher()
    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private var file: PrefsFile!

    override func setUpWithError() throws {
        let directory = try temporaryStoreDirectory(self)
        file = SecureStoreEnvironment(directory: directory, cipher: cipher).file("unreadable_test")
    }

    private func strictStore() throws -> CertificateConfigStore {
        let store = CertificateConfigStore(prefs: try SecurePreferences(
            backing: file, fileName: "unreadable_test", namespace: "config", cipher: cipher, strict: true
        ))
        let now = self.now
        store.clock = { now }
        return store
    }

    private func config(_ version: Int, issuedAt: Int64, expiresAt: Int64) -> CertificateConfig {
        CertificateConfig(version: version, pins: [HostPin(hostname: "api.test", sha256: [pin("A"), pin("B")], version: version)],
                          issuedAt: issuedAt, expiresAt: expiresAt)
    }

    private func updater(_ api: FakeConfigApi, _ store: CertificateConfigStore, _ provider: HttpClientProvider) -> SSLCertificateUpdater {
        let now = self.now
        return SSLCertificateUpdater(configApi: api, configStore: store, httpClientProvider: provider, maxRetryCount: 1, clock: { now }, sleep: { _ in })
    }

    func testAnUpdateWithAnUnreadableStoreAppliesNothingAndWorksAgainAfterwards() async throws {
        let store = try strictStore()
        let api = FakeConfigApi()
        let provider = HttpClientProvider(sslManager: DynamicSSLManager())
        let updater = updater(api, store, provider)
        api.returns(config(4, issuedAt: now - hour, expiresAt: now + hour))
        let first = await updater.updateNow()
        XCTAssertEqual(first, .updated(newVersion: 4))

        // An OLDER config arrives while the watermark cannot be read. With the
        // watermark read as 0 it would have been accepted.
        cipher.broken = true
        api.returns(config(3, issuedAt: now - 2 * hour, expiresAt: now + hour))
        let failed = await updater.updateNow()
        guard case .failed(_, let exception) = failed, case .storeUnreadable? = exception as? PinVaultError else {
            return XCTFail("\(failed)")
        }
        XCTAssertEqual(provider.currentConfig?.computedVersion(), 4)

        cipher.broken = false
        let replay = await updater.updateNow()
        guard case .failed(let reason, _) = replay else { return XCTFail("\(replay)") }
        XCTAssertTrue(reason.lowercased().contains("replay"), reason)
        XCTAssertEqual(try store.load()?.computedVersion(), 4)
    }

    func testStartWithAnUnreadableStoreFailsAndAppliesNoConfig() async throws {
        let store = try strictStore()
        try store.save(config(4, issuedAt: now - hour, expiresAt: now + hour))
        let api = FakeConfigApi()
        api.returns(config(5, issuedAt: now, expiresAt: now + hour))
        api.healthy = { true }
        let provider = HttpClientProvider(sslManager: DynamicSSLManager())

        cipher.broken = true
        let result = try await updater(api, store, provider).initializeAndUpdate()
        guard case .failed(_, let exception) = result, case .storeUnreadable? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertNil(provider.currentConfig, "nothing applied: pinned sessions keep refusing")

        cipher.broken = false
        let again = try await updater(api, store, provider).initializeAndUpdate()
        XCTAssertEqual(again, .ready(version: 5))
    }
}
