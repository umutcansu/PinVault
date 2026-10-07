import XCTest
@testable import PinVault

/// Kotlin `EdgeCaseTest`, the parts below the updater (E28/E30/per-host
/// forceUpdate are `SSLCertificateUpdater` cases, ported with L2).
final class EdgeCaseTests: XCTestCase {

    private let password = "changeit"

    func testE30AnEmptyPinListRefusesTheConnection() {
        let error = assertThrowsPinVault {
            try testManager().checkServerTrusted(
                [TLSFixture.cert("leaf")], hostname: "localhost", port: 443, config: CertificateConfig(version: 1, pins: [], forceUpdate: true)
            )
        }
        XCTAssertTrue(error?.message.contains("No pins configured") == true)
    }

    func testE32ConcurrentSwapsAreThreadSafe() async {
        let provider = HttpClientProvider(sslManager: testManager())
        let configs = (1...5).map { index in
            CertificateConfig(version: index, pins: [HostPin(hostname: "host\(index).com", sha256: [pin("A"), pin("B")], version: index)])
        }
        await withTaskGroup(of: Void.self) { group in
            for config in configs {
                group.addTask { provider.swap(config) }
                group.addTask { _ = provider.get(); _ = provider.currentConfig }
            }
        }
        XCTAssertGreaterThan(provider.getVersion(), 0)
        XCTAssertEqual(provider.getVersion(), provider.currentConfig?.computedVersion())
        _ = provider.get()
    }

    func testE33TwoHostsTwoCertsAreLoaded() {
        let manager = testManager()
        manager.loadHostClientCerts(["alpha.com": TLSFixture.p12("client-a"), "beta.com": TLSFixture.p12("client-b")], password: password)
        let config = CertificateConfig(version: 1, pins: [
            HostPin(hostname: "alpha.com", sha256: [pin("A"), pin("B")], mtls: true, clientCertVersion: 1),
            HostPin(hostname: "beta.com", sha256: [pin("C"), pin("D")], mtls: true, clientCertVersion: 1),
        ])
        let selector = manager.buildCompositeKeyManagers(configProvider: { config })
        XCTAssertEqual(selector?.select(host: "alpha.com", port: 443)?.identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(selector?.select(host: "beta.com", port: 443)?.identity.leaf?.subject.commonName, "client-b")
    }

    func testE35UpdatingOneHostsCertLeavesTheOtherAlone() {
        let manager = testManager()
        manager.loadHostClientCerts(["stable.com": TLSFixture.p12("client-a"), "updating.com": TLSFixture.p12("client-a")], password: password)
        manager.loadHostClientCerts(["stable.com": TLSFixture.p12("client-a"), "updating.com": TLSFixture.p12("client-b")], password: password)
        let selector = manager.buildCompositeKeyManagers()
        XCTAssertEqual(selector?.select(host: "stable.com", port: 443)?.identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(selector?.select(host: "updating.com", port: 443)?.identity.leaf?.subject.commonName, "client-b")
    }

    func testProviderResetLeavesACleanState() {
        let provider = HttpClientProvider(sslManager: testManager())
        provider.swap(CertificateConfig(version: 3, pins: [HostPin(hostname: "host", sha256: [pin("A"), pin("B")], version: 3)]))
        XCTAssertEqual(provider.getVersion(), 3)
        provider.reset()
        XCTAssertEqual(provider.getVersion(), 0)
        XCTAssertNil(provider.currentConfig)
        _ = provider.get()
    }

    func testDuplicatePinsAreReportedOnce() async {
        let events = EventRecorder()
        let manager = testManager()
        manager.setConnectionListener(events.listener)
        let leaf = TLSFixture.cert("leaf")
        let config = CertificateConfig(version: 1, pins: [HostPin(hostname: "localhost", sha256: [leaf.spkiPin, leaf.spkiPin])])
        try? manager.checkServerTrusted([leaf], hostname: "localhost", port: 443, config: config)
        let delivered = await eventually { !events.all.isEmpty }
        XCTAssertTrue(delivered)
        guard case .connection(_, true, _, _, _, _, let expected)? = events.all.first else { return XCTFail("\(events.all)") }
        XCTAssertEqual(expected, [leaf.spkiPin])
    }

    func testTheListenerCanBeReplacedAndRemoved() async {
        let first = EventRecorder()
        let second = EventRecorder()
        let manager = DynamicSSLManager(connectionListener: first.listener)
        manager.dispatchEvent(.configUpdate(status: .updated, newVersion: 2, deviceManufacturer: "Apple", deviceModel: "x"))
        manager.setConnectionListener(second.listener)
        manager.dispatchEvent(.configUpdate(status: .unchanged, newVersion: 2, deviceManufacturer: "Apple", deviceModel: "x"))
        manager.setConnectionListener(nil)
        manager.dispatchEvent(.configUpdate(status: .failed, newVersion: 2, deviceManufacturer: "Apple", deviceModel: "x"))
        let delivered = await eventually { first.all.count == 1 && second.all.count == 1 }
        XCTAssertTrue(delivered)
        try? await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(first.all.count + second.all.count, 2, "nothing goes out without a listener")
    }

    func testEventsAreDeliveredInOrder() async {
        let events = EventRecorder()
        let manager = DynamicSSLManager(connectionListener: events.listener)
        for version in 0..<50 {
            manager.dispatchEvent(.configUpdate(status: .updated, newVersion: version, deviceManufacturer: "Apple", deviceModel: "x"))
        }
        let all = await eventually { events.all.count == 50 }
        XCTAssertTrue(all)
        let versions = events.all.compactMap { event -> Int? in
            if case .configUpdate(_, let version, _, _, _) = event { return version }
            return nil
        }
        XCTAssertEqual(versions, Array(0..<50))
    }
}
