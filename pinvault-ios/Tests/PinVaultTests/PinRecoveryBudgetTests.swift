import XCTest
@testable import PinVault

/// What a failing handshake may cost the backend: the refetch budget across
/// hosts, the single refetch for hosts the config does not know, the bounded
/// state, and one refetch for requests that fail together (Kotlin `PinRecoveryBudgetTest`).
final class PinRecoveryBudgetTests: XCTestCase {

    private final class Clock: @unchecked Sendable {
        var now: Int64 = 1_000_000
    }

    private let minute: Int64 = 60_000
    private var clock = Clock()
    private var refetches = Counter()

    override func setUp() {
        clock = Clock()
        refetches = Counter()
    }

    private func interceptor(updated: Bool = false, onRefetch: @escaping @Sendable () async -> Void = {}) -> PinRecoveryInterceptor {
        let clock = self.clock
        let refetches = self.refetches
        return PinRecoveryInterceptor(
            updater: { refetches.increment(); await onRefetch(); return updated },
            clock: { clock.now }
        )
    }

    private func noPinEntry(_ host: String) -> PinVaultError {
        .sslHandshake(message: "no entry", cause: PinVaultError.unpinnedHost(message: "No pin entry for hostname '\(host)'"))
    }

    /// One request to `host` whose every attempt fails with `failure`.
    private func attempt(_ interceptor: PinRecoveryInterceptor, _ host: String, _ failure: @escaping @Sendable (String) -> PinVaultError = { _ in mismatch() }) async {
        do {
            _ = try await interceptor.intercept(exchange("https://\(host)/")) { _ in throw failure(host) }
            XCTFail("the request should have failed")
        } catch {}
    }

    func testTheRefetchBudgetIsSharedByAllHosts() async {
        let interceptor = interceptor()
        // Every new host name used to bring a fresh budget of its own.
        for index in 0..<40 { await attempt(interceptor, "host\(index).example.com") }
        XCTAssertEqual(refetches.count, PinRecoveryInterceptor.globalMaxRefetches)

        // The window passes: there is budget again.
        clock.now += 6 * minute
        await attempt(interceptor, "later.example.com")
        XCTAssertEqual(refetches.count, PinRecoveryInterceptor.globalMaxRefetches + 1)
    }

    func testHostsWithoutAPinEntryGetOneRefetchPerWindowBetweenThem() async {
        let interceptor = interceptor()
        let unknown: @Sendable (String) -> PinVaultError = { host in
            .sslHandshake(message: "no entry", cause: PinVaultError.unpinnedHost(message: "No pin entry for hostname '\(host)'"))
        }
        await attempt(interceptor, "unknown-1.example.com", unknown)
        await attempt(interceptor, "unknown-2.example.com", unknown)
        await attempt(interceptor, "unknown-3.example.com", unknown)
        XCTAssertEqual(refetches.count, 1, "one refetch: the config may have gained the host")

        // A host managed trust roots refused shares that budget.
        await attempt(interceptor, "managed.example.com") { _ in
            .sslHandshake(message: "x", cause: PinVaultError.managedTrustRoot(message: "does not list"))
        }
        XCTAssertEqual(refetches.count, 1)

        // A real mismatch on a pinned host is not held back by that.
        await attempt(interceptor, "pinned.example.com")
        XCTAssertEqual(refetches.count, 2)

        clock.now += 6 * minute
        await attempt(interceptor, "unknown-4.example.com", unknown)
        XCTAssertEqual(refetches.count, 3)
    }

    func testAHostTheRefetchBroughtInIsRetried() async throws {
        let interceptor = interceptor(updated: true)
        let calls = Counter()
        let failure = noPinEntry("new.example.com")
        let response = try await interceptor.intercept(exchange("https://new.example.com/")) { _ in
            if calls.increment() == 1 { throw failure }
            return fakeResponse(200)
        }
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(refetches.count, 1)
    }

    func testThePerHostStateIsBounded() async {
        let interceptor = interceptor()
        // Failed recoveries for far more hosts than are tracked (the budget is
        // refilled between rounds so each host gets its failure recorded).
        for index in 0..<(PinRecoveryInterceptor.maxTrackedHosts * 3) {
            clock.now += 6 * minute
            await attempt(interceptor, "host\(index).example.com")
        }
        XCTAssertEqual(interceptor.trackedHosts.count, PinRecoveryInterceptor.maxTrackedHosts)
        XCTAssertNotNil(interceptor.trackedHosts["host\(PinRecoveryInterceptor.maxTrackedHosts * 3 - 1).example.com"], "the newest stays")
        XCTAssertNil(interceptor.trackedHosts["host0.example.com"], "the oldest went first")
    }

    func testTheBreakerStillTripsPerHost() async {
        let interceptor = interceptor()
        for _ in 0..<10 { await attempt(interceptor, "api.example.com") }
        XCTAssertEqual(refetches.count, 3, "three failed recoveries, then cooldown")

        // Ten minutes later the host is out of cooldown.
        clock.now += PinRecoveryInterceptor.cooldownMs + 1
        await attempt(interceptor, "api.example.com")
        XCTAssertEqual(refetches.count, 4)
    }

    func testRequestsThatFailTogetherShareOneRefetch() async {
        let threads = 8
        let arrived = Counter()
        let interceptor = interceptor(updated: false) {
            try? await Task.sleep(nanoseconds: 300_000_000)  // the others pile up on the gate meanwhile
        }
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<threads {
                group.addTask {
                    do {
                        _ = try await interceptor.intercept(exchange("https://api.example.com/")) { _ in
                            // All requests are in flight before any of them fails.
                            arrived.increment()
                            let deadline = Date().addingTimeInterval(5)
                            while arrived.count < threads, Date() < deadline { try? await Task.sleep(nanoseconds: 5_000_000) }
                            throw mismatch()
                        }
                    } catch {}
                }
            }
        }
        XCTAssertEqual(refetches.count, 1, "one Config API request for \(threads) failures")
    }
}
