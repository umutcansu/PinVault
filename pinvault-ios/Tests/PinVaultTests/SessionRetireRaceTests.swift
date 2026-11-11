import Foundation
import XCTest
@testable import PinVault

/// A task must never be created on a `URLSession` that was invalidated:
/// URLSession answers that with an Objective-C exception Swift cannot catch,
/// and the process dies. The transport hands a session out and creates the
/// task a moment later, while a pin update, an identity change or a failed
/// per-request check retires that same session from another thread.
final class SessionRetireRaceTests: XCTestCase {

    private var servers: [TestServer] = []

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func transport(_ manager: DynamicSSLManager = testManager()) -> URLSessionTransport {
        URLSessionTransport(
            manager: manager, configuration: .ephemeral, trust: .pinned({ nil }), resolveOverrides: [:], redirects: .sameScheme
        )
    }

    func testCreatingTasksWhileTheSessionsAreRetiredNeverReachesAnInvalidatedSession() {
        let transport = transport()
        let request = URLRequest(url: URL(string: "ws://127.0.0.1:9/socket")!)
        let created = Locked(0)
        // Half of the threads create socket tasks (never resumed: nothing
        // connects), the other half retire every session of the transport.
        DispatchQueue.concurrentPerform(iterations: 4000) { index in
            if index % 2 == 0 {
                transport.retireSessions()
            } else {
                do {
                    let task = try transport.webSocketTask(for: request)
                    created.withLock { $0 += 1 }
                    task.cancel()
                } catch PinVaultError.io {
                    // Lost the race `maxSessionAttempts` times in a row: refused, not crashed.
                } catch {
                    XCTFail("\(error)")
                }
            }
        }
        XCTAssertGreaterThan(created.withLock { $0 }, 1000, "sockets are built on sessions that are still open")
        transport.invalidate()
    }

    func testRequestsSentWhileTheSessionsAreRetiredAllArrive() async throws {
        let server = try TestServer(p12: nil, chain: [])
        try await server.start()
        servers.append(server)
        let transport = transport()
        let session = PinnedSession(transport: transport)
        let url = server.url("/")

        let retiring = Task.detached {
            while !Task.isCancelled {
                transport.retireSessions()
                try? await Task.sleep(nanoseconds: 200_000)
            }
        }
        defer { retiring.cancel() }
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<200 {
                group.addTask { ((try await session.data(from: url)).1 as! HTTPURLResponse).statusCode }
            }
            for try await status in group { XCTAssertEqual(status, 200) }
        }
    }

    /// `invalidate()` cancels a session's tasks. A task cancelled between being
    /// made and getting its collector completed with nobody listening, and the
    /// request never returned. Every request must end, whatever the timing.
    func testARequestCancelledByInvalidateWhileItStartsStillEnds() async throws {
        let server = try TestServer(p12: nil, chain: [])
        try await server.start()
        servers.append(server)
        let url = server.url("/")
        let ended = expectation(description: "every request ended")
        ended.expectedFulfillmentCount = 300
        for round in 0..<300 {
            let transport = transport()
            let session = PinnedSession(transport: transport)
            Task.detached {
                _ = try? await session.data(from: url)
                ended.fulfill()
            }
            Task.detached {
                // Spread around the moment the task is made.
                if round % 3 != 0 { await Task.yield() }
                transport.invalidate()
            }
        }
        await fulfillment(of: [ended], timeout: 30)
    }

    func testAnInvalidatedTransportRefusesInsteadOfRetrying() {
        let transport = transport()
        transport.invalidate()
        XCTAssertThrowsError(try transport.webSocketTask(for: URLRequest(url: URL(string: "ws://127.0.0.1:9/socket")!))) { error in
            guard case PinVaultError.illegalState = error else { return XCTFail("\(error)") }
        }
    }
}
