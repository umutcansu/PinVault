import XCTest
@testable import PinVault

/// A transport answering from a closure.
struct FakeTransport: PinnedTransport {
    let answer: @Sendable (PinnedExchange) async throws -> PinnedResponse

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        try await answer(exchange)
    }

    func invalidate() {}
}

func fakeResponse(_ status: Int = 200, _ body: String = "ok", url: URL? = nil, headers: [String: String] = [:]) -> PinnedResponse {
    PinnedResponse(
        data: Data(body.utf8),
        response: HTTPURLResponse(url: url ?? URL(string: "https://example.com/test")!, statusCode: status, httpVersion: nil, headerFields: headers)!,
        presentedClientCertificate: nil
    )
}

func exchange(_ url: String = "https://example.com/test") -> PinnedExchange {
    PinnedExchange(request: URLRequest(url: URL(string: url)!))
}

/// A pin mismatch as the trust check reports it.
func mismatch(_ message: String = "Certificate pinning failure for example.com") -> PinVaultError {
    .sslHandshake(message: "handshake failed", cause: PinVaultError.certificate(message: message))
}

/// Counts calls (thread-safe).
final class Counter: @unchecked Sendable {
    private let value = Locked(0)
    @discardableResult func increment() -> Int { value.withLock { $0 += 1; return $0 } }
    var count: Int { value.get() }
}

/// Pin mismatch recovery: wrong pin → automatic update → retry (Kotlin `PinRecoveryInterceptorTest`).
final class PinRecoveryInterceptorTests: XCTestCase {

    private func intercept(
        _ interceptor: PinRecoveryInterceptor,
        _ proceed: @escaping @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        try await interceptor.intercept(exchange(), proceed: proceed)
    }

    func testIsPinMismatchDetection() {
        XCTAssertTrue(PinRecoveryInterceptor.isPinMismatch(PinVaultError.sslPeerUnverified(message: "test")))
        XCTAssertTrue(PinRecoveryInterceptor.isPinMismatch(mismatch()))
        XCTAssertTrue(PinRecoveryInterceptor.isPinMismatch(PinVaultError.sslHandshake(message: "x", cause: PinVaultError.unpinnedHost(message: "no entry"))))
        XCTAssertTrue(PinRecoveryInterceptor.isPinMismatch(PinVaultError.sslHandshake(
            message: "x", cause: PinVaultError.certificate(message: "expired config", cause: PinVaultError.configExpired(expiresAt: 1))
        )), "an expired config is what a refetch repairs")
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(PinVaultError.io(message: "generic")))
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(URLError(.timedOut)))
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(PinVaultError.certificate(message: "not wrapped")))
    }

    func testAMismatchTheRefetchDoesNotFixEndsAfterOneRecovery() async {
        // The fallback session carries this interceptor too (as the library's
        // own does) and the updater keeps reporting success: the request still ends.
        let updates = Counter()
        let holder = Locked<PinnedSession?>(nil)
        let interceptor = PinRecoveryInterceptor(updater: { updates.increment(); return true }, newClientProvider: { holder.get() })
        let client = PinnedSession(interceptors: [interceptor], transport: FakeTransport { _ in
            throw PinVaultError.sslPeerUnverified(message: "pin mismatch")
        })
        holder.set(client)
        let error = await assertPinVaultError { _ = try await client.data(from: URL(string: "https://example.com/test")!) }
        XCTAssertEqual(error?.message, "pin mismatch")
        XCTAssertEqual(updates.count, 1, "one refetch, no nested recovery")
    }

    func testPinMismatchTriggersTheUpdaterAndRetriesOnTheNewClient() async throws {
        let updated = Counter()
        let fallback = fakeSession { _ in fakeResponse(200) }
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true }, newClientProvider: { fallback })
        let response = try await intercept(interceptor) { _ in throw PinVaultError.sslPeerUnverified(message: "pin mismatch") }
        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(response.statusCode, 200)
    }

    func testTheRetryRunsOnTheCallersChainFirst() async throws {
        let calls = Counter()
        let fallbackUsed = Counter()
        let fallback = fakeSession { _ in fallbackUsed.increment(); return fakeResponse(500) }
        let interceptor = PinRecoveryInterceptor(updater: { true }, newClientProvider: { fallback })
        let response = try await intercept(interceptor) { _ in
            if calls.increment() == 1 { throw mismatch() }
            return fakeResponse(200)
        }
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(fallbackUsed.count, 0)
    }

    func testTheFallbackRetryIsTaggedSoItDoesNotRecoverAgain() async throws {
        let tags = Locked<Set<PinnedExchange.Tag>>([])
        let fallback = fakeSession { exchange in tags.set(exchange.tags); return fakeResponse(200) }
        let interceptor = PinRecoveryInterceptor(updater: { true }, newClientProvider: { fallback })
        _ = try await intercept(interceptor) { _ in throw mismatch() }
        XCTAssertEqual(tags.get(), [.recoveryAttempt])

        // A tagged request goes straight through, failure or not.
        let updates = Counter()
        let plain = PinRecoveryInterceptor(updater: { updates.increment(); return true })
        do {
            _ = try await plain.intercept(exchange().tagged(.recoveryAttempt)) { _ in throw mismatch() }
            XCTFail("must rethrow")
        } catch {}
        XCTAssertEqual(updates.count, 0)
    }

    func testPinMismatchWithAFailedUpdateRethrowsTheOriginalError() async {
        let interceptor = PinRecoveryInterceptor(updater: { false }, newClientProvider: { nil })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in throw PinVaultError.sslPeerUnverified(message: "pin mismatch") }
        }
        XCTAssertEqual(error?.message, "pin mismatch")
    }

    func testAnUpdaterThatThrowsCountsAsAFailedUpdate() async {
        let interceptor = PinRecoveryInterceptor(updater: { throw PinVaultError.io(message: "offline") })
        let error = await assertPinVaultError { _ = try await self.intercept(interceptor) { _ in throw mismatch() } }
        guard case .sslHandshake? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(interceptor.trackedHosts["example.com"]?.attemptCount, 1)
    }

    func testSSLHandshakeWithACertificateCauseTriggersRecovery() async throws {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true }, newClientProvider: { fakeSession { _ in fakeResponse(200) } })
        let response = try await intercept(interceptor) { _ in
            throw PinVaultError.sslHandshake(message: "handshake failed", cause: PinVaultError.certificate(message: "cert invalid"))
        }
        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(response.statusCode, 200)
    }

    func testSSLHandshakeWithoutACertificateCauseDoesNotTriggerRecovery() async {
        // Only the typed cause counts, never the message text.
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in
                throw PinVaultError.sslHandshake(message: "Certificate pinning failure for host", cause: URLError(.secureConnectionFailed))
            }
        }
        guard case .sslHandshake? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(updated.count, 0, "updater must NOT be called for message-only matches")
    }

    func testAFallbackFailureRethrowsTheOriginalPinError() async {
        // The fallback session carries none of the caller's settings: its failure
        // (here a DNS error) must not replace the pin mismatch the caller hit.
        let fallback = fakeSession { _ in throw PinVaultError.io(message: "api.example.com", cause: URLError(.cannotFindHost)) }
        let interceptor = PinRecoveryInterceptor(updater: { true }, newClientProvider: { fallback })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in
                throw PinVaultError.sslPeerUnverified(message: "Certificate pinning failure for example.com")
            }
        }
        guard case .sslPeerUnverified(let message)? = error else { return XCTFail("caller must see the pin error, got \(String(describing: error))") }
        XCTAssertEqual(message, "Certificate pinning failure for example.com")
    }

    func testAnExpiredServerCertificateDoesNotTriggerAConfigRefresh() async {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in
                throw PinVaultError.sslHandshake(
                    message: "handshake failed",
                    cause: PinVaultError.certificateValidity(message: "Server certificate is expired or not yet valid: NotAfter: 2020-01-01")
                )
            }
        }
        XCTAssertEqual(updated.count, 0, "updater must NOT be called for a validity-window failure")
        guard case .certificateValidity? = error?.pinVaultCause else { return XCTFail("original cause must survive") }
    }

    func testAChainRefusedByThePlatformCAsDoesNotTriggerAConfigRefresh() async {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in
                throw PinVaultError.sslHandshake(message: "handshake failed", cause: PinVaultError.caTrust(message: "not trusted by the platform CAs"))
            }
        }
        XCTAssertEqual(updated.count, 0)
        guard case .caTrust? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
    }

    func testALeafIssuedForAnotherHostDoesNotTriggerAConfigRefresh() async {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true })
        _ = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in
                throw PinVaultError.sslHandshake(message: "x", cause: PinVaultError.hostnameMismatch(message: "not issued for example.com"))
            }
        }
        XCTAssertEqual(updated.count, 0)
    }

    func testAPlainCertificateCauseStillTriggersRecovery() async throws {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true }, newClientProvider: { fakeSession { _ in fakeResponse(200) } })
        let response = try await intercept(interceptor) { _ in throw mismatch() }
        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(response.statusCode, 200)
    }

    func testANonSSLErrorPassesThroughWithoutRecovery() async {
        let updated = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updated.increment(); return true })
        let error = await assertPinVaultError {
            _ = try await self.intercept(interceptor) { _ in throw PinVaultError.io(message: "timeout") }
        }
        XCTAssertEqual(error?.message, "timeout")
        XCTAssertEqual(updated.count, 0)
    }

    func testASuccessfulRecoveryDoesNotZeroThePerHostFailureCounter() async throws {
        // Clearing the state on success let a partial MITM keep the breaker
        // disarmed by interleaving forged handshakes with legitimate ones.
        let succeed = Locked(false)
        let interceptor = PinRecoveryInterceptor(updater: { succeed.get() }, newClientProvider: { fakeSession { _ in fakeResponse(200) } })
        _ = try? await intercept(interceptor) { _ in throw PinVaultError.sslPeerUnverified(message: "pin mismatch") }
        XCTAssertEqual(interceptor.trackedHosts["example.com"]?.attemptCount, 1, "a failure seeds the per-host state")

        succeed.set(true)
        let response = try await intercept(interceptor) { _ in throw PinVaultError.sslPeerUnverified(message: "pin mismatch") }
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(interceptor.trackedHosts["example.com"]?.attemptCount, 1, "the per-host state survives a successful recovery")
    }

    func testAStreamBodyIsNotSentAgainAfterTheRefetch() async {
        let updates = Counter()
        let calls = Counter()
        let interceptor = PinRecoveryInterceptor(updater: { updates.increment(); return true })
        var request = URLRequest(url: URL(string: "https://example.com/upload")!)
        request.httpMethod = "POST"
        request.httpBodyStream = InputStream(data: Data("once".utf8))
        let error = await assertPinVaultError {
            _ = try await interceptor.intercept(PinnedExchange(request: request)) { _ in
                calls.increment()
                throw mismatch()
            }
        }
        guard case .sslHandshake? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(updates.count, 1, "the pins are still repaired")
        XCTAssertEqual(calls.count, 1, "the consumed body is not sent again")
    }

    func testAFailedRetryCountsAsAFailure() async {
        let interceptor = PinRecoveryInterceptor(updater: { true })
        _ = await assertPinVaultError { _ = try await self.intercept(interceptor) { _ in throw mismatch() } }
        XCTAssertEqual(interceptor.trackedHosts["example.com"]?.attemptCount, 1)
    }
}

/// A session over a ``FakeTransport``.
func fakeSession(_ answer: @escaping @Sendable (PinnedExchange) async throws -> PinnedResponse) -> PinnedSession {
    PinnedSession(transport: FakeTransport(answer: answer))
}
