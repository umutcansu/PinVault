import Foundation
import XCTest
@testable import PinVault

/// Records every request and answers 200 (or what `status` says for the host).
final class RecordingURLProtocol: URLProtocol, @unchecked Sendable {
    struct Recorded: Sendable {
        let url: URL
        let method: String
        let contentType: String?
        let body: String
    }

    static let recorded = Locked<[String: [Recorded]]>([:])
    static let status = Locked<[String: Int]>([:])

    static func requests(host: String) -> [Recorded] {
        recorded.withLock { $0[host] ?? [] }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host else { return }
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                body.append(buffer, count: read)
            }
            stream.close()
        }
        let entry = Recorded(
            url: url, method: request.httpMethod ?? "GET",
            contentType: request.value(forHTTPHeaderField: "Content-Type"),
            body: String(decoding: body, as: UTF8.self)
        )
        Self.recorded.withLock { $0[host, default: []].append(entry) }
        let code = Self.status.withLock { $0[host] } ?? 200
        let response = HTTPURLResponse(url: url, statusCode: code, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(#"{"saved":true}"#.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RecordingURLProtocol.self]
        return URLSession(configuration: configuration)
    }
}

/// Port of PinVaultBackendReporterTest: the JSON the demo-server's routes accept.
final class PinVaultBackendReporterTests: XCTestCase {

    private var host = ""

    override func setUp() {
        super.setUp()
        host = "reports-\(UUID().uuidString.lowercased()).example"
    }

    private func reporter(reportSuccessEvents: Bool = true, dedupWindowMs: Int64 = 0,
                          now: @escaping @Sendable () -> Int64 = { 1_000 }) -> PinVaultBackendReporter {
        PinVaultBackendReporter(
            managementUrl: "https://\(host):6650/", session: RecordingURLProtocol.session(),
            reportSuccessEvents: reportSuccessEvents, dedupWindowMs: dedupWindowMs, now: now
        )
    }

    private func connection(success: Bool, host: String = "api.example.com", pin: String = "AAAAprimary=") -> PinVaultConnectionEvent {
        .connection(hostname: host, success: success, pinVersion: 13, deviceManufacturer: "Samsung", deviceModel: "SM-G975F",
                    actualPin: pin, expectedPins: ["AAAAprimary=", "BBBBbackup="])
    }

    func testClientCertRenewalAndAttestationEventsAreNotReported() async {
        let reporter = reporter()
        await reporter.handle(.clientCertRenewal(status: .renewed, notAfterEpochMs: 1, via: .mtls, configApiId: "default",
                                                 deviceManufacturer: "Samsung", deviceModel: "SM-G975F"))
        await reporter.handle(.attestation(configApiId: "default", status: .pass, arc: nil, rejectionReasons: [], warnings: [],
                                           tokenExpiresAt: nil, deviceManufacturer: "Apple", deviceModel: "iPhone17,1"))
        XCTAssertTrue(RecordingURLProtocol.requests(host: host).isEmpty)
    }

    func testASuccessEventPostsHealthyWithAllFields() async throws {
        await reporter().handle(connection(success: true))
        let recorded = try XCTUnwrap(RecordingURLProtocol.requests(host: host).first)
        XCTAssertEqual(recorded.method, "POST")
        XCTAssertEqual(recorded.url.path, "/api/v1/connection-history/client-report")
        XCTAssertEqual(recorded.contentType, "application/json; charset=utf-8")
        XCTAssertEqual(
            recorded.body,
            #"{"hostname":"api.example.com","status":"healthy","responseTimeMs":0,"pinMatched":true,"pinVersion":13,"#
                + #""deviceManufacturer":"Samsung","deviceModel":"SM-G975F","serverCertPin":"AAAAprimary=","storedPin":"AAAAprimary="}"#
        )
    }

    func testAMismatchPostsPinMismatch() async throws {
        await reporter().handle(connection(success: false, host: "evil.example.com", pin: "ATTACKER="))
        let body = try XCTUnwrap(RecordingURLProtocol.requests(host: host).first?.body)
        XCTAssertTrue(body.contains(#""status":"pin_mismatch""#))
        XCTAssertTrue(body.contains(#""pinMatched":false"#))
        XCTAssertTrue(body.contains(#""serverCertPin":"ATTACKER=""#))
    }

    func testConfigUpdatesGoToTheirOwnEndpoint() async throws {
        let reporter = reporter()
        await reporter.handle(.configUpdate(status: .updated, newVersion: 4, deviceManufacturer: "Apple", deviceModel: "iPhone17,1"))
        await reporter.handle(.configUpdate(status: .failed, newVersion: 3, deviceManufacturer: "Apple", deviceModel: "iPhone17,1",
                                            failureReason: #"bad "quote" \ here"#))
        let requests = RecordingURLProtocol.requests(host: host)
        XCTAssertEqual(requests.map(\.url.path), Array(repeating: "/api/v1/connection-history/config-update-report", count: 2))
        XCTAssertEqual(requests[0].body, #"{"status":"config_updated","pinVersion":4,"deviceManufacturer":"Apple","deviceModel":"iPhone17,1"}"#)
        XCTAssertTrue(requests[1].body.hasSuffix(#""failureReason":"bad \"quote\" \\ here"}"#), requests[1].body)
        XCTAssertTrue(requests[1].body.hasPrefix(#"{"status":"config_update_failed""#))
    }

    func testSuccessEventsCanBeSuppressedButAnomaliesNever() async {
        let reporter = reporter(reportSuccessEvents: false)
        await reporter.handle(connection(success: true))
        await reporter.handle(.configUpdate(status: .unchanged, newVersion: 1, deviceManufacturer: "A", deviceModel: "B"))
        XCTAssertTrue(RecordingURLProtocol.requests(host: host).isEmpty)
        await reporter.handle(connection(success: false))
        await reporter.handle(.configUpdate(status: .failed, newVersion: 1, deviceManufacturer: "A", deviceModel: "B", failureReason: "x"))
        XCTAssertEqual(RecordingURLProtocol.requests(host: host).count, 2)
    }

    func testDuplicateHealthyReportsInsideTheWindowAreDropped() async {
        let clock = Locked<Int64>(1_000)
        let reporter = reporter(dedupWindowMs: 60_000, now: { clock.get() })
        await reporter.handle(connection(success: true))
        await reporter.handle(connection(success: true))
        await reporter.handle(connection(success: true, pin: "OTHER="))
        await reporter.handle(connection(success: false))
        XCTAssertEqual(RecordingURLProtocol.requests(host: host).count, 3)
        clock.set(61_001)
        await reporter.handle(connection(success: true))
        XCTAssertEqual(RecordingURLProtocol.requests(host: host).count, 4)
    }

    func testServerErrorsAndUnreachableHostsAreSwallowed() async {
        RecordingURLProtocol.status.withLock { $0[host] = 404 }
        await reporter().handle(connection(success: true))
        XCTAssertEqual(RecordingURLProtocol.requests(host: host).count, 1)
        let unreachable = PinVaultBackendReporter(managementUrl: "https://127.0.0.1:1/", session: PinVaultBackendReporter.defaultSession())
        await unreachable.handle(connection(success: true))
    }

    func testEndpointsAreBuiltFromTheManagementURL() {
        XCTAssertEqual(PinVaultBackendReporter.buildEndpoint("https://h:6650///", "api/x"), "https://h:6650/api/x")
        let reporter = PinVaultBackendReporter(managementUrl: "http://192.168.1.10:6650")
        XCTAssertEqual(reporter.connectionEndpoint, "http://192.168.1.10:6650/api/v1/connection-history/client-report")
        XCTAssertEqual(reporter.configUpdateEndpoint, "http://192.168.1.10:6650/api/v1/connection-history/config-update-report")
    }

    func testTheBuilderExtensionInstallsTheReporterAsTheListener() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://api.example.com") { $0.allowUnpinnedConfigApi().allowUnsigned() }
            .reportToPinVaultBackend(managementUrl: "https://reports.example.com/", reportSuccessEvents: false, dedupWindowMs: 60_000)
            .build()
        XCTAssertNotNil(config.connectionListener)
    }
}
