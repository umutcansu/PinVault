import Foundation
import Network
import Security
import XCTest
@testable import PinVault

/// The certificates of `Fixtures/tls` (see its `generate.sh`).
enum TLSFixture {

    static func data(_ name: String, _ ext: String) -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures/tls") else {
            fatalError("missing TLS fixture \(name).\(ext)")
        }
        return try! Data(contentsOf: url)
    }

    static func cert(_ name: String) -> X509Certificate {
        try! X509Certificate(der: data(name, "der"))
    }

    static func secCert(_ name: String) -> SecCertificate {
        cert(name).secCertificate()!
    }

    /// The SPKI pin of a fixture certificate.
    static func pin(_ name: String) -> String {
        cert(name).spkiPin
    }

    /// The pin of a key that signs nothing: the backup pin of a host entry.
    static var backupPin: String {
        let json = try! JSONSerialization.jsonObject(with: data("fixtures", "json")) as! [String: [String: Any]]
        return json["backup"]!["pin"] as! String
    }

    static func p12(_ name: String) -> Data {
        data(name, "p12")
    }

    static func identity(_ name: String) -> ClientIdentity {
        try! ClientIdentity.fromPKCS12(p12(name), password: "changeit")
    }

    /// A moment every non-dated fixture is valid at: a day after the leaves were made.
    static var validNow: Date {
        cert("leaf").notBefore.addingTimeInterval(86_400)
    }
}

/// A manager whose certificate clock sits inside the fixtures' validity and
/// that ignores the E2E hooks of `PinVault.shared`.
func testManager() -> DynamicSSLManager {
    let manager = DynamicSSLManager()
    let now = TLSFixture.validNow
    manager.wallClock = { now }
    manager.connectionRedirect = { _ in nil }
    manager.externalGeneration = { 0 }
    return manager
}

/// A config with one host entry: `pins` plus the backup pin.
func pinConfig(_ host: String, _ pins: [String], version: Int = 1, expiresAt: Int64 = 0, mtls: Bool = false) -> CertificateConfig {
    CertificateConfig(
        version: version,
        pins: [HostPin(hostname: host, sha256: pins + [TLSFixture.backupPin], version: version, mtls: mtls)],
        expiresAt: expiresAt
    )
}

/// Asserts that `body` throws a ``PinVaultError`` and returns it.
@discardableResult
func assertPinVaultError(
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> Void
) async -> PinVaultError? {
    do {
        try await body()
        XCTFail("expected an error", file: file, line: line)
        return nil
    } catch let error as PinVaultError {
        return error
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
        return nil
    }
}

/// Asserts that `body` throws a ``PinVaultError`` and returns it (synchronous).
@discardableResult
func assertThrowsPinVault(
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) -> PinVaultError? {
    do {
        try body()
        XCTFail("expected an error", file: file, line: line)
        return nil
    } catch let error as PinVaultError {
        return error
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
        return nil
    }
}

extension PinVaultError {
    /// The cause as a ``PinVaultError``.
    var pinVaultCause: PinVaultError? { cause as? PinVaultError }

    /// This error and its causes, outermost first.
    var causeChain: [any Error] {
        var chain: [any Error] = [self]
        var next = cause
        while let current = next, chain.count < 10 {
            chain.append(current)
            next = (current as? PinVaultError)?.cause
        }
        return chain
    }
}

/// An in-process HTTP/1.1 server on 127.0.0.1 (Network.framework), plain or
/// TLS with an identity from a test P12 — the MockWebServer of these tests.
/// Keeps connections alive, records every request with the connection it came
/// on and the client certificate that connection presented.
final class TestServer: @unchecked Sendable {

    enum ClientAuth {
        case none
        /// A CertificateRequest is sent and the handshake fails without a client
        /// certificate. (Network.framework has no "request but do not require"
        /// server option on Apple platforms, so "presented none" shows as a refused connection.)
        case required
    }

    struct Response: Sendable {
        var status = 200
        var headers: [String: String] = [:]
        var body = Data("ok".utf8)

        static func ok(_ body: String = "ok") -> Response { Response(body: Data(body.utf8)) }
        static func status(_ status: Int, _ body: String = "", headers: [String: String] = [:]) -> Response {
            Response(status: status, headers: headers, body: Data(body.utf8))
        }
    }

    struct RecordedRequest: Sendable {
        let method: String
        let path: String
        let headers: [(String, String)]
        let body: Data
        /// Index of the connection in accept order (0-based).
        let connection: Int
        /// Index of the request on its connection (OkHttp `sequenceNumber`).
        let sequenceNumber: Int
        /// The client's leaf on that connection, nil without one.
        let clientCertificate: X509Certificate?
        let tlsVersion: tls_protocol_version_t?

        func header(_ name: String) -> String? {
            headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
        }
    }

    private let queue = DispatchQueue(label: "TestServer")
    private let listener: NWListener
    private let state = Locked(ServerState())
    let isTLS: Bool

    private struct ServerState {
        var queued: [Response] = []
        var handler: (@Sendable (RecordedRequest) -> Response)?
        var requests: [RecordedRequest] = []
        var taken = 0
        var connections = 0
        var open: [Int: NWConnection] = [:]
    }

    /// - Parameters:
    ///   - p12: server identity (`Fixtures/tls/<p12>.p12`); nil = plain HTTP.
    ///   - chain: further certificates the server sends after its leaf (`<name>.der`).
    init(p12: String?, chain: [String] = [], clientAuth: ClientAuth = .none) throws {
        let parameters: NWParameters
        if let p12 {
            let identity = TLSFixture.identity(p12)
            let tls = NWProtocolTLS.Options()
            let certificates = [identity.chain[0]] + chain.map(TLSFixture.secCert)
            sec_protocol_options_set_local_identity(
                tls.securityProtocolOptions,
                sec_identity_create_with_certificates(identity.identity, certificates as CFArray)!
            )
            switch clientAuth {
            case .none:
                break
            case .required:
                sec_protocol_options_set_peer_authentication_required(tls.securityProtocolOptions, true)
            }
            if clientAuth != .none {
                // Any client certificate will do; the tests look at which one came.
                sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in complete(true) }, queue)
            }
            parameters = NWParameters(tls: tls)
            isTLS = true
        } else {
            parameters = .tcp
            isTLS = false
        }
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: 0)
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters)
    }

    /// Starts listening; returns once the port is known.
    func start() async throws {
        let ready = Locked(false)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if !ready.withLock({ done in defer { done = true }; return done }) { continuation.resume() }
                case .failed(let error):
                    if !ready.withLock({ done in defer { done = true }; return done }) { continuation.resume(throwing: error) }
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            listener.start(queue: queue)
        }
    }

    func stop() {
        listener.cancel()
        let open = state.withLock { state -> [NWConnection] in
            defer { state.open = [:] }
            return Array(state.open.values)
        }
        open.forEach { $0.cancel() }
    }

    var port: Int { Int(listener.port?.rawValue ?? 0) }

    /// `https://localhost:<port><path>` (or `http://`).
    func url(_ path: String = "/", host: String = "localhost") -> URL {
        URL(string: "\(isTLS ? "https" : "http")://\(host):\(port)\(path)")!
    }

    func enqueue(_ response: Response) {
        state.withLock { $0.queued.append(response) }
    }

    /// Answers every request (instead of the queue).
    func setHandler(_ handler: (@Sendable (RecordedRequest) -> Response)?) {
        state.withLock { $0.handler = handler }
    }

    var requestCount: Int { state.withLock { $0.requests.count } }
    var connectionCount: Int { state.withLock { $0.connections } }
    var openConnectionCount: Int { state.withLock { $0.open.count } }
    var requests: [RecordedRequest] { state.withLock { $0.requests } }

    /// The next request not taken yet (FIFO), nil when there is none.
    func takeRequest() -> RecordedRequest? {
        state.withLock { state in
            guard state.taken < state.requests.count else { return nil }
            defer { state.taken += 1 }
            return state.requests[state.taken]
        }
    }

    // MARK: Connections

    private final class ConnectionState: @unchecked Sendable {
        let index: Int
        var buffer = Data()
        var served = 0
        var clientCertificate: X509Certificate?
        var tlsVersion: tls_protocol_version_t?
        init(index: Int) { self.index = index }
    }

    private func accept(_ connection: NWConnection) {
        let index = state.withLock { state -> Int in
            defer { state.connections += 1 }
            state.open[state.connections] = connection
            return state.connections
        }
        let context = ConnectionState(index: index)
        connection.stateUpdateHandler = { [weak self] update in
            switch update {
            case .ready:
                if let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata {
                    let security = metadata.securityProtocolMetadata
                    context.tlsVersion = sec_protocol_metadata_get_negotiated_tls_protocol_version(security)
                    var leaf: X509Certificate?
                    _ = sec_protocol_metadata_access_peer_certificate_chain(security) { certificate in
                        if leaf == nil {
                            let ref = sec_certificate_copy_ref(certificate).takeRetainedValue()
                            leaf = try? X509Certificate(certificate: ref)
                        }
                    }
                    context.clientCertificate = leaf
                }
                self?.receive(connection, context)
            case .failed, .cancelled:
                self?.state.withLock { _ = $0.open.removeValue(forKey: index) }
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func receive(_ connection: NWConnection, _ context: ConnectionState) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                context.buffer.append(data)
                while let request = self.parse(context) {
                    let response = self.respond(to: request)
                    connection.send(content: self.encode(response), completion: .contentProcessed { _ in })
                    if response.headers["Connection"]?.lowercased() == "close" {
                        connection.cancel()
                        return
                    }
                }
            }
            if complete || error != nil {
                connection.cancel()
                return
            }
            self.receive(connection, context)
        }
    }

    private func respond(to request: RecordedRequest) -> Response {
        state.withLock { state -> Response in
            state.requests.append(request)
            if let handler = state.handler { return handler(request) }
            return state.queued.isEmpty ? .ok() : state.queued.removeFirst()
        }
    }

    /// One complete request from the buffer, or nil when more bytes are needed.
    private func parse(_ context: ConnectionState) -> RecordedRequest? {
        let separator = Data("\r\n\r\n".utf8)
        guard let end = context.buffer.range(of: separator) else { return nil }
        let head = String(decoding: context.buffer[context.buffer.startIndex..<end.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let requestLine = lines.removeFirst().split(separator: " ")
        guard requestLine.count >= 2 else { return nil }
        let headers: [(String, String)] = lines.compactMap { line in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            return (String(line[..<colon]), line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
        func header(_ name: String) -> String? {
            headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
        }
        var bodyStart = end.upperBound
        var body = Data()
        if header("Transfer-Encoding")?.lowercased().contains("chunked") == true {
            // Chunked: size line, data, CRLF … 0-size chunk, CRLF.
            var cursor = bodyStart
            while true {
                guard let lineEnd = context.buffer[cursor...].range(of: Data("\r\n".utf8)) else { return nil }
                let sizeText = String(decoding: context.buffer[cursor..<lineEnd.lowerBound], as: UTF8.self)
                guard let size = Int(sizeText.split(separator: ";").first ?? "", radix: 16) else { return nil }
                let dataStart = lineEnd.upperBound
                guard context.buffer.endIndex >= dataStart + size + 2 else { return nil }
                if size == 0 {
                    bodyStart = dataStart + 2
                    break
                }
                body.append(context.buffer[dataStart..<(dataStart + size)])
                cursor = dataStart + size + 2
            }
        } else {
            let length = Int(header("Content-Length") ?? "0") ?? 0
            guard context.buffer.endIndex >= bodyStart + length else { return nil }
            body = Data(context.buffer[bodyStart..<(bodyStart + length)])
            bodyStart += length
        }
        context.buffer = Data(context.buffer[bodyStart...])
        defer { context.served += 1 }
        return RecordedRequest(
            method: String(requestLine[0]),
            path: String(requestLine[1]),
            headers: headers,
            body: body,
            connection: context.index,
            sequenceNumber: context.served,
            clientCertificate: context.clientCertificate,
            tlsVersion: context.tlsVersion
        )
    }

    private func encode(_ response: Response) -> Data {
        var text = "HTTP/1.1 \(response.status) \(HTTPURLResponse.localizedString(forStatusCode: response.status))\r\n"
        for (name, value) in response.headers { text += "\(name): \(value)\r\n" }
        // `Transfer-Encoding: chunked` in the headers: the body goes out in 1 KiB chunks, no Content-Length.
        if response.headers.contains(where: { $0.key.lowercased() == "transfer-encoding" && $0.value.lowercased() == "chunked" }) {
            var out = Data((text + "\r\n").utf8)
            var offset = 0
            while offset < response.body.count {
                let chunk = response.body[offset..<min(offset + 1024, response.body.count)]
                out += Data((String(chunk.count, radix: 16) + "\r\n").utf8) + chunk + Data("\r\n".utf8)
                offset += chunk.count
            }
            return out + Data("0\r\n\r\n".utf8)
        }
        text += "Content-Length: \(response.body.count)\r\n\r\n"
        return Data(text.utf8) + response.body
    }
}

/// Polls `condition` until it holds or `timeout` passes.
func eventually(timeout: TimeInterval = 5, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 20_000_000)
    }
    return condition()
}

/// Collects connection events (thread-safe).
final class EventRecorder: @unchecked Sendable {
    private let events = Locked<[PinVaultConnectionEvent]>([])

    var listener: PinVaultConnectionListener {
        { [events] event in events.withLock { $0.append(event) } }
    }

    var all: [PinVaultConnectionEvent] { events.withLock { $0 } }

    /// The `.connection` events, as (hostname, success).
    var connections: [(String, Bool)] {
        all.compactMap { event in
            if case .connection(let hostname, let success, _, _, _, _, _) = event { return (hostname, success) }
            return nil
        }
    }
}
